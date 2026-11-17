package dnstest

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/payam-foundation/dotvpn-dnstest/internal/asn"
)

// Per client address: a burst of rateBurst requests, then rateEvery between requests.
const (
	rateBurst   = 30
	rateEvery   = 250 * time.Millisecond
	maxLimiters = 100_000
)

type network struct {
	IP      string `json:"ip"`
	Family  string `json:"family,omitempty"`
	ASN     string `json:"asn"`
	Org     string `json:"org"`
	Country string `json:"country"`
}

func describe(src *asn.Source, ip netip.Addr) network {
	info := src.Lookup(ip)
	n := network{IP: ip.String(), ASN: info.AS(), Org: info.Org, Country: info.Country}
	if ip.Is4() {
		n.Family = "IPv4"
	} else {
		n.Family = "IPv6"
	}
	return n
}

type limiter struct {
	mu   sync.Mutex
	seen map[netip.Addr]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func (l *limiter) allow(ip netip.Addr, now time.Time) bool {
	// An IPv6 subscriber owns a whole /64; keying on the full address would let
	// one of them fill the table and lock everyone else out.
	if ip.Is6() {
		p, _ := ip.Prefix(64) // 64 is valid for IPv6, so no error
		ip = p.Addr()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen == nil {
		l.seen = map[netip.Addr]*bucket{}
	}
	b := l.seen[ip]
	if b == nil {
		if len(l.seen) >= maxLimiters {
			return false
		}
		b = &bucket{tokens: rateBurst, last: now}
		l.seen[ip] = b
	}
	b.tokens += float64(now.Sub(b.last)) / float64(rateEvery)
	if b.tokens > rateBurst {
		b.tokens = rateBurst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *limiter) sweep(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip, b := range l.seen {
		if now.Sub(b.last) > rateEvery*rateBurst {
			delete(l.seen, ip)
		}
	}
}

// clientAddr is the address of whoever asked. A proxy on a private network
// (Caddy in the same compose project) is believed about the address it forwards.
func clientAddr(r *http.Request) (netip.Addr, bool) {
	hostPort, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	remote := hostPort.Addr().Unmap()
	if remote.IsPrivate() || remote.IsLoopback() {
		fwd := r.Header.Get("X-Forwarded-For")
		if fwd != "" {
			last := strings.TrimSpace(fwd[strings.LastIndex(fwd, ",")+1:])
			if ip, err := netip.ParseAddr(last); err == nil {
				return ip.Unmap().WithZone(""), true
			}
		}
	}
	return remote.WithZone(""), true
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// isPublic is false for addresses that say nothing about a network: private, loopback, link-local, shared (carrier-grade NAT).
func isPublic(ip netip.Addr) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !cgnat.Contains(ip)
}

// httpHandler serves /r/{id}, /ip, /asn and /healthz. origin is the one site allowed to read the answers.
func (h *Handler) httpHandler(src *asn.Source, origin string, lim *limiter) http.Handler {
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, r *http.Request, body any) {
		hd := w.Header()
		hd.Set("Content-Type", "application/json")
		hd.Set("Cache-Control", "no-store")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Add("Vary", "Origin")
		if origin != "" && r.Header.Get("Origin") == origin {
			hd.Set("Access-Control-Allow-Origin", origin)
		}
		_ = json.NewEncoder(w).Encode(body)
	}

	mux.HandleFunc("GET /r/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := strings.ToLower(r.PathValue("id"))
		out := []network{}
		if isID(id) {
			for _, ip := range h.resolversFor(id, time.Now()) {
				out = append(out, describe(src, ip))
			}
		}
		reply(w, r, map[string]any{"resolvers": out})
	})
	mux.HandleFunc("GET /ip", func(w http.ResponseWriter, r *http.Request) {
		ip, ok := clientAddr(r)
		if !ok {
			http.Error(w, "no address", http.StatusBadRequest)
			return
		}
		reply(w, r, describe(src, ip))
	})
	mux.HandleFunc("GET /asn", func(w http.ResponseWriter, r *http.Request) {
		ip, err := netip.ParseAddr(strings.TrimSpace(r.URL.Query().Get("ip")))
		if err != nil || !isPublic(ip.Unmap().WithZone("")) {
			http.Error(w, "not a public address", http.StatusBadRequest)
			return
		}
		reply(w, r, describe(src, ip.Unmap().WithZone("")))
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("ok\n"))
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			if ip, ok := clientAddr(r); !ok || !lim.allow(ip, time.Now()) {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "slow down", http.StatusTooManyRequests)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}
