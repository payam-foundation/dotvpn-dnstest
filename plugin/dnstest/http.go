package dnstest

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/payam-foundation/dotvpn-dnstest/internal/asn"
	"github.com/payam-foundation/dotvpn-dnstest/internal/geo"
)

// Per client address: a burst of rateBurst requests, then rateEvery between requests.
// One page check costs 4 to 8 requests, and a VPN exit address is shared by many
// visitors, so the budget must cover a crowd behind one address.
const (
	rateBurst   = 300
	rateEvery   = 50 * time.Millisecond
	maxLimiters = 100_000
)

type network struct {
	IP      string `json:"ip"`
	Family  string `json:"family,omitempty"`
	ASN     string `json:"asn"`
	Org     string `json:"org"`
	Country string `json:"country"`
	Region  string `json:"region"`
	City    string `json:"city"`
}

// describe joins the network (ASN table) and the place (city database). The city
// database is the better source of the country; the ASN table covers for it while
// it is missing or does not know the address.
func describe(networks *asn.Source, places *geo.Source, ip netip.Addr) network {
	info := networks.Lookup(ip)
	place := places.Lookup(ip)
	n := network{IP: ip.String(), ASN: info.AS(), Org: info.Org, Country: info.Country, Region: place.Region, City: place.City}
	if place.Country != "" {
		n.Country = place.Country
	}
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
func (h *Handler) httpHandler(networks *asn.Source, places *geo.Source, origin string, lim *limiter) http.Handler {
	mux := http.NewServeMux()
	// cors runs before the rate limit, so a 429 is readable by the page too.
	cors := func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Add("Vary", "Origin")
		if origin != "" && r.Header.Get("Origin") == origin {
			hd.Set("Access-Control-Allow-Origin", origin)
		}
	}
	reply := func(w http.ResponseWriter, _ *http.Request, body any) {
		hd := w.Header()
		hd.Set("Content-Type", "application/json")
		hd.Set("Cache-Control", "no-store")
		hd.Set("X-Content-Type-Options", "nosniff")
		_ = json.NewEncoder(w).Encode(body)
	}

	mux.HandleFunc("GET /r/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := strings.ToLower(r.PathValue("id"))
		out := []network{}
		if isID(id) {
			for _, ip := range h.resolversFor(id, time.Now()) {
				out = append(out, describe(networks, places, ip))
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
		reply(w, r, describe(networks, places, ip))
	})
	mux.HandleFunc("GET /asn", func(w http.ResponseWriter, r *http.Request) {
		ip, err := netip.ParseAddr(strings.TrimSpace(r.URL.Query().Get("ip")))
		if err != nil || !isPublic(ip.Unmap().WithZone("")) {
			http.Error(w, "not a public address", http.StatusBadRequest)
			return
		}
		reply(w, r, describe(networks, places, ip.Unmap().WithZone("")))
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("ok\n"))
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cors(w, r)
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
