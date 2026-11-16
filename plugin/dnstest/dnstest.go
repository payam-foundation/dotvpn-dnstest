// Package dnstest is a CoreDNS plugin for a DNS leak test. It is authoritative
// for one zone and never recurses.
//
// A page asks the browser to look up N.ID.<zone> for a random ID. The recursive
// resolver that does the asking reaches this server, which remembers its address
// under ID for a short while, in memory only. The page then reads who asked from
// the HTTP side (see http.go). v4.<zone> and v6.<zone> exist only to give a page
// an IPv4-only and an IPv6-only address to fetch.
package dnstest

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

const (
	maxIDs        = 50_000 // lookups remembered at once; new ones are dropped beyond this
	maxResolvers  = 16     // distinct resolver addresses kept per ID
	staticTTL     = 300
	probeTTL      = 0
	negativeTTL   = 60
	idLength      = 32
	maxProbeLabel = 16
)

// Handler answers the zone.
type Handler struct {
	Next plugin.Handler

	zone string // lower case, fully qualified, trailing dot
	ip4  netip.Addr
	ip6  netip.Addr
	ttl  time.Duration

	mu  sync.Mutex
	ids map[string]*entry
}

type entry struct {
	resolvers map[netip.Addr]struct{}
	expires   time.Time
}

func newHandler(zone string, ip4, ip6 netip.Addr, ttl time.Duration) *Handler {
	return &Handler{zone: strings.ToLower(dns.Fqdn(zone)), ip4: ip4, ip6: ip6, ttl: ttl, ids: map[string]*entry{}}
}

// Name implements plugin.Handler.
func (h *Handler) Name() string { return "dnstest" }

// record remembers that resolver asked for id.
func (h *Handler) record(id string, resolver netip.Addr, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.ids[id]
	if e == nil {
		if len(h.ids) >= maxIDs {
			return
		}
		e = &entry{resolvers: map[netip.Addr]struct{}{}}
		h.ids[id] = e
	}
	if len(e.resolvers) < maxResolvers {
		e.resolvers[resolver] = struct{}{}
	}
	e.expires = now.Add(h.ttl)
}

// resolversFor returns who asked for id, sorted, or nil.
func (h *Handler) resolversFor(id string, now time.Time) []netip.Addr {
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.ids[id]
	if e == nil || !now.Before(e.expires) {
		return nil
	}
	out := make([]netip.Addr, 0, len(e.resolvers))
	for a := range e.resolvers {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// sweep deletes expired lookups.
func (h *Handler) sweep(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, e := range h.ids {
		if !now.Before(e.expires) {
			delete(h.ids, id)
		}
	}
}

// kind says what a name under the zone is.
type kind int

const (
	nameNone  kind = iota // does not exist
	nameApex              // the zone itself
	nameEmpty             // ID.<zone>: no data of its own, but N.ID.<zone> lies below it
	nameBoth              // answers A and AAAA
	nameV4                // answers A only
	nameV6                // answers AAAA only
	nameProbe             // N.ID.<zone>: answers A and AAAA and records the asker
)

// classify returns what rel (the name with the zone cut off, no trailing dot)
// is, and the lookup ID for a probe.
func classify(rel string) (kind, string) {
	if rel == "" {
		return nameApex, ""
	}
	labels := strings.Split(rel, ".")
	switch len(labels) {
	case 1:
		switch labels[0] {
		case "v4":
			return nameV4, ""
		case "v6":
			return nameV6, ""
		case "api", "ns1":
			return nameBoth, ""
		}
		// NODATA, not NXDOMAIN: a resolver minimising the query name asks for
		// this name first and must not stop before it reaches the probe name.
		if isID(labels[0]) {
			return nameEmpty, ""
		}
	case 2:
		if isID(labels[1]) && isProbeLabel(labels[0]) {
			return nameProbe, labels[1]
		}
	}
	return nameNone, ""
}

func isID(s string) bool {
	if len(s) != idLength {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func isProbeLabel(s string) bool {
	if s == "" || len(s) > maxProbeLabel {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

// ServeDNS implements plugin.Handler.
func (h *Handler) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := strings.ToLower(state.Name())
	if !dns.IsSubDomain(h.zone, qname) {
		return dns.RcodeRefused, nil
	}
	rel := strings.TrimSuffix(strings.TrimSuffix(qname, h.zone), ".")
	k, id := classify(rel)

	if k == nameProbe {
		if from, err := netip.ParseAddr(state.IP()); err == nil {
			h.record(id, from.Unmap().WithZone(""), time.Now())
		}
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.RecursionAvailable = false

	switch {
	case k == nameNone:
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{h.soa()}
	case k == nameApex && (state.QType() == dns.TypeSOA || state.QType() == dns.TypeANY):
		m.Answer = []dns.RR{h.soa()}
	case k == nameApex && state.QType() == dns.TypeNS:
		m.Answer = []dns.RR{h.ns()}
		m.Extra = h.glue()
	default:
		ttl := uint32(staticTTL)
		if k == nameProbe {
			ttl = probeTTL
		}
		wantA := k == nameBoth || k == nameV4 || k == nameProbe
		wantAAAA := k == nameBoth || k == nameV6 || k == nameProbe
		hdr := func(t uint16) dns.RR_Header {
			return dns.RR_Header{Name: state.QName(), Rrtype: t, Class: dns.ClassINET, Ttl: ttl}
		}
		switch state.QType() {
		case dns.TypeA, dns.TypeANY:
			if wantA && h.ip4.IsValid() {
				m.Answer = []dns.RR{&dns.A{Hdr: hdr(dns.TypeA), A: h.ip4.AsSlice()}}
			}
		case dns.TypeAAAA:
			if wantAAAA && h.ip6.IsValid() {
				m.Answer = []dns.RR{&dns.AAAA{Hdr: hdr(dns.TypeAAAA), AAAA: h.ip6.AsSlice()}}
			}
		}
		if len(m.Answer) == 0 {
			m.Ns = []dns.RR{h.soa()} // name exists, type does not
		}
	}

	m = state.Scrub(m)
	if err := w.WriteMsg(m); err != nil {
		return dns.RcodeServerFailure, err
	}
	return dns.RcodeSuccess, nil
}

func (h *Handler) soa() dns.RR {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: h.zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: negativeTTL},
		Ns:      "ns1." + h.zone,
		Mbox:    "hostmaster." + h.zone,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  negativeTTL,
	}
}

func (h *Handler) ns() dns.RR {
	return &dns.NS{Hdr: dns.RR_Header{Name: h.zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: staticTTL}, Ns: "ns1." + h.zone}
}

func (h *Handler) glue() []dns.RR {
	name := "ns1." + h.zone
	var rr []dns.RR
	if h.ip4.IsValid() {
		rr = append(rr, &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: staticTTL}, A: h.ip4.AsSlice()})
	}
	if h.ip6.IsValid() {
		rr = append(rr, &dns.AAAA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: staticTTL}, AAAA: h.ip6.AsSlice()})
	}
	return rr
}
