package dnstest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"github.com/payam-foundation/dotvpn-dnstest/internal/asn"
)

const (
	zone = "dnstest.example.org."
	id   = "0123456789abcdef0123456789abcdef"
)

var (
	ip4 = netip.MustParseAddr("203.0.113.10")
	ip6 = netip.MustParseAddr("2001:db8::10")
)

func ask(t *testing.T, h *Handler, name string, qtype uint16, from string) (int, *dns.Msg) {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(name, qtype)
	rec := dnstest.NewRecorder(&test.ResponseWriter{RemoteIP: from})
	code, err := h.ServeDNS(context.Background(), rec, req)
	if err != nil {
		t.Fatal(err)
	}
	return code, rec.Msg
}

func TestClassify(t *testing.T) {
	cases := []struct {
		rel  string
		want kind
		id   string
	}{
		{"", nameApex, ""},
		{"v4", nameV4, ""},
		{"v6", nameV6, ""},
		{"api", nameBoth, ""},
		{"ns1", nameBoth, ""},
		{"1." + id, nameProbe, id},
		{"abc123." + id, nameProbe, id},
		{id, nameEmpty, ""},                          // between the probe name and the zone
		{"1.ABCDEF", nameNone, ""},                   // not an ID
		{"1." + id[:31], nameNone, ""},               // too short
		{"1." + id[:31] + "g", nameNone, ""},         // not hex
		{"x.1." + id, nameNone, ""},                  // too deep
		{"UPPER." + id, nameNone, ""},                // names arrive lower-cased; upper case is not a probe label
		{"waytoolonglabelname1." + id, nameNone, ""}, // over 16 characters
		{"www", nameNone, ""},
	}
	for _, c := range cases {
		got, gotID := classify(c.rel)
		if got != c.want || gotID != c.id {
			t.Errorf("classify(%q) = %v %q, want %v %q", c.rel, got, gotID, c.want, c.id)
		}
	}
}

func TestOutOfZoneIsRefused(t *testing.T) {
	h := newHandler(zone, ip4, ip6, time.Minute)
	for _, name := range []string{"example.com.", "example.org.", "evil-dnstest.example.org.", "."} {
		code, _ := ask(t, h, name, dns.TypeA, "198.51.100.1")
		if code != dns.RcodeRefused {
			t.Errorf("%s: code %d, want REFUSED", name, code)
		}
	}
}

func TestProbeRecordsTheAsker(t *testing.T) {
	h := newHandler(zone, ip4, ip6, time.Minute)
	code, msg := ask(t, h, "1."+id+"."+zone, dns.TypeA, "198.51.100.7")
	if code != dns.RcodeSuccess || len(msg.Answer) != 1 {
		t.Fatalf("code %d, answers %v", code, msg.Answer)
	}
	a := msg.Answer[0].(*dns.A)
	if a.A.String() != "203.0.113.10" || a.Hdr.Ttl != 0 || !msg.Authoritative {
		t.Fatalf("bad answer %v (authoritative %v)", a, msg.Authoritative)
	}
	ask(t, h, "2."+id+"."+zone, dns.TypeAAAA, "2001:db8:ffff::53")
	ask(t, h, "3."+id+"."+zone, dns.TypeA, "198.51.100.7") // same resolver again

	got := h.resolversFor(id, time.Now())
	if len(got) != 2 || got[0].String() != "198.51.100.7" || got[1].String() != "2001:db8:ffff::53" {
		t.Fatalf("resolvers = %v", got)
	}
	// Other IDs and expired IDs show nothing.
	if h.resolversFor("f"+id[1:], time.Now()) != nil {
		t.Error("unknown id must be empty")
	}
	if h.resolversFor(id, time.Now().Add(2*time.Minute)) != nil {
		t.Error("expired id must be empty")
	}
	h.sweep(time.Now().Add(2 * time.Minute))
	if len(h.ids) != 0 {
		t.Errorf("sweep left %d ids", len(h.ids))
	}
}

func TestStaticNames(t *testing.T) {
	h := newHandler(zone, ip4, ip6, time.Minute)
	cases := []struct {
		name  string
		qtype uint16
		rcode int
		want  int // answers
	}{
		{"v4." + zone, dns.TypeA, dns.RcodeSuccess, 1},
		{"v4." + zone, dns.TypeAAAA, dns.RcodeSuccess, 0}, // exists, no such type
		{"v6." + zone, dns.TypeAAAA, dns.RcodeSuccess, 1},
		{"v6." + zone, dns.TypeA, dns.RcodeSuccess, 0},
		{"api." + zone, dns.TypeA, dns.RcodeSuccess, 1},
		{"api." + zone, dns.TypeAAAA, dns.RcodeSuccess, 1},
		{"nope." + zone, dns.TypeA, dns.RcodeNameError, 0},
		{id + "." + zone, dns.TypeA, dns.RcodeSuccess, 0}, // empty non-terminal: NODATA, so minimising resolvers go on
		{id + "." + zone, dns.TypeNS, dns.RcodeSuccess, 0},
		{zone, dns.TypeSOA, dns.RcodeSuccess, 1},
		{zone, dns.TypeNS, dns.RcodeSuccess, 1},
		{zone, dns.TypeA, dns.RcodeSuccess, 0},
	}
	for _, c := range cases {
		_, msg := ask(t, h, c.name, c.qtype, "198.51.100.1")
		if msg.Rcode != c.rcode || len(msg.Answer) != c.want {
			t.Errorf("%s %s: rcode %d answers %d, want %d and %d", c.name, dns.TypeToString[c.qtype], msg.Rcode, len(msg.Answer), c.rcode, c.want)
		}
	}
	// Non-probe names never record anything.
	if len(h.ids) != 0 {
		t.Errorf("static names recorded %d ids", len(h.ids))
	}
}

func TestMemoryIsBounded(t *testing.T) {
	h := newHandler(zone, ip4, ip6, time.Minute)
	now := time.Now()
	r := netip.MustParseAddr("198.51.100.1")
	for i := range maxResolvers + 10 {
		h.record(id, netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), now)
	}
	if n := len(h.resolversFor(id, now)); n != maxResolvers {
		t.Errorf("kept %d resolvers, want %d", n, maxResolvers)
	}
	h.ids = map[string]*entry{}
	for i := range maxIDs + 5 {
		h.record(string(rune('a'+i%26))+time.Duration(i).String(), r, now)
	}
	if len(h.ids) != maxIDs {
		t.Errorf("kept %d ids, want %d", len(h.ids), maxIDs)
	}
}

func TestHTTP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip2asn.tsv")
	tsv := "198.51.100.0\t198.51.100.255\t64500\tDE\tEXAMPLE-AS - Example Resolver GmbH\n" +
		"203.0.113.0\t203.0.113.255\t64501\tUS\tTEST-NET Test Net\n"
	if err := os.WriteFile(path, []byte(tsv), 0o600); err != nil {
		t.Fatal(err)
	}
	src := asn.NewSource(path)
	if err := src.Refresh(); err != nil {
		t.Fatal(err)
	}
	h := newHandler(zone, ip4, ip6, time.Minute)
	h.record(id, netip.MustParseAddr("198.51.100.7"), time.Now())
	srv := h.httpHandler(src, "https://dotvpn.org", &limiter{})

	get := func(target, remote, origin, fwd string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.RemoteAddr = remote
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if fwd != "" {
			req.Header.Set("X-Forwarded-For", fwd)
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}

	rec := get("/r/"+id, "172.18.0.5:4000", "https://dotvpn.org", "192.0.2.1")
	var body struct{ Resolvers []network }
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Resolvers) != 1 || body.Resolvers[0].ASN != "AS64500" || body.Resolvers[0].Country != "DE" || body.Resolvers[0].Org != "Example Resolver GmbH" {
		t.Fatalf("resolvers = %+v", body.Resolvers)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://dotvpn.org" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("headers = %v", rec.Header())
	}
	if rec := get("/r/"+id, "172.18.0.5:4000", "https://evil.example", ""); rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("foreign origin must not be allowed")
	}
	if rec := get("/r/not-an-id", "172.18.0.5:4000", "", ""); rec.Code != 200 || rec.Body.String() != "{\"resolvers\":[]}\n" {
		t.Errorf("bad id: %d %q", rec.Code, rec.Body.String())
	}

	// /ip trusts the forwarded address only from a private proxy.
	var me network
	rec = get("/ip", "172.18.0.5:4000", "", "9.9.9.9, 203.0.113.50")
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if me.IP != "203.0.113.50" || me.Family != "IPv4" || me.ASN != "AS64501" {
		t.Errorf("behind proxy: %+v", me)
	}
	rec = get("/ip", "198.51.100.9:4000", "", "203.0.113.50")
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if me.IP != "198.51.100.9" {
		t.Errorf("public peer must not set its own address: %+v", me)
	}
	rec = get("/ip", "[2001:db8::1]:4000", "", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if me.IP != "2001:db8::1" || me.Family != "IPv6" || me.ASN != "" {
		t.Errorf("ipv6: %+v", me)
	}

	// /asn names the network of a public address and refuses the rest.
	rec = get("/asn?ip=203.0.113.9", "172.18.0.5:4000", "https://dotvpn.org", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 200 || me.IP != "203.0.113.9" || me.ASN != "AS64501" || me.Country != "US" {
		t.Errorf("asn: %d %+v", rec.Code, me)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://dotvpn.org" {
		t.Error("asn must allow the site origin")
	}
	if rec := get("/asn?ip=203.0.113.9", "172.18.0.5:4000", "https://evil.example", ""); rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("asn: foreign origin must not be allowed")
	}
	for _, bad := range []string{"", "nope", "10.0.0.1", "127.0.0.1", "::1", "100.64.0.1", "169.254.1.1", "fe80::1", "fd00::1", "example.com"} {
		if rec := get("/asn?ip="+bad, "172.18.0.5:4000", "", ""); rec.Code != http.StatusBadRequest {
			t.Errorf("asn %q: code %d", bad, rec.Code)
		}
	}
}

func TestRateLimit(t *testing.T) {
	var l limiter
	ip := netip.MustParseAddr("198.51.100.1")
	now := time.Now()
	for i := range rateBurst {
		if !l.allow(ip, now) {
			t.Fatalf("request %d refused inside the burst", i)
		}
	}
	if l.allow(ip, now) {
		t.Fatal("request past the burst allowed")
	}
	if !l.allow(ip, now.Add(rateEvery)) {
		t.Fatal("token not refilled")
	}
	if !l.allow(netip.MustParseAddr("198.51.100.2"), now) {
		t.Fatal("limits must be per address")
	}
	v6 := netip.MustParseAddr("2001:db8::1")
	for range rateBurst {
		l.allow(v6, now)
	}
	if l.allow(netip.MustParseAddr("2001:db8::ffff"), now) {
		t.Fatal("one IPv6 /64 must share a limit")
	}
	l.sweep(now.Add(time.Hour))
	if len(l.seen) != 0 {
		t.Fatalf("sweep left %d", len(l.seen))
	}
}

func TestDetect(t *testing.T) {
	defer func(f func(context.Context, int) (netip.Addr, error)) { findIP = f }(findIP)
	found := map[int]netip.Addr{4: ip4}
	findIP = func(_ context.Context, family int) (netip.Addr, error) {
		if a, ok := found[family]; ok {
			return a, nil
		}
		return netip.Addr{}, errors.New("none")
	}

	// Explicit values win and are never looked up.
	o := options{ip4: netip.MustParseAddr("198.51.100.1")}
	if err := detect(context.Background(), &o); err != nil || o.ip4 != netip.MustParseAddr("198.51.100.1") || o.ip6.IsValid() {
		t.Fatalf("got %+v, %v", o, err)
	}
	// Unset ones are found. A missing IPv6 is not fatal.
	o = options{}
	if err := detect(context.Background(), &o); err != nil || o.ip4 != ip4 || o.ip6.IsValid() {
		t.Fatalf("got %+v, %v", o, err)
	}
	// No address at all cannot serve.
	found = map[int]netip.Addr{}
	if err := detect(context.Background(), &options{}); err == nil {
		t.Fatal("want error without any address")
	}
}

func TestParseCorefile(t *testing.T) {
	ok := "dnstest {\n ip4 203.0.113.10\n ip6 \"\"\n origin\n http 127.0.0.1:8053\n ttl 30s\n update off\n}"
	o, err := parse(caddy.NewTestController("dns", ok))
	if err != nil || o.ip4 != ip4 || o.ip6.IsValid() || o.http != "127.0.0.1:8053" || o.ttl != 30*time.Second || o.update != 0 {
		t.Fatalf("got %+v, %v", o, err)
	}
	for _, bad := range []string{
		"dnstest {\n ip4 2001:db8::1\n}",           // wrong family
		"dnstest {\n ip4 203.0.113.10\n ttl 0s\n}", // not positive
		"dnstest {\n ip4 203.0.113.10\n nope x\n}", // unknown key
		"dnstest {\n update 1s\n}",                 // hammering iptoasn.com
	} {
		if _, err := parse(caddy.NewTestController("dns", bad)); err == nil {
			t.Errorf("want error for %q", bad)
		}
	}
}
