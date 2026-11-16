package asn

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sample = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET - Cloudflare, Inc.\n" +
	"1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n" +
	"8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE - Google LLC\n" +
	"2606:4700::\t2606:4700:ffff:ffff:ffff:ffff:ffff:ffff\t13335\tUS\tCLOUDFLARENET - Cloudflare, Inc.\n" +
	"5.9.0.0\t5.9.255.255\t24940\tDE\tHETZNER-AS Hetzner Online GmbH\n" +
	"not a line\n" +
	"9.9.9.0\t9.9.9.255\tx\tUS\tbroken\n"

func TestLookup(t *testing.T) {
	table, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ip      string
		want    string
		org     string
		country string
	}{
		{"1.0.0.0", "AS13335", "Cloudflare, Inc.", "US"},
		{"1.0.0.255", "AS13335", "Cloudflare, Inc.", "US"},
		{"1.0.1.0", "", "", ""},       // not routed
		{"0.255.255.255", "", "", ""}, // before the first range
		{"8.8.8.8", "AS15169", "Google LLC", "US"},
		{"8.8.9.0", "", "", ""}, // after the range
		{"2606:4700:4700::1111", "AS13335", "Cloudflare, Inc.", "US"},
		{"::ffff:5.9.1.1", "AS24940", "HETZNER-AS Hetzner Online GmbH", "DE"},
		{"9.9.9.9", "", "", ""}, // broken line was skipped
	}
	for _, c := range cases {
		got := table.Lookup(netip.MustParseAddr(c.ip))
		if got.AS() != c.want || got.Org != c.org || got.Country != c.country {
			t.Errorf("%s: got %+v, want %s %q %s", c.ip, got, c.want, c.org, c.country)
		}
	}
	if table.Len() != 4 {
		t.Errorf("Len = %d, want 4", table.Len())
	}
}

func TestParseRejectsEmpty(t *testing.T) {
	if _, err := Parse(strings.NewReader("<html>rate limited</html>\n")); err == nil {
		t.Fatal("want error for input with no ranges")
	}
}

func TestSourceRefresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip2asn.tsv")
	s := NewSource(path)
	if err := s.Refresh(); err == nil {
		t.Fatal("want error for missing file")
	}
	if got := s.Lookup(netip.MustParseAddr("8.8.8.8")); got.ASN != 0 {
		t.Fatalf("missing file must give zero Info, got %+v", got)
	}
	if err := os.WriteFile(path, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Refresh(); err != nil {
		t.Fatal(err)
	}
	if got := s.Lookup(netip.MustParseAddr("8.8.8.8")); got.AS() != "AS15169" {
		t.Fatalf("got %+v", got)
	}
	// A bad replacement keeps the good table.
	if err := os.WriteFile(path, []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	if err := s.Refresh(); err == nil {
		t.Fatal("want error for garbage file")
	}
	if got := s.Lookup(netip.MustParseAddr("8.8.8.8")); got.AS() != "AS15169" {
		t.Fatalf("good table lost: %+v", got)
	}
}
