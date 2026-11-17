package geo

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestURLs(t *testing.T) {
	const base = "https://download.db-ip.com/free/dbip-city-lite-"
	cases := []struct {
		now  time.Time
		want []string
	}{
		{time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC), []string{base + "2026-11.mmdb.gz", base + "2026-10.mmdb.gz"}},
		{time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), []string{base + "2027-01.mmdb.gz", base + "2026-12.mmdb.gz"}},
		// Stepping back one month from the 31st must not skip to the month before.
		{time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC), []string{base + "2026-03.mmdb.gz", base + "2026-02.mmdb.gz"}},
	}
	for _, c := range cases {
		if got := URLs(c.now); !slices.Equal(got, c.want) {
			t.Errorf("URLs(%v) = %v, want %v", c.now, got, c.want)
		}
	}
}

func TestSourceRefreshRejectsBadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "city.mmdb")
	s := NewSource(path)
	if err := s.Refresh(); err == nil {
		t.Fatal("want error for missing file")
	}
	if err := os.WriteFile(path, []byte("<html>rate limited</html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Refresh(); err == nil {
		t.Fatal("want error for a file that is not an MMDB")
	}
	if s.Loaded() {
		t.Fatal("a bad file must not be loaded")
	}
	if got := s.Lookup(netip.MustParseAddr("8.8.8.8")); got != (Place{}) {
		t.Fatalf("unloaded source must give the zero Place, got %+v", got)
	}
}
