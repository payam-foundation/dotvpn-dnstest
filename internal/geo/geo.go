// Package geo maps an IP address to a place, from the DB-IP "IP to City Lite"
// MMDB (https://db-ip.com, CC BY 4.0: credit DB-IP wherever the result is shown).
//
// The file is memory-mapped, so the table costs almost no heap and a refresh is
// one pointer swap.
package geo

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/payam-foundation/dotvpn-dnstest/internal/feed"
)

// Place is where an address is. Any field may be empty; the zero value means unknown.
type Place struct {
	Country string // ISO 3166-1 alpha-2
	Region  string
	City    string
}

// record is the part of a DB-IP record that is read.
type record struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		Names struct {
			EN string `maxminddb:"en"`
		} `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	City struct {
		Names struct {
			EN string `maxminddb:"en"`
		} `maxminddb:"names"`
	} `maxminddb:"city"`
}

// Source serves lookups from a file and swaps in a new database when the file
// changes. A missing file is not fatal: lookups return the zero Place until it appears.
//
// The superseded reader is never closed by hand: it may still serve a lookup, and
// the library unmaps it once nothing references it.
type Source struct {
	path string
	cur  atomic.Pointer[maxminddb.Reader]
	mu   sync.Mutex
	mod  time.Time
	size int64
}

// NewSource returns a Source for path. Call Refresh to load it.
func NewSource(path string) *Source { return &Source{path: path} }

// Lookup returns the place of ip, or the zero Place when it is unknown.
func (s *Source) Lookup(ip netip.Addr) Place {
	r := s.cur.Load()
	if r == nil || !ip.IsValid() {
		return Place{}
	}
	var rec record
	if err := r.Lookup(ip.Unmap()).Decode(&rec); err != nil {
		return Place{}
	}
	p := Place{Country: rec.Country.ISOCode, City: rec.City.Names.EN}
	if len(rec.Subdivisions) > 0 {
		p.Region = rec.Subdivisions[0].Names.EN
	}
	if p.Country == "ZZ" { // DB-IP's "unknown"
		return Place{}
	}
	return p
}

// Loaded reports whether a database is in use.
func (s *Source) Loaded() bool { return s.cur.Load() != nil }

// open reads path and checks that it is a city database with a search tree.
func open(path string) (*maxminddb.Reader, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(r.Metadata.DatabaseType, "City") || r.Metadata.NodeCount == 0 {
		_ = r.Close()
		return nil, fmt.Errorf("geo: %q is not a city database", r.Metadata.DatabaseType)
	}
	return r, nil
}

// Refresh loads the file when its modification time or size changed since the
// last load. On error the previous database stays in use.
func (s *Source) Refresh() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := os.Stat(s.path)
	if err != nil {
		return err
	}
	if st.ModTime().Equal(s.mod) && st.Size() == s.size {
		return nil
	}
	r, err := open(s.path)
	if err != nil {
		return err
	}
	s.cur.Store(r)
	s.mod, s.size = st.ModTime(), st.Size()
	return nil
}

// URLs lists this month's file, then last month's. DB-IP publishes on the 1st and
// the new file can lag, so the old one covers the gap.
func URLs(now time.Time) []string {
	now = now.UTC()
	prev := now.AddDate(0, -1, 1-now.Day()) // day 1 first: stepping back from the 31st skips a month
	urls := make([]string, 0, 2)
	for _, t := range []time.Time{now, prev} {
		urls = append(urls, "https://download.db-ip.com/free/dbip-city-lite-"+t.Format("2006-01")+".mmdb.gz")
	}
	return urls
}

// Feed keeps the file current from DB-IP.
func (s *Source) Feed() feed.Feed {
	return feed.Feed{
		Name: "city database",
		Path: s.path,
		URLs: URLs,
		Check: func(path string) error {
			r, err := open(path)
			if err != nil {
				return err
			}
			return r.Close()
		},
		Load: s.Refresh,
	}
}
