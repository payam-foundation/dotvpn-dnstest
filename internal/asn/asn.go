// Package asn maps an IP address to the network that announces it, from the
// iptoasn.com "combined" TSV (public domain, no key, no dependency).
//
// One line per range: start, end, AS number, country, AS description. Range 0
// means "not routed" and is dropped. IPv4 is stored as IPv4-mapped IPv6 so one
// sorted slice and one binary search serve both families.
package asn

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/payam-foundation/dotvpn-dnstest/internal/feed"
)

// Info describes the network of an address. The zero value means unknown.
type Info struct {
	ASN     uint32
	Country string // ISO 3166-1 alpha-2, "" when unknown
	Org     string
}

// AS returns "AS13335", or "" when the network is unknown.
func (i Info) AS() string {
	if i.ASN == 0 {
		return ""
	}
	return "AS" + strconv.FormatUint(uint64(i.ASN), 10)
}

type span struct {
	start, end [16]byte
	asn        uint32
	country    [2]byte
	org        uint32 // index into Table.orgs
}

// Table is an immutable, sorted set of ranges.
type Table struct {
	spans []span
	orgs  []string
}

// Len is the number of ranges.
func (t *Table) Len() int {
	if t == nil {
		return 0
	}
	return len(t.spans)
}

// Lookup returns the network of ip, or the zero Info when no range holds it.
func (t *Table) Lookup(ip netip.Addr) Info {
	if t == nil || !ip.IsValid() {
		return Info{}
	}
	key := ip.Unmap().As16()
	// First span that starts after ip; the candidate is the one before it.
	i := sort.Search(len(t.spans), func(n int) bool { return compare(t.spans[n].start, key) > 0 })
	if i == 0 {
		return Info{}
	}
	s := t.spans[i-1]
	if compare(s.end, key) < 0 {
		return Info{}
	}
	info := Info{ASN: s.asn, Org: t.orgs[s.org]}
	if s.country != [2]byte{} {
		info.Country = string(s.country[:])
	}
	return info
}

func compare(a, b [16]byte) int { return strings.Compare(string(a[:]), string(b[:])) }

// org turns "CLOUDFLARENET - Cloudflare, Inc." into "Cloudflare, Inc.". The
// whole text is kept when it has no " - ".
func org(raw string) string {
	raw = strings.TrimSpace(raw)
	if _, rest, ok := strings.Cut(raw, " - "); ok {
		return strings.TrimSpace(rest)
	}
	return raw
}

// Parse reads the TSV. Malformed lines are skipped, and an input with no valid
// range at all is an error, so a truncated or wrong download never replaces a
// good table.
func Parse(r io.Reader) (*Table, error) {
	t := &Table{}
	interned := map[string]uint32{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 5 {
			continue
		}
		start, err1 := netip.ParseAddr(f[0])
		end, err2 := netip.ParseAddr(f[1])
		number, err3 := strconv.ParseUint(f[2], 10, 32)
		if err1 != nil || err2 != nil || err3 != nil || number == 0 || start.Is4() != end.Is4() {
			continue
		}
		s := span{start: start.Unmap().As16(), end: end.Unmap().As16(), asn: uint32(number)}
		if len(f[3]) == 2 && f[3] != "ZZ" {
			s.country = [2]byte{f[3][0], f[3][1]}
		}
		name := org(f[4])
		idx, ok := interned[name]
		if !ok {
			idx = uint32(len(t.orgs))
			interned[name] = idx
			t.orgs = append(t.orgs, name)
		}
		s.org = idx
		t.spans = append(t.spans, s)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(t.spans) == 0 {
		return nil, fmt.Errorf("asn: no valid ranges")
	}
	sort.Slice(t.spans, func(a, b int) bool { return compare(t.spans[a].start, t.spans[b].start) < 0 })
	return t, nil
}

// Source serves lookups from a file and swaps in a new table when the file
// changes. A missing file is not fatal: lookups return the zero Info until it appears.
type Source struct {
	path string
	cur  atomic.Pointer[Table]
	mu   sync.Mutex
	mod  time.Time
	size int64
}

// NewSource returns a Source for path. Call Refresh to load it.
func NewSource(path string) *Source { return &Source{path: path} }

// Lookup returns the network of ip.
func (s *Source) Lookup(ip netip.Addr) Info { return s.cur.Load().Lookup(ip) }

// Len is the number of ranges currently loaded.
func (s *Source) Len() int { return s.cur.Load().Len() }

// Refresh loads the file when its modification time or size changed since the
// last load. On error the previous table stays in use.
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
	f, err := os.Open(s.path)
	if err != nil {
		return err
	}
	defer f.Close()
	t, err := Parse(f)
	if err != nil {
		return err
	}
	s.cur.Store(t)
	s.mod, s.size = st.ModTime(), st.Size()
	return nil
}

// DefaultURL is the combined IPv4 and IPv6 table, public domain.
const DefaultURL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"

// Feed keeps the file current from DefaultURL.
func (s *Source) Feed() feed.Feed {
	return feed.Feed{
		Name: "ASN table",
		Path: s.path,
		URLs: func(time.Time) []string { return []string{DefaultURL} },
		Check: func(path string) error {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = Parse(f)
			return err
		},
		Load: s.Refresh,
	}
}
