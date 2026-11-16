package asn

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// DefaultURL is the combined IPv4 and IPv6 table, public domain.
const DefaultURL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"

const (
	maxDownload = 256 << 20 // the real file is about 11 MB gzipped, 40 MB plain
	retryAfter  = 5 * time.Minute
)

// fetch downloads url into file when it is newer than file. It reports whether
// file was replaced.
func fetch(ctx context.Context, client *http.Client, url, file string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	if st, err := os.Stat(file); err == nil {
		req.Header.Set("If-Modified-Since", st.ModTime().UTC().Format(http.TimeFormat))
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return false, nil
	case http.StatusOK:
	default:
		return false, fmt.Errorf("%s: %s", url, resp.Status)
	}

	zr, err := gzip.NewReader(io.LimitReader(resp.Body, maxDownload))
	if err != nil {
		return false, fmt.Errorf("gunzip: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(file), ".ip2asn-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := io.Copy(tmp, io.LimitReader(zr, maxDownload)); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	check, err := os.Open(tmp.Name())
	if err != nil {
		return false, err
	}
	_, err = Parse(check)
	check.Close()
	if err != nil {
		return false, fmt.Errorf("downloaded table is not usable: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return false, err
	}
	stamp := time.Now()
	if t, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		stamp = t
	}
	if err := os.Chtimes(tmp.Name(), stamp, stamp); err != nil {
		return false, err
	}
	return true, os.Rename(tmp.Name(), file)
}

// Keep downloads the table now and then every interval, until ctx ends. It asks
// only for a table newer than the file (If-Modified-Since), rejects one that does
// not parse, and swaps a good one in atomically, so lookups never see a partial
// or bad table. A failed round keeps the old table and retries after a few minutes.
// ponytail: no staleness alarm. Add one if a week-old table should page someone.
func (s *Source) Keep(ctx context.Context, client *http.Client, url string, every time.Duration, logf func(format string, args ...any)) {
	for {
		wait := every
		updated, err := fetch(ctx, client, url, s.path)
		if err == nil {
			// Also picks up a table that was already on disk but not loaded yet.
			before := s.Len()
			if err = s.Refresh(); err == nil && (updated || s.Len() != before) {
				logf("ASN table loaded, %d ranges", s.Len())
			}
		}
		if err != nil {
			logf("ASN table update failed: %v", err)
			wait = min(retryAfter, every)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}
