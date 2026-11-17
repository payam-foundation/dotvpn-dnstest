// Package feed keeps a data file on disk current: it downloads a gzipped file on a
// schedule, checks it, and replaces the old one atomically. What the file means
// is up to the caller (Check and Load), so one loop serves every table.
package feed

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	maxDownload = 512 << 20 // the largest feed is about 60 MB gzipped, 130 MB plain
	retryAfter  = 5 * time.Minute
)

// Feed describes one downloaded file.
type Feed struct {
	Name string // for log lines
	Path string // where the current file lives
	// URLs lists the places to try at time now, best first. A 404 moves on to the next,
	// which lets a monthly file fall back to last month's until the new one is published.
	URLs func(now time.Time) []string
	// Check rejects a file that is not usable, so a bad download never replaces a good file.
	Check func(path string) error
	// Load makes the file at Path the one in use. It is called every round, so a file
	// that was already on disk but not yet loaded is picked up too.
	Load func() error
}

var errNotFound = errors.New("not found")

// fetch downloads url into file when it is newer than file. It reports whether
// file was replaced.
func fetch(ctx context.Context, client *http.Client, url, file string, check func(string) error) (bool, error) {
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
	case http.StatusNotFound:
		return false, fmt.Errorf("%s: %w", url, errNotFound)
	case http.StatusOK:
	default:
		return false, fmt.Errorf("%s: %s", url, resp.Status)
	}

	zr, err := gzip.NewReader(io.LimitReader(resp.Body, maxDownload))
	if err != nil {
		return false, fmt.Errorf("gunzip: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(file), ".feed-*")
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
	if err := check(tmp.Name()); err != nil {
		return false, fmt.Errorf("downloaded file is not usable: %w", err)
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

// update tries each URL until one answers with something other than 404.
func (f Feed) update(ctx context.Context, client *http.Client, now time.Time) (bool, error) {
	var err error
	for _, url := range f.URLs(now) {
		var updated bool
		if updated, err = fetch(ctx, client, url, f.Path, f.Check); !errors.Is(err, errNotFound) {
			return updated, err
		}
	}
	return false, err
}

// Watch calls Load every interval until ctx ends, for a file something else
// replaces. Errors go to logf.
func (f Feed) Watch(ctx context.Context, interval time.Duration, logf func(format string, args ...any)) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := f.Load(); err != nil {
				logf("%s: %v", f.Name, err)
			}
		}
	}
}

// Keep updates the file now and then every interval, until ctx ends. It asks only
// for a file newer than the one on disk (If-Modified-Since), rejects one that fails
// Check, and swaps a good one in atomically, so readers never see a partial or bad
// file. A failed round keeps the old file and retries after a few minutes.
// ponytail: no staleness alarm. Add one if a week-old table should page someone.
func (f Feed) Keep(ctx context.Context, client *http.Client, every time.Duration, logf func(format string, args ...any)) {
	for {
		wait := every
		updated, err := f.update(ctx, client, time.Now().UTC())
		if err == nil {
			err = f.Load()
			if err == nil && updated {
				logf("%s updated", f.Name)
			}
		}
		if err != nil {
			logf("%s update failed: %v", f.Name, err)
			wait = min(retryAfter, every)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}
