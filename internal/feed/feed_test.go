package feed

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// okIfPrefixed accepts a file that starts with "good".
func okIfPrefixed(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(b), "good") {
		return errors.New("bad content")
	}
	return nil
}

func TestFetch(t *testing.T) {
	good := "good table\n"
	modified := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	body := gz(t, good)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if since, err := http.ParseTime(r.Header.Get("If-Modified-Since")); err == nil && !modified.After(since) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Last-Modified", modified.Format(http.TimeFormat))
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	file := filepath.Join(t.TempDir(), "table")
	ctx := context.Background()

	updated, err := fetch(ctx, srv.Client(), srv.URL, file, okIfPrefixed)
	if err != nil || !updated {
		t.Fatalf("first fetch: updated=%v err=%v", updated, err)
	}
	got, err := os.ReadFile(file)
	if err != nil || string(got) != good {
		t.Fatalf("file = %q, err %v", got, err)
	}
	if st, _ := os.Stat(file); !st.ModTime().Equal(modified) {
		t.Errorf("mtime = %v, want the server's Last-Modified", st.ModTime())
	}

	// Unchanged upstream: nothing is rewritten.
	if updated, err := fetch(ctx, srv.Client(), srv.URL, file, okIfPrefixed); err != nil || updated {
		t.Fatalf("second fetch: updated=%v err=%v", updated, err)
	}

	// A bad download never replaces a good table, and leaves no temp file behind.
	modified = modified.Add(time.Hour)
	body = gz(t, "<html>rate limited</html>\n")
	if _, err := fetch(ctx, srv.Client(), srv.URL, file, okIfPrefixed); err == nil {
		t.Fatal("want error for unusable table")
	}
	if got, _ := os.ReadFile(file); string(got) != good {
		t.Fatalf("good table was replaced by %q", got)
	}
	body = []byte("not gzip")
	if _, err := fetch(ctx, srv.Client(), srv.URL, file, okIfPrefixed); err == nil {
		t.Fatal("want error for non-gzip body")
	}
	entries, _ := os.ReadDir(filepath.Dir(file))
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestUpdateFallsBackOnNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/new" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(gz(t, "good old\n"))
	}))
	defer srv.Close()

	f := Feed{
		Path:  filepath.Join(t.TempDir(), "table"),
		URLs:  func(time.Time) []string { return []string{srv.URL + "/new", srv.URL + "/old"} },
		Check: okIfPrefixed,
	}
	if updated, err := f.update(context.Background(), srv.Client(), time.Now()); err != nil || !updated {
		t.Fatalf("updated=%v err=%v", updated, err)
	}

	// Nothing published anywhere is an error, not silence.
	f.URLs = func(time.Time) []string { return []string{srv.URL + "/new"} }
	f.Path = filepath.Join(t.TempDir(), "other")
	if _, err := f.update(context.Background(), srv.Client(), time.Now()); !errors.Is(err, errNotFound) {
		t.Fatalf("err = %v, want not found", err)
	}
}
