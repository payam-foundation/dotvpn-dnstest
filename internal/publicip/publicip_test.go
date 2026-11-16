package publicip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestUsable(t *testing.T) {
	for _, c := range []struct {
		ip     string
		family int
		want   bool
	}{
		{"203.0.113.10", 4, true},
		{"2606:4700::1", 6, true},
		{"10.0.0.5", 4, false},
		{"192.168.1.2", 4, false},
		{"172.16.0.1", 4, false},
		{"100.64.1.1", 4, false}, // carrier-grade NAT
		{"127.0.0.1", 4, false},
		{"169.254.1.1", 4, false},
		{"fd00::1", 6, false}, // unique local
		{"fe80::1", 6, false},
		{"::1", 6, false},
		{"203.0.113.10", 6, false}, // wrong family
		{"2606:4700::1", 4, false},
	} {
		if got := Usable(netip.MustParseAddr(c.ip), c.family); got != c.want {
			t.Errorf("Usable(%s, %d) = %v, want %v", c.ip, c.family, got, c.want)
		}
	}
}

func TestRemoteTakesTheFirstUsableAnswer(t *testing.T) {
	answer := func(code int, body string) string {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(body))
		})).URL
	}
	urls := []string{
		answer(http.StatusInternalServerError, "oops"),
		answer(http.StatusOK, "<html>blocked</html>"),
		answer(http.StatusOK, "10.1.2.3\n"), // a private address is not an answer
		answer(http.StatusOK, " 203.0.113.10\n"),
		answer(http.StatusOK, "203.0.113.99"),
	}
	ip, err := remote(context.Background(), http.DefaultClient, urls, 4)
	if err != nil || ip != netip.MustParseAddr("203.0.113.10") {
		t.Fatalf("got %v, %v", ip, err)
	}
	if _, err := remote(context.Background(), http.DefaultClient, urls[:3], 4); err == nil {
		t.Fatal("want error when no service gives a public address")
	}
}
