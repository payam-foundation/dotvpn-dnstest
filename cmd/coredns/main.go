// Command coredns is CoreDNS with only the plugins the leak test needs, plus dnstest.
//
// "coredns healthcheck" asks the running server for its own zone over DNS and
// HTTP and exits 0 when both answer. The image is distroless, so there is no dig.
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/coremain"
	"github.com/miekg/dns"

	_ "github.com/coredns/coredns/plugin/bufsize"
	_ "github.com/coredns/coredns/plugin/cancel"
	_ "github.com/coredns/coredns/plugin/errors"
	_ "github.com/payam-foundation/dotvpn-dnstest/plugin/dnstest"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		if err := healthcheck(os.Getenv("DNSTEST_ZONE")); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	// Execution order. No log plugin: nothing here may write a per-query record.
	if err := dnsserver.SetDirectives([]string{"bufsize", "cancel", "errors", "dnstest"}); err != nil {
		panic(err)
	}
	coremain.Run()
}

func healthcheck(zone string) error {
	if zone == "" {
		return fmt.Errorf("DNSTEST_ZONE is not set")
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("v4."+zone), dns.TypeA)
	c := &dns.Client{Timeout: 3 * time.Second}
	for _, network := range []string{"udp", "tcp"} {
		c.Net = network
		r, _, err := c.Exchange(m, "127.0.0.1:53")
		if err != nil {
			return fmt.Errorf("dns %s: %w", network, err)
		}
		if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
			return fmt.Errorf("dns %s: rcode %s, %d answers", network, dns.RcodeToString[r.Rcode], len(r.Answer))
		}
	}
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Get("http://127.0.0.1:8053/healthz")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http: %s", resp.Status)
	}
	return nil
}
