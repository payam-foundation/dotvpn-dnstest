package dnstest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/payam-foundation/dotvpn-dnstest/internal/asn"
	"github.com/payam-foundation/dotvpn-dnstest/internal/publicip"
)

var log = clog.NewWithPlugin("dnstest")

func init() { plugin.Register("dnstest", setup) }

// findIP is publicip.Find, replaceable in tests.
var findIP = publicip.Find

type options struct {
	ip4, ip6 netip.Addr
	http     string
	asnPath  string
	update   time.Duration // how often to look for a new ASN table, 0 = never
	origin   string
	ttl      time.Duration
}

// parse reads the block:
//
//	dnstest {
//	    ip4 203.0.113.10    # optional: found by itself when unset
//	    ip6 2001:db8::10    # optional: found by itself when unset
//	    http :8053
//	    asn /data/ip2asn.tsv
//	    origin https://dotvpn.org
//	    update 1h           # how often to fetch a new ASN table; "off" to never
//	    ttl 60s
//	}
func parse(c *caddy.Controller) (options, error) {
	o := options{http: ":8053", asnPath: "/data/ip2asn.tsv", update: time.Hour, ttl: time.Minute}
	c.Next() // dnstest
	for c.NextBlock() {
		key := c.Val()
		args := c.RemainingArgs()
		// An empty environment substitution leaves a key with no value: it means "unset".
		if len(args) == 0 || (len(args) == 1 && args[0] == "") {
			continue
		}
		if len(args) != 1 {
			return o, c.ArgErr()
		}
		var err error
		switch key {
		case "ip4":
			o.ip4, err = netip.ParseAddr(args[0])
			if err == nil && !o.ip4.Is4() {
				err = c.Errf("ip4 %q is not an IPv4 address", args[0])
			}
		case "ip6":
			o.ip6, err = netip.ParseAddr(args[0])
			if err == nil && !o.ip6.Is6() {
				err = c.Errf("ip6 %q is not an IPv6 address", args[0])
			}
		case "http":
			o.http = args[0]
		case "asn":
			o.asnPath = args[0]
		case "update":
			if args[0] == "off" {
				o.update = 0
				break
			}
			o.update, err = time.ParseDuration(args[0])
			if err == nil && o.update < time.Minute {
				err = c.Errf("update must be at least 1m, or off")
			}
		case "origin":
			o.origin = args[0]
		case "ttl":
			o.ttl, err = time.ParseDuration(args[0])
			if err == nil && o.ttl <= 0 {
				err = c.Errf("ttl must be positive")
			}
		default:
			return o, c.Errf("unknown property %q", key)
		}
		if err != nil {
			return o, err
		}
	}
	return o, nil
}

// detect fills in the addresses that were not set, from the host itself. A host
// without IPv6 simply gets no AAAA records; one without any public address cannot serve.
// ponytail: found once at start. Restart after the host's address changes.
func detect(ctx context.Context, o *options) error {
	var errs []error
	for _, a := range []struct {
		family int
		set    *netip.Addr
	}{{4, &o.ip4}, {6, &o.ip6}} {
		if a.set.IsValid() {
			continue
		}
		ip, err := findIP(ctx, a.family)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		*a.set = ip
		log.Infof("found public IPv%d address %s", a.family, ip)
	}
	if !o.ip4.IsValid() && !o.ip6.IsValid() {
		return fmt.Errorf("no public address, set ip4 or ip6: %w", errors.Join(errs...))
	}
	for _, err := range errs {
		log.Warningf("%v", err)
	}
	return nil
}

func setup(c *caddy.Controller) error {
	o, err := parse(c)
	if err != nil {
		return plugin.Error("dnstest", err)
	}
	found, cancelFind := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelFind()
	if err := detect(found, &o); err != nil {
		return plugin.Error("dnstest", err)
	}
	h := newHandler(dnsserver.GetConfig(c).Zone, o.ip4, o.ip6, o.ttl)
	src := asn.NewSource(o.asnPath)
	lim := &limiter{}
	srv := &http.Server{
		Handler:           h.httpHandler(src, o.origin, lim),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	// Ends background work on shutdown.
	ctx, stop := context.WithCancel(context.Background())

	c.OnStartup(func() error {
		if err := src.Refresh(); err != nil {
			// The first download is under way; Keep loads it as soon as it lands.
			log.Warningf("no ASN table yet: %v", err)
		} else {
			log.Infof("ASN table loaded, %d ranges", src.Len())
		}
		ln, err := net.Listen("tcp", o.http)
		if err != nil {
			return err
		}
		go func() {
			if err := srv.Serve(ln); err != http.ErrServerClosed {
				log.Errorf("http: %v", err)
			}
		}()
		if o.update > 0 {
			go src.Keep(ctx, &http.Client{Timeout: 3 * time.Minute}, asn.DefaultURL, o.update, log.Infof)
		} else {
			go src.Watch(ctx.Done(), 30*time.Second, func(err error) { log.Warningf("ASN table: %v", err) })
		}
		go func() {
			tick := time.NewTicker(10 * time.Second)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case now := <-tick.C:
					h.sweep(now)
					lim.sweep(now)
				}
			}
		}()
		return nil
	})
	c.OnShutdown(func() error {
		stop()
		down, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return srv.Shutdown(down)
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		h.Next = next
		return h
	})
	return nil
}
