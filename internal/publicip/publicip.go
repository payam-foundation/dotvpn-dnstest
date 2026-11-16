// Package publicip finds the public address of this host, so nobody has to type it into a config.
//
// It asks the kernel first: connecting a UDP socket sends no packet but picks the source
// address the host would use, which is the public address on a VPS with a direct one.
// Behind NAT (AWS, GCP, Oracle and others) that address is private, so it then asks
// outside services over one address family at a time and takes the first usable answer.
package publicip

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

var (
	// Any routable target works: nothing is sent to it.
	routeTarget = map[int]string{4: "8.8.8.8:53", 6: "[2001:4860:4860::8888]:53"}
	// Plain-text "what is my address" services that answer over one family. Several, so one outage is not fatal.
	services = map[int][]string{
		4: {"https://api4.ipify.org", "https://ipv4.icanhazip.com", "https://v4.ident.me"},
		6: {"https://api6.ipify.org", "https://ipv6.icanhazip.com", "https://v6.ident.me"},
	}
	cgnat = netip.MustParsePrefix("100.64.0.0/10")
)

// Usable reports whether ip is a public address of the given family (4 or 6).
func Usable(ip netip.Addr, family int) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || (family == 4) != ip.Is4() {
		return false
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !cgnat.Contains(ip)
}

// Find returns the public address of the host for family 4 or 6. The error says what
// was tried when the host has no address of that family.
func Find(ctx context.Context, family int) (netip.Addr, error) {
	if ip, err := local(ctx, family); err == nil && Usable(ip, family) {
		return ip, nil
	}
	return remote(ctx, familyClient(family), services[family], family)
}

// local is the source address the kernel would use to reach the internet.
func local(ctx context.Context, family int) (netip.Addr, error) {
	network := fmt.Sprintf("udp%d", family)
	conn, err := (&net.Dialer{}).DialContext(ctx, network, routeTarget[family])
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()
	ip, ok := netip.AddrFromSlice(conn.LocalAddr().(*net.UDPAddr).IP)
	if !ok {
		return netip.Addr{}, fmt.Errorf("no local IPv%d address", family)
	}
	return ip.Unmap(), nil
}

// familyClient never leaves its address family, so a dual-stack service answers with the right one.
func familyClient(family int) *http.Client {
	d := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return d.DialContext(ctx, fmt.Sprintf("tcp%d", family), addr)
			},
			DisableKeepAlives: true,
		},
	}
}

// remote asks each URL in turn and returns the first public address of the family.
func remote(ctx context.Context, client *http.Client, urls []string, family int) (netip.Addr, error) {
	var last error
	for _, url := range urls {
		ip, err := ask(ctx, client, url)
		if err == nil && Usable(ip, family) {
			return ip, nil
		}
		if err == nil {
			err = fmt.Errorf("%s answered %s, not a public IPv%d address", url, ip, family)
		}
		last = err
	}
	return netip.Addr{}, fmt.Errorf("no public IPv%d address found: %w", family, last)
}

func ask(ctx context.Context, client *http.Client, url string) (netip.Addr, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("%s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return netip.Addr{}, err
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%s: %w", url, err)
	}
	return ip.Unmap(), nil
}
