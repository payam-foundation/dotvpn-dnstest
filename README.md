# DotVPN DNStest

DNS leak test server for the dotvpn connection check. CoreDNS with one small plugin, Caddy for HTTPS, and an hourly ASN table refresh, in Docker Compose on its own VPS.

[![CI](https://github.com/payam-foundation/dotvpn-dnstest/actions/workflows/ci.yml/badge.svg)](https://github.com/payam-foundation/dotvpn-dnstest/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/payam-foundation/dotvpn-dnstest)](https://github.com/payam-foundation/dotvpn-dnstest/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/payam-foundation/dotvpn-dnstest)](go.mod)
[![Image](https://img.shields.io/badge/ghcr.io-dotvpn--dnstest-blue?logo=docker)](https://github.com/payam-foundation/dotvpn-dnstest/pkgs/container/dotvpn-dnstest)
[![License](https://img.shields.io/badge/license-PolyForm%20Noncommercial-lightgrey)](LICENSE)

The server is authoritative for one delegated subdomain and nothing else. It never recurses and answers `REFUSED` for every other name, so it is not an open resolver. Nothing else uses it.

**Privacy:** no query log is written (no `log` plugin, no Caddy access log). Results live 60 seconds in memory and vanish on restart. This is the "what we keep" text on the web check page.

- [How it works](#how-it-works)
- [DNS names](#dns-names)
- [HTTP API](#http-api)
- [Configuration](#configuration)
- [Set up](#set-up)
- [Verify and troubleshoot](#verify-and-troubleshoot)
- [Development](#development)

## How it works

```mermaid
sequenceDiagram
    participant B as Browser (dotvpn-web)
    participant R as Visitor's resolver
    participant D as dnstest :53
    participant A as api.&lt;zone&gt; (Caddy)

    B->>R: look up N.ID.<zone>
    R->>D: query N.ID.<zone>
    D-->>D: remember ID -> resolver address (60 s)
    D-->>R: A / AAAA, TTL 0
    B->>A: GET /r/ID
    A-->>B: resolvers with ASN, org, country
    B->>A: GET v4.<zone>/ip and v6.<zone>/ip
    A-->>B: address of each family
```

1. The page asks the browser to look up `N.ID.<zone>` for a random 128-bit `ID` (32 lowercase hex characters).
2. The visitor's recursive resolver reaches this server. The `dnstest` plugin remembers `ID -> resolver address`.
3. The page reads `GET https://api.<zone>/r/<ID>` and gets the resolver addresses with ASN, organisation and country.
4. `v4.<zone>` resolves to an IPv4 address only and `v6.<zone>` to an IPv6 address only. Fetching `/ip` on both shows whether the visitor has a second, possibly leaking, address family.

## DNS names

| Name | Answers |
| --- | --- |
| `<zone>` | SOA, NS |
| `ns1.<zone>`, `api.<zone>` | A and AAAA |
| `v4.<zone>` | A only |
| `v6.<zone>` | AAAA only |
| `N.ID.<zone>` | A and AAAA, TTL 0, records the asker |
| `ID.<zone>` | NODATA (empty non-terminal, so name-minimising resolvers continue to the probe name) |
| anything else under the zone | NXDOMAIN |
| anything outside the zone | REFUSED |

The wildcard probe names answer with the VPS address on purpose: browsers then try to fetch from it, and a closed `443` fails fast.

## HTTP API

Served by Caddy on `api.<zone>`, `v4.<zone>` and `v6.<zone>`, backed by the plugin on `127.0.0.1:8053`.

### `GET /r/{id}`

Resolvers that asked for a probe name under `ID` in the last 60 seconds. An unknown or malformed `ID` gives an empty list, not an error.

```json
{
  "resolvers": [
    { "ip": "203.0.113.53", "family": "IPv4", "asn": "AS64496", "org": "Example Resolver Inc", "country": "NL" }
  ]
}
```

### `GET /ip`

The address of the caller. Use it on `v4.<zone>` and `v6.<zone>`.

```json
{ "ip": "198.51.100.7", "family": "IPv4", "asn": "AS64511", "org": "Example ISP", "country": "DE" }
```

### `GET /asn?ip=ADDRESS`

The network of a public address, for example one WebRTC revealed. Same body as `/ip`. A missing, malformed, private, loopback, link-local or shared (carrier-grade NAT) address gives `400`.

### `GET /healthz`

Plain `ok`. Not rate limited.

### Behaviour of all endpoints

- CORS: `Access-Control-Allow-Origin` is sent only when the request `Origin` equals `DNSTEST_ORIGIN`.
- Rate limit: per client address, a burst of 30 requests, then one request per 250 ms. Over the limit answers `429` with `Retry-After: 1`.
- `Cache-Control: no-store` on every answer.
- An empty `asn`, `org` or `country` means the ASN table has no entry for that address (or is not downloaded yet).

## Configuration

Environment variables, set in `.env` (see `.env.example`):

| Variable | Required | Meaning |
| --- | --- | --- |
| `DNSTEST_ZONE` | yes | Delegated zone, for example `dnstest.example.org` |
| `DNSTEST_ORIGIN` | yes | The one site allowed to read answers, for example `https://dotvpn.org` |
| `DNSTEST_IP4`, `DNSTEST_IP6` | no | Override the auto-detected public addresses. Must match the glue records. |
| `DNSTEST_ASN_UPDATE` | no | ASN refresh interval (a duration of at least `1m`, default `1h`), or `off` |

`Corefile` options of the `dnstest` block:

| Option | Default | Meaning |
| --- | --- | --- |
| `ip4`, `ip6` | detected | Addresses answered for names under the zone |
| `http` | `:8053` | HTTP listen address (`127.0.0.1:8053` in `Corefile`) |
| `asn` | `/data/ip2asn.tsv` | Path of the ASN table |
| `update` | `1h` | Refresh interval, or `off` |
| `origin` | none | CORS origin |
| `ttl` | `1m` | How long a recorded resolver is kept |

## Set up

You need a VPS with a public IPv4 and IPv6 address and Docker with the compose plugin.

### 1. DNS records (at the registrar or DNS host of the parent zone)

Replace `example.org` with the parent domain, `dnstest` with the label you chose, and the addresses with the VPS addresses.

```
dnstest        NS    ns1.dnstest.example.org.
ns1.dnstest    A     203.0.113.10
ns1.dnstest    AAAA  2001:db8::10
```

The `A` and `AAAA` records for `ns1.dnstest` are glue: the parent zone must carry them, because the name server lives inside the zone it serves. Do not add any other record under `dnstest`; this server answers for the whole subtree.

One name server works in practice. A second host or anycast is out of scope.

### 2. Firewall

Open these inbound ports on the VPS, for IPv4 and IPv6:

| Port | Protocol | Why |
| --- | --- | --- |
| 53 | UDP and TCP | DNS. TCP is required for large answers and by some resolvers. |
| 80 | TCP | Caddy certificate issuance (HTTP-01) and redirect. |
| 443 | TCP | `api.`, `v4.`, `v6.` HTTPS. |

Do not open 8053 or 2019. They listen on the loopback address only. Caddy serves certificates only for `api.`, `v4.` and `v6.`.

### 3. Install

The server finds this host's public IPv4 and IPv6 address when it starts: first from the address the kernel would use to reach the internet, then, behind NAT, by asking ipify, icanhazip and ident.me over one address family at a time. A host with no IPv6 simply gets no AAAA answers. Set `DNSTEST_IP4` or `DNSTEST_IP6` only to override this.

```sh
git clone https://github.com/payam-foundation/dotvpn-dnstest /opt/dotvpn-dnstest
cd /opt/dotvpn-dnstest
cp .env.example .env     # set DNSTEST_ZONE and DNSTEST_ORIGIN
docker compose up -d
```

`compose.yaml` pins the image to the latest release tag. Until the first release-please PR is merged and the image is published, `docker compose up` cannot pull it. Build it locally first: `docker build -t ghcr.io/payam-foundation/dotvpn-dnstest:v0.0.0 .`, then `docker compose up -d`.

### 4. Automatic updates

- `main` of this repository is what the VPS follows. Merging a release-please PR bumps the image tag in `compose.yaml` and publishes the signed image to GHCR.
- Third-party images (Caddy, distroless, Go) are pinned by digest. Renovate opens PRs to bump the digests; Dependabot handles Go modules and GitHub Actions.
- `deploy/update.sh` fast-forwards to `origin/main`, pulls, restarts, then probes: the in-container health check (DNS over UDP and TCP plus HTTP), a `dig` of a probe name, and an HTTPS request. If the probe fails it returns to the previous commit and image tags, remembers the bad commit in `.last-failed` so it is not retried, and exits non-zero.
- The ASN table comes from [iptoasn.com](https://iptoasn.com) (public domain). The server fetches it at start and then hourly with `If-Modified-Since`, rejects anything that does not parse, and swaps it in atomically. A failed round keeps the old table and retries after five minutes. If the table is missing the test still works, only the ASN fields are empty.

Install the timer:

```sh
sudo cp deploy/dotvpn-dnstest-update.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dotvpn-dnstest-update.timer
```

Edit `WorkingDirectory` and `ExecStart` in the service file if you cloned somewhere other than `/opt/dotvpn-dnstest`. The script needs `git`, `docker`, `dig` (`dnsutils` or `bind-tools`) and `curl` on the host.

## Verify and troubleshoot

From another machine:

```sh
dig +short @203.0.113.10 v4.dnstest.example.org A        # the VPS IPv4 address
dig +short dnstest.example.org NS                        # delegation works end to end
dig +norecurse @203.0.113.10 example.com A               # status: REFUSED
curl -s https://v4.dnstest.example.org/ip
```

| Symptom | Check |
| --- | --- |
| `dig` of the NS record fails | Delegation or glue at the parent zone is missing or wrong. |
| `dig @VPS` times out | Port 53 UDP and TCP closed, in the VPS firewall or at the provider. |
| HTTPS fails on first start | Caddy is still getting a certificate; retry after a minute. Ports 80 and 443 must be open. |
| `/r/ID` returns an empty list | The resolver has not asked yet, 60 seconds passed, or the server restarted. |
| `asn`, `org`, `country` empty | ASN table not downloaded yet or no entry for the address. Look at `docker compose logs coredns`. |
| Wrong addresses in answers | Compare with the log line at start; set `DNSTEST_IP4` / `DNSTEST_IP6`. |

Logs: `docker compose logs coredns caddy`.

## Development

```sh
go vet ./... && go test -race -count=1 ./...
scripts/smoke.sh          # builds the image, digs a probe name, reads /r/ID
```

Go 1.27 is required. `cmd/coredns` is CoreDNS v1.15 with only the plugins it needs (`bufsize`, `cancel`, `errors`) plus `plugin/dnstest`. If a parent directory has a `go.work`, set `GOWORK=off` for `./...` builds.

CI runs: format, vet, staticcheck, gosec, tests with the race detector, govulncheck, Trivy on the source tree, shellcheck, gitleaks, and the Docker smoke test.

Commit with sign-off (`git commit -s`) and Conventional Commit PR titles. See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## Licence

PolyForm Noncommercial 1.0.0, see [LICENSE](LICENSE).
