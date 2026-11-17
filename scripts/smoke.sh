#!/usr/bin/env bash
# Smoke test: build the image, start the server, dig a probe name, then read the
# result over HTTP and check the resolver shows up with its network.
#   scripts/smoke.sh [image]     (builds dotvpn-dnstest:smoke when no image is given)
set -euo pipefail

cd "$(dirname "$0")/.."
image="${1:-}"
if [ -z "$image" ]; then
  image=dotvpn-dnstest:smoke
  docker build -t "$image" .
fi

# alpine pinned by digest; only the test client uses it.
client=alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
zone=dnstest.example.org
id=0123456789abcdef0123456789abcdef
name=smoke-$$
data=$(mktemp -d)
trap 'docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$data"' EXIT

# 127.0.0.0/8 is where the client's queries come from inside the shared namespace.
printf '127.0.0.0\t127.255.255.255\t64500\tZZ\tLOOPBACK-AS - Smoke Test Net\n' >"$data/ip2asn.tsv"
chmod 755 "$data"
chmod 644 "$data/ip2asn.tsv"

docker run -d --name "$name" --read-only --cap-drop ALL \
  --sysctl net.ipv4.ip_unprivileged_port_start=53 \
  -e DNSTEST_ZONE="$zone" -e DNSTEST_IP4=203.0.113.10 -e DNSTEST_UPDATE=off -e DNSTEST_ORIGIN=https://example.org \
  -v "$data:/data:ro" "$image" >/dev/null

probe() { docker run --rm --network "container:$name" "$client" sh -c "apk add -q --no-cache bind-tools curl >/dev/null && $*"; }

for _ in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Running}}' "$name")" = true ] || { docker logs "$name"; exit 1; }
  docker exec "$name" /usr/local/bin/coredns healthcheck 2>/dev/null && break
  sleep 1
done
docker exec "$name" /usr/local/bin/coredns healthcheck

out=$(probe "dig +short +tries=1 @127.0.0.1 1.$id.$zone A; dig +short +tcp @127.0.0.1 2.$id.$zone A; dig +short @127.0.0.1 v6.$zone AAAA; dig +norecurse @127.0.0.1 example.com A | grep -c 'status: REFUSED'")
echo "$out"
[ "$(echo "$out" | grep -c '^203.0.113.10$')" = 2 ] || { echo "probe names must answer with the server address" >&2; exit 1; }
echo "$out" | tail -n1 | grep -qx 1 || { echo "out-of-zone query must be REFUSED" >&2; exit 1; }

body=$(probe "curl -fsS http://127.0.0.1:8053/r/$id")
echo "$body"
echo "$body" | grep -q '"asn":"AS64500"' || { echo "resolver missing from /r/ID" >&2; exit 1; }
echo "$body" | grep -q '"org":"Smoke Test Net"' || { echo "resolver org missing" >&2; exit 1; }
echo "smoke ok"
