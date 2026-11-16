#!/usr/bin/env bash
# Fetch main, pull images, restart, probe. On a failed probe, return to the
# previous commit and remember the bad one so the timer does not retry it.
# Run from the checkout by the systemd timer (see dotvpn-dnstest-update.service).
set -euo pipefail

cd "$(dirname "$0")/.."
[ -f .env ] || { echo "no .env next to compose.yaml" >&2; exit 2; }
set -a
# shellcheck source=/dev/null
. ./.env
set +a
: "${DNSTEST_ZONE:?set DNSTEST_ZONE in .env}"

for cmd in git docker dig curl; do
  command -v "$cmd" >/dev/null || { echo "missing $cmd" >&2; exit 2; }
done

failed=.last-failed
prev=$(git rev-parse HEAD)

# probe: the server answers a probe name over UDP and TCP, and HTTPS works.
# Caddy may still be getting a certificate right after a first start, so retry.
probe() {
  local _
  for _ in $(seq 1 12); do
    if docker compose exec -T coredns /usr/local/bin/coredns healthcheck \
      && [ "$(dig +short +tries=1 +time=3 @127.0.0.1 "1.$(printf '%032d' 0).${DNSTEST_ZONE}" A)" ] \
      && curl -fsS --max-time 5 --resolve "api.${DNSTEST_ZONE}:443:127.0.0.1" "https://api.${DNSTEST_ZONE}/ip" >/dev/null; then
      return 0
    fi
    sleep 5
  done
  return 1
}

git fetch --quiet origin main
next=$(git rev-parse FETCH_HEAD)
if [ "$next" = "$prev" ] && [ ! -f "$failed" ]; then
  # Same commit: still pull, in case a digest-pinned tag moved upstream (it should not), then done.
  docker compose pull --quiet
  docker compose up -d --remove-orphans
  exit 0
fi
if [ -f "$failed" ] && [ "$(cat "$failed")" = "$next" ]; then
  echo "skipping $next: it failed the probe before" >&2
  exit 0
fi

git merge --ff-only --quiet "$next"
if ! docker compose pull --quiet; then
  # The tag may not be published yet (release PR just merged). Try again next run.
  echo "pull failed, staying on $prev" >&2
  git reset --hard --quiet "$prev"
  exit 1
fi
docker compose up -d --remove-orphans

if probe; then
  rm -f "$failed"
  docker image prune -f --filter "until=168h" >/dev/null
  echo "updated to $next"
  exit 0
fi

echo "probe failed on $next, rolling back to $prev" >&2
echo "$next" >"$failed"
git reset --hard --quiet "$prev"
docker compose pull --quiet || true
docker compose up -d --remove-orphans
exit 1
