#!/usr/bin/env bash
# End to end inside the image (read-only root, no capabilities): the real traceroute traces the loopback, two saved
# outputs with a route change are fed through standard input, and status, changes, show and the reports are produced
# from the same volume. Needs Docker. Usage: tools/docker_e2e.sh [image]
set -euo pipefail
IMAGE="${1:-pathmap}"
VOL="pathmap-e2e-$$"
TMP="$(mktemp -d)"
trap 'docker volume rm -f "$VOL" >/dev/null 2>&1 || true; rm -rf "$TMP"' EXIT

[ "$(docker run --rm --entrypoint id "$IMAGE" -u)" != 0 ]   # not root
docker run --rm --entrypoint traceroute "$IMAGE" --version 2>&1 | grep -qi traceroute
docker volume create "$VOL" >/dev/null
# the volume is created by root: give it to the image's user
docker run --rm --user 0 -v "$VOL":/data --entrypoint chown "$IMAGE" 10001 /data

RUN=(docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp -v "$VOL":/data "$IMAGE")
RUNI=(docker run --rm -i --read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp -v "$VOL":/data "$IMAGE")

# 1. the real program, on the loopback
"${RUN[@]}" trace 127.0.0.1 | tee /dev/stderr | grep -q '127.0.0.1: .*reached'
"${RUN[@]}" trace 127.0.0.1 >/dev/null
"${RUN[@]}" status --stale 1h | tee /dev/stderr | grep -q '127.0.0.1: '

# 2. saved outputs: 10 runs on one route, then 5 on another
route() {   # $1 = router at hop 2
printf 'traceroute to 203.0.113.9 (203.0.113.9), 30 hops max, 60 byte packets\n'
printf ' 1  192.0.2.1  1.0 ms  1.1 ms  1.2 ms\n 2  %s  5.0 ms  5.1 ms  5.2 ms\n 3  203.0.113.9  9.0 ms  9.1 ms  9.2 ms\n' "$1"
}
for i in 0 1 2 3 4 5 6 7 8 9; do
  route 198.51.100.1 | "${RUNI[@]}" parse - --target 203.0.113.9 --time "2026-10-01T0$i:00:00Z" --store >/dev/null
done
for i in 0 1 2 3 4; do
  route 198.51.100.77 | "${RUNI[@]}" parse - --target 203.0.113.9 --time "2026-10-01T1$i:00:00Z" --store >/dev/null
done
"${RUN[@]}" changes 203.0.113.9 | tee /dev/stderr | grep -q 'hop 2: 198.51.100.1 -> 198.51.100.77'
if "${RUN[@]}" changes --fail-on-change >/dev/null; then echo "expected exit 1 with a change to report" >&2; exit 1; fi
"${RUN[@]}" show 203.0.113.9 | tee /dev/stderr | grep -q '198.51.100.77'
"${RUN[@]}" report --out /data/report.html >/dev/null
"${RUN[@]}" report --format html 203.0.113.9 | grep -q 'Route changed'
"${RUN[@]}" report --format json 203.0.113.9 | grep -q '"203.0.113.9"'
# a published report must not contain the addresses
"${RUN[@]}" report --anonymize --format html > "$TMP/anon.html"
grep -q 'node-' "$TMP/anon.html"
! grep -q -e '198.51.100' -e '203.0.113' "$TMP/anon.html"
# a bad target is a usage error (exit 2)
set +e; "${RUN[@]}" trace -- '-oProxyCommand=x' >/dev/null 2>&1; rc=$?; set -e
[ "$rc" = 2 ]
echo "docker end-to-end: OK"
