#!/usr/bin/env bash
# Turn a job's service CONTAINERS into the connection URLs the tests read, and write them to
# $GITHUB_ENV.
#
#   ./scripts/ci-service-endpoints.sh postgres=<cid> mysql=<cid> valkey=<cid>
#
# WHY THIS EXISTS. On a GitHub-hosted runner a job owns the whole machine, so `ports: - 5432:5432`
# and `postgres://…@localhost:5432/` are the same fact stated twice. On the busbar-xl fleet FOUR
# runner agents share one box, and the host's port 5432 is a single resource: the second job to
# start a postgres service dies in `Initialize containers` with
#
#     Bind for 0.0.0.0:5432 failed: port is already allocated
#
# before one line of the job has run. That is not a flake to be retried, it is two jobs asking for
# the same port — and it is the reason a naive lift of a hosted workflow onto several agents per box
# fails immediately.
#
# The fix is to stop publishing to the host at all. The runner already puts every service container
# on a per-job bridge network (`github_network_<uuid>`) with a network-alias; that network, and the
# address on it, are private to the job. Two jobs on one box get two networks and two addresses, and
# there is no shared resource left to collide on. This script reads those addresses and states them
# as URLs, so the workflows say `${BUSBAR_TEST_POSTGRES_URL}` exactly as before and nothing below
# the workflow layer changes.
#
# A LOOKUP THAT SILENTLY RETURNS NOTHING IS WORSE THAN A RED. An empty address here would produce
# `postgres://busbar:busbar@:5432/busbar_test`, which fails deep inside a test with a connection
# error that names neither this step nor the missing container. So every argument must resolve, and
# a container without an address on its network is a hard failure with the container id in it.
#
# NON-EMPTY IS NOT THE SAME AS ONE ADDRESS (item 492). The inspect template ranges over EVERY network
# the container is on; with no separator, a container on two networks yielded two IPs glued together
# ("172.18.0.2172.19.0.3") -- non-empty, so it passed, and the garbage URL failed deep inside a test
# exactly as the paragraph above says must not happen. Each address is now its own line, and
# pick_addr accepts exactly ONE well-formed IPv4 address; zero, several or a malformed one is a hard
# failure that dumps the container's networks.
#
#   ./scripts/ci-service-endpoints.sh --selftest   # pick_addr over fixtures; no docker, no GITHUB_ENV
set -euo pipefail

addr_of() { # $1 = container id. One address per line, one line per network.
  docker inspect -f '{{range $n, $c := .NetworkSettings.Networks}}{{$c.IPAddress}}{{"\n"}}{{end}}' "$1" 2>/dev/null
}

# pick_addr (stdin: addr_of's lines) -> the one address, or non-zero with the reason on stderr.
pick_addr() {
  local addrs n
  addrs="$(grep -v '^[[:space:]]*$' || true)"
  n="$(printf '%s' "$addrs" | grep -c . || true)"
  if [ "$n" -ne 1 ]; then
    echo "expected exactly one address on the job network, found $n${addrs:+: $(printf '%s' "$addrs" | tr '\n' ' ')}" >&2
    return 1
  fi
  if ! printf '%s' "$addrs" | grep -qE '^([0-9]{1,3}[.]){3}[0-9]{1,3}$'; then
    echo "not an IPv4 address: '$addrs'" >&2
    return 1
  fi
  printf '%s' "$addrs"
}

selftest() {
  local fail=0 got
  got="$(printf '172.18.0.2\n' | pick_addr 2>/dev/null)" && [ "$got" = "172.18.0.2" ] \
    && echo "ok: one network -> its address" || { fail=1; echo "FAIL: one network not resolved (got '$got')"; }
  if got="$(printf '172.18.0.2\n172.19.0.3\n' | pick_addr 2>/dev/null)"; then
    fail=1; echo "FAIL: two networks accepted as '$got'"
  else echo "ok: two networks -> refused, not concatenated"; fi
  if printf '\n' | pick_addr >/dev/null 2>&1; then fail=1; echo "FAIL: no address accepted"
  else echo "ok: no address -> refused"; fi
  if printf '172.18.0.2172.19.0.3\n' | pick_addr >/dev/null 2>&1; then fail=1; echo "FAIL: glued addresses accepted"
  else echo "ok: a malformed (glued) address -> refused"; fi
  if [ "$fail" = 0 ]; then echo "ci-service-endpoints selftest: PASS"; else echo "ci-service-endpoints selftest: FAIL"; fi
  return "$fail"
}

if [ "${1:-}" = "--selftest" ]; then selftest; exit $?; fi

[ -n "${GITHUB_ENV:-}" ] || { echo "ci-service-endpoints.sh: no GITHUB_ENV; this is a CI-only step" >&2; exit 2; }
[ $# -gt 0 ] || { echo "ci-service-endpoints.sh: name=<container-id> arguments required" >&2; exit 2; }

for arg in "$@"; do
  name="${arg%%=*}"
  cid="${arg#*=}"
  [ -n "$cid" ] && [ "$cid" != "$name" ] || {
    echo "::error::service '$name' has no container id — is it declared under services: in this job?" >&2
    exit 1
  }
  ip="$(addr_of "$cid" | pick_addr)" || {
    echo "::error::service '$name' (container $cid) has no single address on its job network" >&2
    docker inspect "$cid" --format '{{json .NetworkSettings.Networks}}' >&2 || true
    exit 1
  }
  case "$name" in
    postgres) echo "BUSBAR_TEST_POSTGRES_URL=postgres://busbar:busbar@${ip}:5432/busbar_test" >>"$GITHUB_ENV" ;;
    mysql)    echo "BUSBAR_TEST_MYSQL_URL=mysql://busbar:busbar@${ip}:3306/busbar_test"       >>"$GITHUB_ENV" ;;
    valkey)   echo "VALKEY_URL=redis://${ip}:6379"                                            >>"$GITHUB_ENV" ;;
    *) echo "ci-service-endpoints.sh: unknown service '$name'" >&2; exit 2 ;;
  esac
  # PRINTED, because a scope nobody can see is a scope nobody can size. These are addresses on a
  # throwaway bridge network with fixture credentials; there is nothing here to redact.
  echo "  $name -> $ip"
done
