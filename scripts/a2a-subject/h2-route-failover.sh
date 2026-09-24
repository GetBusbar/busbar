#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Gating scenario `a2a.battery|h2-route-failover` -- H2 (ARCHITECTURE.md #2.2 step 5, ROUTE) for the
# A2A plane. Proves the Teller order at step 5: a down agent's failures are surfaced per-attempt
# (`InvalidAgentResponse`, 502) while the circuit breaker is still closed, and once the breaker trips
# (docs/a2a.md: "error rate >= 0.5 over at least 5 outcomes in a 30-second window") the SAME agent
# ends every further unit TERMINAL -- HTTP 503, an exact `Retry-After`, `UnsupportedOperation`
# (`-32004`) -- WITHOUT dialling the backend at all (there is no second, healthy pool member to fail
# over to on this fixture, so "terminal" is the documented outcome ARCHITECTURE.md #2.2 names for a
# down lane with no failover target).
#
# EVERY CLAIM ABOVE IS JUDGED, not narrated: `judge_route_failover` below reads the recorded calls
# and refuses the PASS unless each pre-trip attempt answered 502, at least one attempt was
# dispatched before the trip, every call from the trip on answered 503, the tripped body carries
# UNSUPPORTED_OPERATION, and the tripped response carries a `Retry-After` that is a whole number of
# seconds within the first-trip cooldown (15 s) and EXACTLY the number the body's "Retry after Ns"
# names. `--selftest` proves that judge bites, with no busbar and no network.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

# judge_route_failover <records-file>
# One line per call, in order: "<status><TAB><retry-after header, or empty><TAB><body>".
# Prints "<tripped_at, 1-based; 0 if never><TAB><failure count><TAB><detail>".
judge_route_failover() {
  python3 - "$1" <<'PY'
import re, sys
FIRST_TRIP_COOLDOWN_SECS = 15  # docs/a2a.md: "cooldown 15 s escalating to 120 s"
rows = []
for line in open(sys.argv[1], encoding="utf-8").read().splitlines():
    status, ra, body = (line.split("\t", 2) + ["", ""])[:3]
    rows.append((status, ra.strip(), body))
bad = []
trip = next((i for i, r in enumerate(rows) if r[0] == "503"), None)
statuses = " ".join(r[0] for r in rows)
if trip is None:
    bad.append("breaker never tripped across %d down-agent calls (statuses: %s)" % (len(rows), statuses))
else:
    if trip == 0:
        bad.append("the FIRST call already answered 503, so no attempt was ever dispatched and no "
                   "per-attempt 502 was surfaced (statuses: %s)" % statuses)
    pre = [r[0] for r in rows[:trip] if r[0] != "502"]
    if pre:
        bad.append("pre-trip attempts must each surface the down agent's 502; got %s (statuses: %s)"
                   % (" ".join(pre), statuses))
    post = [r[0] for r in rows[trip:] if r[0] != "503"]
    if post:
        bad.append("once tripped every further call must be terminal 503; got %s (statuses: %s)"
                   % (" ".join(post), statuses))
    status, ra, body = rows[trip]
    if "UNSUPPORTED_OPERATION" not in body:
        bad.append("tripped body missing UNSUPPORTED_OPERATION: %s" % body)
    if not re.fullmatch(r"[0-9]+", ra):
        bad.append("tripped 503 carries no whole-seconds Retry-After (got %r)" % ra)
    else:
        n = int(ra)
        if not 1 <= n <= FIRST_TRIP_COOLDOWN_SECS:
            bad.append("Retry-After %d is outside the first-trip cooldown 1..%d"
                       % (n, FIRST_TRIP_COOLDOWN_SECS))
        m = re.search(r"Retry after ([0-9]+)s", body)
        if m is None or int(m.group(1)) != n:
            bad.append("Retry-After %d is not exactly the body's own figure (%s)"
                       % (n, m.group(0) if m else "no 'Retry after Ns' in body"))
print("%d\t%d\t%s" % (0 if trip is None else trip + 1, len(bad), "; ".join(bad)))
PY
}

if [ "${1:-}" = "--selftest" ]; then
  st_dir="$(mktemp -d)"; st_fail=0
  tb='{"error":{"data":{"reason":"UNSUPPORTED_OPERATION"},"message":"UNSUPPORTED_OPERATION: agent `probe` is unavailable ... Retry after 12s"}}'
  # case <name> <want PASS|FAIL> <records...>
  st_case() {
    local name="$1" want="$2"; shift 2
    printf '%s\n' "$@" >"$st_dir/r"
    local got fails
    got="$(judge_route_failover "$st_dir/r")"; fails="$(printf '%s' "$got" | cut -f2)"
    if { [ "$want" = PASS ] && [ "$fails" = 0 ]; } || { [ "$want" = FAIL ] && [ "$fails" != 0 ]; }; then
      echo "  ok: $name"
    else
      echo "  MISS: $name (judge said: $got)"; st_fail=$((st_fail+1))
    fi
  }
  T=$'\t'
  st_case "five 502s then a terminal 503 with an exact Retry-After is judged PASS" PASS \
    "502${T}${T}x" "502${T}${T}x" "502${T}${T}x" "502${T}${T}x" "502${T}${T}x" \
    "503${T}12${T}$tb" "503${T}12${T}$tb" "503${T}11${T}$tb"
  st_case "503 from the first call (nothing ever dispatched) is RED" FAIL \
    "503${T}12${T}$tb" "503${T}12${T}$tb" "503${T}12${T}$tb"
  st_case "a pre-trip attempt that is not a 502 is RED" FAIL \
    "502${T}${T}x" "500${T}${T}x" "503${T}12${T}$tb"
  st_case "a tripped 503 with no Retry-After is RED" FAIL \
    "502${T}${T}x" "503${T}${T}$tb"
  st_case "a Retry-After that differs from the body's own figure is RED" FAIL \
    "502${T}${T}x" "503${T}7${T}$tb"
  st_case "a Retry-After beyond the first-trip cooldown is RED" FAIL \
    "502${T}${T}x" "503${T}120${T}${tb/12s/120s}"
  st_case "a call that answers non-503 after the trip is RED" FAIL \
    "502${T}${T}x" "503${T}12${T}$tb" "502${T}${T}x"
  st_case "a tripped body without UNSUPPORTED_OPERATION is RED" FAIL \
    "502${T}${T}x" "503${T}12${T}Retry after 12s"
  st_case "a breaker that never trips is RED" FAIL \
    "502${T}${T}x" "502${T}${T}x"
  rm -rf "$st_dir"
  [ "$st_fail" -eq 0 ] || { echo "FAIL	h2-route-failover self-test: $st_fail expectation(s) did not hold"; exit 1; }
  echo "PASS	h2-route-failover self-test: the judge refuses every shape the PASS string would misdescribe"
  exit 0
fi

# shellcheck source=h2-lib.sh
source "${here}/h2-lib.sh"

WORK="${H2_WORK:-${here}/../../target/h2-scratch/a2a-route-failover.$$}"
trap 'h2_stop' EXIT

H2_GROUPS_YAML="groups:
  h2-oracle:
    limits:
      - { budget: 1000000, per: day }"

h2_boot "$WORK" "$H2_GROUPS_YAML" || { echo "FAIL	boot failed, see $WORK/busbar.log" ; exit 1; }

failures=0
detail=""

read -r kid tok <<<"$(h2_mint h2-oracle)"
[ -n "$tok" ] || { h2_verdict FAIL "mint failed"; exit 1; }
bound="$(h2_bind "$tok")"

printf 'down' > "$H2_CONTROL_FILE"

records="$WORK/route-calls.tsv"
: >"$records"
tripped_at=""
posts_at_trip=""
for i in 1 2 3 4 5 6 7 8; do
  hdr="$WORK/route-$i.headers"
  read -r s b <<<"$(h2_call "$bound" "route-$i" "$hdr")"
  ra="$(tr -d '\r' <"$hdr" | sed -n 's/^[Rr][Ee][Tt][Rr][Yy]-[Aa][Ff][Tt][Ee][Rr]:[[:space:]]*//p' | head -1)"
  printf '%s\t%s\t%s\n' "$s" "$ra" "$b" >>"$records"
  if [ "$s" = "503" ] && [ -z "$tripped_at" ]; then
    tripped_at="$i"
    # Dispatched calls BEFORE the trip, counted as POSTs the agent received -- the agent-card GETs
    # busbar makes at boot are egress too, and must not stand in for a dialled attempt.
    posts_at_trip="$(h2_egress_post_count)"
  fi
done

IFS=$'\t' read -r judged_trip judged_failures judged_detail <<<"$(judge_route_failover "$records")"
failures=$((failures + judged_failures))
[ "$judged_failures" -eq 0 ] || detail="${detail}${judged_detail}; "

if [ -n "$tripped_at" ]; then
  # Every pre-trip attempt was actually dialled: one POST per attempt before the trip.
  [ "$posts_at_trip" -ge $((tripped_at - 1)) ] && [ "$posts_at_trip" -gt 0 ] || {
    failures=$((failures+1))
    detail="${detail}only ${posts_at_trip} POST(s) reached the agent before the trip at attempt ${tripped_at} (want >= $((tripped_at - 1)), and > 0); "
  }
  egress_at_trip="$(h2_egress_post_count)"
  # One more call after the trip must add NO further egress: a tripped cell answers terminal without
  # dialling the backend at all.
  h2_call "$bound" "route-post-trip" >/dev/null
  egress_after="$(h2_egress_post_count)"
  [ "$egress_after" -eq "$egress_at_trip" ] || { failures=$((failures+1)); detail="${detail}egress grew by $((egress_after-egress_at_trip)) after the breaker tripped (want 0, terminal must not dial); "; }
fi

if [ "$failures" -eq 0 ]; then
  h2_verdict PASS "down agent surfaced per-attempt 502s, breaker tripped at attempt ${tripped_at} to a terminal 503/UNSUPPORTED_OPERATION with a Retry-After equal to the body's own figure, and no further egress was dialled once tripped"
else
  h2_verdict FAIL "$detail"
fi
