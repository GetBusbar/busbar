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
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
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

statuses=""
tripped_at=""
out=""
# A 503 IS NOT SELF-IDENTIFYING. busbar answers 503 while it is still coming up AND when a cell's
# breaker has tripped, with the same status line; only the BODY distinguishes them, and this loop
# read the status alone. So a boot that had not finished (h2_boot used to return as soon as any
# HTTP code came back at all -- see h2-lib.sh) recorded `tripped_at=1`, and the scenario went on to
# assert things about a breaker that had not tripped, on a busbar that was not serving. The
# UNSUPPORTED_OPERATION check below already knew what a real trip looks like; it just ran too late
# to stop the wrong attempt being recorded as the trip. Move that discrimination into the test that
# decides, and keep any non-terminal 503 as evidence in its own right.
notserving=""
for i in 1 2 3 4 5 6 7 8; do
  read -r s b <<<"$(h2_call "$bound" "route-$i")"
  statuses="${statuses}${s} "
  if [ "$s" = "503" ]; then
    case "$b" in
      *UNSUPPORTED_OPERATION*)
        if [ -z "$tripped_at" ]; then tripped_at="$i"; out="$b"; fi
        ;;
      *)
        # A 503 that is not the breaker's terminal answer. Recorded, never silently taken for one.
        notserving="${notserving}attempt-${i} "
        ;;
    esac
  fi
done

if [ -n "$notserving" ]; then
  failures=$((failures+1))
  detail="${detail}503s with no UNSUPPORTED_OPERATION body at ${notserving}- a 'not serving' 503 is byte-identical to a tripped-breaker 503 in its status line, so this scenario cannot tell them apart and must not guess; h2_boot waits for a 200 agent-card before this loop runs, so a 503 here is a real fault; "
fi

[ -n "$tripped_at" ] || { failures=$((failures+1)); detail="${detail}breaker never tripped across 8 down-agent calls (statuses: ${statuses}); "; }

if [ -n "$tripped_at" ]; then
  # Redundant with the loop above by construction (only an UNSUPPORTED_OPERATION body sets
  # tripped_at now) and kept deliberately: if the loop's discrimination is ever loosened, this is
  # the assertion that goes red rather than the scenario quietly widening what counts as a trip.
  case "$out" in
    *UNSUPPORTED_OPERATION*) ;;
    *) failures=$((failures+1)); detail="${detail}tripped body missing UNSUPPORTED_OPERATION: ${out}; " ;;
  esac
  egress_at_trip="$(h2_egress_count)"
  # One more call after the trip must add NO further egress: a tripped cell answers terminal without
  # dialling the backend at all.
  h2_call "$bound" "route-post-trip" >/dev/null
  egress_after="$(h2_egress_count)"
  [ "$egress_after" -eq "$egress_at_trip" ] || { failures=$((failures+1)); detail="${detail}egress grew by $((egress_after-egress_at_trip)) after the breaker tripped (want 0, terminal must not dial); "; }
fi

# Before the trip, egress DID reach the agent (each attempt actually dialled and got a real 502).
[ "$(h2_egress_count)" -gt 0 ] || { failures=$((failures+1)); detail="${detail}zero egress recorded even before the trip; "; }

if [ "$failures" -eq 0 ]; then
  h2_verdict PASS "down agent surfaced per-attempt 502s, breaker tripped at attempt ${tripped_at} to a terminal 503/UNSUPPORTED_OPERATION, and no further egress was dialled once tripped"
else
  h2_verdict FAIL "$detail"
fi
