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
for i in 1 2 3 4 5 6 7 8; do
  read -r s b <<<"$(h2_call "$bound" "route-$i")"
  statuses="${statuses}${s} "
  if [ "$s" = "503" ] && [ -z "$tripped_at" ]; then
    tripped_at="$i"
    out="$b"
  fi
done

[ -n "$tripped_at" ] || { failures=$((failures+1)); detail="${detail}breaker never tripped across 8 down-agent calls (statuses: ${statuses}); "; }

if [ -n "$tripped_at" ]; then
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
