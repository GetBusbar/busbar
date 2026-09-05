#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Gating scenario `mcp.rig|h2-admit-refusal` -- H2 (ARCHITECTURE.md #2.2 step 4, ADMIT) for the MCP
# plane. Proves the Teller order at step 4: a principal already past AUTHENTICATE/VERIFY but over
# its group's `requests` budget is refused at ADMIT (native 429, `budget_exhausted`) before ROUTE
# ever dials -- no egress, no charge beyond the draws already posted by the calls that were let
# through.
#
# `requests` rather than `budget` cents: an MCP tools/call carries no llm rate-card pricing, so a
# cents-denominated `budget` limit is never exceeded by an unpriced call (spend_cents stays 0
# forever). `requests` is the dimension the group chain enforces independent of pricing, and it is
# the one docs/a2a.md and docs/mcp.md both name for this plane's admission.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=h2-lib.sh
source "${here}/h2-lib.sh"

WORK="${H2_WORK:-${here}/../../target/h2-scratch/admit-refusal.$$}"
trap 'h2_stop' EXIT

H2_GROUPS_YAML="groups:
  h2-broke:
    limits:
      - { requests: 1, per: day }"

h2_boot "$WORK" "$H2_GROUPS_YAML" || { echo "FAIL	boot failed, see $WORK/busbar.log" ; exit 1; }

failures=0
detail=""

read -r kid tok <<<"$(h2_mint h2-broke)"
[ -n "$tok" ] || { h2_verdict FAIL "mint failed"; exit 1; }
bound="$(h2_bind "$tok")"

# First call: within budget, admitted, dispatched.
read -r first_status _ <<<"$(h2_call "$bound" "first")"
[ "$first_status" = "200" ] || { failures=$((failures+1)); detail="${detail}first_status=${first_status}(want 200); "; }

egress_mid="$(h2_egress_count)"
usage_mid="$(h2_usage "$kid")"

# Second call on the same exhausted `requests` budget: refused at ADMIT.
read -r second_status second_body <<<"$(h2_call "$bound" "second")"
[ "$second_status" = "429" ] || { failures=$((failures+1)); detail="${detail}second_status=${second_status}(want 429); "; }
case "$second_body" in
  *budget_exhausted*) ;;
  *) failures=$((failures+1)); detail="${detail}second_body missing reason=budget_exhausted: ${second_body}; " ;;
esac

egress_after="$(h2_egress_count)"
egress_delta_on_refusal="$((egress_after - egress_mid))"
[ "$egress_delta_on_refusal" -eq 0 ] || { failures=$((failures+1)); detail="${detail}egress_delta_on_refusal=${egress_delta_on_refusal}(want 0); "; }

usage_after="$(h2_usage "$kid")"
req_mid="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("requests") or 0)' <<<"$usage_mid")"
req_after="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("requests") or 0)' <<<"$usage_after")"
[ "$req_mid" -eq "$req_after" ] || { failures=$((failures+1)); detail="${detail}usage_requests_delta_on_refusal=$((req_after-req_mid))(want 0); "; }

if [ "$failures" -eq 0 ]; then
  h2_verdict PASS "first call admitted (200); second on the exhausted requests budget refused 429/budget_exhausted; zero egress and zero usage delta on the refusal"
else
  h2_verdict FAIL "$detail"
fi
