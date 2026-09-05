#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Gating scenario `a2a.battery|h2-meter-row` -- H2 (ARCHITECTURE.md #2.2 step 6, METER) for the A2A
# plane. Proves the Teller order at step 6: one served `message/send` settles to a usage delta of
# EXACTLY one request, priced by `per_request_fee` (docs/a2a.md: "A successful call records one
# metered event with resource `agent:<agent_id>` and provider `a2a`").
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=h2-lib.sh
source "${here}/h2-lib.sh"

WORK="${H2_WORK:-${here}/../../target/h2-scratch/a2a-meter-row.$$}"
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

usage_before="$(h2_usage "$kid")"

read -r meter_status meter_body <<<"$(h2_call "$bound" "meter")"
[ "$meter_status" = "200" ] || { failures=$((failures+1)); detail="${detail}meter_status=${meter_status}(want 200): ${meter_body}; "; }

usage_after="$(h2_usage "$kid")"
req_before="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("requests") or 0)' <<<"$usage_before")"
req_after="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("requests") or 0)' <<<"$usage_after")"
spend_before="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("spend_cents") or 0)' <<<"$usage_before")"
spend_after="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("spend_cents") or 0)' <<<"$usage_after")"
req_delta="$((req_after - req_before))"
spend_delta="$((spend_after - spend_before))"

[ "$req_delta" -eq 1 ] || { failures=$((failures+1)); detail="${detail}usage_requests_delta=${req_delta}(want exactly 1); "; }
[ "$spend_delta" -eq 1 ] || { failures=$((failures+1)); detail="${detail}usage_spend_cents_delta=${spend_delta}(want exactly 1, the configured per_request_fee); "; }

if [ "$failures" -eq 0 ]; then
  h2_verdict PASS "one served message/send settled to a usage delta of exactly 1 request, priced at per_request_fee=1 cent"
else
  h2_verdict FAIL "$detail"
fi
