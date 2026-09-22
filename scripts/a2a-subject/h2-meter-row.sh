#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Gating scenario `a2a.battery|h2-meter-row` -- H2 (ARCHITECTURE.md #2.2 step 6, METER) for the A2A
# plane. Proves the Teller order at step 6: one served `message/send` settles to a usage delta of
# EXACTLY one request, priced by `per_request_fee` (docs/a2a.md: "A successful call records one
# metered event with resource `agent:<agent_id>` and provider `a2a`").
#
# THE SUBJECT IS NOW A BILLING-ON DEPLOYMENT (#42), and the third assertion below is the one that
# says so. `h2-lib.sh` used to write `per_request_fee: 1` and no `rate_card:` key at all, which under
# #42 is billing OFF -- and billing off is not a smaller version of billing on, it is a different
# node: `plane_host/govern.rs:226` gates the whole metering write on `cost.pricing_enabled()`
# (`rate_card.is_some()`), so that subject recorded NO metering row for a served call. Measured on
# the release binary, `GET /api/v1/admin/usage` answered `by_model: []` and `total.requests: 0` while
# this rig read 1 request and 1 cent and called it proof of the meter.
#
# WHAT DID NOT CHANGE, AND WHY IT DID NOT. The two deltas below are unmoved by the switch, and that
# is a measured fact rather than an assumption: `GET /api/v1/admin/keys/<kid>/usage` reads the BUDGET
# CELL (`derived_bucket_usage`, governance/state.rs:1581), and that cell is bumped by the ADMISSION
# charge in `try_admit` (state.rs:2033) one step before the meter, on a path with no card gate at
# all. Its `spend_cents` is `Σ counts × rates + per_request_fee × billable_requests`, and this
# plane's counts are empty on both settings, so the fee is the whole figure either way.
#
# WHAT DID CHANGE is the row's EXISTENCE. Under the old config the assertion below could not have
# been written; under this one it gates. That is the meter proving it ran, rather than the admission
# counter standing in for it -- and it is also why the two legs beside this one (h2-class-price.sh,
# h2-card-epoch.sh) have a money surface to read at all.
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

# THE METER ITSELF RAN — the assertion the old billing-OFF subject could not carry. The two deltas
# above are the ADMISSION counter's; this one is the metering series', and it is a different write
# on a different path (`plane_host/govern.rs:226` → `GovState::record_metering`, state.rs:871). One
# served call posts exactly one row, named for the resource it was admitted on and the plane that
# served it, and `GET /api/v1/admin/usage` is the only admin surface it appears on.
# Write-behind (`usage_flush_interval_ms`, 100ms), so the read waits a flush cadence with margin.
sleep 2
row_requests="$(h2_meter_row_field "agent:probe" "a2a" requests)"
[ "$row_requests" = "1" ] || { failures=$((failures+1)); detail="${detail}metering rows for (agent:probe, a2a) report requests=${row_requests}(want exactly 1; '-' means the meter wrote no row at all); "; }

if [ "$failures" -eq 0 ]; then
  h2_verdict PASS "one served message/send settled to a usage delta of exactly 1 request priced at per_request_fee=1 cent, and posted exactly one metering row named (agent:probe, a2a)"
else
  h2_verdict FAIL "$detail"
fi
