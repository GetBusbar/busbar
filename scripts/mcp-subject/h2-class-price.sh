#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Gating scenario `mcp.rig|h2-class-price` -- H2 (BUSBAR-1.6.0.md THE DESIGN, §1 step 6, METER) for the MCP
# plane, and the PRICING half of that step rather than the posting half. h2-meter-row.sh proves ONE
# served `tools/call` settles to ONE row carrying the flat fee (#44). This leg asks the question that
# one cannot: what did the call MEASURE, and what does the card charge for it (#71 -- "a plane's
# whole money obligation is to emit ONE fact per unit: raw counts keyed by plane-declared class
# strings ... the MONEY VIEW computes Σ count × rate" at READ time).
#
# THE CLASSES ARE NOT A CHOICE THIS SCRIPT MAKES. This plane declares TWO and names both in
# constants (`crates/busbar-plane-mcp/src/tool_meta.rs:33-52`):
#
#   tool_calls   family `count`, direction Response, default_divisor 1
#   bytes        family `byte`,  direction Response, default_divisor 1
#
# Divisor one on both is load-bearing for the expected value: there is no per-N-units term, so no
# rounding to argue about (#44). One served `tools/call` therefore owes
#
#     price = tool_calls × rate(tool_calls) + bytes × rate(bytes)   [+ the flat fee, #44]
#
# with `tool_calls = 1` (the declaration's own words: "A tool call is FLAT-metered ... the call class
# divides by one and counts calls") and `bytes` = the length of the answer read back -- direction
# Response, which both declarations state. The mock upstream answers with a JSON result document, so
# `bytes > 0` is not an estimate.
#
# THE PLANE'S OWN DECLARATION ALREADY CONFESSES HALF OF THIS, verbatim, at meta.rs:28-31: "the codec
# today posts a quantity of zero for its request event, so a deployment that priced the call class
# would be pricing something the codec does not currently report a number for. That is a gap between
# what the design's table declares and what the engine beside the codec measures". This leg is that
# sentence made falsifiable. A confession in a doc comment is not a gate; an exit code is.
#
# THREE THINGS MUST HOLD FOR THE PRICE LINE TO MEAN ANYTHING, asked separately so a red says WHICH
# one fell:
#   (1) THE CARD MUST BE ABLE TO NAME THE CLASSES. If it cannot, `rate(tool_calls)` is not a number
#       any operator can set and the product is unreachable for everyone, forever. Asked of the
#       binary's own boot: this leg's node boots WITH the card, and a card that cannot name them is
#       refused at boot (#77(5)).
#   (2) THE PLANE MUST REPORT COUNTS. #71 gives the plane exactly one obligation and this is it. A
#       count of zero for a call that happened is not a price of zero, it is a MEASUREMENT THAT DID
#       NOT HAPPEN.
#   (3) THE PRICE MUST BE THE PRODUCT. Not independently checkable while either factor is missing, so
#       it is reported as BLOCKED BY the ones that fell, never as passed.
#
# WHERE THE COUNTS AND THE PRICE ARE READ: the `/admin/usage` row's `classes` object (new in 1.6.0,
# FLIP-A2A ruling), each plane-declared class's `{count, cost}`, cost in micro-units and priced by the
# card in force at the row's instant. Not the LLM token columns: `tool_calls` and `bytes` are not
# tokens, and a reader that summed token columns could only ever see zero here.
#
# THE CARD IS THIS LEG'S OWN: `tools.rate_card` (#47) prices `tool_calls` at 2 and `bytes` at 3
# micro-units per unit. The lib's default card prices both at an explicit 0 (#77(5)), against which
# "price = Σ count × rate" would hold for any count at all; non-zero, distinct rates make the product
# answerable. Integer rates and a divisor of one leave nothing to round (#44).
#
# THE CONTROL, so that a red here is a finding and not a broken probe: the same read must show the
# metering row EXISTS and carries one request, and the key's own spend reads the flat fee: 1 cent,
# because the classes add 2 + 3 × bytes micro-units, which is far below the one cent the single
# truncation to whole cents would need to move (`derive_spend_cents`, kernel-ledger cost/project.rs).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=h2-lib.sh
source "${here}/h2-lib.sh"

WORK="${H2_WORK:-${here}/../../target/h2-scratch/mcp-class-price.$$}"
trap 'h2_stop' EXIT

H2_GROUPS_YAML="groups:
  h2-oracle:
    limits:
      - { budget: 1000000, per: day }"

# The rates, in micro-units per unit, and the card that carries them.
RATE_TOOL_CALLS=2
RATE_BYTES=3
FEE_MICROS=10000 # tools.fees.per_request: 1 cent, lifted by the one scale (1 cent = 10000 micros)
export H2_RATE_CARD_YAML="  rate_card:
    probe_ping: { units: { tool_calls: ${RATE_TOOL_CALLS}, bytes: ${RATE_BYTES} } }"

# ── (1) THE CARD MUST BE ABLE TO NAME THE CLASSES ─────────────────────────────────────────────────
h2_boot "$WORK" "$H2_GROUPS_YAML" || {
  echo "FAIL	(1) a node whose tools.rate_card prices this plane's declared classes 'tool_calls' and 'bytes' did not boot: $(grep -v '^\s*$' "$WORK/busbar.log" 2>/dev/null | tail -1 | cut -c1-300)"
  exit 1
}

failures=0
detail=""

read -r kid tok <<<"$(h2_mint h2-oracle)"
[ -n "$tok" ] || { h2_verdict FAIL "mint failed"; exit 1; }
bound="$(h2_bind "$tok")"

read -r call_status _ <<<"$(h2_call "$bound" "price")"
[ "$call_status" = "200" ] || { failures=$((failures+1)); detail="${detail}call_status=${call_status}(want 200); "; }
sleep 2

# ── THE CONTROL: billing is ON and the row is there ───────────────────────────────────────────────
row_requests="$(h2_meter_row_field "probe_ping" "mcp" requests)"
[ "$row_requests" = "1" ] || { failures=$((failures+1)); detail="${detail}metering row for (probe_ping, mcp) reports requests=${row_requests}(want 1 -- with no such row the rig is not reading a billing-ON node at all); "; }
key_spend="$(h2_usage_field "$kid" spend_cents)"
h2_int_is "$key_spend" -eq 1 || { failures=$((failures+1)); detail="${detail}the key's own spend reads ${key_spend}(want 1, the flat fee -- the classes add well under a cent, and if this is wrong the rig is not reading money correctly and the reds below cannot be trusted); "; }

# ── (2) THE PLANE MUST REPORT COUNTS ──────────────────────────────────────────────────────────────
# Each declared class's count off the row's `classes` object. Asked through h2_int_is so ANY read
# that is not a positive integer -- `-` (no row), 0 (the class absent from the row), empty,
# non-numeric -- is a failure (item 499).
tc_count="$(h2_meter_row_class "probe_ping" "mcp" tool_calls count)"
by_count="$(h2_meter_row_class "probe_ping" "mcp" bytes count)"
if ! h2_int_is "$tc_count" -gt 0; then
  failures=$((failures+1))
  detail="${detail}(2) the served call reported classes.tool_calls.count=${tc_count} (want > 0: one call is one tool_call); "
fi
if ! h2_int_is "$by_count" -gt 0; then
  failures=$((failures+1))
  detail="${detail}(2) the served call reported classes.bytes.count=${by_count} (want > 0: the upstream answered with a document); "
fi

# ── (3) THE PRICE MUST BE THE PRODUCT ─────────────────────────────────────────────────────────────
tc_cost="$(h2_meter_row_class "probe_ping" "mcp" tool_calls cost)"
by_cost="$(h2_meter_row_class "probe_ping" "mcp" bytes cost)"
spend_micros="$(h2_meter_row_field "probe_ping" "mcp" spend_micros)"
if [ "$failures" -ne 0 ]; then
  detail="${detail}(3) price = Σ count × rate is BLOCKED BY the above (classes.tool_calls.cost=${tc_cost}, classes.bytes.cost=${by_cost}, row spend_micros=${spend_micros}); "
else
  want_tc=$((tc_count * RATE_TOOL_CALLS))
  want_by=$((by_count * RATE_BYTES))
  if ! h2_int_is "$tc_cost" -eq "$want_tc"; then
    failures=$((failures+1))
    detail="${detail}(3) classes.tool_calls.cost=${tc_cost} micro-units (want ${tc_count} × ${RATE_TOOL_CALLS} = ${want_tc}); "
  fi
  if ! h2_int_is "$by_cost" -eq "$want_by"; then
    failures=$((failures+1))
    detail="${detail}(3) classes.bytes.cost=${by_cost} micro-units (want ${by_count} × ${RATE_BYTES} = ${want_by}); "
  fi
  if ! h2_int_is "$spend_micros" -eq $((FEE_MICROS + want_tc + want_by)); then
    failures=$((failures+1))
    detail="${detail}(3) the row charged spend_micros=${spend_micros} (want the fee ${FEE_MICROS} + Σ count × rate ${want_tc} + ${want_by} = $((FEE_MICROS + want_tc + want_by))); "
  fi
fi

if [ "$failures" -eq 0 ]; then
  h2_verdict PASS "one served tools/call reported tool_calls=${tc_count} and bytes=${by_count} under the declared classes, the card priced them at ${tc_cost} + ${by_cost} micro-units (Σ count × rate), and the row charged that + the fee = ${spend_micros}"
else
  h2_verdict FAIL "$detail"
fi
