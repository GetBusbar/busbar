#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Gating scenario `mcp.rig|h2-class-price` -- H2 (ARCHITECTURE.md #2.2 step 6, METER) for the MCP
# plane, and the PRICING half of that step rather than the posting half. h2-meter-row.sh proves ONE
# served `tools/call` settles to ONE row carrying the flat fee (#44). This leg asks the question that
# one cannot: what did the call MEASURE, and what does the card charge for it (#71 -- "a plane's
# whole money obligation is to emit ONE fact per unit: raw counts keyed by plane-declared class
# strings ... the MONEY VIEW computes Σ count × rate" at READ time).
#
# THE CLASSES ARE NOT A CHOICE THIS SCRIPT MAKES. This plane declares TWO and names both in
# constants (`crates/busbar-plane-mcp/src/meta.rs:33-52`):
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
#       any operator can set and the product is unreachable for everyone, forever.
#   (2) THE PLANE MUST REPORT COUNTS. #71 gives the plane exactly one obligation and this is it. A
#       count of zero for a call that happened is not a price of zero, it is a MEASUREMENT THAT DID
#       NOT HAPPEN.
#   (3) THE PRICE MUST BE THE PRODUCT. Not independently checkable while either factor is missing, so
#       it is reported as BLOCKED BY the ones that fell, never as passed.
#
# THE CONTROL, so that a red here is a finding and not a broken probe: the same read must show the
# metering row EXISTS and carries the flat fee exactly. That row exists only because the rig's config
# now carries `rate_card:`, so the control also witnesses the billing switch itself.
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

h2_boot "$WORK" "$H2_GROUPS_YAML" || { echo "FAIL	boot failed, see $WORK/busbar.log" ; exit 1; }

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
[ "$key_spend" -eq 1 ] || { failures=$((failures+1)); detail="${detail}the key's own spend reads ${key_spend}(want 1, the flat fee -- if this is wrong the rig is not reading money correctly and the reds below cannot be trusted); "; }

# ── (1) THE CARD MUST BE ABLE TO NAME THE CLASSES ─────────────────────────────────────────────────
# Asked of the binary, not of a script's opinion of the grammar: `--validate` runs the exact
# load → resolve → validate that boot runs.
card_verdict="$(h2_validate_card 'rate_card:
  tool_calls: { input_utok: 2 }
  bytes: { input_utok: 3 }')"
if [ "$card_verdict" != "ok" ]; then
  failures=$((failures+1))
  detail="${detail}(1) a rate card naming this plane's declared classes 'tool_calls' and 'bytes' does not resolve: ${card_verdict}; "
fi

# ── (2) THE PLANE MUST REPORT COUNTS ──────────────────────────────────────────────────────────────
# Every quantity column the money surface exposes for this row, summed. The request COUNT is
# deliberately excluded: a request is not a quantity, it is what #44's flat fee prices.
quantity="$(h2_meter_row_quantity "probe_ping" "mcp")"
if [ "$quantity" = "-" ] || [ "$quantity" -le 0 ] 2>/dev/null; then
  failures=$((failures+1))
  detail="${detail}(2) the served call reported quantity=${quantity} under this plane's declared classes 'tool_calls'/'bytes' (want > 0: one call is one tool_call, and the upstream answered with a document); "
fi

# ── (3) THE PRICE MUST BE THE PRODUCT ─────────────────────────────────────────────────────────────
spend_micros="$(h2_meter_row_field "probe_ping" "mcp" spend_micros)"
if [ "$failures" -ne 0 ]; then
  detail="${detail}(3) price = Σ count × rate is BLOCKED BY the above; the row charged spend_micros=${spend_micros}, which is the flat per-request fee (1 cent = 10000 micro-units) and nothing else; "
fi

if [ "$failures" -eq 0 ]; then
  h2_verdict PASS "one served tools/call reported non-zero counts under the declared classes, a card can price them, and the row charged Σ count × rate + fee"
else
  h2_verdict FAIL "$detail"
fi
