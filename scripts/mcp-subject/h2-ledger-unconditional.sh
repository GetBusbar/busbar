#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Gating scenario `mcp.rig|h2-ledger-unconditional` -- H2 (ARCHITECTURE.md #2.2 step 6, METER)
# for the MCP plane, and the ONE claim at that step that has nothing to do with money:
#
#     A SERVED CALL POSTS ITS METERING ROW. THE RATE CARD HAS NOTHING TO DO WITH IT.
#
# THE RULING THIS ENCODES, in the owner's own words: *"planes always ledger"*, and *"its a kernal
# default all planes run though. no tunring things on or off by plane"*, and -- on #42 itself --
# *"Billing is OPTIONAL per plane; rate_card PRESENCE is the switch... AGREED. but its not an on off
# in the plane."* Read with #43/#71 (plugins are PRICING-BLIND; pricing is a READ-TIME view) and
# #77(3) (price is NEVER stored; money is a read-time conversion), the model is one sentence: THE
# LEDGER IS THE RECORD OF WHAT HAPPENED AND THE CARD IS A LENS APPLIED LATER. #42 stays true exactly
# as written -- rate_card presence IS the billing switch -- because billing is the READ, not the
# WRITE.
#
# WHAT IT IS WRITTEN AGAINST. `crates/busbar-kernel/src/plane_host/govern.rs:226` wraps the whole
# metering write in `if state.app.cost.pricing_enabled()` -- which is `rate_card.is_some()`
# (`cost.rs:649`). That makes the LEDGER conditional on the CARD, which inverts the model: a plane
# whose ledger write depends on a card is a plane that knows about money, and #43/#71 forbid exactly
# that. Measured on the release binary, same traffic, one config key apart:
#
#     rate_card ABSENT   GET /api/v1/admin/usage -> by_model: [],  total.requests: 0
#     rate_card PRESENT  GET /api/v1/admin/usage -> by_model: [ {probe_ping, mcp, requests: 1} ]
#
# The exchange happened both times. Only one of them left a record of it.
#
# THE LEG IS A PAIR, AND THE PAIR IS WHAT MAKES A RED MEAN SOMETHING. A leg that only booted without
# a card could go red because the row-reading helper is broken, the mock never answered, or the key
# never resolved -- none of which is the defect. So the SAME assertion is made twice against the same
# binary, the same mock upstream and the same call, with the card as the ONLY difference:
#
#   CONTROL (card present)  the row must be there. This is the reading half proving itself. If this
#                           arm is red the other arm's red says nothing and the leg reports so.
#   CLAIM   (card absent)   the row must STILL be there. Today it is not.
#
# WHAT IT DOES NOT ASSERT, on purpose. Not the row's PRICE: with no card there is nothing to price
# against, and whether an uncarded deployment should nonetheless bill #44's flat fee is an open
# question this leg deliberately does not answer (see the note in
# `docs/design/BUSBAR-1.6.0.md` Part 7 section 13). This leg asserts the COUNT-BEARING ROW EXISTS,
# which is the half the ruling settles.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

WORK_ROOT="${H2_WORK:-${here}/../../target/h2-scratch/mcp-ledger-unconditional.$$}"

# h2_arm <workdir> -- boot (with whatever `H2_RATE_CARD_YAML` the caller set), serve one call, and
# report "<status> <metering-row-requests>". `-` for the row means this node metered nothing at all.
h2_arm() {
  bash -c '
    set -uo pipefail
    here="$1"; work="$2"
    source "${here}/h2-lib.sh"
    trap "h2_stop" EXIT
    h2_boot "$work" "groups:
  h2-oracle:
    limits:
      - { budget: 1000000, per: day }" >/dev/null 2>&1 || { echo "boot-failed"; exit 0; }
    read -r kid tok <<<"$(h2_mint h2-oracle)"
    [ -n "$tok" ] || { echo "mint-failed"; exit 0; }
    bound="$(h2_bind "$tok")"
    read -r st _ <<<"$(h2_call "$bound" "ledger")"
    # The metering write is write-behind (`usage_flush_interval_ms`, 100ms), so the read waits a
    # flush cadence with margin rather than racing it.
    sleep 2
    printf "%s %s\n" "$st" "$(h2_meter_row_field "probe_ping" "mcp" requests)"
  ' _ "$here" "$1"
}

# The row's lane is the PUBLISHED tool name (`catalogue.rs:1050`, `{server}_{tool}` with
# `NAMESPACE_SEP = "_"`, `config.rs:83`) -- `probe_ping` -- and its provider is the literal `"mcp"`
# (`method.rs:2517`).
#
# `H2_RATE_CARD_YAML=" "` is a card-ABSENT config: a blank line where the key would go. It is the
# shape `h2-lib.sh` wrote for every rig before the billing switch landed, so this arm's subject is
# literally the deployment the rigs used to prove everything against.
claim="$(H2_RATE_CARD_YAML=" " h2_arm "${WORK_ROOT}/no-card")"
control="$(h2_arm "${WORK_ROOT}/with-card")"

failures=0
detail=""

read -r control_status control_row <<<"$control"
read -r claim_status claim_row <<<"$claim"

# ── THE CONTROL, read first: if this is red nothing below is evidence ─────────────────────────────
control_ok=1
if [ "$control_status" != "200" ] || [ "${control_row:-x}" != "1" ]; then
  control_ok=0
  failures=$((failures+1))
  detail="${detail}CONTROL (rate_card present) answered status=${control_status} row_requests=${control_row}(want 200 and 1) -- the reading half of this leg is not working, so the claim arm below is NOT evidence of anything; "
fi

# ── THE CLAIM ─────────────────────────────────────────────────────────────────────────────────────
if [ "$claim_status" != "200" ]; then
  failures=$((failures+1))
  detail="${detail}CLAIM (rate_card absent) answered ${claim_status}(want 200: an unbilled plane still serves -- #42 names the failover/routing-proxy deployment it exists for); "
elif [ "${claim_row:-x}" != "1" ]; then
  failures=$((failures+1))
  if [ "$control_ok" -eq 1 ]; then
    detail="${detail}CLAIM (rate_card absent) served the call and metered row_requests=${claim_row}, while the SAME call on the SAME binary with a card metered 1. The exchange happened both times; only one left a record. plane_host/govern.rs:226 gates record_metering on cost.pricing_enabled() (rate_card.is_some(), cost.rs:649) -- that makes the LEDGER conditional on the CARD, and the card is a read-time lens (#43/#71/#77(3)), never a condition on the write. Owner: 'planes always ledger'; 'its a kernal default all planes run though. no tunring things on or off by plane'; "
  else
    detail="${detail}CLAIM (rate_card absent) metered row_requests=${claim_row}, but see the control above; "
  fi
fi

if [ "$failures" -eq 0 ]; then
  printf 'PASS\t%s\n' "one served tools/call posted its metering row with the rate card absent AND present: the ledger records what happened and the card is a lens applied at read time"
else
  printf 'FAIL\t%s\n' "$detail"
  exit 1
fi
