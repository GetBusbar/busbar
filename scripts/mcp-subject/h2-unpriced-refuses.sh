#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Gating scenario `mcp.rig|h2-unpriced-refuses` -- H2 (ARCHITECTURE.md #2.2 step 6, METER) for the
# MCP plane: the MONEY-SACRED branch of the billing switch (#42).
#
# THE RULE, in the decision's own words: "rate_card PRESENT ⇒ billed: a hit class not priced ⇒
# REFUSE (money-sacred, never a silent 0) ... A cost request returns: the price if billing-on &
# priced; FAILS if billing-on & unpriced; 0 if billing-off. A silent 0 is ONLY ever returned when
# rate_card is absent." #77(5) says where the refusal may land: "Unpriced class = BOOT REFUSAL when
# billing is on; free is an EXPLICIT zero row, never silent." So EITHER the node refuses to boot, OR
# the call is refused -- both are refusals and this leg accepts either. What it does not accept is a
# 200 that quietly charges nothing for the classes it hit.
#
# THIS LEG IS A PAIR, AND THE PAIR IS THE POINT. A leg that only asserted "refuse" could be passed by
# a node that refuses everything, and a leg that only asserted "serve" could be passed by a node that
# never bills. So both arms of #42's switch are driven against the same binary, the same mock
# upstream and the same call:
#
#   ARM 1 -- BILLING OFF (`rate_card:` absent entirely). The call MUST be served and MUST bill the
#            flat fee and nothing else. This is the silent zero that IS correct, and #42 names the
#            deployment it exists for: "user X wants failover on breaker-trip, doesn't care about
#            billing". An unbilled plane still gets admission and breaker enforcement, which is why
#            the call is expected to succeed rather than to be turned away.
#
#   ARM 2 -- BILLING ON with a card that prices neither class the call hits. This plane declares
#            `tool_calls` and `bytes` (`crates/busbar-plane-mcp/src/meta.rs:33-52`) and the card
#            carries an entry for neither -- it cannot, since `rate_card:` keys are validated against
#            `models:` (see h2-class-price.sh). So EVERY served mcp call on a billing-ON node hits
#            unpriced classes, and #42 says every one of them must be refused rather than billed zero
#            for what it moved.
#
# WHY THIS IS NOT THE REFUSAL h2-admit-refusal.sh ALREADY PROVES. That leg refuses a caller who is
# over a `requests: 1/day` COUNT budget -- a quantity the node HAS and has exhausted. This one
# refuses a caller whose classes the node cannot put a price on at all. Different question, different
# evidence: one is arithmetic against a cap, the other is the absence of a number. Neither
# substitutes for the other, and neither is rewritten by the other.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

WORK_ROOT="${H2_WORK:-${here}/../../target/h2-scratch/mcp-unpriced-refuses.$$}"

# ── ARM 1: BILLING OFF -- the silent zero that IS correct ─────────────────────────────────────────
# Run in a subshell with its OWN boot: the two arms differ only in the config's `rate_card:` key, and
# `h2-lib.sh` writes that key once per boot.
arm_off="$(
  H2_RATE_CARD_YAML=" " bash -c '
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
    read -r st _ <<<"$(h2_call "$bound" "billing-off")"
    printf "%s %s\n" "$st" "$(h2_usage_field "$kid" spend_cents)"
  ' _ "$here" "${WORK_ROOT}/off"
)"

# ── ARM 2: BILLING ON, classes unpriced ───────────────────────────────────────────────────────────
arm_on="$(
  bash -c '
    set -uo pipefail
    here="$1"; work="$2"
    source "${here}/h2-lib.sh"
    trap "h2_stop" EXIT
    if ! h2_boot "$work" "groups:
  h2-oracle:
    limits:
      - { budget: 1000000, per: day }" >/dev/null 2>&1; then
      # A boot refusal IS the #77(5) outcome, and it is reported as such rather than as a harness
      # failure -- but only when the binary actually refused, which the log is asked about.
      if grep -qi "unpriced\|no rate\|rate_card" "${work}/busbar.log" 2>/dev/null; then
        echo "boot-refused-unpriced"
      else
        echo "boot-failed"
      fi
      exit 0
    fi
    read -r kid tok <<<"$(h2_mint h2-oracle)"
    [ -n "$tok" ] || { echo "mint-failed"; exit 0; }
    bound="$(h2_bind "$tok")"
    read -r st _ <<<"$(h2_call "$bound" "billing-on-unpriced")"
    printf "%s %s\n" "$st" "$(h2_usage_field "$kid" spend_cents)"
  ' _ "$here" "${WORK_ROOT}/on"
)"

failures=0
detail=""

# ARM 1 must SERVE and must bill exactly the flat fee.
read -r off_status off_spend <<<"$arm_off"
if [ "$off_status" != "200" ]; then
  failures=$((failures+1))
  detail="${detail}arm 1 (billing OFF, rate_card absent) answered ${off_status}(want 200: an unbilled plane still serves -- #42's failover/routing-proxy deployment); "
elif [ "${off_spend:-x}" != "1" ]; then
  failures=$((failures+1))
  detail="${detail}arm 1 (billing OFF) billed spend_cents=${off_spend}(want exactly 1, the flat per_request_fee and nothing else); "
fi

# ARM 2 must REFUSE -- at boot or at the call, either is #42-compliant.
read -r on_status on_spend <<<"$arm_on"
case "$arm_on" in
  boot-refused-unpriced)
    : # #77(5): "Unpriced class = BOOT REFUSAL when billing is on". Compliant.
    ;;
  boot-failed|mint-failed)
    failures=$((failures+1))
    detail="${detail}arm 2 (billing ON) could not be driven (${arm_on}); "
    ;;
  *)
    if [ "$on_status" = "200" ]; then
      failures=$((failures+1))
      detail="${detail}arm 2 (billing ON, classes 'tool_calls'/'bytes' unpriced) was SERVED 200 and billed spend_cents=${on_spend} -- the flat fee alone, with both hit classes silently priced at zero. #42: a silent 0 is ONLY ever correct when rate_card is ABSENT, and here it is PRESENT; the call owed a refusal (or the node owed a boot refusal, #77(5)); "
    fi
    ;;
esac

if [ "$failures" -eq 0 ]; then
  printf 'PASS\t%s\n' "billing OFF serves and bills the flat fee alone; billing ON with the declared classes unpriced refuses rather than billing them zero"
else
  printf 'FAIL\t%s\n' "$detail"
  exit 1
fi
