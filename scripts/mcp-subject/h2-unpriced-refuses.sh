#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Gating scenario `mcp.rig|h2-unpriced-refuses` -- H2 (BUSBAR-1.6.0.md THE DESIGN, §1 step 6, METER) for the
# MCP plane: the MONEY-SACRED branch of the billing switch (#42).
#
# THE RULE, in the decision's own words: "rate_card PRESENT ⇒ billed: a hit class not priced ⇒
# REFUSE (money-sacred, never a silent 0) ... A cost request returns: the price if billing-on &
# priced; FAILS if billing-on & unpriced; 0 if billing-off. A silent 0 is ONLY ever returned when
# rate_card is absent." #77(5) says where the refusal lands: "Unpriced class = BOOT REFUSAL when
# billing is on; free is an EXPLICIT zero row, never silent." So a billing-ON config that leaves a declared class unpriced never serves anything, because it never
# boots. ARCHITECT ruling (unpriced-refuses): "Arm 2 uses a card that truly leaves a declared class
# unpriced and asserts the named boot refusal (#77(5)). Q25b's named 409 applies to usage reads over
# an unpriced class." So the 409 of OWNER RULING Q25b (`unpriced_class`, naming lane + class) is a
# USAGE READ's answer, not this leg's: a node that booted with an unpriced declared class has already
# failed #77(5), whatever its calls or reads say afterwards.
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
#            THE FIGURE THIS ARM ASSERTS IS THE SHIPPED ONE, NOT A SETTLED ONE, and that is stated
#            rather than hidden. #42's own words say an uncarded node should "serve free, no
#            metering, no ledger charge", which reads as spend 0; the code says otherwise in terms
#            (`root/kernel.rs`'s `card_from_config`: "absent prices every class at nothing and STILL
#            CHARGES THE FLAT FEE, which is exactly what the previous release bills for that
#            deployment", and `RateCard::absent_in` carries the fee by construction,
#            `kernel-ledger/src/cost/rate.rs:184`). Measured: 1. A second ruling is owed
#            (`docs/design/BUSBAR-1.6.0.md` Part 7 section 13); until it lands this arm asserts what
#            the tree ships rather than picking a side, so a change in EITHER direction is visible
#            here instead of silent.
#
#   ARM 2 -- BILLING ON with a card that TRULY leaves a declared class unpriced. This plane declares
#            `tool_calls` and `bytes` (`crates/busbar-plane-mcp/src/tool_meta.rs`), and the plane's
#            own card (`tools.rate_card`, #47) configures `tool_calls` and omits `bytes`. The node
#            MUST refuse to boot, and must say why in the named words of the config validator
#            (`crates/busbar-kernel/src/config_validate/mod.rs`): "tools.rate_card does not configure
#            billable unit(s) bytes declared by this plane". Any other outcome is a failure: a node
#            that boots and serves 200 bills `bytes` at a zero nobody configured; a node that boots
#            and refuses the call has moved the refusal off the boot #77(5) puts it on; a boot that
#            fails for some other reason is not evidence of this refusal at all.
#
#            THE CARD THE LIB BOOTS BY DEFAULT IS NOT THIS ARM'S, and that is why this arm writes its
#            own: `tool_calls: 0, bytes: 0` configures BOTH classes -- an explicit 0 is #77(5)'s
#            "free is an EXPLICIT zero row" -- so its 200 is correct and asks nothing of #42.
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

# ── ARM 2: BILLING ON, a declared class (`bytes`) unpriced ────────────────────────────────────────
# The card configures `tool_calls` and leaves `bytes` out: present, so billing is ON (#42), and silent
# about a class the plane declares, so #77(5) refuses the boot.
ARM2_CARD='  rate_card:
    probe_ping: { units: { tool_calls: 0 } }'
# The validator's named refusal, its stable part: the section, the rule, and the class it names.
ARM2_REFUSAL='tools.rate_card does not configure billable unit(s) bytes declared by this plane'
arm_on="$(
  H2_RATE_CARD_YAML="$ARM2_CARD" bash -c '
    set -uo pipefail
    here="$1"; work="$2"; refusal="$3"
    source "${here}/h2-lib.sh"
    trap "h2_stop" EXIT
    if ! h2_boot "$work" "groups:
  h2-oracle:
    limits:
      - { budget: 1000000, per: day }" >/dev/null 2>&1; then
      # The boot refused. It counts only when the binary named THIS refusal; the log is asked, and
      # a boot that died of something else is reported with the line that says what.
      if grep -qF "$refusal" "${work}/busbar.log" 2>/dev/null; then
        echo "boot-refused-unpriced"
      else
        echo "boot-failed-otherwise $(grep -v "^\s*$" "${work}/busbar.log" 2>/dev/null | tail -1 | tr -d "\t" | cut -c1-240)"
      fi
      exit 0
    fi
    read -r kid tok <<<"$(h2_mint h2-oracle)"
    [ -n "$tok" ] || { echo "booted mint-failed"; exit 0; }
    bound="$(h2_bind "$tok")"
    read -r st _ <<<"$(h2_call "$bound" "billing-on-unpriced")"
    printf "booted %s %s\n" "$st" "$(h2_usage_field "$kid" spend_cents)"
  ' _ "$here" "${WORK_ROOT}/on" "$ARM2_REFUSAL"
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

# ARM 2 must REFUSE TO BOOT, naming the unpriced class (#77(5)).
case "$arm_on" in
  boot-refused-unpriced)
    : # #77(5): "Unpriced class = BOOT REFUSAL when billing is on", in the validator's named words.
    ;;
  boot-failed-otherwise*)
    failures=$((failures+1))
    detail="${detail}arm 2 (billing ON, tools.rate_card silent about 'bytes') did not boot, but its log never names the #77(5) refusal (want \"${ARM2_REFUSAL}\"); last log line: ${arm_on#boot-failed-otherwise }; "
    ;;
  "booted 200 "*)
    failures=$((failures+1))
    detail="${detail}arm 2 (billing ON, tools.rate_card silent about declared class 'bytes') BOOTED and served 200, billing spend_cents=${arm_on##* } -- 'bytes' silently priced at zero. #77(5): an unpriced class is a BOOT REFUSAL when billing is on; #42: a silent 0 is only ever correct when rate_card is ABSENT; "
    ;;
  booted*)
    failures=$((failures+1))
    detail="${detail}arm 2 (billing ON, tools.rate_card silent about declared class 'bytes') BOOTED (${arm_on}); #77(5) puts the refusal at boot, so a node that boots this config has already failed it, whatever the call then answers; "
    ;;
  *)
    failures=$((failures+1))
    detail="${detail}arm 2 could not be read (${arm_on:-empty}); "
    ;;
esac

if [ "$failures" -eq 0 ]; then
  printf 'PASS\t%s\n' "billing OFF serves and bills the flat fee alone; billing ON with declared class bytes unpriced refuses to boot, named (#77(5))"
else
  printf 'FAIL\t%s\n' "$detail"
  exit 1
fi
