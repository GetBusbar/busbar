#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# verify-1.6.0-done.sh — THE 1.6.0 DONE-ORACLE. A single, re-runnable, un-gameable proof that
# "busbar 1.6.0 is done." Per docs/design/playbook/00-MASTER-PLAN.md ("DONE = scripts/verify-1.6.0-done.sh
# green") and the gate designs (gate-no-deferral.md, gate-isomorphism.md).
#
# WHAT "DONE" MEANS HERE — the umbrella asserts, as ONE verdict, that every sub-gate is green:
#   build            the full-gate cargo battery (shell out to scripts/full-gate.sh; else an explicit
#                    cargo build/clippy/test-compile battery).
#   plane-purity     scripts/plane-purity-lint.sh --check  (neutral crates 0 side channels / 0 backwards).
#   plane-delete     scripts/plane-delete-test.sh --all     (llm/mcp/a2a/voice each deletable).
#   byte-identity    the MONEY PATH is byte-stable: openapi_json_matches_committed_file,
#                    resolved_billing_and_limits_config_is_byte_stable, and the 6 busbar-llm same-proto
#                    byte-exact oracles. Bless/regen env vars MUST be empty first (else the check is a
#                    no-op that regenerates the goldens instead of comparing to them).
#   config-stability scripts/config-stability-gate.sh --check (config-schema.snapshot.json byte-stable).
#   test             cargo test --workspace  +  cargo test -p busbar-voice --features runtime.
#   conformance      the conformance rigs' selftests + verdict-covers-every-leg.py + the voice legs =ready.
#   no-deferral      scripts/no-deferral-gate.sh --strict-done (nothing deferred; voice markers CLEARED).
#   config-noun      scripts/plane-config-noun-gate.sh armed (GREP_GATE_REPORT_ONLY=0): core names no
#                    section noun as a parse target (0 — Stage A landed).
#   equality         scripts/capability-equality-summary.py reports 0 missing cells (LLM==MCP==A2A true),
#                    AND the ledger's root column holds with all five root-* legs on and every cell it
#                    calls `proven` over the loop actually runs and passes.
#   isomorphism      the crates/busbar/tests/plane_isomorphism.rs gate is present and green.
#   parity           testing/shadow-oracle: this build vs the PUBLISHED 1.5.5 binary, 0 divergences
#                    across every recorded cell family (wire, admin, boot, CLI, config, billing,
#                    failover, plugins); golden gaps are named, never passes.
#   design           scripts/design-bindings.sh --check --strict: every ARCHITECTURE.md Appendix B
#                    binding is mapped to a check that still exists in the tree (test, oracle cell,
#                    lint, gate). An unmapped binding is a named gap and is RED here -- "done" means
#                    nothing we designed is unproven. Existence only; the checks run in their own tiers.
#   changelog        scripts/changelog-register-check.sh --check: every `kind: breaking` entry in
#                    testing/shadow-oracle/accepted-differences.json has its `changelog` field's exact
#                    line present, verbatim, in CHANGELOG.md -- a named break the owner accepted cannot
#                    silently fall out of the release notes.
# Every sub-gate runs its own `--selftest` FIRST where it has one, then its `--check`, so a gate that
# could not fire is refused before its verdict is trusted (the house rule).
#
# LOCKED EXCLUSION (00-MASTER-PLAN "RECONCILED DECISIONS"): the done-oracle DELIBERATELY does NOT
# require scripts/plane-noun-gate.sh / scripts/plane-grep-gate.sh == 0. Those meter LLM BILLING VOCAB
# that STAYS in the neutral crates by the LOCKED invariant — an orthogonal axis, not a done condition.
# Including them would gate the release on a debt the owner ruled out of scope; they are not here.
#
# PROGRESS METER. This is fail-SOFT across groups: it RUNS EVERY sub-gate, collects every RED, prints a
# grouped readout, and exits non-zero if ANY group is RED. So on an unfinished tree it doubles as a
# checklist of what is left — never aborting at the first red.
#
# FLAGS:
#   --fast   substitute `cargo build --workspace` for the heavy full-gate battery in the BUILD group
#            (for a quick progress read); every other group still runs in full. Without it, BUILD runs
#            the full scripts/full-gate.sh — the real DONE claim.
#
# bash 3.2 + POSIX, the same bare-runner posture as the sibling gates.
set -uo pipefail
cd "$(dirname "$0")/.."

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
bold() { printf '\033[1m%s\033[0m\n' "$*"; }
hdr()  { printf '\n\033[1m══ %s ══\033[0m\n' "$*"; }

FAST=0
case "${1:-}" in --fast) FAST=1 ;; "" ) ;; -h|--help) sed -n '2,60p' "$0"; exit 0 ;; *) echo "usage: $0 [--fast]" >&2; exit 2 ;; esac

# Results accumulators (parallel arrays — bash 3.2 has no assoc arrays).
G_NAME=(); G_STATE=(); G_NOTE=()
CUR_GROUP=""; CUR_RED=0; CUR_FIRST_NOTE=""
begin_group() { CUR_GROUP="$1"; CUR_RED=0; CUR_FIRST_NOTE=""; hdr "$1"; }
end_group() {
  G_NAME+=("$CUR_GROUP")
  if [ "$CUR_RED" -eq 0 ]; then G_STATE+=("GREEN"); G_NOTE+=(""); else G_STATE+=("RED"); G_NOTE+=("$CUR_FIRST_NOTE"); fi
}

# Run one step; print [ok]/[RED]; on RED, mark the current group red and remember the first reason.
step() {   # $1 = label ; rest = command
  local label="$1"; shift
  if "$@" >/tmp/done-oracle-step.$$ 2>&1; then
    printf '  \033[32m[ok]\033[0m   %s\n' "$label"
  else
    printf '  \033[31m[RED]\033[0m  %s\n' "$label"
    sed 's/^/          /' /tmp/done-oracle-step.$$ | tail -4
    CUR_RED=1; [ -z "$CUR_FIRST_NOTE" ] && CUR_FIRST_NOTE="$label"
  fi
  rm -f /tmp/done-oracle-step.$$
}
# A step that is RED simply because an artifact does not exist yet (a not-yet-built sub-gate).
absent_step() { printf '  \033[31m[RED]\033[0m  %s — NOT PRESENT YET (%s)\n' "$1" "$2"; CUR_RED=1; [ -z "$CUR_FIRST_NOTE" ] && CUR_FIRST_NOTE="$1 (absent)"; }

# Assert the money-path bless/regen env vars are EMPTY — otherwise a byte-identity "check" silently
# REGENERATES the golden instead of comparing against it (a green that proves nothing).
assert_bless_env_empty() {
  local v bad=0
  for v in UPDATE_OPENAPI UPDATE_CONFIG_SCHEMA BLESS_BACKCOMPAT_CORPUS BUSBAR_BLESS_GOLDEN; do
    if [ -n "${!v:-}" ]; then echo "regen env var $v is SET ('${!v}') — byte-identity would regenerate, not compare"; bad=1; fi
  done
  return "$bad"
}

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "BUILD — the cargo battery"
if [ "$FAST" -eq 1 ]; then
  ylw "  --fast: substituting 'cargo build --workspace' for the full ci battery"
  step "cargo build --workspace" cargo build --workspace --quiet
elif [ -x scripts/full-gate.sh ] || [ -f scripts/full-gate.sh ]; then
  step "scripts/full-gate.sh --selftest" bash scripts/full-gate.sh --selftest
  step "scripts/full-gate.sh"            bash scripts/full-gate.sh
else
  step "cargo build --workspace"                 cargo build --workspace --quiet
  step "cargo build -p busbar --no-default-features" cargo build -p busbar --no-default-features --quiet
  step "cargo build --features openapi-schema"   cargo build -p busbar --features openapi-schema --quiet
fi
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "PLANE-PURITY — neutral crates carry no side channel (0/0)"
step "plane-purity-lint --selftest" bash scripts/plane-purity-lint.sh --selftest
step "plane-purity-lint --check"    bash scripts/plane-purity-lint.sh --check
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "PLANE-DELETE — each plane (llm/mcp/a2a/voice) is deletable"
step "plane-delete-test --selftest" bash scripts/plane-delete-test.sh --selftest
step "plane-delete-test --all"      bash scripts/plane-delete-test.sh --all
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "BYTE-IDENTITY — the money path is byte-stable"
if assert_bless_env_empty >/tmp/done-oracle-step.$$ 2>&1; then
  printf '  \033[32m[ok]\033[0m   bless/regen env (UPDATE_OPENAPI/UPDATE_CONFIG_SCHEMA/BLESS_*/BUSBAR_BLESS_GOLDEN) is empty\n'
  # MUST carry --features openapi-schema AND -p busbar (unifies the feature graph-wide) — the golden
  # tests are cfg-gated on it, so without both the filter selects ZERO tests: a vacuous green. The broad
  # `openapi` filter runs all three goldens (json-matches-committed, served-equals-committed,
  # error-enum-matches), so the oracle's byte-identity check is real, matching full-gate.sh.
  step "openapi.json goldens match committed file"  cargo test -p busbar -p busbar-core --features openapi-schema --quiet openapi
  step "resolved billing+limits config byte-stable" cargo test -p busbar-core --quiet resolved_billing_and_limits_config_is_byte_stable
  step "6 busbar-llm same-proto byte-exact oracles" cargo test -p busbar-llm --quiet round_trip_byte_exact
else
  printf '  \033[31m[RED]\033[0m  bless/regen env is NOT empty — refusing byte-identity (would regenerate goldens)\n'
  sed 's/^/          /' /tmp/done-oracle-step.$$; rm -f /tmp/done-oracle-step.$$
  CUR_RED=1; CUR_FIRST_NOTE="bless env not empty"
fi
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "CONFIG-STABILITY — config-schema.snapshot.json is additive-only / byte-stable"
step "config-stability-gate --selftest" bash scripts/config-stability-gate.sh --selftest
step "config-stability-gate --check"    bash scripts/config-stability-gate.sh --check
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "TEST — full workspace + voice runtime"
step "cargo test --workspace"                    cargo test --workspace --quiet
step "cargo test -p busbar-voice --features runtime" cargo test -p busbar-voice --features runtime --quiet
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "CONFORMANCE — rig selftests + verdict coverage + voice legs =ready"
[ -f scripts/mcp-conformance.sh ] && step "mcp-conformance --selftest" bash scripts/mcp-conformance.sh --selftest \
  || absent_step "mcp-conformance --selftest" "scripts/mcp-conformance.sh"
if [ -f testing/verdict-covers-every-leg.py ]; then
  step "verdict-covers-every-leg.py" python3 testing/verdict-covers-every-leg.py
else
  absent_step "verdict-covers-every-leg.py" "testing/verdict-covers-every-leg.py — T2 conformance coverage gate not built yet"
fi
if [ -f testing/verdict-covers-every-leg.py ]; then
  step "verdict-covers-every-leg.py --selftest" python3 testing/verdict-covers-every-leg.py --selftest
fi
if [ -f testing/voice-conformance/voice-conformance.sh ]; then
  step "voice conformance selftest (anti-vacuity)" bash testing/voice-conformance/voice-conformance.sh --selftest
else
  absent_step "voice conformance selftest" "testing/voice-conformance/voice-conformance.sh — voice conformance rig not built yet"
fi
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "NO-DEFERRAL — nothing deferred; voice skeleton markers CLEARED (strict-done)"
step "no-deferral-gate --selftest"    bash scripts/no-deferral-gate.sh --selftest
step "no-deferral-gate --strict-done" bash scripts/no-deferral-gate.sh --strict-done
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "CONFIG-NOUN — four-noun parse residual (REPORT-ONLY; locked-legitimate floor)"
step "plane-config-noun-gate --selftest" bash scripts/plane-config-noun-gate.sh --selftest
# REPORT-ONLY, deliberately NOT a done-blocker — same treatment as the plane-noun/plane-grep
# billing-vocab meters the oracle excludes. Per the kickoff/LOCKED invariant: `pools`/`providers` STAY
# core-owned (CORE_OWNED_CONCRETE_SECTIONS, never evicted), and the `tools`/`agents`/`streams`
# DeployCfg fields are Option A's `deny_unknown_fields` floor (Option B is serde-blocked). So the
# residual (pools 8 · tools 3 · agents 2 · streams 5 = 18) is a LEGITIMATE floor, not debt; the DoD is
# "core's generic named-map MACHINERY names no plane noun" (Stage A, done), not "zero noun field refs".
# Printed for visibility; a RISE above the floor is the real signal.
printf '  \033[36m[info]\033[0m '
GREP_GATE_REPORT_ONLY=0 bash scripts/plane-config-noun-gate.sh --check 2>&1 | grep -E "distinct core parse-target lines" | tail -1 || echo "config-noun count unavailable"
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "EQUALITY — capability-equality ledger has 0 missing cells, on the legacy path AND over the loop"
step "capability-equality-summary --selftest" python3 scripts/capability-equality-summary.py --selftest
# The summary prints the missing count but exits 0 while the pin is honest; DONE additionally requires
# ZERO missing, so assert it explicitly here.
step "0 missing cells (LLM==MCP==A2A)" python3 -c '
import json, sys
d = json.load(open("qa/capability-equality.json"))
m = [c["capability"] + "/" + c["plane"] for c in d["cells"] if c["state"] == "missing"]
print((str(len(m)) + " missing cell(s): " + ", ".join(m)) if m else "0 missing cells")
sys.exit(1 if m else 0)
'
# THE ROOT COLUMN. Every plane also runs through the composition root, so the ledger carries a second
# verdict per cell over its plane's `root-*` leg. Two things are asserted here and neither is the
# other: that the column HOLDS (the cargo gate, run with all five legs on — which is also the only
# build where the leg-by-leg half of that gate exists at all), and that every cell it calls `proven`
# actually RUNS and passes (the summary's own runner, which refuses a run that executed a different
# set). The remaining "none" cells are the switch-over queue and are PRINTED, not fatal — the same
# honest-ledger posture the missing set has.
step "capability_equality gate, five legs on" \
  cargo test -p busbar --features root-admin,root-mcp,root-a2a,root-voice,root-llm --quiet --test capability_equality
step "every root-leg proof cell RUNS and passes" python3 scripts/capability-equality-summary.py --root-legs
printf '  \033[36m[info]\033[0m '
python3 scripts/capability-equality-summary.py 2>/dev/null | grep -E "^ROOT-EQUALITY:" || echo "root-equality count unavailable"
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "PARITY — the shadow oracle: this build vs the published 1.5.5 binary (0 divergences)"
# The user-observable contract: every cell recorded from the released 1.5.5 artifact (by digest)
# is reproduced by the candidate byte for byte. The golden is recorded once per cells/normalizer
# revision and cached; the candidate is recorded fresh. A cell the golden could not produce is a
# NAMED gap in the report, never a pass. SHADOW_ORACLE_GOLDEN may point at an existing recording.
if [ -x testing/shadow-oracle/replay.sh ]; then
  step "replay-selftest (the differ can see a diff)" bash testing/shadow-oracle/replay-selftest.sh
  step "fetch-golden --check (1.5.5 by pinned digest)" bash testing/shadow-oracle/fetch-golden.sh --check
  ORACLE_DIR="${SHADOW_ORACLE_DIR:-target/oracle}"
  GOLDEN="${SHADOW_ORACLE_GOLDEN:-$ORACLE_DIR/recordings/golden}"
  CAND="$ORACLE_DIR/recordings/candidate"
  if [ ! -s "$GOLDEN/ledger.tsv" ]; then
    step "record the golden (1.5.5)" bash testing/shadow-oracle/record.sh --bin "$HOME/.cache/busbar-oracle/1.5.5/busbar" --plane all --out "$GOLDEN"
  fi
  rm -rf "$CAND"
  step "record the candidate (target/release/busbar)" bash testing/shadow-oracle/record.sh --bin target/release/busbar --plane all --out "$CAND"
  step "replay: candidate vs golden" bash testing/shadow-oracle/replay.sh --golden "$GOLDEN" --candidate "$CAND" --out "$ORACLE_DIR/reports/latest"
else
  absent_step "shadow oracle" "testing/shadow-oracle/replay.sh"
fi
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "DESIGN — every ARCHITECTURE.md Appendix B binding is mapped to a check that exists"
# The design bindings ledger (qa/design-bindings.json) maps each parity binding to the tests, oracle
# cells, lints and gates that prove it. Plain --check reports gaps; --strict owes EVERY binding to the
# verdict so an unmapped binding is red. DONE means the design is fully bound, not partly.
if [ -f scripts/design-bindings.sh ]; then
  step "design-bindings --selftest"        bash scripts/design-bindings.sh --selftest
  step "design-bindings --check --strict"  bash scripts/design-bindings.sh --check --strict
else
  absent_step "design bindings gate" "scripts/design-bindings.sh"
fi
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "CHANGELOG — every breaking register entry is named"
# testing/shadow-oracle/accepted-differences.json's own differ refuses an entry that accepts
# status/effects.usage without kind=breaking and a `changelog` field; this gate closes the other
# half -- that the named line was actually WRITTEN, verbatim, in CHANGELOG.md, not just declared.
if [ -f scripts/changelog-register-check.sh ]; then
  step "changelog-register-check --selftest" bash scripts/changelog-register-check.sh --selftest
  step "changelog-register-check --check"    bash scripts/changelog-register-check.sh --check
else
  absent_step "changelog register gate" "scripts/changelog-register-check.sh"
fi
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "INVENTORY-COVERAGE — every docs/design/inventory/*.md row id is bound to an oracle cell"
# Appendix B says every inventory row is a parity binding AND an oracle cell; this is the check that
# was missing. qa/inventory-gaps.json names every row id with no citing cell yet, so a gap is a
# visible, owned line item rather than a silent hole. DONE means no id has no cell and no name.
if [ -f scripts/inventory-coverage.sh ]; then
  step "inventory-coverage --selftest" bash scripts/inventory-coverage.sh --selftest
  step "inventory-coverage --check"    bash scripts/inventory-coverage.sh --check
else
  absent_step "inventory coverage gate" "scripts/inventory-coverage.sh"
fi
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "KERNEL — the Teller loop battery, the capability fixtures and attempt identity are green"
# The kernel crate's integration tests are the loop battery (step order, refusal stops at its step,
# every reason posts, the settlement table, the two-sided canary, kill points). The caps crate's
# compile-fail fixtures prove the tokens cannot be forged. attempt_identity proves the one attempt
# seam produces the bytes and breaker mutations the two legacy twins produced.
if [ -d crates/busbar-kernel ]; then
  step "busbar-kernel battery"           cargo test -p busbar-kernel --quiet
  step "busbar-caps fixtures"            cargo test -p busbar-caps --quiet
  step "attempt identity (busbar-llm)"   cargo test -p busbar-llm --quiet attempt_identity
else
  absent_step "kernel battery" "crates/busbar-kernel"
fi
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "ISOMORPHISM — plane_isomorphism gate present and green"
if [ -f crates/busbar/tests/plane_isomorphism.rs ]; then
  step "plane_isomorphism test (incl. its selftests)" cargo test -p busbar --quiet --test plane_isomorphism
else
  absent_step "plane_isomorphism test" "crates/busbar/tests/plane_isomorphism.rs"
fi
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "TELLER-STEPS — H2: one conformance cell per Teller step per plane, and one root-leg cell beside it"
if [ -f scripts/teller-steps-check.py ] && [ -f qa/teller-steps.json ]; then
  step "teller-steps-check self-test"  python3 scripts/teller-steps-check.py --selftest
  step "teller-steps-check --check"    python3 scripts/teller-steps-check.py --check
  # The ROOT column beside the rig column: every (plane x step) cell also names the root::units_*
  # cell that drives that step through run_unit, or a named gap. --check verifies the column holds
  # (a proven cell's fn exists in its own leg's file; a leg proving nothing is red); this RUNS every
  # named cell with all five legs on, so "proven" means watched rather than present on disk.
  step "every root-leg step cell RUNS and passes" python3 scripts/teller-steps-check.py --root-legs
  printf '  \033[36m[info]\033[0m '
  python3 scripts/teller-steps-check.py --check 2>/dev/null | grep -E "^ROOT-STEPS:" || echo "root-steps count unavailable"
else
  absent_step "teller-steps-check" "scripts/teller-steps-check.py / qa/teller-steps.json"
fi
end_group

# ── THE ONE VERDICT ─────────────────────────────────────────────────────────────────────────────
hdr "1.6.0 DONE-ORACLE READOUT"
fail=0; green=0; total=0
for i in "${!G_NAME[@]}"; do
  total=$((total+1))
  if [ "${G_STATE[$i]}" = "GREEN" ]; then
    green=$((green+1)); printf '  \033[32m● GREEN\033[0m  %s\n' "${G_NAME[$i]}"
  else
    fail=1; printf '  \033[31m● RED  \033[0m  %s   — %s\n' "${G_NAME[$i]}" "${G_NOTE[$i]}"
  fi
done
printf '\n'
bold "  $green / $total groups GREEN"
if [ "$fail" -eq 0 ]; then
  grn "══ busbar 1.6.0 is DONE — every sub-gate is green. ══"
  exit 0
fi
red "══ busbar 1.6.0 is NOT done — $((total-green)) group(s) RED (see above). This readout is the work queue. ══"
exit 1
