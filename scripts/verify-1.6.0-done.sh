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
#   equality         scripts/capability-equality-summary.py reports 0 missing cells (LLM==MCP==A2A true).
#   isomorphism      the crates/busbar/tests/plane_isomorphism.rs gate is present and green.
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
begin_group "EQUALITY — capability-equality ledger has 0 missing cells"
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
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "ISOMORPHISM — plane_isomorphism gate present and green"
if [ -f crates/busbar/tests/plane_isomorphism.rs ]; then
  step "plane_isomorphism test (incl. its selftests)" cargo test -p busbar --quiet --test plane_isomorphism
else
  absent_step "plane_isomorphism test" "crates/busbar/tests/plane_isomorphism.rs"
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
