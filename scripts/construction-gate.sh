#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# construction-gate.sh — THE CONSTRUCTION GATE: measures how the tree is BUILT against
# docs/design/ARCHITECTURE.md, with ceilings the owner tightens in qa/construction.toml.
#
# WHY. The shadow oracle proves the code on HEAD is user-correct. Nothing, until this script,
# measured whether it is well constructed: one function sends the upstream attempt, request-path
# functions are readable, planes talk to the kernel through the ABI only, every installable seam is
# actually installed by production, the neutral crates know no dialect, the request terminal has one
# set of doors. Each of those is an invariant the design states and the code drifted from because no
# instrument watched it. This is the instrument.
#
# HOUSE LEDGER STYLE (testing/fleet-fixtures/lib.sh + verdict.sh). Every invariant records exactly
# one ledger row per scope and never controls flow; verdict.sh is the only place anything is
# decided. So no rule masks another, a rule that did not run is RED (not silently green), and zero
# rows is RED by construction. GATE_NAME is "construction".
#
# WHAT RUNS. Pure bash + python3 stdlib; no cargo build (FAST tier). The Rust scanning discipline is
# the purity lint's (comments and doc-comments stripped with string literals respected; tests/ files
# and #[cfg(test)] mods classified as test code), ported into scripts/construction-gate/rules.py.
# The neutral-no-dialect rule does not re-implement policy at all: it runs scripts/plane-purity-lint.sh
# and counts that lint's DIALECT/KEY rows, so the noun list and the frozen-wire allow-list live in
# exactly one place.
#
# MODES
#   --check          (default) run every rule, write target/construction/report.md, exit by verdict.
#   --summary        one line per rule: STATUS  rule  current / ceiling.
#   --calibrate OUT  write a copy of the toml whose ceilings equal today's measurements (a ratchet
#                    the owner can adopt; the self-test uses it to obtain a green baseline).
#   --selftest       copy the tree under target/, calibrate a green baseline, then plant each
#                    violation in turn and require exactly ONE FAIL row naming that rule.
#
# ENVIRONMENT
#   CONSTRUCTION_TOML   ceilings file (default qa/construction.toml)
#   CONSTRUCTION_OUT    output directory (default target/construction)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HELPERS="$ROOT/scripts/construction-gate"
TOML="${CONSTRUCTION_TOML:-$ROOT/qa/construction.toml}"
OUT="${CONSTRUCTION_OUT:-$ROOT/target/construction}"
SELFTEST_SCRATCH=""   # set by --selftest; read by its EXIT trap, so never `local`

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
hdr()  { printf '\n== %s ==\n' "$*"; }

command -v python3 >/dev/null 2>&1 || { red "construction-gate: python3 is required"; exit 2; }
[ -f "$TOML" ] || { red "construction-gate: ceilings file not found: $TOML"; exit 2; }

# ── the delegated scan ───────────────────────────────────────────────────────────────────────────
# plane-purity-lint.sh owns the dialect/plane-noun policy. --baseline always exits 0 and leaves its
# per-hit rows where PLANE_PURITY_HITS_OUT points. Its own function because --calibrate needs it
# exactly as much as --check does, and each needs it exactly once.
purity_scan() {
  mkdir -p "$OUT"
  rm -f "$OUT/purity-hits.tsv"
  PLANE_PURITY_HITS_OUT="$OUT/purity-hits.tsv" \
    bash "$ROOT/scripts/plane-purity-lint.sh" --baseline >"$OUT/purity-lint.log" 2>&1 || true
}

# ── measure: the purity lint first (the delegated scanner), then every rule into the ledger ──────
# Populates $OUT with rows.tsv, expected-ids, report.md, summary.txt, rows.json and the ledger.
# Returns the verdict's exit code. $1 = "quiet" suppresses per-row echo.
measure() {
  local quiet="${1:-}"
  mkdir -p "$OUT"
  export LEDGER="$OUT/ledger.tsv"
  : >"$LEDGER"
  # shellcheck source=testing/fleet-fixtures/lib.sh
  . "$ROOT/testing/fleet-fixtures/lib.sh"

  purity_scan

  if ! python3 "$HELPERS/rules.py" --root "$ROOT" --toml "$TOML" \
        --purity-hits "$OUT/purity-hits.tsv" --rows "$OUT/rows.tsv" \
        --expected "$OUT/expected-ids" --report "$OUT/report.md" \
        --summary "$OUT/summary.txt" --json "$OUT/rows.json" >"$OUT/rules.log" 2>&1; then
    # The measuring half died: record that as a row so the verdict sees a FAIL, never silence.
    record "rules-helper" FAIL "scripts/construction-gate/rules.py ran to completion" \
      "$(tail -3 "$OUT/rules.log" | tr '\n' ' ')" >/dev/null
    printf 'rules-helper\n' >"$OUT/expected-ids"
    : >"$OUT/summary.txt"
  else
    while IFS=$'\t' read -r id status title detail; do
      [ -n "$id" ] || continue
      if [ -n "$quiet" ]; then
        record "$id" "$status" "$title" "$detail" >/dev/null
      else
        record "$id" "$status" "$title" "$detail"
      fi
    done <"$OUT/rows.tsv"
  fi

  # The surface ceilings. Self-contained on purpose: scripts/loc-surface.py owns the counting rule
  # (non-blank, non-comment code lines under src/, minus #[cfg(test)] mods and src/tests/), this
  # block only turns its exit code into one ledger row per ceiling. Every figure is the one in
  # ARCHITECTURE.md section 1.1 and none is calibratable: they are owner decisions, not ratchets
  # that drift upward with the tree.
  #
  # THREE rows, not one, because the pair's ceiling is a budget for what a PLUGIN AUTHOR reads. The
  # closed span grammar and the transport-facing contract each moved out from under it into a crate
  # of their own, and a ceiling nothing measures is a ceiling that has been abolished rather than
  # met: each split crate is gated at its own figure here, beside the pair it left. The figures
  # themselves live in qa/construction.toml's [gate.surface_ceilings] (owner decisions, never
  # ratcheted by the tree) — read from there, not restated here, so --calibrate can also produce a
  # green value for them in a scratch copy without this script itself carrying two sources of truth.
  local surface_ceilings sc_contract_caps sc_grammar sc_contract_transport
  surface_ceilings="$(python3 - "$TOML" <<'PYEOF'
import sys, tomllib
with open(sys.argv[1], "rb") as fh:
    cfg = tomllib.load(fh)
sc = cfg.get("gate", {}).get("surface_ceilings", {})
for key, default in (("contract_caps", 3500), ("grammar", 500), ("contract_transport", 1000)):
    print(sc.get(key, default))
PYEOF
)"
  { read -r sc_contract_caps; read -r sc_grammar; read -r sc_contract_transport; } <<<"$surface_ceilings"
  local surface_spec surface_id surface_crates surface_limit surface_what
  for surface_spec in \
    "contract+caps|busbar-contract,busbar-caps|$sc_contract_caps|the contract pair's plugin-visible surface" \
    "grammar|busbar-grammar|$sc_grammar|the closed span grammar's surface" \
    "contract-transport|busbar-contract-transport|$sc_contract_transport|the transport-facing contract's surface"
  do
    IFS='|' read -r surface_id surface_crates surface_limit surface_what <<<"$surface_spec"
    surface_id="surface-ceiling:$surface_id"
    local surface_out surface_rc surface_now surface_status surface_detail
    surface_out="$(python3 "$ROOT/scripts/loc-surface.py" \
                     --ceiling "$surface_crates=$surface_limit" 2>&1)"; surface_rc=$?
    surface_now="$(printf '%s\n' "$surface_out" | awk '$1=="total"{print $2}')"
    surface_now="${surface_now:-?}"
    if [ "$surface_rc" -eq 0 ]; then
      surface_status=PASS
      surface_detail="$surface_what is $surface_now lines"
    else
      surface_status=FAIL
      surface_detail="$(printf '%s\n' "$surface_out" | tail -3 | tr '\n' ' ')"
    fi
    if [ -n "$quiet" ]; then
      record "$surface_id" "$surface_status" \
        "$surface_what stays under its ceiling" "$surface_detail" >/dev/null
    else
      record "$surface_id" "$surface_status" \
        "$surface_what stays under its ceiling" "$surface_detail"
    fi
    printf '%s\n' "$surface_id" >>"$OUT/expected-ids"
    printf '%-4s  %-32s %6s / %-6s  %s\n' "$surface_status" "$surface_id" "$surface_now" \
      "$surface_limit" "$surface_what" >>"$OUT/summary.txt"
  done

  local verdict_out rc
  verdict_out="$(GATE_NAME="construction" EXPECTED_IDS="$(cat "$OUT/expected-ids")" \
                 LEDGER="$LEDGER" bash "$ROOT/testing/fleet-fixtures/verdict.sh" 2>&1)"
  rc=$?
  printf '%s\n' "$verdict_out" >"$OUT/verdict.txt"
  [ -n "$quiet" ] || { echo; printf '%s\n' "$verdict_out"; }
  {
    printf '\n## Verdict\n\n```\n'
    printf '%s\n' "$verdict_out" | grep -v '^::'
    printf '```\n'
  } >>"$OUT/report.md" 2>/dev/null
  return "$rc"
}

# ── self-test: every rule proves it can see its own violation ────────────────────────────────────
run_selftest() {
  hdr "construction-gate SELF-TEST (each planted violation must produce exactly one FAIL row)"
  # A PRIVATE scratch directory, not a fixed path this run first deletes. Two selftests in one
  # checkout — a developer's and CI's, or two CI jobs sharing a workspace — planted their violations
  # into the same tree and deleted each other's, and the loser reported on whatever the winner had
  # planted. mktemp gives each run its own; the trap takes it away again on any exit.
  mkdir -p "$ROOT/target/construction"
  # SELFTEST_SCRATCH is deliberately not `local`: the EXIT trap fires after this function's frame is
  # gone, and a trap that cannot read the path it is meant to delete deletes nothing (under `set -u`
  # it does not even run) -- which is the leak this whole change exists to close.
  SELFTEST_SCRATCH="$(mktemp -d "$ROOT/target/construction/selftest.XXXXXX")" || {
    red "construction-gate: could not create a scratch directory under $ROOT/target/construction"
    return 1
  }
  trap 'rm -rf "$SELFTEST_SCRATCH"' EXIT
  local scratch="$SELFTEST_SCRATCH"
  local pristine="$scratch/pristine" tree="$scratch/tree"
  mkdir -p "$pristine" "$tree"
  # The scratch copy carries everything the gate reads: every crate's src, every crate's Cargo.toml
  # (manifest-allowlist reads `[dependencies]` straight from disk, not from the Tree scan), the
  # scripts, the ceilings and the ledger machinery. No target/, so the copy is small and never
  # recurses into itself.
  local src_dirs manifests
  src_dirs="$(cd "$ROOT" && ls -d crates/*/src)"
  manifests="$(cd "$ROOT" && ls crates/*/Cargo.toml)"
  # shellcheck disable=SC2086
  (cd "$ROOT" && tar -cf - $src_dirs $manifests scripts qa testing/fleet-fixtures) | tar -C "$pristine" -xf -
  (cd "$pristine" && tar -cf - .) | tar -C "$tree" -xf -
  # THE SABOTEUR COMES FROM THE COPY, NOT THE LIVE TREE. plant.py and rules.py are one instrument in
  # two halves -- the planter forges exactly what the scanner is looking for -- and the scanner under
  # test is the COPY's. Running the live planter against a copied scanner means an edit landing in
  # scripts/ while a run is in flight changes the saboteur mid-run but not its subject, and the run
  # reports a rule "failing" that neither half is wrong about. A run is a snapshot: one tree, one set
  # of scripts, start to finish.
  local gate="$tree/scripts/construction-gate.sh" fail=0
  local planter="$tree/scripts/construction-gate/plant.py"

  # 1. Calibrate a green baseline: every ceiling equals today's measurement in the pristine copy.
  CONSTRUCTION_OUT="$scratch/out-calibrate" bash "$gate" --calibrate "$scratch/calibrated.toml" >/dev/null 2>&1
  [ -f "$scratch/calibrated.toml" ] || { red "SELF-TEST FAILED: could not calibrate a baseline"; return 1; }

  local out="$scratch/out"
  CONSTRUCTION_TOML="$scratch/calibrated.toml" CONSTRUCTION_OUT="$out" bash "$gate" --check >/dev/null 2>&1
  local fails
  fails="$(awk -F'\t' '$2=="FAIL"{n++} END{print n+0}' "$out/ledger.tsv")"
  local rows
  rows="$(awk 'NF{n++} END{print n+0}' "$out/ledger.tsv")"
  if [ "$fails" -eq 0 ] && [ "$rows" -gt 0 ]; then
    note "baseline: calibrated pristine copy is GREEN ($rows rows, 0 FAIL)"
  else
    fail=1; note "baseline FAILED: expected 0 FAIL rows on the calibrated pristine copy, got $fails of $rows"
    awk -F'\t' '$2=="FAIL"' "$out/ledger.tsv" | sed 's/^/    /'
  fi
  cp "$out/rows.json" "$scratch/baseline-rows.json"

  # 2. The scanner agrees with the purity lint on the one measurement both make (production
  #    busbar_core:: reaches from the planes): a ported scanner that drifted would lie here first.
  local mine lint
  mine="$(python3 -c "import json,sys; print(sum(r['current'] for r in json.load(open(sys.argv[1])) if r['id'].startswith('ports-only:')))" "$out/rows.json")"
  lint="$(awk -F'\t' '$1=="BACKWARDS"{n++} END{print n+0}' "$out/purity-hits.tsv")"
  if [ "$mine" = "$lint" ]; then
    note "scanner parity: production busbar_core:: reaches = $mine (rules.py) = $lint (plane-purity-lint.sh)"
  else
    fail=1; note "scanner parity FAILED: rules.py counts $mine production reaches, plane-purity-lint.sh counts $lint"
  fi

  # 3. Plant each violation and require exactly one FAIL row, naming the rule.
  local rule rc
  for rule in one-attempt-seam request-path-fn-size ports-only:busbar-voice ports-only-tests:busbar-voice \
              ports-only:busbar-llm \
              no-uninstalled-seam neutral-no-dialect single-terminal \
              token-sealed teller-step-order one-teller-loop one-teller-loop:run_gauntlet \
              no-response-escapes-audit terminal-doors-in-audit-step one-pick-site \
              loc-ceilings:kernel:arena loc-ceilings:kernel:ticks manifest-allowlist:hook-test-plugin \
              source-denylist:busbar-plane-llm lean-core no-default-bodies sealed-unit-traits \
              hold-discipline:no-early-exit forbid-unsafe:busbar-plane-llm \
              token-sealed:kernel-seal token-sealed:admit-token-mint kernel-seal-impls seal-sites \
              plane-no-money one-pricing-site one-pricing-site:fee-fields \
              legacy-reach:busbar_core legacy-reach:busbar_llm legacy-reach:busbar_substrate; do
    python3 "$planter" "$rule" "$pristine" "$tree" "$scratch/calibrated.toml" "$scratch/baseline-rows.json"; rc=$?
    # exit 3 = the rule's subject is absent from this tree (nothing to plant): noted, not failed
    [ "$rc" -ne 3 ] || { note "SKIP $rule: nothing to plant (subject absent from this tree)"; continue; }
    [ "$rc" -eq 0 ] || { fail=1; note "plant FAILED for $rule"; continue; }
    CONSTRUCTION_TOML="$scratch/calibrated.toml" CONSTRUCTION_OUT="$out" bash "$gate" --check >/dev/null 2>&1
    local failed_ids
    failed_ids="$(awk -F'\t' '$2=="FAIL"{print $1}' "$out/ledger.tsv" | tr '\n' ' ' | sed 's/ $//')"
    # A planted violation lights exactly the rows named here — normally just the rule itself. The
    # one pair that legitimately co-fires is the seal: `token-sealed:kernel-seal` is the scoped
    # read of `KernelSeal::acquire_for_kernel` and `seal-sites` is the flat workspace scan of the
    # same symbol, so one production call site IS both findings and a planter cannot separate them
    # (seal-sites scans every crate's src). This expectation is written out EXACTLY, as the full
    # sorted set — not as "a superset containing the rule" — so a third row joining the set is
    # still a self-test failure. It reads as a co-fire only because the stale seal-sites waiver that
    # used to swallow the second row is gone; the pair was always there, unmeasured.
    local expected="$rule"
    [ "$rule" != "token-sealed:kernel-seal" ] || expected="token-sealed:kernel-seal seal-sites"
    if [ "$failed_ids" = "$expected" ]; then
      note "RED $rule: planted violation produced exactly the expected FAIL row(s) [$expected]"
    else
      fail=1; note "RED $rule FAILED: expected FAIL rows [$expected], got [${failed_ids:-none}]"
      awk -F'\t' '$2=="FAIL"{print "    " $1 ": " $4}' "$out/ledger.tsv"
    fi
  done

  # 4. The informational rule: planting a shared block raises its duplicated-line count and still
  #    produces no FAIL row (it is a WARN, never a gate).
  rule=duplicate-dispatch
  python3 "$planter" "$rule" "$pristine" "$tree" "$scratch/calibrated.toml" "$scratch/baseline-rows.json"; rc=$?
  if [ "$rc" -eq 3 ]; then
    note "SKIP $rule: nothing to plant (a twin is absent from this tree)"
  else
    [ "$rc" -eq 0 ] || { fail=1; note "plant FAILED for $rule"; }
    CONSTRUCTION_TOML="$scratch/calibrated.toml" CONSTRUCTION_OUT="$out" bash "$gate" --check >/dev/null 2>&1
    local before after dupfails
    before="$(python3 -c "import json,sys; print([r['current'] for r in json.load(open(sys.argv[1])) if r['id']=='duplicate-dispatch'][0])" "$scratch/baseline-rows.json")"
    after="$(python3 -c "import json,sys; print([r['current'] for r in json.load(open(sys.argv[1])) if r['id']=='duplicate-dispatch'][0])" "$out/rows.json")"
    dupfails="$(awk -F'\t' '$2=="FAIL"{n++} END{print n+0}' "$out/ledger.tsv")"
    if [ "$after" -gt "$before" ] && [ "$dupfails" -eq 0 ]; then
      note "WARN $rule: planted shared block raised duplicated lines $before -> $after with 0 FAIL rows"
    else
      fail=1; note "WARN $rule FAILED: duplicated lines $before -> $after, FAIL rows $dupfails (expected a rise and 0)"
    fi
  fi

  # 5. Zero rows is red: a ledger nothing wrote must not pass the verdict.
  local empty="$scratch/empty.tsv"; : >"$empty"
  if GATE_NAME=construction EXPECTED_IDS="one-attempt-seam" LEDGER="$empty" \
       bash "$ROOT/testing/fleet-fixtures/verdict.sh" >/dev/null 2>&1; then
    fail=1; note "VACUOUS FAILED: an empty ledger passed the verdict"
  else
    note "VACUOUS: an empty ledger is RED (zero rows never pass)"
  fi

  if [ "$fail" -ne 0 ]; then
    red "construction-gate SELF-TEST FAILED — a rule would let its violation through"
    return 1
  fi
  grn "construction-gate self-test: ALL GREEN (every rule proved on a planted violation)"
  return 0
}

case "${1:-}" in
  --selftest)
    run_selftest; exit $?
    ;;
  --summary)
    measure quiet >/dev/null
    hdr "construction gate — current / ceiling ($TOML)"
    cat "$OUT/summary.txt"
    tail -1 "$OUT/verdict.txt"
    exit 0
    ;;
  --calibrate)
    [ -n "${2:-}" ] || { echo "usage: $0 --calibrate <out.toml>" >&2; exit 2; }
    # ONE scan of the tree, not two. This used to run the whole measure — purity lint, rules.py,
    # the loc-surface ceilings, the ledger and the verdict — and then throw all of it away and scan
    # the tree a second time for the ceilings. rules.py already computes the rows and calibrates
    # from them in a single pass, so the only thing measure was contributing was the purity hits
    # file; that is all that runs first now. The written toml is unchanged.
    purity_scan
    python3 "$HELPERS/rules.py" --root "$ROOT" --toml "$TOML" --purity-hits "$OUT/purity-hits.tsv" --calibrate "$2"
    # rules.py only calibrates the rules IT measures. The surface ceilings are measured by
    # scripts/loc-surface.py, not by rules.py, so their calibrated value is measured fresh right
    # here (a ceiling high enough to always pass, so only the "total" figure is wanted) and patched
    # into the [gate.surface_ceilings] table rules.py already copied through unchanged.
    for surface_spec in \
      "contract_caps|busbar-contract,busbar-caps" \
      "grammar|busbar-grammar" \
      "contract_transport|busbar-contract-transport"
    do
      IFS='|' read -r surface_key surface_crates <<<"$surface_spec"
      surface_now="$(python3 "$ROOT/scripts/loc-surface.py" --ceiling "$surface_crates=999999999" 2>/dev/null \
                      | awk '$1=="total"{print $2}')"
      [ -n "$surface_now" ] || continue
      python3 - "$2" "$surface_key" "$surface_now" <<'PYEOF'
import re
import sys

toml_path, key, val = sys.argv[1], sys.argv[2], sys.argv[3]
with open(toml_path, encoding="utf-8") as fh:
    text = fh.read()
text = re.sub(rf"(?m)^({re.escape(key)}\s*=\s*)\d+$", rf"\g<1>{val}", text)
with open(toml_path, "w", encoding="utf-8") as fh:
    fh.write(text)
PYEOF
    done
    note "calibrated ceilings written to $2 (every ceiling = today's measurement)"
    exit 0
    ;;
  --check | "")
    hdr "construction gate — measuring $ROOT against $TOML"
    measure; rc=$?
    note "report: $OUT/report.md"
    exit "$rc"
    ;;
  -h | --help)
    sed -n '2,40p' "$0"
    ;;
  *)
    echo "usage: $0 [--check | --summary | --calibrate <out.toml> | --selftest]" >&2
    exit 2
    ;;
esac
