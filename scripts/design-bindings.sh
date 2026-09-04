#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# design-bindings.sh -- THE DESIGN BINDINGS GATE.
#
# Answers "is what we built compliant with what we designed?" for docs/design/ARCHITECTURE.md
# Appendix B (the parity bindings). qa/design-bindings.json maps every binding to the checks that
# prove it (tests, shadow-oracle cells, lints, gates). This script does NOT run those checks; it
# proves that every referenced check still EXISTS in the tree and that every binding has at least
# one, and it writes one ledger row per binding through the fleet-fixtures ledger so the verdict is
# the same single-decision mechanism every other functional gate uses:
#
#   PASS   every referenced check exists and the binding has at least one
#   FAIL   a referenced check vanished (a test renamed away, a cell dropped, a script deleted)
#   SKIP   the binding is unmapped -- a NAMED gap with the suggested check in the detail column
#
# Two postures, one verdict.sh:
#   --check           owes only the MAPPED bindings to verdict.sh, so gaps are reported (SKIP rows,
#                     a printed gap list) but do not turn the run red. Day-to-day use.
#   --check --strict  owes EVERY binding, so any SKIP is red -- verdict.sh already refuses a skip on
#                     an owed id. This is what scripts/verify-1.6.0-done.sh runs: DONE means no gap.
#   In both, zero rows is red (verdict.sh's vacuous-run guard) and a vanished check is red.
#
#   --write           regenerate qa/design-bindings.json + qa/DESIGN-BINDINGS.md from Appendix B,
#                     preserving hand-added `checks` entries.
#   --selftest        the gate proves itself first: a binding with a bogus test ref is exactly ONE
#                     FAIL; an empty binding table is the vacuous red; a strict run with an
#                     unmapped binding is red while the plain run of the same table is green.
#
# Nothing here executes a test. A slower tier can run the referenced `test` kinds with cargo and the
# `oracle-*` kinds through testing/shadow-oracle/replay.sh; see qa/DESIGN-BINDINGS.md.
#
# bash 3.2 + python3 (stdlib) -- the bare-runner posture of the sibling gates.
set -uo pipefail
cd "$(dirname "$0")/.."
repo="$(pwd)"

PY=python3
DERIVE="scripts/design-bindings.py"
BINDINGS="qa/design-bindings.json"
# Absolute: verdict.sh changes directory before reading the ledger, so a relative path would point
# it at an empty file and every run would read as vacuous.
WORK="${DESIGN_BINDINGS_WORK:-${repo}/target/design-bindings}"
case "$WORK" in /*) ;; *) WORK="${repo}/${WORK}" ;; esac
mkdir -p "$WORK"

usage() { sed -n '5,34p' "$0"; }

# Run the existence verification over one bindings file into one ledger, then let verdict.sh decide.
#   run_check <bindings.json> <ledger.tsv> <strict:0|1> [extra derive args...]
run_check() {
  local bindings="$1" ledger="$2" strict="$3"; shift 3
  local rows owed pb status
  export LEDGER="$ledger"; : >"$LEDGER"
  # shellcheck source=../testing/fleet-fixtures/lib.sh
  source "${repo}/testing/fleet-fixtures/lib.sh"
  rows="$("$PY" "$DERIVE" --verify --bindings "$bindings" "$@")" || return 2
  owed=""
  while IFS=$'\t' read -r pb status title detail; do
    [ -n "$pb" ] || continue
    record "$pb" "$status" "$title" "$detail" >/dev/null
    if [ "$strict" = 1 ] || [ "$status" != SKIP ]; then owed="${owed}${pb} "; fi
  done <<EOF
$rows
EOF
  GATE_NAME="design bindings" EXPECTED_IDS="$owed" LEDGER="$LEDGER" \
    bash "${repo}/testing/fleet-fixtures/verdict.sh"
}

check() {
  local strict="$1" ledger="$WORK/ledger.tsv" rc
  [ -f "$BINDINGS" ] || { echo "design-bindings: $BINDINGS missing -- run $0 --write first" >&2; return 2; }
  run_check "$BINDINGS" "$ledger" "$strict"; rc=$?
  # The gap list: every SKIP row names the binding and the check that would prove it.
  local skips
  skips="$(awk -F'\t' '$2=="SKIP"{n++} END{print n+0}' "$ledger")"
  if [ "$skips" -gt 0 ]; then
    echo
    echo "design bindings: ${skips} UNMAPPED binding(s) -- no check proves them yet (plan in qa/DESIGN-BINDINGS.md):"
    awk -F'\t' '$2=="SKIP"{printf "  %-8s %s\n", $1, $4}' "$ledger"
    if [ "$strict" = 1 ]; then echo "design bindings --strict: a gap is red. DONE requires every binding mapped."; fi
  fi
  return "$rc"
}

# ── SELF-TEST ──────────────────────────────────────────────────────────────────────────────────
selftest() {
  echo "== design bindings SELF-TEST (the gate proves itself before it judges the tree) =="
  local tmp fails=0 cases=0 rc n
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/design-bindings-selftest.XXXXXX")"
  trap 'rm -rf "$tmp"' RETURN
  say() { printf '%s  %s\n' "$1" "$2"; cases=$((cases+1)); [ "$1" = PASS ] || fails=$((fails+1)); }
  fails_in() { awk -F'\t' '$2=="FAIL"{n++} END{print n+0}' "$1"; }

  # A real test fn and a real cell, so the fixture is proven against the actual tree; then one
  # bogus test ref on a second binding.
  local real_fn real_cell
  real_fn="$("$PY" - <<'EOF'
import importlib.util,sys
spec=importlib.util.spec_from_file_location("db","scripts/design-bindings.py"); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
idx=m.test_index(m.CRATES)
print(sorted(k for k,v in idx.items() if len(v)==1)[0])
EOF
)"
  real_cell="$("$PY" -c 'import json;print(json.load(open("testing/shadow-oracle/cells.json"))["cells"][0]["id"])')"

  # (a) one bogus ref among good ones -> exactly one FAIL, red
  cat >"$tmp/bogus.json" <<EOF
{"bindings": [
 {"id":"PB-1","surface":"good","binding":"x","inventory":"x","status":"mapped",
  "checks":[{"kind":"test","ref":"${real_fn}","status":"mapped"},{"kind":"oracle-cell","ref":"${real_cell}","status":"mapped"}]},
 {"id":"PB-2","surface":"bogus","binding":"x","inventory":"x","status":"mapped",
  "checks":[{"kind":"test","ref":"this_test_fn_does_not_exist_anywhere_selftest","status":"mapped"}]}
]}
EOF
  run_check "$tmp/bogus.json" "$tmp/a.tsv" 0 >"$tmp/a.log" 2>&1; rc=$?
  n="$(fails_in "$tmp/a.tsv")"
  if [ "$rc" != 0 ] && [ "$n" = 1 ] && grep -q $'^PB-2\tFAIL' "$tmp/a.tsv" && grep -q $'^PB-1\tPASS' "$tmp/a.tsv"; then
    say PASS "one bogus test ref -> exactly one FAIL (PB-2), the real refs PASS, run red"
  else
    say FAIL "bogus ref: rc=$rc fails=$n (expected rc!=0, 1 FAIL)"; cat "$tmp/a.log"
  fi

  # (b) a vanished cell id is also a FAIL
  cat >"$tmp/cell.json" <<EOF
{"bindings": [
 {"id":"PB-3","surface":"cell","binding":"x","inventory":"x","status":"mapped",
  "checks":[{"kind":"oracle-cell","ref":"no.such.family|nope|nope","status":"mapped"}]}
]}
EOF
  run_check "$tmp/cell.json" "$tmp/b.tsv" 0 >"$tmp/b.log" 2>&1; rc=$?
  [ "$rc" != 0 ] && [ "$(fails_in "$tmp/b.tsv")" = 1 ] && say PASS "a vanished oracle cell id -> one FAIL, red" \
    || { say FAIL "vanished cell: rc=$rc fails=$(fails_in "$tmp/b.tsv")"; cat "$tmp/b.log"; }

  # (c) an empty table -> zero rows -> the vacuous red
  echo '{"bindings": []}' >"$tmp/empty.json"
  run_check "$tmp/empty.json" "$tmp/c.tsv" 0 >"$tmp/c.log" 2>&1; rc=$?
  [ "$rc" != 0 ] && grep -q "VACUOUS RUN" "$tmp/c.log" && say PASS "empty binding table -> zero rows -> vacuous red" \
    || { say FAIL "empty table: rc=$rc"; cat "$tmp/c.log"; }

  # (d) an unmapped binding: plain check green (named gap), strict check red
  cat >"$tmp/gap.json" <<EOF
{"bindings": [
 {"id":"PB-1","surface":"good","binding":"x","inventory":"x","status":"mapped",
  "checks":[{"kind":"test","ref":"${real_fn}","status":"mapped"}]},
 {"id":"PB-4","surface":"gap","binding":"x","inventory":"x","status":"unmapped","suggestion":"a unit test",
  "checks":[{"kind":"test","ref":"","status":"unmapped"}]}
]}
EOF
  run_check "$tmp/gap.json" "$tmp/d.tsv" 0 >"$tmp/d.log" 2>&1; rc=$?
  [ "$rc" = 0 ] && grep -q $'^PB-4\tSKIP' "$tmp/d.tsv" && say PASS "unmapped binding, plain --check -> SKIP row, run green (a named gap)" \
    || { say FAIL "plain gap: rc=$rc"; cat "$tmp/d.log"; }
  run_check "$tmp/gap.json" "$tmp/e.tsv" 1 >"$tmp/e.log" 2>&1; rc=$?
  [ "$rc" != 0 ] && grep -q "SKIPPED: PB-4" "$tmp/e.log" && say PASS "same table, --strict -> the SKIP is red" \
    || { say FAIL "strict gap: rc=$rc"; cat "$tmp/e.log"; }

  # (e) the derivation reads the real Appendix B and finds the table (a parser that finds no rows
  #     would make the whole ledger vacuous)
  n="$("$PY" "$DERIVE" --summary --bindings /dev/null 2>/dev/null | sed -n 's/^bindings \([0-9]*\).*/\1/p')"
  [ "${n:-0}" -gt 50 ] && say PASS "Appendix B parses to ${n} bindings" || say FAIL "Appendix B parse yielded '${n}' bindings"

  # (f) --write preserves a hand-added check
  cp docs/design/ARCHITECTURE.md "$tmp/arch.md"
  cat >"$tmp/hand.json" <<EOF
{"bindings": [{"id":"PB-1","surface":"x","binding":"x","inventory":"x","status":"mapped",
  "checks":[{"kind":"test","ref":"${real_fn}","status":"mapped","source":"hand"}]}]}
EOF
  "$PY" "$DERIVE" --write --arch "$tmp/arch.md" --bindings "$tmp/hand.json" --out-json "$tmp/out.json" --out-md "$tmp/out.md" >/dev/null 2>&1
  if "$PY" -c "
import json,sys
d=json.load(open('$tmp/out.json'))
b=[x for x in d['bindings'] if x['id']=='PB-1'][0]
sys.exit(0 if any(c['ref']=='$real_fn' and c['kind']=='test' for c in b['checks']) else 1)"; then
    say PASS "--write preserves a hand-added check on PB-1"
  else
    say FAIL "--write dropped the hand-added check"
  fi

  echo
  if [ "$fails" -eq 0 ]; then echo "design bindings selftest: GREEN (${cases} cases)"; return 0; fi
  echo "design bindings selftest: RED (${fails}/${cases} cases failed)"; return 1
}

STRICT=0; MODE=""
for arg in "$@"; do
  case "$arg" in
    --check) MODE=check ;;
    --strict) STRICT=1 ;;
    --write) MODE=write ;;
    --selftest) MODE=selftest ;;
    -h|--help) usage; exit 0 ;;
    *) echo "usage: $0 --check [--strict] | --write | --selftest" >&2; exit 2 ;;
  esac
done
case "$MODE" in
  check) check "$STRICT" ;;
  write) "$PY" "$DERIVE" --write ;;
  selftest) selftest ;;
  *) usage; exit 2 ;;
esac
