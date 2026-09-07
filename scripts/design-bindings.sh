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
#   PASS   `mapped`: every referenced check exists AND compares something
#   FAIL   `unproven`: checks are cited but nothing they name settles anything -- a referenced check
#          vanished (a test renamed away, a cell dropped, a script deleted), or every citation is an
#          oracle cell the pinned golden never recorded. A citation list is not a proof: a binding
#          that can read "proven" while nothing was compared is worse than one that reads unmapped.
#   SKIP   the binding is unmapped -- a NAMED gap with the suggested check in the detail column
#
# Two postures, one verdict.sh:
#   --check           owes only the non-SKIP bindings to verdict.sh, so gaps are reported (SKIP rows,
#                     a printed gap list) but do not turn the run red. An UNPROVEN binding is a FAIL
#                     row, and a FAIL is red in both postures. Day-to-day use.
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
    # A DECLARED GAP IS NEVER OWED, IN EITHER POSTURE. It is not a probe that could have run and
    # did not: the check is real and the backend is absent, which is why it is written down with an
    # owner and a reason instead. Owing it would make it red; folding it into PASS would make it a
    # lie. It stays out of the owed set and is reported on its own line below, in both --check and
    # --check --strict, exactly as a named gap is treated everywhere else in this tree.
    case "$status" in
      GAP) continue ;;
    esac
    if [ "$strict" = 1 ] || [ "$status" != SKIP ]; then owed="${owed}${pb} "; fi
  done <<EOF
$rows
EOF
  GATE_NAME="design bindings" EXPECTED_IDS="$owed" LEDGER="$LEDGER" \
    bash "${repo}/testing/fleet-fixtures/verdict.sh"
}

# regen_clean → 0 if the committed ledger is what a fresh derivation from Appendix B produces.
#
# WHAT --strict ACTUALLY VERIFIED, AND WHAT IT DID NOT. Every row it judges comes out of the CACHED
# qa/design-bindings.json. Appendix B of ARCHITECTURE.md is the SOURCE of that file and was never
# opened: --strict proved that every binding IN THE CACHE is mapped, which is a statement about the
# cache. Add a binding to Appendix B and do not re-run --write, and --strict stays green — the new
# binding is unmapped, unproven, and invisible, because it is not in the file being read. That is the
# precise inverse of what "DONE requires every binding mapped" is meant to mean.
#
# So a strict run re-derives from Appendix B into a temp dir and diffs. The regen is written OUTSIDE
# the tree and nothing here rewrites the committed ledger: a check that repairs what it is checking
# has not checked anything.
regen_clean() {
  local tmp rc=0
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/design-bindings-regen.XXXXXX")" || return 2
  if ! python3 "${repo}/scripts/design-bindings.py" --write \
        --out-json "$tmp/fresh.json" --out-md "$tmp/fresh.md" >"$tmp/regen.log" 2>&1; then
    echo "design bindings REGEN-CLEAN: the derivation from Appendix B FAILED --" >&2
    sed 's/^/    /' "$tmp/regen.log" >&2
    rm -rf "$tmp"; return 2
  fi
  diff -u "$BINDINGS" "$tmp/fresh.json" >"$tmp/json.diff" 2>&1 || rc=1
  diff -u "${repo}/qa/DESIGN-BINDINGS.md" "$tmp/fresh.md" >"$tmp/md.diff" 2>&1 || rc=1
  if [ "$rc" -ne 0 ]; then
    echo
    echo "design bindings REGEN-CLEAN: RED -- the committed ledger is NOT what Appendix B derives."
    echo "  --strict judges the rows in $BINDINGS. If that file is stale, a binding added to"
    echo "  ARCHITECTURE.md Appendix B is absent from every row --strict reads, so it is unmapped,"
    echo "  unproven, and green. Regenerate with 'scripts/design-bindings.sh --write' and commit both"
    echo "  qa/design-bindings.json and qa/DESIGN-BINDINGS.md."
    head -40 "$tmp/json.diff" | sed 's/^/    /'
    head -20 "$tmp/md.diff"   | sed 's/^/    /'
  else
    echo "design bindings REGEN-CLEAN: the committed ledger matches a fresh derivation from Appendix B"
  fi
  rm -rf "$tmp"
  return "$rc"
}

check() {
  local strict="$1" ledger="$WORK/ledger.tsv" rc regen_rc=0 gaps_rc=0
  [ -f "$BINDINGS" ] || { echo "design-bindings: $BINDINGS missing -- run $0 --write first" >&2; return 2; }
  # THE GAP REGISTER IS JUDGED BEFORE THE BINDINGS IT FORGIVES. A register over its ceiling, or one
  # carrying an entry that no longer excuses anything, is red in BOTH postures -- otherwise the way
  # to make this gate green would be to add a row to a file, which is the failure the register is
  # meant to make impossible rather than convenient.
  "$PY" "$DERIVE" --verify-gaps --bindings "$BINDINGS" || gaps_rc=$?
  # REGEN-CLEAN first, and only under --strict: plain --check is the gap REPORT, and a report on a
  # slightly stale ledger is still a useful report. --strict is the DONE claim, and that claim is
  # about Appendix B, not about a cache of it.
  if [ "$strict" = 1 ]; then
    regen_clean || regen_rc=$?
  fi
  run_check "$BINDINGS" "$ledger" "$strict"; rc=$?
  [ "$regen_rc" -ne 0 ] && rc="$regen_rc"
  [ "$gaps_rc" -ne 0 ] && rc="$gaps_rc"
  # The declared-gap list: reported in every posture, counted, and never silent. A gap the reader
  # cannot see is indistinguishable from a pass, which is the whole reason it is printed here.
  local gapn
  gapn="$(awk -F'\t' '$2=="GAP"{n++} END{print n+0}' "$ledger")"
  if [ "$gapn" -gt 0 ]; then
    echo
    echo "design bindings: ${gapn} DECLARED GAP(s) -- proven where this host can prove them, and"
    echo "declared with an owner and a reason where it cannot (qa/design-bindings-gaps.json):"
    awk -F'\t' '$2=="GAP"{printf "  %-8s %s\n", $1, $4}' "$ledger"
    echo "design bindings: a declared gap is NEVER a pass. It is out of the owed set in both postures."
  fi
  # The UNPROVEN list, printed before the gap list because it is the worse condition: a gap is
  # honest about naming nothing, while an unproven binding names checks and proves nothing by them.
  # These are FAIL rows, so they are already red in BOTH postures -- plain --check included. A
  # binding is never demoted to a waiver to clear this list; it is fixed, or it becomes a named gap.
  local unproven
  unproven="$(awk -F'\t' '$2=="FAIL"{n++} END{print n+0}' "$ledger")"
  if [ "$unproven" -gt 0 ]; then
    echo
    echo "design bindings: ${unproven} UNPROVEN binding(s) -- checks are cited, but nothing they name compares anything:"
    awk -F'\t' '$2=="FAIL"{printf "  %-8s %s\n", $1, $4}' "$ledger"
    echo "design bindings: an unproven binding is RED in every posture. Make the citation real, or record it as a named gap."
  fi
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
  # A cell the GOLDEN RECORDED, not merely the first line of cells.json: two thirds of the cell
  # list is protocol surface the 1.5.5 binary never served, and the golden carries those as SKIP.
  # `skipped_cell` is one of them, and case (b2) below needs it.
  local skipped_cell
  pick_cell() { "$PY" - "$1" <<'PYEOF'
import json, sys
want = sys.argv[1]
led = {}
for ln in open("testing/shadow-oracle/golden/1.5.5/ledger.tsv", encoding="utf-8"):
    p = ln.rstrip("\n").split("\t")
    if len(p) >= 2:
        led[p[0]] = p[1]
ids = [c["id"] for c in json.load(open("testing/shadow-oracle/cells.json"))["cells"]]
if want == "recorded":
    print(sorted(i for i in ids if led.get(i) == "PASS")[0])
else:
    print(sorted(i for i in ids if i.startswith("mcp|") and led.get(i) == "SKIP")[0])
PYEOF
  }
  real_cell="$(pick_cell recorded)"
  skipped_cell="$(pick_cell skipped-mcp)"

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

  # (b2) a cell that EXISTS in cells.json but that the golden recorded as SKIP proves nothing, and
  #      is a FAIL too. Without this the ledger's strongest-looking evidence — an oracle cell id —
  #      could name surface the pinned binary never served and read green forever.
  cat >"$tmp/skipped.json" <<EOF
{"bindings": [
 {"id":"PB-3","surface":"skipped cell","binding":"x","inventory":"x","status":"mapped",
  "checks":[{"kind":"oracle-cell","ref":"${skipped_cell}","status":"mapped"}]}
]}
EOF
  run_check "$tmp/skipped.json" "$tmp/b2.tsv" 0 >"$tmp/b2.log" 2>&1; rc=$?
  [ "$rc" != 0 ] && [ "$(fails_in "$tmp/b2.tsv")" = 1 ] && grep -q "golden never recorded it" "$tmp/b2.tsv" \
    && say PASS "an oracle cell the golden never recorded -> one FAIL, red" \
    || { say FAIL "unrecorded cell: rc=$rc fails=$(fails_in "$tmp/b2.tsv") ($skipped_cell)"; cat "$tmp/b2.log"; }

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

  # (g) the inversion this gate's verdict rests on: an OWED id with NO ledger row is DID NOT RUN,
  #     red, and named. Every gate in this tree is only as honest as that branch — a run whose
  #     second step died before it could record must not read as green just because the first
  #     step's PASS row is the only row present. Driven straight through verdict.sh with a
  #     hand-built ledger, the same way the cases above drive it through run_check.
  printf 'PB-1\tPASS\tprobe ran\t\n' >"$tmp/norow.tsv"
  GATE_NAME="design bindings" EXPECTED_IDS="PB-1 PB-DID-NOT-RUN" LEDGER="$tmp/norow.tsv" \
    bash "${repo}/testing/fleet-fixtures/verdict.sh" >"$tmp/g.log" 2>&1; rc=$?
  if [ "$rc" != 0 ] && grep -q "DID NOT RUN *PB-DID-NOT-RUN" "$tmp/g.log" \
     && grep -q "DID NOT RUN: PB-DID-NOT-RUN" "$tmp/g.log" && grep -q "PASS *PB-1" "$tmp/g.log"; then
    say PASS "an owed id with no ledger row -> red, named DID NOT RUN (the PASS row does not carry it)"
  else
    say FAIL "owed id with no row: rc=$rc (expected rc!=0 and a named DID NOT RUN line)"; cat "$tmp/g.log"
  fi

  # (h) REGEN-CLEAN. --strict judges the rows in the CACHED qa/design-bindings.json and never opened
  #     Appendix B, so a binding added to ARCHITECTURE.md and not re-derived was simply absent from
  #     everything --strict reads: unmapped, unproven, and green. Prove both arms of the new check —
  #     the committed ledger is clean, and a ledger with one binding removed is REFUSED.
  if ( regen_clean ) >"$tmp/h-clean.log" 2>&1; then
    say PASS "REGEN-CLEAN: the committed ledger matches a fresh derivation from Appendix B"
  else
    say FAIL "REGEN-CLEAN: the committed ledger does not match Appendix B"; cat "$tmp/h-clean.log"
  fi
  "$PY" -c "
import json,sys
d=json.load(open('${repo}/qa/design-bindings.json'))
d['bindings']=d['bindings'][1:]
json.dump(d, open('$tmp/stale.json','w'), indent=1, ensure_ascii=False)
"
  if ( BINDINGS="$tmp/stale.json" regen_clean ) >"$tmp/h-stale.log" 2>&1; then
    say FAIL "REGEN-CLEAN: a ledger missing a binding was ACCEPTED -- a binding added to Appendix B would stay invisible to --strict"
  else
    say PASS "REGEN-CLEAN: a ledger missing one binding is REFUSED (a stale cache cannot hide an unmapped binding)"
  fi

  # (i) THE COUNTS TELL THE TRUTH. The summary used to call a binding `mapped` on the strength of the
  #     citation list alone, while --verify judged the very same binding FAIL. So a binding whose only
  #     evidence was an oracle cell the pinned golden never recorded read as PROVEN in
  #     qa/DESIGN-BINDINGS.md and as broken in the ledger, at the same time, from the same file. This
  #     case pins the two together: such a binding is `unproven`, verdict FAIL, and counted nowhere
  #     near `mapped`.
  if "$PY" - "$skipped_cell" <<'PYEOF'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("db", "scripts/design-bindings.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
cells = json.load(open("testing/shadow-oracle/cells.json"))
b = {"id": "PB-1", "surface": "its only cell is one the golden never recorded",
     "checks": [{"kind": "oracle-cell", "ref": sys.argv[1], "status": "mapped"}]}
ctx = m.check_context(cells, m.CRATES, m.ROOT, m.GOLDEN_LEDGER)
status, verdict, detail = m.binding_verdict(b, ctx)
b["status"] = status
c = m.counts([b])
ok = (status == "unproven" and verdict == "FAIL"
      and c["mapped"] == 0 and c["unproven"] == 1 and c["unmapped"] == 0)
if not ok:
    print(f"status={status} verdict={verdict} counts={c} detail={detail}", file=sys.stderr)
sys.exit(0 if ok else 1)
PYEOF
  then
    say PASS "counts() follows the verdict: a binding whose only cell the golden skipped is unproven, not mapped"
  else
    say FAIL "counts() called a binding with nothing compared 'mapped'"
  fi

  # (j) A GATE NOBODY RUNS PROVES NOTHING. `(root/ref).exists()` was the whole test for a gate/lint
  #     ref, so a script that had stopped being invoked -- or that was only ever NAMED in a workflow
  #     comment or a step title -- carried a binding as proven for as long as the file stayed on disk.
  #     Driven against a fixture tree rather than the repo, so the case asserts the RULE and does not
  #     move the day a real workflow is edited. Both arms, because a check that only ever says no is
  #     no better than one that only ever says yes.
  if "$PY" - <<'PYEOF'
import importlib.util, pathlib, sys, tempfile
spec = importlib.util.spec_from_file_location("db", "scripts/design-bindings.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
with tempfile.TemporaryDirectory() as td:
    root = pathlib.Path(td)
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / "scripts").mkdir()
    for name in ("ran.sh", "talked-about.sh", "titled.sh", "orphan.sh", "nested.sh"):
        (root / "scripts" / name).write_text("#!/bin/sh\n")
    # ran.sh runs nested.sh, and mentions a data file it merely READS.
    (root / "scripts" / "ran.sh").write_text(
        "#!/bin/sh\n# scripts/talked-about.sh used to run here\n"
        "bash scripts/nested.sh --check\ncat qa/data.json\n")
    (root / "qa").mkdir()
    (root / "qa" / "data.json").write_text("{}\n")
    (root / ".github" / "workflows" / "ci.yml").write_text(
        "jobs:\n  a:\n    steps:\n"
        "      - name: run scripts/titled.sh one day\n"
        "        run: scripts/ran.sh --check\n"
        "      # scripts/talked-about.sh documents the phase this replaces\n")
    ctx = m.check_context({"cells": []}, root / "crates", root, root / "no-ledger.tsv")
    want = {"scripts/ran.sh": True,
            # reached only through a script the workflow runs -- still run by CI
            "scripts/nested.sh": True,
            "scripts/talked-about.sh": False,
            "scripts/titled.sh": False,
            "scripts/orphan.sh": False,
            # a data file an invoked script reads is an input to a gate, never a gate
            "qa/data.json": False}
    bad = []
    for ref, expected in want.items():
        got, why = m.check_verdict({"kind": "gate", "ref": ref, "status": "mapped"}, ctx)
        if got is not expected:
            bad.append(f"{ref}: got {got}, wanted {expected} ({why})")
        if not expected and "invokes it" not in why:
            bad.append(f"{ref}: reason does not name the missing invocation ({why})")
    if bad:
        print("; ".join(bad), file=sys.stderr)
    sys.exit(1 if bad else 0)
PYEOF
  then
    say PASS "a gate/lint ref is proof only when a workflow INVOKES it (a comment or a step title is not an invocation)"
  else
    say FAIL "the runs-in-CI check does not separate an invoked gate from one that only exists on disk"
  fi

  # (k) A NOTE THAT SAYS "UNTESTED" OUTRANKS A GREEN CITATION. Some rows carried a note in the
  #     ledger's own words -- "does not exist in crates/", "vacuously true", "untested" -- while
  #     being counted as mapped, because a test fn of some other subsystem happened to match the ref
  #     by name. A binding whose own record says nothing was compared is unproven, whatever its
  #     citation list looks like. Driven with an injected table so the case asserts the rule; the
  #     second arm pins that the four real ids are actually in the shipped table.
  if "$PY" - <<'PYEOF'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("db", "scripts/design-bindings.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
shipped = set(m.UNPROVEN_BY_NOTE)
bad = []
for want in ("PB-17", "PB-48", "PB-58", "PB-61"):
    if want not in shipped:
        bad.append(f"{want} is not carried as unproven-by-note")
    if not m.UNPROVEN_BY_NOTE[want].strip() if want in shipped else False:
        bad.append(f"{want} carries no reason")
# The rule itself: a real, existing test ref does NOT rescue a row the note disqualifies.
ctx = m.check_context({"cells": []}, m.CRATES, m.ROOT, m.GOLDEN_LEDGER)
real = sorted(k for k, v in ctx["idx"].items() if len(v) == 1)[0]
m.UNPROVEN_BY_NOTE = {"PB-SELFTEST": "the surface this binding names does not exist in crates/"}
b = {"id": "PB-SELFTEST", "surface": "noted untested",
     "checks": [{"kind": "test", "ref": real, "status": "mapped"}]}
status, verdict, detail = m.binding_verdict(b, ctx)
if not (status == "unproven" and verdict == "FAIL" and "does not exist in crates/" in detail):
    bad.append(f"a noted-untested row with a real test ref came back {status}/{verdict}: {detail}")
# and the same row is `mapped` once the note is gone, so the table is what decides, not the ref
m.UNPROVEN_BY_NOTE = {}
if m.binding_verdict(b, ctx)[0] != "mapped":
    bad.append("removing the note did not restore the row -- the case proves nothing")
if bad:
    print("; ".join(bad), file=sys.stderr)
sys.exit(1 if bad else 0)
PYEOF
  then
    say PASS "a binding whose own note says nothing was compared is unproven, whatever it cites"
  else
    say FAIL "a noted-untested binding was still counted as proven"
  fi

  # (l) A BARE NAME TWO FILES BOTH DECLARE NAMES NO TEST. `ref in idx` asked only whether SOMETHING
  #     somewhere in the tree bore that name, so a citation survived the deletion of the very test it
  #     was written against as long as a namesake existed elsewhere -- which is the exact failure this
  #     ledger is for. Such a ref proves nothing until it is written `path.rs::name`. Both arms, over
  #     a real ambiguous name found in the tree, so the case cannot pass vacuously.
  if "$PY" - <<'PYEOF'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("db", "scripts/design-bindings.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
ctx = m.check_context({"cells": []}, m.CRATES, m.ROOT, m.GOLDEN_LEDGER)
shared = sorted(k for k, v in ctx["idx"].items() if len(v) > 1)
if not shared:
    print("no name is declared in two files -- the case would pass vacuously", file=sys.stderr)
    sys.exit(1)
name = shared[0]
files = sorted(ctx["idx"][name])
bad = []
ok, why = m.check_verdict({"kind": "test", "ref": name, "status": "mapped"}, ctx)
if ok:
    bad.append(f"the bare ambiguous ref {name} was accepted as proof")
elif "path.rs::name" not in why:
    bad.append(f"the reason does not say how to fix it: {why}")
for f in files:
    ok, why = m.check_verdict({"kind": "test", "ref": f"{f}::{name}", "status": "mapped"}, ctx)
    if not ok:
        bad.append(f"the disambiguated ref {f}::{name} was refused: {why}")
# and a disambiguator pointing at a file that does not declare it is still refused
ok, _ = m.check_verdict({"kind": "test", "ref": f"crates/nowhere/src/lib.rs::{name}", "status": "mapped"}, ctx)
if ok:
    bad.append("a disambiguator naming the wrong file was accepted")
# no bare ambiguous ref may survive in the shipped ledger
for pb, entries in m.SEED.items():
    for kind, ref, _p in entries:
        if kind == "test" and "::" not in ref and len(ctx["idx"].get(ref, ())) > 1:
            bad.append(f"{pb} still cites the ambiguous bare name {ref}")
if bad:
    print("; ".join(bad), file=sys.stderr)
sys.exit(1 if bad else 0)
PYEOF
  then
    say PASS "a bare test name two files declare proves nothing; path.rs::name does, and only for the right file"
  else
    say FAIL "an ambiguous bare test ref was accepted as proof"
  fi

  # ── THE DECLARED-GAP REGISTER ────────────────────────────────────────────────────────────────
  # A gap register is a way of NOT weakening the gate only if each of its rules is enforced. One
  # arm per rule, each driven on a planted register over a two-binding fixture whose second binding
  # cites a cell the pinned golden never recorded (the mysql store cell, which is exactly that in
  # this tree), so the fixture fails for the real reason before any gap is declared.
  cat >"$tmp/gapfix.json" <<EOF
{"bindings": [
 {"id":"PB-1","surface":"good","binding":"x","inventory":"x","status":"mapped",
  "checks":[{"kind":"test","ref":"${real_fn}","status":"mapped"}]},
 {"id":"PB-2","surface":"needs a backend","binding":"x","inventory":"x","status":"mapped",
  "checks":[{"kind":"test","ref":"${real_fn}","status":"mapped"},
            {"kind":"oracle-cell","ref":"plugins.store-persist|store-mysql","status":"mapped"}]}
]}
EOF
  gapreg() {  # gapreg <out> <expected> <binding> <cells-json>
    cat >"$1" <<EOF
{"expected": $2, "gaps": [
 {"id":"DBG-selftest","binding":"$3","owner":"selftest","declared_at":"2026-09-06",
  "cells": $4, "reason":"the selftest's planted gap"}
]}
EOF
  }

  # (k) with NO register, the fixture is red -- the condition every arm below is a delta from.
  echo '{"expected":0,"gaps":[]}' >"$tmp/gap-none.json"
  run_check "$tmp/gapfix.json" "$tmp/k.tsv" 0 --gaps "$tmp/gap-none.json" >"$tmp/k.log" 2>&1; rc=$?
  [ "$rc" != 0 ] && grep -q $'^PB-2\tFAIL' "$tmp/k.tsv" \
    && say PASS "gap register: an unrecordable cell with NO entry is FAIL, red (the undeclared state)" \
    || { say FAIL "gap register: undeclared unrecordable cell was not red (rc=$rc)"; cat "$tmp/k.log"; }

  # (l) declared: the binding is GAP, NEVER PASS, and the run is green -- the whole point.
  gapreg "$tmp/gap-ok.json" 1 PB-2 '["plugins.store-persist|store-mysql"]'
  run_check "$tmp/gapfix.json" "$tmp/l.tsv" 0 --gaps "$tmp/gap-ok.json" >"$tmp/l.log" 2>&1; rc=$?
  if [ "$rc" = 0 ] && grep -q $'^PB-2\tGAP' "$tmp/l.tsv" && ! grep -q $'^PB-2\tPASS' "$tmp/l.tsv"; then
    say PASS "gap register: a declared gap is reported GAP, never PASS, and does not turn the run red"
  else
    say FAIL "gap register: declared gap did not read as GAP (rc=$rc)"; cat "$tmp/l.tsv"; cat "$tmp/l.log"
  fi
  # ...and it is out of the owed set under --strict too, or "declared" would just mean "red later".
  run_check "$tmp/gapfix.json" "$tmp/l2.tsv" 1 --gaps "$tmp/gap-ok.json" >"$tmp/l2.log" 2>&1; rc=$?
  [ "$rc" = 0 ] && grep -q $'^PB-2\tGAP' "$tmp/l2.tsv" \
    && say PASS "gap register: --strict keeps a declared gap out of the owed set as well" \
    || { say FAIL "gap register: --strict reddened a declared gap (rc=$rc)"; cat "$tmp/l2.log"; }

  # (m) A GAP FORGIVES ONLY WHAT IT NAMES: an entry naming some other cell excuses nothing here.
  gapreg "$tmp/gap-wrong.json" 1 PB-2 '["plugins.store-persist|store-valkey"]'
  run_check "$tmp/gapfix.json" "$tmp/m.tsv" 0 --gaps "$tmp/gap-wrong.json" >"$tmp/m.log" 2>&1; rc=$?
  [ "$rc" != 0 ] && grep -q $'^PB-2\tFAIL' "$tmp/m.tsv" \
    && say PASS "gap register: an entry forgives ONLY the cells it names; another cell stays FAIL" \
    || { say FAIL "gap register: an entry widened itself past the cells it named (rc=$rc)"; cat "$tmp/m.log"; }

  # (n) THE CEILING IS ASSERTED: two declared gaps against a ceiling of one is RED.
  cat >"$tmp/gap-over.json" <<EOF
{"expected": 1, "gaps": [
 {"id":"DBG-a","binding":"PB-1","owner":"selftest","cells":["plugins.store-persist|store-mysql"],"reason":"r"},
 {"id":"DBG-b","binding":"PB-2","owner":"selftest","cells":["plugins.store-persist|store-mysql"],"reason":"r"}
]}
EOF
  if "$PY" "$DERIVE" --verify-gaps --bindings "$tmp/gapfix.json" --gaps "$tmp/gap-over.json" \
       >"$tmp/n.log" 2>&1; then
    say FAIL "gap register: a register OVER its ceiling was accepted"; cat "$tmp/n.log"
  else
    grep -q "ceiling of 1" "$tmp/n.log" \
      && say PASS "gap register: more gaps than the asserted ceiling is red, naming the ceiling" \
      || { say FAIL "gap register: over-ceiling red did not name the ceiling"; cat "$tmp/n.log"; }
  fi

  # (o) AN UNUSED ENTRY IS A LIE: an entry on a binding that proves fine today is RED, and the
  #     message says to delete it rather than leave a waiver standing over nothing.
  gapreg "$tmp/gap-idle.json" 1 PB-1 '["plugins.store-persist|store-mysql"]'
  if "$PY" "$DERIVE" --verify-gaps --bindings "$tmp/gapfix.json" --gaps "$tmp/gap-idle.json" \
       >"$tmp/o.log" 2>&1; then
    say FAIL "gap register: an entry that forgives NOTHING was accepted"; cat "$tmp/o.log"
  else
    grep -q "forgives nothing on PB-1" "$tmp/o.log" && grep -q "Delete the entry" "$tmp/o.log" \
      && say PASS "gap register: an entry that forgives nothing is red, and is told to delete itself" \
      || { say FAIL "gap register: unused-entry red did not name the entry"; cat "$tmp/o.log"; }
  fi

  # (p) A gap is DECLARED, with an owner and a reason, or it is not declared.
  cat >"$tmp/gap-bare.json" <<EOF
{"expected": 1, "gaps": [
 {"id":"DBG-bare","binding":"PB-2","cells":["plugins.store-persist|store-mysql"]}
]}
EOF
  if "$PY" "$DERIVE" --verify-gaps --bindings "$tmp/gapfix.json" --gaps "$tmp/gap-bare.json" \
       >"$tmp/p.log" 2>&1; then
    say FAIL "gap register: an entry with no owner and no reason was accepted"; cat "$tmp/p.log"
  else
    grep -q "no \`owner\`" "$tmp/p.log" && grep -q "no \`reason\`" "$tmp/p.log" \
      && say PASS "gap register: an entry with no owner and no reason is red on both counts" \
      || { say FAIL "gap register: bare-entry red did not name owner and reason"; cat "$tmp/p.log"; }
  fi

  # (q) the register the tree actually ships is honest, judged against the shipped ledger.
  if "$PY" "$DERIVE" --verify-gaps >"$tmp/q.log" 2>&1; then
    say PASS "gap register: the committed qa/design-bindings-gaps.json is within its ceiling and forgives what it names"
  else
    say FAIL "gap register: the committed register is RED"; cat "$tmp/q.log"
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
