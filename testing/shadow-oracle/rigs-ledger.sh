#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# testing/shadow-oracle/rigs-ledger.sh — fold the MCP / A2A / voice CONFORMANCE RIGS into the shadow
# oracle's own ledger, so the ship gate can finally see them.
#
# THE GAP THIS CLOSES. The shadow oracle's cells.json carries 1,380 mcp/a2a cells that are all named
# SKIPs whose reason is "go through the conformance rigs" (see testing/shadow-oracle/cells.json and
# enumerate-cells.py) — real coverage, but coverage that lives ENTIRELY in three other scripts'
# verdicts (scripts/mcp-conformance.sh, scripts/a2a-subject/boot.sh,
# testing/voice-conformance/voice-conformance.sh). Nothing ever wrote those verdicts into the ledger
# replay.sh's verdict reads, so "zero unaccepted divergences" was true of the oracle's own cells while
# 1,380 cells sat SKIPPED, unseen by anyone who read only the shadow oracle's verdict. This script is
# the bridge: it runs the three rigs against ONE binary, converts each rig's own machine-readable
# result into ONE ledger row per scenario / requirement / leg, and decides through the SAME
# ledger-and-verdict inversion every other gate in this tree uses (testing/fleet-fixtures/lib.sh +
# verdict.sh): every owed row is recorded exactly once, no rig's result can mask another's, and a
# row that never showed up is DID NOT RUN — red, never silently absent.
#
# WHY A SEPARATE LEDGER RATHER THAN TEACHING replay.sh TO SHELL OUT TO THE RIGS ITSELF. The three rigs
# have three different arming contracts (a binary env var, a battery directory, a suite pin) and three
# different failure shapes (a suite that never started vs. one that ran and found defects), and
# replay.sh's own job — comparing a candidate recording to a golden LLM-plane recording — is already
# fully specified without them. Keeping this bridge in its own file means a rig's arming or output
# shape can change without touching the LLM-plane replayer, and vice versa; the two verdicts are
# combined only by a human (or a CI job) reading both, exactly as the mcp/a2a/voice conformance
# workflows are read alongside the shadow-oracle workflow today.
#
# WHAT "MACHINE-READABLE" MEANS FOR EACH RIG, AND WHY NOTHING UPSTREAM WAS RE-PARSED FROM PRETTY TEXT:
#   MCP  --official-subject   already writes one `checks.json` per executed scenario under its `-o`
#                              output directory (scripts/mcp-conformance.sh, official_subject()). This
#                              script points that at a workdir under target/ and reads the JSON
#                              directly. Nothing in mcp-conformance.sh changes.
#   A2A  --battery             already writes testing/a2a-harness/reports/subject.json, a `results`
#                              array of `{id, outcome, role}` (a2aht/runner.py::report). Read directly.
#   A2A  --tck                 already writes `<work>/out/subject.json`'s `per_requirement` map, the
#                              SAME file scripts/a2a-subject/boot.sh's own assert_tck_number() reads.
#                              Read directly; testing/a2a-tck/subject-waivers.json is read alongside it
#                              for the pinned waiver set.
#   voice --verdict            had NO machine-readable output at all — each leg prints a `RESULT
#                              <slice> <PASS|FAIL> <detail>` line that voice-conformance.sh reformats
#                              for a human and then discards. This is the ONE gap this change had to
#                              fill upstream: an ADDITIVE `VOICE_RESULT_LOG` env var
#                              (testing/voice-conformance/voice-conformance.sh, `_process_leg`) that,
#                              when set, ALSO appends a `<leg>\t<slice>\t<verdict>\t<detail>` TSV row
#                              per slice. The default (unset) run's stdout and behaviour do not change
#                              by one byte; see the file's own header for the flag's contract.
#
# ROW IDS
#   mcp.rig|<scenario>       one row per EXECUTED scenario (the scenario's checks.json), not per check
#                            — the ship gate needs "did busbar pass this scenario", not a 190-row dump
#                            of individual assertions. FAIL if any check in the scenario is FAILURE.
#                            ALSO one row per scripts/mcp-subject/h2-*.sh gating scenario (tracker row
#                            H2's per-Teller-step cells for this plane: authenticate/verify/admit/
#                            meter/audit/exit — see run_h2_mcp()), ids `mcp.rig|h2-<step>`, folded
#                            into this SAME namespace rather than a second one.
#   a2a.battery|<id>         one row per battery test id (the a2aht `results[].id`). ALSO one row per
#                            scripts/a2a-subject/h2-*.sh gating scenario (tracker row H2's per-Teller-
#                            step cells for this plane: verify/admit/route/meter/audit/exit — see
#                            run_h2_a2a()), ids `a2a.battery|h2-<step>`.
#   a2a.tck|<requirement>    one row per MUST-level requirement in the TCK's own per_requirement map.
#                            A requirement the suite itself marks NOT TESTED or SKIPPED (both are the
#                            suite's own limitation, never evidence about busbar), or a FAIL inside the
#                            pinned waiver set (testing/a2a-tck/subject-waivers.json), is recorded as
#                            SKIP — named, with the reason or the waiver file quoted in the detail
#                            column — and EXCLUDED from what this run owes, so a known, dated,
#                            suite-or-waiver limitation cannot turn the gate red, and a real regression
#                            cannot hide behind one either. A SKIP row is NEVER counted as a PASS.
#   voice.rig|<leg>          one row per voice leg (not per slice): PASS only if every slice of that
#                            leg reported PASS; a NO RESULT slice, or any non-PASS verdict, is FAIL.
#
# BASELINE (rigs-baseline.json, next to this script)
#   The rows' expected status AS OF THE LAST SIGN-OFF, in the same spirit as
#   testing/shadow-oracle/owed-baseline.txt: a rig's OWN verdict can shrink silently (a scenario the
#   suite used to run quietly stops running, a flaky leg that used to pass is reported once and never
#   looked at again) with nothing anywhere going red, because "PASS" simply stopped being asserted.
#   `--rebaseline` accepts THIS run's rows as the new baseline and (re)writes the file. `--check` (the
#   default once a baseline exists) diffs this run's rows against it:
#     * a row that was PASS at baseline and is NOT PASS now is a REGRESSION — a synthetic
#       `baseline|<id>` FAIL row is recorded and OWED, so verdict.sh reports it by name.
#     * a row present now that was not in the baseline is NEW COVERAGE — printed, never gated.
#     * a row that was PASS at baseline and produced NO row at all this run is caught for free by the
#       ordinary "did not run" path below (its id is added to what this run owes).
#
# USAGE
#   rigs-ledger.sh --bin <busbar-binary> [--rebaseline] [--check] [--baseline <file>] [--work <dir>]
#   rigs-ledger.sh --selftest
#
# ARMING
#   MCP_SUBJECT_BUSBAR_BIN / A2A_SUBJECT_BUSBAR_BIN are set from --bin for the MCP and A2A legs. The
#   voice battery arms itself (it drives its OWN `voice-conform` harness binary built from this tree,
#   never busbar's server binary — see testing/voice-conformance/lib/conform-bin.sh), so --bin plays
#   no part in that leg; it is still required, so a run cannot silently skip the two legs that do need
#   it by never providing one.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "${here}/../.." && pwd)"

say() { printf '%s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,80p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

BIN="" REBASELINE=0 CHECK=0 SELFTEST=0
BASELINE="${here}/rigs-baseline.json"
WORK="${RIGS_LEDGER_WORK:-${repo}/target/rigs-ledger}"

# Mirrors testing/shadow-oracle/replay.sh's owed-baseline discipline: a rig's OWN verdict can shrink
# silently (a scenario stops running, a leg that used to pass is never looked at again) with nothing
# going red, because "PASS" simply stopped being asserted. This closes that hole for the rig ledger
# itself. Defined here (ABOVE both --selftest and the real run) so --selftest drives this exact
# function rather than a copy of it.
fold_baseline_regressions() {  # fold_baseline_regressions <ledger> <baseline-json>  -> prints owed rows on stdout
  local ledger="$1" baseline_file="$2"
  [ -s "$baseline_file" ] || return 0
  python3 - "$ledger" "$baseline_file" <<'PY'
import json, sys

ledger_path, baseline_path = sys.argv[1], sys.argv[2]
current = {}
with open(ledger_path, encoding="utf-8") as f:
    for line in f:
        parts = line.rstrip("\n").split("\t")
        if len(parts) >= 2:
            current[parts[0]] = parts[1]

with open(baseline_path, encoding="utf-8") as f:
    baseline = (json.load(f) or {}).get("rows") or {}

for row_id in sorted(current):
    if row_id not in baseline:
        sys.stderr.write(f"rigs-ledger: new coverage (not yet in the baseline): {row_id}\n")

for row_id, was in sorted(baseline.items()):
    if was != "PASS":
        continue
    now = current.get(row_id)
    if now == "PASS":
        continue
    reason = "did not run this time" if now is None else f"now {now}"
    print(f"{row_id}\tFAIL\tPASS at the last sign-off, {reason}\tsee rigs-baseline.json; if this is a "
          f"deliberate, understood change, rerun with --rebaseline")
PY
}

while [ $# -gt 0 ]; do
  case "$1" in
    --bin) BIN="$2"; shift 2 ;;
    --rebaseline) REBASELINE=1; shift ;;
    --check) CHECK=1; shift ;;
    --selftest) SELFTEST=1; shift ;;
    --baseline) BASELINE="$2"; shift 2 ;;
    --work) WORK="$2"; shift 2 ;;
    --help|-h) usage 0 ;;
    *) echo "unknown arg: $1" >&2; usage 2 ;;
  esac
done

# ── --selftest lives entirely below, before anything real is armed ──────────────────────────────
if [ "$SELFTEST" = 1 ]; then
  # shellcheck disable=SC2317  # invoked below, not dead code
  run_selftest() {
    say "== rigs-ledger SELF-TEST (the ledger and the vacuous-run guard cannot be lied to) =="
    local failures=0 tmp; tmp="$(mktemp -d)"
    # NOT a RETURN trap: `source` below counts as its own function-like return in bash, so a RETURN
    # trap set here would fire (and delete $tmp) the moment lib.sh finishes sourcing -- before the
    # `record` calls further down ever run. Cleaned up by hand at every exit path instead.

    # RED 1: a PASS at baseline that becomes a FAIL this run must produce exactly one FAIL row for
    # it, and the overall verdict must go red because of it. Drives the REAL ledger/verdict path
    # (testing/fleet-fixtures/lib.sh + verdict.sh) and the REAL fold_baseline_regressions above, not
    # a re-implementation of either.
    local ledger="$tmp/ledger.tsv" baseline="$tmp/baseline.json"
    : >"$ledger"
    printf '{"rows":{"fake.rig|scenario-a":"PASS"}}\n' >"$baseline"
    export LEDGER="$ledger"
    # shellcheck source=../fleet-fixtures/lib.sh
    source "${repo}/testing/fleet-fixtures/lib.sh"
    # The fake rig's current result: the same id, now FAIL (the flip this self-test exists to prove).
    record "fake.rig|scenario-a" FAIL "fake rig: scenario-a" "flipped from PASS to FAIL by the fixture" >/dev/null
    local owed="fake.rig|scenario-a" baseline_rows baseline_owed="" n_baseline_rows
    baseline_rows="$(fold_baseline_regressions "$ledger" "$baseline")"
    if [ -n "$baseline_rows" ]; then
      while IFS=$'\t' read -r id st title detail; do
        [ -n "$id" ] || continue
        record "baseline|$id" "$st" "$title" "$detail" >/dev/null
        baseline_owed="${baseline_owed} baseline|$id"
      done <<<"$baseline_rows"
    fi
    n_baseline_rows="$(printf '%s' "$baseline_rows" | grep -c . || true)"
    if [ "$n_baseline_rows" -eq 1 ] \
        && awk -F'\t' '$1=="baseline|fake.rig|scenario-a" && $2=="FAIL"{f=1} END{exit !f}' "$ledger"; then
      say "  ok: the PASS-at-baseline row that flipped to FAIL produced exactly one FAIL baseline row"
    else
      say "  MISS: expected exactly one FAIL baseline|fake.rig|scenario-a row (fold_baseline_regressions produced $n_baseline_rows row(s))"
      failures=$((failures+1))
    fi
    if GATE_NAME="selftest" EXPECTED_IDS="${owed}${baseline_owed}" LEDGER="$ledger" \
        bash "${repo}/testing/fleet-fixtures/verdict.sh" >/dev/null 2>&1; then
      say "  MISS: a run carrying a flipped PASS->FAIL row was accepted as green"
      failures=$((failures+1))
    else
      say "  ok: a run carrying a flipped PASS->FAIL row is red"
    fi

    # RED 2: an EMPTY result (a rig that produced zero rows) must be vacuous-red, exactly like every
    # other gate in this tree. Proven against the REAL verdict.sh, on a genuinely empty ledger.
    local empty_ledger="$tmp/empty.tsv"; : >"$empty_ledger"
    if GATE_NAME="selftest" EXPECTED_IDS="whatever.rig|x" LEDGER="$empty_ledger" \
        bash "${repo}/testing/fleet-fixtures/verdict.sh" >/dev/null 2>&1; then
      say "  MISS: a ledger with zero rows was accepted as a verdict"
      failures=$((failures+1))
    else
      say "  ok: zero rows is red (vacuous run), never a silent pass"
    fi

    rm -rf "$tmp"
    [ "$failures" -eq 0 ] || die "$failures self-test expectation(s) did not hold. No verdict from \
this script means anything until they do."
    say "rigs-ledger self-test: PASS."
  }
  run_selftest
  exit 0
fi

# ── real run: everything below needs a binary ────────────────────────────────────────────────────
[ -n "$BIN" ] && [ -x "$BIN" ] \
  || die "usage: $0 --bin <busbar-binary> [--rebaseline] [--check] [--baseline f] [--work d]
          (--bin must be an executable busbar built from the commit under test — see the MCP/A2A
          subject legs' own arming rules for why a URL or an unbuilt path is not accepted here.)"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

mkdir -p "$WORK"
export LEDGER="${WORK}/ledger.tsv"
: >"$LEDGER"
# shellcheck source=../fleet-fixtures/lib.sh
source "${repo}/testing/fleet-fixtures/lib.sh"

owed_ids=""

# ── MCP: official suite, subject leg ─────────────────────────────────────────────────────────────
run_mcp() {
  say ""
  say "== rig: MCP official conformance suite (subject = busbar) =="
  local out="${WORK}/mcp-subject"
  rm -rf "$out"
  MCP_SUBJECT_BUSBAR_BIN="$BIN" MCP_SUBJECT_OUT="$out" \
    bash "${repo}/scripts/mcp-conformance.sh" --official-subject \
    >"${WORK}/mcp-subject.log" 2>&1 || true
  # Read whatever checks.json landed, REGARDLESS of mcp-conformance.sh's own exit code: its
  # assert_covered + baseline gate is a separate, already-enforced verdict about the MCP suite alone
  # (see its own --official-subject). This ledger's job is to see every scenario it produced, not to
  # re-decide whether that script itself was happy.
  if [ ! -d "$out" ]; then
    record "mcp.rig|_no_output" FAIL "MCP official-subject leg produced no output directory" \
      "see ${WORK}/mcp-subject.log"
    owed_ids="${owed_ids} mcp.rig|_no_output"
    return
  fi
  local rows
  rows="$(python3 - "$out" <<'PY'
import glob, json, os, re, sys

outdir = sys.argv[1]
scenarios = {}
for f in sorted(glob.glob(os.path.join(outdir, "*", "checks.json"))):
    dirname = os.path.basename(os.path.dirname(f))
    # `server-<scenario>-<ISO-8601 stamp>` -> `<scenario>`. Same exact-shape strip as
    # scripts/mcp-conformance.sh's own executed_scenarios(), for the same reason: a loose character
    # class eats the numeric tail of a scenario like `sep-2164` and reports it as never executed.
    name = re.sub(r"^server-", "", dirname)
    name = re.sub(r"-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z$", "", name)
    # setdefault BEFORE the inner loop, not inside it: a checks.json that parses to an empty list
    # (the suite ran the scenario and asserted nothing) must still leave the scenario NAMED in
    # `scenarios`, or it vanishes from this ledger entirely -- a directory the suite wrote, silently
    # absent from every row below. That is exactly the "executed nothing, read as green" shape this
    # whole bridge exists to refuse.
    entry = scenarios.setdefault(name, [])
    try:
        checks = json.load(open(f, encoding="utf-8"))
    except Exception as e:
        entry.append(("FAILURE", f"checks.json unreadable: {e}"))
        continue
    for c in checks:
        entry.append((c.get("status", "?"), c.get("name") or c.get("id", "?")))

n_checks = sum(len(v) for v in scenarios.values())
n_pass = sum(1 for v in scenarios.values() for s, _ in v if s == "SUCCESS")
print(f"META\t{len(scenarios)}\t{n_checks}\t{n_pass}")
for name in sorted(scenarios):
    checks = scenarios[name]
    failing = [d for s, d in checks if s == "FAILURE"]
    if failing:
        print(f"ROW\t{name}\tFAIL\tfailing check(s): {', '.join(failing)}")
    elif not checks:
        print(f"ROW\t{name}\tFAIL\tthe suite wrote this scenario's directory but checks.json recorded zero checks")
    elif all(s == "SKIPPED" for s, _ in checks):
        print(f"ROW\t{name}\tSKIP\tevery check in this scenario was SKIPPED by the suite")
    else:
        print(f"ROW\t{name}\tPASS\t{len(checks)} check(s), all SUCCESS/WARNING")
PY
)"
  while IFS=$'\t' read -r kind a b c; do
    case "$kind" in
      META) say "   scenarios: $a   checks: $b   checks passing: $c" ;;
      ROW)
        record "mcp.rig|$a" "$b" "MCP official-subject: $a" "$c" >/dev/null
        [ "$b" = SKIP ] || owed_ids="${owed_ids} mcp.rig|$a"
        ;;
    esac
  done <<<"$rows"
}

# ── MCP: H2 gating scenarios (tracker row H2 -- authenticate/verify/admit/meter/audit/exit) ────────
#
# THE GAP THIS CLOSES. qa/teller-steps.json's mcp row named six real gaps: no LEDGERED scenario
# proved the Teller order at those six steps for this plane (the official suite's own scenarios
# cover decode/route, and only those). scripts/mcp-subject/h2-*.sh are the closing scenarios, one
# script per step, each booting its own throwaway busbar (mirroring testing/shadow-oracle/scripts/
# teller-*.sh's isolation for the llm plane) and printing one `PASS\t<detail>` or `FAIL\t<detail>`
# line. This function runs every h2-*.sh next to h2-lib.sh (h2-lib.sh and h2-mock-upstream.mjs are
# helpers, not scenarios, and are excluded by name) and folds each into the SAME `mcp.rig|*` id
# space the official-subject leg above uses, as `mcp.rig|h2-<step>` -- one ledger, one namespace, no
# second row-id convention for this plane.
run_h2_mcp() {
  say ""
  say "== rig: MCP H2 gating scenarios (tracker row H2; subject = busbar) =="
  local dir="${repo}/scripts/mcp-subject" f name status detail
  for f in "$dir"/h2-*.sh; do
    [ "$(basename "$f")" = "h2-lib.sh" ] && continue
    name="$(basename "$f" .sh)"
    detail="$(MCP_SUBJECT_BUSBAR_BIN="$BIN" H2_WORK="${WORK}/mcp-h2-${name}" bash "$f" 2>"${WORK}/mcp-h2-${name}.log")"
    status="$(printf '%s' "$detail" | cut -f1)"
    detail="$(printf '%s' "$detail" | cut -f2-)"
    case "$status" in
      PASS|FAIL) ;;
      *) status="FAIL"; detail="scenario produced no PASS/FAIL verdict line -- see ${WORK}/mcp-h2-${name}.log" ;;
    esac
    record "mcp.rig|${name}" "$status" "MCP H2 gating: ${name}" "$detail" >/dev/null
    owed_ids="${owed_ids} mcp.rig|${name}"
  done
}

# ── A2A: independent battery, subject leg ────────────────────────────────────────────────────────
run_a2a_battery() {
  say ""
  say "== rig: A2A independent battery (subject = busbar) =="
  local report="${repo}/testing/a2a-harness/reports/subject.json"
  rm -f "$report"
  A2A_SUBJECT_BUSBAR_BIN="$BIN" \
    bash "${repo}/scripts/a2a-subject/boot.sh" --battery \
    >"${WORK}/a2a-battery.log" 2>&1 || true
  if [ ! -s "$report" ]; then
    record "a2a.battery|_no_output" FAIL "A2A battery leg produced no reports/subject.json" \
      "see ${WORK}/a2a-battery.log"
    owed_ids="${owed_ids} a2a.battery|_no_output"
    return
  fi
  local rows
  rows="$(python3 - "$report" <<'PY'
import json, sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
results = doc.get("results") or []
# Same outcome grouping a2aht/runner.py uses for its own BAD_OUTCOMES, split three ways for the
# ledger: a real PASS, a real defect (FAIL/ERROR/NOT_CONFIGURED — the harness's own "this makes the
# run red" set), or an outcome that is not a verdict about busbar at all (OBSERVED/INAPPLICABLE).
NOT_A_VERDICT = {"OBSERVED", "INAPPLICABLE"}
n_pass = sum(1 for r in results if r.get("outcome") == "PASS")
print(f"META\t{len(results)}\t{n_pass}")
for r in results:
    rid = r.get("id", "?")
    outcome = str(r.get("outcome", "?"))
    role = r.get("role", "?")
    if outcome == "PASS":
        status = "PASS"
    elif outcome in NOT_A_VERDICT:
        status = "SKIP"
    else:
        status = "FAIL"
    print(f"ROW\t{rid}\t{status}\toutcome={outcome} role={role}")
PY
)"
  while IFS=$'\t' read -r kind a b c; do
    case "$kind" in
      META) say "   battery test ids: $a   PASS: $b" ;;
      ROW)
        record "a2a.battery|$a" "$b" "A2A battery: $a" "$c" >/dev/null
        [ "$b" = SKIP ] || owed_ids="${owed_ids} a2a.battery|$a"
        ;;
    esac
  done <<<"$rows"
}

# ── A2A: H2 gating scenarios (tracker row H2 -- verify/admit/route/meter/audit/exit) ───────────────
#
# Same shape as run_h2_mcp() above, for the sibling plane: scripts/a2a-subject/h2-*.sh (h2-lib.sh and
# h2-mock-agent.mjs are helpers, excluded by name) fold into the SAME `a2a.battery|*` id space the
# independent-battery leg above uses, as `a2a.battery|h2-<step>`.
run_h2_a2a() {
  say ""
  say "== rig: A2A H2 gating scenarios (tracker row H2; subject = busbar) =="
  local dir="${repo}/scripts/a2a-subject" f name status detail
  for f in "$dir"/h2-*.sh; do
    [ "$(basename "$f")" = "h2-lib.sh" ] && continue
    name="$(basename "$f" .sh)"
    detail="$(A2A_SUBJECT_BUSBAR_BIN="$BIN" H2_WORK="${WORK}/a2a-h2-${name}" bash "$f" 2>"${WORK}/a2a-h2-${name}.log")"
    status="$(printf '%s' "$detail" | cut -f1)"
    detail="$(printf '%s' "$detail" | cut -f2-)"
    case "$status" in
      PASS|FAIL) ;;
      *) status="FAIL"; detail="scenario produced no PASS/FAIL verdict line -- see ${WORK}/a2a-h2-${name}.log" ;;
    esac
    record "a2a.battery|${name}" "$status" "A2A H2 gating: ${name}" "$detail" >/dev/null
    owed_ids="${owed_ids} a2a.battery|${name}"
  done
}

# ── A2A: official TCK, subject leg ───────────────────────────────────────────────────────────────
run_a2a_tck() {
  say ""
  say "== rig: A2A official TCK (subject = busbar) =="
  local tckwork="${A2A_TCK_WORK:-${WORK}/a2a-tck-work}"
  rm -rf "${tckwork}/out"
  local waivers="${repo}/testing/a2a-tck/subject-waivers.json"
  A2A_SUBJECT_BUSBAR_BIN="$BIN" A2A_TCK_WORK="$tckwork" \
    bash "${repo}/scripts/a2a-subject/boot.sh" --tck \
    >"${WORK}/a2a-tck.log" 2>&1 || true
  local report="${tckwork}/out/subject.json"
  if [ ! -s "$report" ]; then
    record "a2a.tck|_no_output" FAIL "A2A TCK leg produced no per-requirement report at $report" \
      "see ${WORK}/a2a-tck.log"
    owed_ids="${owed_ids} a2a.tck|_no_output"
    return
  fi
  local rows
  rows="$(python3 - "$report" "$waivers" <<'PY'
import json, sys

report_path, waivers_path = sys.argv[1], sys.argv[2]
report = json.load(open(report_path, encoding="utf-8"))
per = report.get("per_requirement") or {}
must = {k: v for k, v in per.items() if isinstance(v, dict) and v.get("level") == "MUST"}
waived = set((json.load(open(waivers_path, encoding="utf-8")) or {}).get("waived") or [])

n_pass = n_fail = n_skip = 0
print(f"META\t{len(must)}\t{len(waived)}")
for k in sorted(must):
    status_raw = must[k].get("status")
    if status_raw == "PASS":
        status, detail = "PASS", "PASS"
        n_pass += 1
    elif status_raw in ("NOT TESTED", "SKIPPED"):
        status = "SKIP"
        detail = f"{status_raw}: a suite limitation (confirmed identical against the pinned a2a-go " \
                 "control in testing/a2a-tck/baselines/), not evidence about busbar"
        n_skip += 1
    elif status_raw == "FAIL":
        if k in waived:
            status = "SKIP"
            detail = f"FAIL, but WAIVED in {waivers_path} (see WAIVERS.md) -- never counted as PASS"
            n_skip += 1
        else:
            status = "FAIL"
            detail = "FAIL, outside the pinned waiver set"
            n_fail += 1
    else:
        status = "FAIL"
        detail = f"unrecognised requirement status: {status_raw!r}"
        n_fail += 1
    print(f"ROW\t{k}\t{status}\t{detail}")
PY
)"
  while IFS=$'\t' read -r kind a b c; do
    case "$kind" in
      META) say "   MUST requirements: $a   pinned waivers: $b" ;;
      ROW)
        record "a2a.tck|$a" "$b" "A2A TCK MUST requirement: $a" "$c" >/dev/null
        [ "$b" = SKIP ] || owed_ids="${owed_ids} a2a.tck|$a"
        ;;
    esac
  done <<<"$rows"
}

# ── voice: the four-leg battery ──────────────────────────────────────────────────────────────────
run_voice() {
  say ""
  say "== rig: voice conformance battery =="
  local log="${WORK}/voice-results.tsv"
  : >"$log"
  # No busbar binary is threaded through: the voice legs drive their OWN `voice-conform` harness
  # binary built from this tree (testing/voice-conformance/lib/conform-bin.sh), never a server
  # busbar binary. --bin is still required at the top of this script so a caller cannot silently
  # skip the two legs that DO need it by never supplying one.
  VOICE_RESULT_LOG="$log" bash "${repo}/testing/voice-conformance/voice-conformance.sh" --verdict \
    >"${WORK}/voice.log" 2>&1 || true
  if [ ! -s "$log" ]; then
    record "voice.rig|_no_output" FAIL "voice battery produced no VOICE_RESULT_LOG rows" \
      "see ${WORK}/voice.log"
    owed_ids="${owed_ids} voice.rig|_no_output"
    return
  fi
  local rows
  rows="$(python3 - "$log" <<'PY'
import collections, sys

legs = collections.OrderedDict()
for line in open(sys.argv[1], encoding="utf-8"):
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 3:
        continue
    leg, sl = parts[0], parts[1]
    verdict = parts[2]
    detail = parts[3] if len(parts) > 3 else ""
    legs.setdefault(leg, []).append((sl, verdict, detail))

print(f"META\t{len(legs)}")
for leg, entries in legs.items():
    vacuous = [(s, d) for s, v, d in entries if v == "NORESULT"]
    failing = [(s, v) for s, v, _ in entries if v not in ("PASS", "NORESULT")]
    if vacuous:
        status = "FAIL"
        detail = "slice(s) with NO RESULT (vacuous-ready): " + ", ".join(s for s, _ in vacuous)
    elif failing:
        status = "FAIL"
        detail = "failing slice(s): " + ", ".join(f"{s}:{v}" for s, v in failing)
    else:
        status = "PASS"
        detail = f"{len(entries)} slice(s), all PASS"
    print(f"ROW\t{leg}\t{status}\t{detail}")
PY
)"
  while IFS=$'\t' read -r kind a b c; do
    case "$kind" in
      META) say "   legs reported: $a" ;;
      ROW)
        record "voice.rig|$a" "$b" "voice rig leg: $a" "$c" >/dev/null
        owed_ids="${owed_ids} voice.rig|$a"
        ;;
    esac
  done <<<"$rows"
}

run_mcp
run_h2_mcp
run_a2a_battery
run_h2_a2a
run_a2a_tck
run_voice

# ── baseline: rebaseline, or diff against the last sign-off ─────────────────────────────────────
# Uses fold_baseline_regressions(), defined once above (before --selftest, so --selftest drives the
# same function rather than a copy of it).
baseline_owed=""
if [ "$REBASELINE" != 1 ] && [ -s "$BASELINE" ]; then
  say ""
  say "== baseline check against $(basename "$BASELINE") =="
  baseline_rows="$(fold_baseline_regressions "$LEDGER" "$BASELINE")"
  if [ -n "$baseline_rows" ]; then
    while IFS=$'\t' read -r id status title detail; do
      [ -n "$id" ] || continue
      record "baseline|$id" "$status" "$title" "$detail" >/dev/null
      baseline_owed="${baseline_owed} baseline|$id"
    done <<<"$baseline_rows"
  fi
elif [ "$REBASELINE" != 1 ]; then
  say ""
  say "== no baseline at $BASELINE yet -- run with --rebaseline first to sign one off =="
fi

GATE_NAME="plane rigs" EXPECTED_IDS="${owed_ids}${baseline_owed}" LEDGER="$LEDGER" \
  bash "${repo}/testing/fleet-fixtures/verdict.sh"
rc=$?

if [ "$REBASELINE" = 1 ]; then
  python3 - "$LEDGER" "$BASELINE" <<'PY'
import json, sys

ledger_path, baseline_path = sys.argv[1], sys.argv[2]
rows = {}
with open(ledger_path, encoding="utf-8") as f:
    for line in f:
        parts = line.rstrip("\n").split("\t")
        if len(parts) >= 2:
            rows[parts[0]] = parts[1]
with open(baseline_path, "w", encoding="utf-8") as f:
    json.dump({"rows": rows}, f, indent=2, sort_keys=True)
    f.write("\n")
print(f"rebaselined {baseline_path}: {len(rows)} row(s)")
PY
fi

say ""
say "ledger: $LEDGER"
exit "$rc"
