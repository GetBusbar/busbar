#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# LLM SPEC CONFORMANCE GATE — vendor the providers' published specs, validate a shadow-oracle
# recording of busbar's LLM plane against them, and decide through the one shared verdict.
#
#   run.sh [--recording <dir>] [--out <dir>] [--cells <cells.json>] [--no-vendor]
#
#   --recording   a testing/shadow-oracle/record.sh output (default target/oracle/recordings/candidate)
#   --out         where ledger.tsv, report.json, report.md, owed.txt, owed-gaps.txt go
#                 (default target/llm-conformance/<basename of recording>)
#   --cells       the cell universe (default testing/shadow-oracle/cells.json)
#   --no-vendor   trust the cache as-is (vendor.sh --check still runs: an absent spec is red)
#
# ONE MECHANISM, THE SAME AS EVERY OTHER GATE HERE: validate.py appends one ledger row per owed
# id and never decides anything; the verdict (testing/fleet-fixtures/verdict.sh) diffs the ledger
# against the ids that were OWED. The owed list is computed HERE from cells.json, independently of
# the validator's own loop, so a cell the validator silently dropped shows up as DID NOT RUN rather
# than as green. Ids the validator recorded as SKIP are named gaps: they are printed, counted, and
# removed from the owed set (a skip is never a pass, and it is never silent either).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "${here}/../.." && pwd)"

RECORDING="${repo}/target/oracle/recordings/candidate" OUT="" CELLS="${repo}/testing/shadow-oracle/cells.json" VENDOR=1
GAPS="${here}/named-gaps.json"
while [ $# -gt 0 ]; do
  case "$1" in
    --recording) RECORDING="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --cells) CELLS="$2"; shift 2 ;;
    --gaps) GAPS="$2"; shift 2 ;;
    --no-vendor) VENDOR=0; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[ -n "$OUT" ] || OUT="${repo}/target/llm-conformance/$(basename "$RECORDING")"
mkdir -p "$OUT"
# Resolve to an absolute path: verdict.sh below `cd`s into its OWN directory before reading
# $LEDGER (so its `awk` can find it regardless of the caller's cwd), which silently turns a
# relative --out into a nonexistent path once verdict.sh has cd'ed away -- the ledger.tsv this
# very script just populated then reads as 0 lines and the whole run reports a false VACUOUS RUN,
# even though every row above passed. Absolutizing here (once, right after mkdir -p guarantees the
# directory exists) keeps every downstream consumer of $OUT/$LEDGER correct regardless of cwd.
OUT="$(cd "$OUT" && pwd)"
export LEDGER="${OUT}/ledger.tsv"
: >"$LEDGER"

echo "═══ LLM SPEC CONFORMANCE ═══"
echo "recording: ${RECORDING}"
echo "out:       ${OUT}"
echo

# 1. the specs, pinned by digest (network only for what the cache lacks)
if [ "$VENDOR" -eq 1 ]; then
  bash "${here}/vendor.sh" || { echo "run: specs could not be vendored/verified; nothing was validated" >&2; exit 1; }
else
  bash "${here}/vendor.sh" --check || { echo "run: spec cache incomplete (--no-vendor); nothing was validated" >&2; exit 1; }
fi
echo

# 2. validate: one row per cell x direction. Its exit code is NOT the verdict; the ledger is.
python3 "${here}/validate.py" --recording "$RECORDING" --out "$OUT" --cells "$CELLS" --ledger "$LEDGER" >"${OUT}/validate.log" 2>&1
vrc=$?
grep -v '^::' "${OUT}/validate.log" | grep -E '^(FAIL|SKIP) ' -A1 || true
[ "$vrc" -eq 0 ] || { echo; echo "validate.py exit ${vrc}:"; tail -5 "${OUT}/validate.log"; }
echo

# 3. owed = every llm cell x direction (from cells.json, independent of the validator's loop),
#    minus the ids the validator named as gaps (SKIP rows).
python3 "${here}/validate.py" --owed --cells "$CELLS" >"${OUT}/owed-all.txt"
awk -F'\t' '$2=="SKIP"{print $1}' "$LEDGER" | sort -u >"${OUT}/owed-gaps.txt"
sort -u "${OUT}/owed-all.txt" | comm -23 - "${OUT}/owed-gaps.txt" >"${OUT}/owed.txt"
OWED="$(tr '\n' ' ' <"${OUT}/owed.txt")"
echo "owed ids: $(wc -l <"${OUT}/owed.txt" | tr -d ' ')   named gaps (SKIP, not owed): $(wc -l <"${OUT}/owed-gaps.txt" | tr -d ' ')"
if [ -s "${OUT}/owed-gaps.txt" ]; then
  echo "named gaps:"
  while IFS= read -r gid; do
    printf '  %-56s %s\n' "$gid" "$(awk -F'\t' -v i="$gid" '$1==i{print $4; exit}' "$LEDGER")"
  done <"${OUT}/owed-gaps.txt"
fi

# 3b. THE GAPS ARE THE ONES THAT WERE DECLARED, IN THE NUMBER THAT WAS DECLARED. Step 3 takes every
# SKIP id OUT of the owed set — which is right (a skip is never a pass, so it must not be judged as
# one) and is also precisely how a gap hides: an id that stops being checked stops being counted,
# and a run that verified one thing fewer reads exactly as green as a run that verified one more.
# The only thing that was ever asserted about them was that they got printed. So they are reconciled
# against named-gaps.json here: each observed gap must be named by an entry (with an owner and a
# rationale), each must carry its own reason on its own row, and the count must be the declared one.
# The result is a LEDGER ROW like every other check, added to the owed set, so it is the single
# verdict below that decides — and so this reconciliation failing to run is itself DID NOT RUN.
#
# The row is only added when the VALIDATOR wrote at least one row of its own. "Zero rows is red" is
# the guard the verdict opens with, and it counts rows in the ledger — so a row appended here by the
# gate's own bookkeeping would be the one row that makes a run which judged NOTHING stop looking
# vacuous. A run with no validator rows is already RED for the better reason; this check has nothing
# to reconcile there and must not be what answers for it.
GAP_ID="gate|llm-conformance|named-gaps"
if [ "$(awk 'NF{n++} END{print n+0}' "$LEDGER")" -gt 0 ]; then
python3 - "$GAPS" "${OUT}/owed-gaps.txt" "$LEDGER" "$GAP_ID" <<'PY'
import json, re, sys
gaps_path, observed_path, ledger_path, rid = sys.argv[1:5]

def record(status, title, detail=""):
    clean = lambda s: str(s).replace("\t", " ").replace("\n", " ")
    with open(ledger_path, "a") as f:
        f.write(f"{rid}\t{status}\t{clean(title)}\t{clean(detail)}\n")
    print(f"{status}  {rid}  {title}" + (f"\n      {detail}" if detail else ""))
    if status != "PASS":
        print(f"::error title=llm-spec named gaps::{clean(title)} — {clean(detail)}")

title = "named gaps are the declared ones, in the declared number"
try:
    with open(gaps_path) as f:
        doc = json.load(f)
except (OSError, ValueError) as e:
    record("FAIL", title, f"{gaps_path} could not be read: {e} — the gate cannot tell a known gap from a new one")
    sys.exit(0)

entries = doc.get("accepted") or []
for e in entries:
    if not all(e.get(k) for k in ("cells", "owner", "rationale")):
        record("FAIL", title, f"entry {e.get('cells', '?')!r} needs cells, owner and rationale — a gap with no owner is a gap nobody is fixing")
        sys.exit(0)

with open(observed_path) as f:
    observed = [ln.strip() for ln in f if ln.strip()]

reasons = {}
with open(ledger_path) as f:
    for ln in f:
        p = ln.rstrip("\n").split("\t")
        if len(p) >= 4 and p[1] == "SKIP":
            reasons[p[0]] = p[3].strip()

problems = []
for gid in observed:
    if not any(re.search(e["cells"], gid) for e in entries):
        problems.append(f"{gid} is a gap NO entry names (reason on the row: {reasons.get(gid, '(none)')!r})")
    elif not reasons.get(gid):
        problems.append(f"{gid} is a gap whose own row carries no reason")
note = ""
expected = doc.get("expected")
if not isinstance(expected, int):
    problems.append(f"'expected' must be the number of gaps allowed, got {expected!r}")
elif len(observed) > expected:
    # A count as well as the naming above, because a NEW gap can fall inside an EXISTING entry's
    # regex — same name, one more thing unverified — and the naming alone would not see it.
    problems.append(f"{len(observed)} gap(s) observed, {expected} declared — a gap that is not in the count is a gap that hid")
elif len(observed) < expected:
    # Coverage GROWING is never red (same rule as testing/shadow-oracle/accepted-gaps.json): a gap
    # that closed is the outcome this file exists to drive towards. It is printed, not punished,
    # and the declared number should come down with it.
    note = f" — {expected - len(observed)} declared gap(s) did not occur; lower 'expected' in {gaps_path} to hold the new floor"

if problems:
    record("FAIL", title, "; ".join(problems))
else:
    record("PASS", title, f"{len(observed)} gap(s) of at most {expected}, each named by {gaps_path}{note}")
PY
# Appended with a SPACE, never a newline: verdict.sh splits the owed list on newlines the moment it
# contains one, so a single trailing newline here would turn the whole space-separated list into one
# unmatchable id and every real row into DID NOT RUN. No id in this gate contains a space.
OWED="${OWED} ${GAP_ID}"
echo "$GAP_ID" >>"${OUT}/owed.txt"
fi
[ -f "${OUT}/report.md" ] && { echo; sed -n '1,200p' "${OUT}/report.md"; }
echo

# 4. the verdict — the ONLY place anything is decided
GATE_NAME="llm spec conformance" EXPECTED_IDS="$OWED" LEDGER="$LEDGER" bash "${repo}/testing/fleet-fixtures/verdict.sh"
