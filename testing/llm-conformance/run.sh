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
#   --named-gaps  the named-conformance-gap register (default named-gaps.json)
#   --no-vendor   trust the cache as-is (vendor.sh --check still runs: an absent spec is red)
#
# ONE MECHANISM, THE SAME AS EVERY OTHER GATE HERE: validate.py appends one ledger row per owed
# id and never decides anything; the verdict (testing/fleet-fixtures/verdict.sh) diffs the ledger
# against the ids that were OWED. The owed list is computed HERE from cells.json, independently of
# the validator's own loop, so a cell the validator silently dropped shows up as DID NOT RUN rather
# than as green. Ids the validator recorded as SKIP are named gaps: they are printed, counted, and
# removed from the owed set (a skip is never a pass, and it is never silent either).
#
# A third row class sits beside them: GAP — a row that WAS judged against the pinned document and
# failed on exactly the violation an owner-registered entry in named-gaps.json names (a documented
# provider frame the published spec's schema omits). A gap is reported in its own column, kept out
# of the owed set like a skip, counted by the verdict, and never called a pass. The register itself
# is owed: every entry gets a `named-gap|<id>` row that is RED if it went stale or never fired.
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
    --named-gaps) GAPS="$2"; shift 2 ;;
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
python3 "${here}/validate.py" --recording "$RECORDING" --out "$OUT" --cells "$CELLS" --ledger "$LEDGER" --named-gaps "$GAPS" >"${OUT}/validate.log" 2>&1
vrc=$?
grep -v '^::' "${OUT}/validate.log" | grep -E '^(FAIL|SKIP|GAP) ' -A1 || true
[ "$vrc" -eq 0 ] || { echo; echo "validate.py exit ${vrc}:"; tail -5 "${OUT}/validate.log"; }
echo

# 3. owed = every llm cell x direction (from cells.json, independent of the validator's loop),
#    minus the ids the validator named as gaps (SKIP rows).
#    minus the ids the validator classified as named conformance gaps (GAP rows), PLUS one owed id
#    per entry in the register — an entry that went stale or never fired owes a red row of its own.
python3 "${here}/validate.py" --owed --cells "$CELLS" >"${OUT}/owed-all.txt"
python3 "${here}/named_gaps.py" --ids --gaps "$GAPS" --cells "$CELLS" >>"${OUT}/owed-all.txt" \
  || { echo "run: the named-gap register ${GAPS} is malformed; nothing may be judged against it" >&2; exit 1; }
# Print the whole register's state, in scope or not: an entry the run's cell universe never reaches
# owes nothing here, and saying so out loud is how a regex that stopped matching anything is noticed.
echo "named-gap register ($GAPS):"
python3 "${here}/named_gaps.py" --check --gaps "$GAPS" --cells "$CELLS" | sed 's/^/  /'
awk -F'\t' '$2=="SKIP"{print $1}' "$LEDGER" | sort -u >"${OUT}/owed-gaps.txt"
awk -F'\t' '$2=="GAP"{print $1}' "$LEDGER" | sort -u >"${OUT}/named-gap-rows.txt"
sort -u "${OUT}/owed-all.txt" | comm -23 - "${OUT}/owed-gaps.txt" | comm -23 - "${OUT}/named-gap-rows.txt" >"${OUT}/owed.txt"
# ONE ID PER LINE, not space-separated: the register's own owed ids (`named-gap|<id>`) carry the
# entry's human name, spaces and all, and a one-line list would split each of them into three
# "probes that did not run". verdict.sh splits a list containing newlines on newlines only.
OWED="$(cat "${OUT}/owed.txt")"
GAP_ROWS="$(tr '\n' ' ' <"${OUT}/named-gap-rows.txt")"
echo "owed ids: $(wc -l <"${OUT}/owed.txt" | tr -d ' ')   named gaps (SKIP, not owed): $(wc -l <"${OUT}/owed-gaps.txt" | tr -d ' ')   named conformance gaps (GAP, not owed): $(wc -l <"${OUT}/named-gap-rows.txt" | tr -d ' ')"
if [ -s "${OUT}/owed-gaps.txt" ]; then
  echo "named gaps:"
  while IFS= read -r gid; do
    printf '  %-56s %s\n' "$gid" "$(awk -F'\t' -v i="$gid" '$1==i{print $4; exit}' "$LEDGER")"
  done <"${OUT}/owed-gaps.txt"
fi
if [ -s "${OUT}/named-gap-rows.txt" ]; then
  echo "named conformance gaps (registered in $(basename "$GAPS")):"
  while IFS= read -r gid; do
    printf '  %-56s %s\n' "$gid" "$(awk -F'\t' -v i="$gid" '$1==i{print $4; exit}' "$LEDGER")"
  done <"${OUT}/named-gap-rows.txt"
fi
[ -f "${OUT}/report.md" ] && { echo; sed -n '1,200p' "${OUT}/report.md"; }
echo

# 4. the verdict — the ONLY place anything is decided
GATE_NAME="llm spec conformance" EXPECTED_IDS="$OWED" GAP_IDS="$GAP_ROWS" LEDGER="$LEDGER" \
  bash "${repo}/testing/fleet-fixtures/verdict.sh"
