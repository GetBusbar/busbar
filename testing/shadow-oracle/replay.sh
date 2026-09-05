#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# The shadow oracle REPLAYER: diff a candidate recording against the golden, cell by cell, and give
# ONE verdict through the same ledger inversion as every other gate in this tree
# (testing/fleet-fixtures/lib.sh + verdict.sh): every owed cell writes exactly one ledger row, and
# verdict.sh is the only place anything is decided. A cell the golden recorded that the candidate
# did not is DID NOT RUN — red in its own column, never green by silence.
#
#   replay.sh --golden <dir> --candidate <dir> --out <dir> [--cells cells.json] [--family <regex>]
#
# <out>/  report.json report.md owed.txt owed-gaps.txt diverging.txt ledger.tsv
# Exit non-zero on any divergence, any owed cell missing, or zero rows.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "${here}/../.." && pwd)"

GOLDEN="" CAND="" OUT="" CELLS="${here}/cells.json" FAMILY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --golden) GOLDEN="$2"; shift 2 ;;
    --candidate) CAND="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --cells) CELLS="$2"; shift 2 ;;
    --family) FAMILY="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[ -d "$GOLDEN" ] && [ -d "$CAND" ] && [ -n "$OUT" ] || { echo "usage: $0 --golden <dir> --candidate <dir> --out <dir> [--cells f] [--family re]" >&2; exit 2; }
# absolute paths: verdict.sh runs from the repo root, so a relative --out would make it read an empty
# ledger and (correctly) call the run vacuous
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"; GOLDEN="$(cd "$GOLDEN" && pwd)"; CAND="$(cd "$CAND" && pwd)"
[ -s "${GOLDEN}/ledger.tsv" ] || { echo "replay: golden has no ledger.tsv — record it first" >&2; exit 2; }
command -v python3 >/dev/null || { echo "replay.sh needs python3" >&2; exit 2; }

mkdir -p "$OUT"
export LEDGER="${OUT}/ledger.tsv"; : >"$LEDGER"
# shellcheck source=../fleet-fixtures/lib.sh
source "${repo}/testing/fleet-fixtures/lib.sh"

rows="$(python3 "${here}/diff-cells.py" --golden "$GOLDEN" --candidate "$CAND" --out "$OUT" --cells "$CELLS" ${FAMILY:+--family "$FAMILY"})" \
  || { echo "replay: diff-cells.py failed" >&2; exit 1; }

while IFS=$'\t' read -r id status classes first; do
  [ -n "$id" ] || continue
  record "$id" "$status" "$classes" "$first" >/dev/null
done <<<"$rows"

OWED="$(tr '\n' ' ' <"${OUT}/owed.txt")"
echo
echo "golden gaps (recorded SKIP/FAIL on the golden, not owed): $(wc -l <"${OUT}/owed-gaps.txt" | tr -d ' ')"
GATE_NAME="shadow oracle vs golden" EXPECTED_IDS="$OWED" LEDGER="$LEDGER" bash "${repo}/testing/fleet-fixtures/verdict.sh"
rc=$?
echo "report: ${OUT}/report.md"
exit $rc
