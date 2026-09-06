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
#             [--accepted accepted-differences.json] [--allow-harness-skew]
#             [--baseline owed-baseline.txt] [--accepted-gaps accepted-gaps.json] [--rebaseline]
#             [--no-check-golden]
#
# <out>/  report.json report.md owed.txt owed-gaps.txt diverging.txt ledger.tsv
# Exit non-zero on any divergence, any owed cell missing, or zero rows. Exit 2 (before anything is
# compared) if golden and candidate were not proven to come from the same harness revision — see
# harness-rev.sh — unless --allow-harness-skew is given.
#
# Recorder-shrinks-the-gate guard: the golden itself can quietly stop owing a cell it used to pass
# (moved to SKIP/FAIL, or dropped from cells.json entirely) with nobody noticing, because that cell
# simply leaves the owed set — no red anywhere. owed-baseline.txt is the owed ids as of the last
# sign-off; any of those ids the CURRENT golden no longer owes is RED unless accepted-gaps.json
# names it with an owner and a rationale (same discipline as accepted-differences.json: named,
# never silent). A newly-owed id (coverage grew) is fine and just printed. `--rebaseline` accepts
# the current golden's owed set as the new baseline and rewrites the file.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "${here}/../.." && pwd)"

GOLDEN="" CAND="" OUT="" CELLS="${here}/cells.json" FAMILY="" ACCEPTED="${here}/accepted-differences.json"
ALLOW_SKEW=0 BASELINE="${here}/owed-baseline.txt" ACCEPTED_GAPS="${here}/accepted-gaps.json" REBASELINE=0 CHECK_GOLDEN=1
while [ $# -gt 0 ]; do
  case "$1" in
    --golden) GOLDEN="$2"; shift 2 ;;
    --candidate) CAND="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --cells) CELLS="$2"; shift 2 ;;
    --family) FAMILY="$2"; shift 2 ;;
    --accepted) ACCEPTED="$2"; shift 2 ;;
    --allow-harness-skew) ALLOW_SKEW=1; shift ;;
    --baseline) BASELINE="$2"; shift 2 ;;
    --accepted-gaps) ACCEPTED_GAPS="$2"; shift 2 ;;
    --rebaseline) REBASELINE=1; shift ;;
    --no-check-golden) CHECK_GOLDEN=0; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[ -d "$GOLDEN" ] && [ -d "$CAND" ] && [ -n "$OUT" ] || { echo "usage: $0 --golden <dir> --candidate <dir> --out <dir> [--cells f] [--family re] [--accepted f] [--allow-harness-skew] [--baseline f] [--accepted-gaps f] [--rebaseline] [--no-check-golden]" >&2; exit 2; }
# absolute paths: verdict.sh runs from the repo root, so a relative --out would make it read an empty
# ledger and (correctly) call the run vacuous
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"; GOLDEN="$(cd "$GOLDEN" && pwd)"; CAND="$(cd "$CAND" && pwd)"
[ -s "${GOLDEN}/ledger.tsv" ] || { echo "replay: golden has no ledger.tsv — record it first" >&2; exit 2; }
command -v python3 >/dev/null || { echo "replay.sh needs python3" >&2; exit 2; }

# ── the golden's binary provenance, BEFORE anything is compared ──────────────────────────────────
# diff-cells.py already refuses a pair of recordings that did not come from the same HARNESS
# revision. The other half of "this diff is about busbar" is that the golden came from the binary we
# still believe is the golden binary: meta.json records the sha256 of the file record.sh executed,
# and fetch-golden.sh --check-golden re-hashes the cached release artifact against it. Skipped only
# when the golden names no binary (the tracked selftest fixtures) or this host has no cached golden
# binary at all (exit 5) — replaying two recordings does not require the release on disk. A real
# MISMATCH is fatal: the golden was made by some other build that happens to share a version string.
if [ "$CHECK_GOLDEN" = 1 ] && [ -s "${GOLDEN}/meta.json" ]; then
  gver="$(python3 -c 'import json,sys; print((json.load(open(sys.argv[1])).get("version") or "").replace("busbar ","").strip())' "${GOLDEN}/meta.json" 2>/dev/null || true)"
  gbin="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("binary_sha256") or "")' "${GOLDEN}/meta.json" 2>/dev/null || true)"
  if [ -n "$gver" ] && [ -n "$gbin" ]; then
    cg_out="$(bash "${here}/fetch-golden.sh" --version "$gver" --check-golden "$GOLDEN" 2>&1)"; cg_rc=$?
    case "$cg_rc" in
      0) echo "$cg_out" ;;
      5) echo "replay: golden binary provenance NOT CHECKED on this host (no cached ${gver} binary); comparing anyway" >&2 ;;
      *) echo "$cg_out" >&2
         echo "replay: refusing to compare — the golden on disk was not proven to come from the pinned ${gver} binary. Re-run testing/shadow-oracle/fetch-golden.sh, or pass --no-check-golden if you know why." >&2
         exit 2 ;;
    esac
  fi
fi

mkdir -p "$OUT"
export LEDGER="${OUT}/ledger.tsv"; : >"$LEDGER"
# shellcheck source=../fleet-fixtures/lib.sh
source "${repo}/testing/fleet-fixtures/lib.sh"

diff_args=(--golden "$GOLDEN" --candidate "$CAND" --out "$OUT" --cells "$CELLS" --accepted "$ACCEPTED")
[ -z "$FAMILY" ] || diff_args+=(--family "$FAMILY")
[ "$ALLOW_SKEW" != 1 ] || diff_args+=(--allow-harness-skew)
rows="$(python3 "${here}/diff-cells.py" "${diff_args[@]}")"
rc=$?
if [ "$rc" -ne 0 ]; then
  if [ "$rc" -eq 2 ]; then exit 2; fi   # diff-cells.py already printed the reason to stderr
  echo "replay: diff-cells.py failed" >&2
  exit 1
fi

while IFS=$'\t' read -r id status classes first; do
  [ -n "$id" ] || continue
  record "$id" "$status" "$classes" "$first" >/dev/null
done <<<"$rows"

# ── owed-baseline: the golden must not silently stop owing a cell it used to ─────────────────────
if [ "$REBASELINE" = 1 ]; then
  sort -u "${OUT}/owed.txt" >"$BASELINE"
  echo "rebaselined ${BASELINE}: $(wc -l <"$BASELINE" | tr -d ' ') owed ids"
  baseline_rows=""
elif [ -s "$BASELINE" ]; then
  baseline_rows="$(python3 - "$OUT" "$BASELINE" "$ACCEPTED_GAPS" <<'PY'
import json, os, re, sys

out, baseline_path, gaps_path = sys.argv[1], sys.argv[2], sys.argv[3]


def read_ids(p):
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8") as f:
        return [ln.strip() for ln in f if ln.strip()]


owed = set(read_ids(os.path.join(out, "owed.txt")))
gap_reason = {}
gpath = os.path.join(out, "owed-gaps.txt")
if os.path.exists(gpath):
    with open(gpath, encoding="utf-8") as f:
        for ln in f:
            parts = ln.rstrip("\n").split("\t")
            if parts and parts[0]:
                gap_reason[parts[0]] = "\t".join(parts[1:])
# "scope" is every id this run has an opinion about (owed now, or a named golden gap now). A
# baseline id outside scope (e.g. this run used --family to cover only part of cells.json) is
# neither confirmed nor regressed here — silently skipped, not a false alarm.
scope = owed | set(gap_reason)

accepted = []
if os.path.exists(gaps_path):
    try:
        doc = json.load(open(gaps_path, encoding="utf-8"))
    except Exception as e:
        sys.exit(f"accepted-gaps: {gaps_path} is not valid JSON: {e}")
    for e in doc.get("accepted", []):
        if "owner" not in e or "rationale" not in e or not e.get("cells"):
            sys.exit(f"accepted-gaps: entry {e.get('id', '?')!r} needs cells, owner and rationale — named, never silent")
        accepted.append({"id": e.get("id", e["cells"]), "rx": re.compile(e["cells"]), "owner": e["owner"], "rationale": e["rationale"]})


def find_accept(cid):
    for e in accepted:
        if e["rx"].search(cid):
            return e
    return None


baseline = read_ids(baseline_path)
for cid in sorted(owed - set(baseline)):
    sys.stderr.write(f"owed-baseline: new coverage (not yet in the baseline): {cid}\n")

for cid in baseline:
    if cid not in scope:
        continue
    if cid in owed:
        continue
    reason = gap_reason.get(cid, "no longer present in cells.json")
    e = find_accept(cid)
    if e:
        print(f"{cid}\tPASS\tACCEPTED named gap ({e['id']}, owner {e['owner']}): {e['rationale']}\t{reason}")
    else:
        print(f"{cid}\tFAIL\towed-baseline regression\tgolden no longer owes this id (was PASS at baseline; now: {reason}) — name it in accepted-gaps.json with an owner and rationale, or if intentional run replay.sh --rebaseline")
PY
)"
  brc=$?
  [ "$brc" -eq 0 ] || { echo "replay: owed-baseline check failed" >&2; exit 1; }
else
  baseline_rows=""
fi

baseline_ids=""
if [ -n "$baseline_rows" ]; then
  while IFS=$'\t' read -r id status classes first; do
    [ -n "$id" ] || continue
    record "$id" "$status" "$classes" "$first" >/dev/null
    baseline_ids="${baseline_ids}${id}
"
  done <<<"$baseline_rows"
fi

# ONE ID PER LINE, and the newlines are the point. These ids are cells.json ids, and 84 of them
# contain a space (`…|GET /.well-known/agent-card.json|ok`). Flattened to a space-separated string
# they came apart in the verdict's owed loop into fragments that owe nothing, so the oracle's own
# gate reported hundreds of phantom `did not run` rows. verdict.sh reads a newline-separated owed
# set line by line; keep it that way.
OWED="$(<"${OUT}/owed.txt")"
echo
echo "golden gaps (recorded SKIP/FAIL on the golden, not owed): $(wc -l <"${OUT}/owed-gaps.txt" | tr -d ' ')"
GATE_NAME="shadow oracle vs golden" EXPECTED_IDS="${OWED}
${baseline_ids}" LEDGER="$LEDGER" bash "${repo}/testing/fleet-fixtures/verdict.sh"
rc=$?
echo "report: ${OUT}/report.md"
exit $rc
