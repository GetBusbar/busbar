#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Merge a store-cell recording artifact into the committed golden. RUN BY A HUMAN, LOCALLY.
#
#   import-store-cells.sh <artifact-dir> [--golden <dir>]
#   import-store-cells.sh --selftest
#
# THE LOOP THIS CLOSES. `plugins.store-persist|store-{postgres,mysql,valkey}` need a real durable
# backend. The golden was recorded on a laptop, so two of the three read `SKIP … named gap`, and a
# gap on the golden side makes the candidate's own recording of them unfalsifiable: the differ has
# nothing to compare. `.github/workflows/oracle-record-store-cells.yml` records the three from the
# PUBLISHED 1.5.5 binary against the same pinned backends ci.yml's shadow-oracle job uses, and
# uploads them. It cannot write the golden — a gate that rewrites its own reference is not a gate —
# so this script is the human's half: merge, re-stamp, PRINT THE DIFF, and stop.
#
# IT DOES NOT COMMIT, AND THAT IS THE POINT. Accepting bytes into the reference is a review. The
# script leaves the working tree dirty and prints what changed; `git add`/`git commit` are the
# operator's, under the operator's name, after they have read it.
#
# ── WHAT IT REFUSES, AND WHY EACH REFUSAL IS ITS OWN CHECK ──────────────────────────────────────
#
# A ROW THAT IS NOT `PASS`. A `SKIP` row in the artifact means the recorder did not see the backend
# and named the gap instead. Importing it would write the gap back over the golden while the merge
# note said three cells had been recorded — the artifact would document its own failure as a
# success. Checked here, and not only in the workflow, because this script must be safe against an
# artifact from a run that was never green.
#
# A FOREIGN `binary_sha256`. The golden is the answer to "what did THIS binary do". A recording made
# by a different build that happens to share the version string is a different question, and merging
# it produces a golden whose cells came from two binaries with nothing saying so.
# merge-recordings.py refuses this too; it is checked FIRST here so the operator gets a message
# about their artifact rather than one about a merge they did not know they had started.
#
# A HARNESS OR HOST SKEW IS *NOT* REFUSED — it is recorded. The artifact is recorded on
# `x86_64-unknown-linux-gnu` and the golden on `aarch64-apple-darwin`; the harness moves whenever
# cells.json or the normalizer does. Both are reportable rather than fatal (see merge-recordings.py),
# so this script passes --allow-harness-skew and --allow-host-skew WITH a note naming which cells
# came from where. The binary sha must still match either way: a different host recording the same
# bytes is fine, a different binary is not.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

STORE_CELL_IDS=(
  "plugins.store-persist|store-postgres"
  "plugins.store-persist|store-mysql"
  "plugins.store-persist|store-valkey"
)

die() { printf 'import-store-cells: %s\n' "$*" >&2; exit 1; }

# The id as it appears in a cell FILENAME: record.sh writes `cells/<id with | -> __>.json`.
cell_file() { printf '%s.json' "${1//|/__}"; }

# ── THE IMPORT ───────────────────────────────────────────────────────────────────────────────────
# Split out as a function so --selftest drives THE SAME code the operator runs. A self-test that
# re-implements the check it is testing proves only that two copies agree.
import_artifact() {  # import_artifact <artifact-dir> <golden-dir> <scratch-dir>
  local art="$1" golden="$2" scratch="$3" id verdict rows

  [ -d "$art" ] || die "no such artifact directory: $art"
  [ -f "$art/meta.json" ] || die "$art has no meta.json; that is not a recording"
  [ -f "$art/ledger.tsv" ] || die "$art has no ledger.tsv; that is not a recording"
  [ -f "$golden/meta.json" ] || die "$golden has no meta.json; that is not a golden"

  # ── the three ids, all PASS, and nothing else ──────────────────────────────────────────────────
  rows=$(awk -F'\t' 'NF' "$art/ledger.tsv" | wc -l | tr -d ' ')
  [ "$rows" = "${#STORE_CELL_IDS[@]}" ] \
    || die "the artifact carries ${rows} ledger rows; this import accepts exactly ${#STORE_CELL_IDS[@]} (the store cells and nothing else)"
  for id in "${STORE_CELL_IDS[@]}"; do
    verdict="$(awk -F'\t' -v id="$id" '$1==id{print $2; exit}' "$art/ledger.tsv")"
    case "$verdict" in
      PASS) ;;
      "")   die "the artifact has no row for ${id}; it is not the recording this import is for" ;;
      *)    die "${id} is ${verdict} in the artifact, not PASS — a recording that named a gap must not be written over the golden ($(awk -F'\t' -v id="$id" '$1==id{print $3; exit}' "$art/ledger.tsv"))" ;;
    esac
    [ -f "$art/cells/$(cell_file "$id")" ] \
      || die "${id} says PASS but has no cell file; the artifact is not whole"
  done

  # ── the same binary, or nothing ────────────────────────────────────────────────────────────────
  local gsha asha gver aver
  gsha="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("binary_sha256",""))' "$golden/meta.json")"
  asha="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("binary_sha256",""))' "$art/meta.json")"
  gver="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("version",""))' "$golden/meta.json")"
  aver="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("version",""))' "$art/meta.json")"
  [ -n "$asha" ] || die "the artifact's meta.json carries no binary_sha256; an unproven recording"
  [ "$asha" = "$gsha" ] \
    || die "the artifact was recorded by a DIFFERENT binary than the golden — artifact ${asha}, golden ${gsha}. Same version string is not the same bytes; refusing."
  [ "$aver" = "$gver" ] \
    || die "the artifact records ${aver} and the golden records ${gver}; a golden holds one version"

  # ── rebaseline: the three ids leave the golden before the recording enters ─────────────────────
  # merge-recordings.py demands DISJOINT parts, which is the rule that stops a merged ledger holding
  # two verdicts for one cell. The golden already carries a row for each of these three (a PASS for
  # any that a laptop could do, a SKIP naming the gap for the rest), so the rows and any cell file
  # are removed from the golden's copy FIRST. That removal is the "rebaseline": the golden stops
  # asserting anything about these three, and the artifact is then the only thing that does.
  rm -rf "$scratch"
  mkdir -p "$scratch"
  cp -R "$golden" "$scratch/base"
  for id in "${STORE_CELL_IDS[@]}"; do
    rm -f "$scratch/base/cells/$(cell_file "$id")"
  done
  python3 - "$scratch/base" "${STORE_CELL_IDS[@]}" <<'PY'
import json, os, sys
base, ids = sys.argv[1], set(sys.argv[2:])
led = os.path.join(base, "ledger.tsv")
kept = [l for l in open(led, encoding="utf-8") if l.split("\t", 1)[0] not in ids]
open(led, "w", encoding="utf-8").writelines(kept)
# `recorded` counts PASS rows. Dropping a PASS row and leaving the count alone would hand
# merge-recordings.py a part that says it holds one more cell than it does, and the merged total
# would be wrong by exactly the number of store cells the laptop HAD managed to record — the one
# arithmetic error nobody would think to look for.
npass = sum(1 for l in kept if l.split("\t")[1:2] == ["PASS"])
ncell = len(os.listdir(os.path.join(base, "cells")))
if npass != ncell:
    sys.exit(f"import-store-cells: after the rebaseline the golden has {npass} PASS rows and "
             f"{ncell} cell files; refusing to merge a part that does not describe itself")
m = json.load(open(os.path.join(base, "meta.json")))
m["recorded"] = npass
json.dump(m, open(os.path.join(base, "meta.json"), "w"), indent=2, ensure_ascii=False)
open(os.path.join(base, "meta.json"), "a").write("\n")
print(f"rebaselined: the golden minus the store cells holds {npass} PASS cells")
PY

  # ── merge ──────────────────────────────────────────────────────────────────────────────────────
  local note
  note="STORE CELLS IMPORTED $(date -u +%Y-%m-%d) from .github/workflows/oracle-record-store-cells.yml: \
$(printf '%s, ' "${STORE_CELL_IDS[@]}" | sed 's/, $//') were re-recorded from the SAME published \
binary (${asha:0:8}...) against the service containers testing/fleet-fixtures/service-images.tsv \
pins — the same pin ci.yml's shadow-oracle job records the CANDIDATE side against, which is what \
makes the two sides comparable. HOST SKEW IS EXPECTED AND IS THE REASON THIS EXISTS: these three \
cells boot a real Postgres, MySQL and Valkey, which the darwin host the rest of the golden was \
recorded on does not have, so they came off a linux runner while every other cell did not. HARNESS \
SKEW: the recording tree and the golden's tree are both named in harness_rev_history below. No cell \
was hand-edited and no cell outside these three was touched."
  python3 "${here}/merge-recordings.py" \
    --out "$scratch/merged" \
    --allow-harness-skew \
    --allow-host-skew \
    --note "$note" \
    --cells "${here}/cells.json" \
    "$scratch/base" "$art" || die "merge-recordings.py refused the merge"

  # ── write it back ──────────────────────────────────────────────────────────────────────────────
  # cells/, ledger.tsv and meta.json only. `raw/` is not checked into the golden (and is not in the
  # artifact either — it holds live minted key material), so it is not written here.
  rm -rf "${golden:?}/cells"
  cp -R "$scratch/merged/cells" "$golden/cells"
  cp "$scratch/merged/ledger.tsv" "$golden/ledger.tsv"
  cp "$scratch/merged/meta.json" "$golden/meta.json"
  python3 -c 'import json,sys;m=json.load(open(sys.argv[1]));print("imported: %d recorded cells, harness_rev %s, host %s" % (m["recorded"], m["harness_rev"][:12], m["host_triple"]))' "$golden/meta.json"
}

# ── SELFTEST ─────────────────────────────────────────────────────────────────────────────────────
# Over a FIXTURE golden and FIXTURE artifacts, never the real tree: a self-test that rewrote the
# committed golden to prove it could would be the exact accident this script is careful about.
selftest() {
  local w failed=0
  w="$(mktemp -d)"
  ok()  { printf '  ok    %s\n' "$1"; }
  bad() { printf '  FAIL  %s\n' "$1"; failed=1; }

  # A minimal but REAL golden: one unrelated PASS cell, plus the three store rows in the shape the
  # committed golden has them (one PASS that a laptop managed, two SKIPs naming the gap).
  local sha="deadbeef$(printf 'a%.0s' {1..56})"
  mkdir -p "$w/golden/cells"
  printf '{"status":200,"applied":[]}' >"$w/golden/cells/self__a__ok.json"
  printf '{"status":200,"applied":[]}' >"$w/golden/cells/plugins.store-persist__store-postgres.json"
  {
    printf 'self|a|ok\tPASS\tfixture\t\n'
    printf 'plugins.store-persist|store-postgres\tPASS\tscript store-persist.sh: status 0\t\n'
    printf 'plugins.store-persist|store-mysql\tSKIP\tUNSUPPORTED\tnamed gap\n'
    printf 'plugins.store-persist|store-valkey\tSKIP\tUNSUPPORTED\tnamed gap\n'
  } >"$w/golden/ledger.tsv"
  python3 - "$w/golden/meta.json" "$sha" <<'PY'
import json, sys
json.dump({"binary": "<oracle-cache>/1.5.5/busbar", "version": "busbar 1.5.5", "recorded": 2,
           "binary_sha256": sys.argv[2], "harness_rev": "a" * 64,
           "host_triple": "aarch64-apple-darwin", "at": "2026-09-06T18:10:32Z"},
          open(sys.argv[1], "w"), indent=2)
PY

  # A good artifact: the three ids, all PASS, same binary, a different host and harness.
  make_artifact() {  # make_artifact <dir> <binary-sha> <postgres-verdict>
    local d="$1" s="$2" v="$3"
    mkdir -p "$d/cells"
    printf 'plugins.store-persist|store-postgres\t%s\tscript store-persist.sh: status 0\t\n' "$v" >"$d/ledger.tsv"
    printf 'plugins.store-persist|store-mysql\tPASS\tscript store-persist.sh: status 0\t\n' >>"$d/ledger.tsv"
    printf 'plugins.store-persist|store-valkey\tPASS\tscript store-persist.sh: status 0\t\n' >>"$d/ledger.tsv"
    printf '{"status":200,"applied":[]}' >"$d/cells/plugins.store-persist__store-postgres.json"
    printf '{"status":200,"applied":[]}' >"$d/cells/plugins.store-persist__store-mysql.json"
    printf '{"status":200,"applied":[]}' >"$d/cells/plugins.store-persist__store-valkey.json"
    python3 - "$d/meta.json" "$s" <<'PY'
import json, sys
json.dump({"binary": "<oracle-cache>/1.5.5/busbar", "version": "busbar 1.5.5", "recorded": 3,
           "binary_sha256": sys.argv[2], "harness_rev": "b" * 64,
           "host_triple": "x86_64-unknown-linux-gnu", "at": "2026-09-07T04:00:00Z"},
          open(sys.argv[1], "w"), indent=2)
PY
  }

  echo "import-store-cells selftest: what the import refuses, and what it accepts"

  # (a) a non-PASS row is REFUSED. The whole failure this guards: a run whose backend never came up
  #     names a gap, and importing the gap writes the golden's own blind spot back over itself while
  #     the artifact's notes claim three recordings.
  make_artifact "$w/art-skip" "$sha" SKIP
  # In a SUBSHELL, so a refusal's `exit` ends the attempt and not the self-test. The file writes an
  # import makes are still real — which is exactly what case (c) below then checks.
  if ( import_artifact "$w/art-skip" "$w/golden" "$w/s1" ) >"$w/skip.log" 2>&1; then
    bad "a SKIP row was ACCEPTED"
  elif grep -q 'is SKIP in the artifact, not PASS' "$w/skip.log"; then
    ok "a non-PASS row is refused, naming the cell and its verdict"
  else
    bad "a SKIP row was refused for the wrong reason: $(tail -1 "$w/skip.log")"
  fi

  # (b) a FOREIGN binary sha is REFUSED. Same version string, different bytes: the golden would hold
  #     cells from two binaries and nothing would say so.
  make_artifact "$w/art-foreign" "cafe1234$(printf 'b%.0s' {1..56})" PASS
  if ( import_artifact "$w/art-foreign" "$w/golden" "$w/s2" ) >"$w/foreign.log" 2>&1; then
    bad "a foreign binary_sha256 was ACCEPTED"
  elif grep -q 'recorded by a DIFFERENT binary' "$w/foreign.log"; then
    ok "a foreign binary_sha256 is refused, naming both digests"
  else
    bad "a foreign sha was refused for the wrong reason: $(tail -1 "$w/foreign.log")"
  fi

  # (c) NEITHER REFUSAL TOUCHED THE GOLDEN. A check that refuses AFTER writing is not a refusal.
  if [ "$(cat "$w/golden/ledger.tsv" | wc -l | tr -d ' ')" = 4 ] \
     && [ "$(ls "$w/golden/cells" | wc -l | tr -d ' ')" = 2 ]; then
    ok "a refused import left the golden exactly as it found it"
  else
    bad "a refused import modified the golden"
  fi

  # (d) the good artifact IS accepted, the three ids are rebaselined onto the recording, and the
  #     count is the arithmetic it should be: 2 recorded - 1 store PASS removed + 3 = 4.
  make_artifact "$w/art-good" "$sha" PASS
  if ( import_artifact "$w/art-good" "$w/golden" "$w/s3" ) >"$w/good.log" 2>&1; then
    local rec cells
    rec="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["recorded"])' "$w/golden/meta.json")"
    cells="$(ls "$w/golden/cells" | wc -l | tr -d ' ')"
    if [ "$rec" = 4 ] && [ "$cells" = 4 ]; then
      ok "a good artifact merges: 4 recorded cells, 4 cell files, the three store ids rebaselined"
    else
      bad "a good artifact merged to recorded=${rec}, cells=${cells}, want 4/4"
    fi
    if grep -q 'HOST SKEW ALLOWED' "$w/good.log" && grep -q 'HARNESS SKEW ALLOWED' "$w/good.log"; then
      ok "the skew is REPORTED on the way through, not silently accepted"
    else
      bad "a skewed merge said nothing about its skew"
    fi
  else
    bad "a good artifact was refused: $(tail -3 "$w/good.log")"
  fi

  rm -rf "$w"
  if [ "$failed" = 0 ]; then
    echo "import-store-cells selftest: both refusals hold, and a good artifact still merges"
    return 0
  fi
  echo "import-store-cells selftest: RED"
  return 1
}

# ── ENTRY ────────────────────────────────────────────────────────────────────────────────────────
GOLDEN="${here}/golden/1.5.5"
ART=""
while [ $# -gt 0 ]; do
  case "$1" in
    --selftest) selftest; exit $? ;;
    --golden) GOLDEN="$2"; shift 2 ;;
    -h|--help) sed -n '5,8p' "$0"; exit 0 ;;
    -*) die "unknown argument: $1" ;;
    *) ART="$1"; shift ;;
  esac
done
[ -n "$ART" ] || die "usage: import-store-cells.sh <artifact-dir> [--golden <dir>]   (or --selftest)"

# The artifact as downloaded may be the workflow's `merged/` tree or the directory `gh run download`
# unpacked it into; accept either rather than making the operator guess.
if [ ! -f "$ART/meta.json" ] && [ -f "$ART/merged/meta.json" ]; then
  ART="$ART/merged"
fi

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
import_artifact "$ART" "$GOLDEN" "$SCRATCH/work"

echo
echo "── the diff this import produced ────────────────────────────────────────────────────────────"
echo "NOTHING IS COMMITTED. Read it, then commit it yourself if it is what you meant to accept."
echo
git -C "$(cd "${here}/../.." && pwd)" --no-pager diff --stat -- "${GOLDEN#"$(cd "${here}/../.." && pwd)/"}" || true
echo
git -C "$(cd "${here}/../.." && pwd)" --no-pager diff -- "${GOLDEN#"$(cd "${here}/../.." && pwd)/"}/ledger.tsv" || true
