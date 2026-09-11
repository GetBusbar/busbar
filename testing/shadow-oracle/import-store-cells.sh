#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Merge a `oracle record store cells` artifact into the committed golden.
#
# THE PROBLEM THIS EXISTS FOR. Three cells — plugins.store-persist|store-{postgres,mysql,valkey} —
# need a live backend. Nothing but CI has all three, CI is x86_64-unknown-linux-gnu, and the
# committed golden was recorded on aarch64-apple-darwin. So the cells cannot be recorded where the
# golden lives, and the recording that CAN make them is of a different file: the same published
# 1.5.5 release, a different per-triple build of it.
#
# WHAT MAKES THAT SAFE. Not that the hosts differ — `--allow-host-skew` is about which machine
# recorded, and has never been allowed to relax which build ran. What makes it safe is that BOTH
# digests are pinned: each is a `busbar-<triple>` row in golden-digests.tsv, the table fetch-golden.sh
# verifies every download and every cache hit against. That is the merge identity the tool enforces
# under `--pinned-binaries`, and this script's job is to name the table and then get out of the way.
# An unpinned digest is refused by the tool, not by a check here, because a rule enforced in two
# places is a rule that can disagree with itself.
#
# IT DOES NOT COMMIT. Accepting a golden is a review: this prints the diff and stops. The one thing
# it will never do is edit a golden cell file, which is the failure mode the shadow oracle exists to
# make unnecessary.
#
#   testing/shadow-oracle/import-store-cells.sh <artifact-dir> [--yes]
#
# <artifact-dir> is the tree `gh run download` produced, or the directory inside it: either the
# artifact root or the single `oracle-store-cells-<run-id>/` beneath it is accepted.
set -euo pipefail

# This file lives at testing/shadow-oracle/, so the repo root is two levels up, not one.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
data="$here/testing/shadow-oracle"
[ -x "$here/bin/oracle" ] || { echo "import-store-cells: $here is not a busbar checkout (no bin/oracle)" >&2; exit 1; }
golden="$data/golden/1.5.5"
digests="$data/golden-digests.tsv"
oracle="$here/bin/oracle"

die() { printf 'import-store-cells: %s\n' "$*" >&2; exit 1; }

[ $# -ge 1 ] || die "usage: testing/shadow-oracle/import-store-cells.sh <artifact-dir> [--yes]"
src="$1"; shift
assume_yes=0
for a in "$@"; do [ "$a" = "--yes" ] && assume_yes=1; done

# `gh run download` without -n makes a directory per artifact. Accept either level, so a caller who
# passed the download root does not get a "no meta.json" error naming a path they never typed.
if [ ! -f "$src/meta.json" ]; then
  n=0; only=""
  for d in "$src"/*/; do [ -f "$d/meta.json" ] && { n=$((n + 1)); only="${d%/}"; }; done
  [ "$n" = 1 ] || die "$src holds no meta.json and $n subdirectories that do — name the artifact directory"
  src="$only"
fi
src="$(cd "$src" && pwd)"

# ── WHAT THE ARTIFACT MUST BE ───────────────────────────────────────────────────────────────────
# Checked before anything is merged, because a half-valid artifact merged and then rolled back has
# already touched the golden, and the point of this script is that the golden is only ever replaced
# wholesale by a tool that refused to do it wrong.
[ -f "$src/ledger.tsv" ] || die "$src has no ledger.tsv"
[ -d "$src/cells" ] || die "$src has no cells/"
[ ! -d "$src/raw" ] || die "$src carries raw/ — that tree holds live key material and is deliberately not published; this is not the artifact the workflow uploads"

want_ids="plugins.store-persist|store-mysql
plugins.store-persist|store-postgres
plugins.store-persist|store-valkey"
got_ids="$(awk -F'\t' 'NF{print $1}' "$src/ledger.tsv" | LC_ALL=C sort)"
[ "$got_ids" = "$(printf '%s\n' "$want_ids" | LC_ALL=C sort)" ] \
  || die "the artifact's ledger is not the three store cells; it names:
$got_ids"
not_pass="$(awk -F'\t' 'NF && $2!="PASS"{printf " %s(%s)", $1, $2}' "$src/ledger.tsv")"
[ -z "$not_pass" ] || die "the artifact carries a non-PASS row:${not_pass}. A recording that did not
  pass is a finding to read, not a golden to import — the cells it would install are what the
  product did on a bad run, and every later replay would be measured against that."

# A PASS ROW IS NOT ENOUGH: THE CELL BEHIND IT MUST BE AN ANSWER (AUDIT NOTE-36). A script driver
# that gives up writes a capture nothing in the product produced — `{status:-1, effects:{error:
# "port N busy"}}` was the shipped shape — and the recorder side of the refusal is the pinned tool's
# (harness_error, and a non-zero driver exit). This is the MERGE side of the same rule, and it is
# checked here rather than trusted upstream because a merge is the last place a cell can be stopped
# before it becomes the reference every later candidate is measured against. Zero of the 915 cells
# in the committed golden carry any of these markers: a recording that answers busbar's questions
# has no `error` in its effects and no -1 status.
#
# ONE NOTCH WIDER, AND THE NOTCH IS WHERE THE EXEMPTION LIVES. `effects.error` is a refusal UNLESS
# the cell is DECLARED a named gap in busbar's own cells.json — `needs_fixture: "<ENV VAR>"`, the
# string form, which says WHICH fixture's absence excuses it. The pinned tool's SKIP semantics are
# not re-judged by any of this and never can be from here: what is judged is whether the cell was
# ENTITLED to the exemption it is carrying. Even a declared gap is refused as a MERGE INPUT, and for
# a different reason — a gap is a SKIP row with no cell file at all, so a gap that arrives as a cell
# is an artifact that recorded something while claiming it could not.
bad_cells="$(python3 - "$src/cells" "$data/cells.json" <<'PY'
import json, pathlib, sys

cells = json.load(open(sys.argv[2], encoding="utf-8"))["cells"]
# id -> the fixture variable whose absence excuses it. `needs_fixture` is a boolean on most cells
# ("this cell needs the fixture tree") and a string only on the ones that may be gaps.
entitled = {c["id"]: c["needs_fixture"] for c in cells
            if isinstance(c.get("needs_fixture"), str)}
# the cell FILE name is the id with every `|` written `__`, the spelling record.sh writes
by_file = {i.replace("|", "__") + ".json": v for i, v in entitled.items()}

bad = []
for path in sorted(pathlib.Path(sys.argv[1]).glob("*.json")):
    try:
        cell = json.load(path.open(encoding="utf-8"))
    except Exception as exc:  # a cell that will not parse is not a cell
        bad.append(f"{path.name}: unreadable ({exc})")
        continue
    effects = cell.get("effects")
    marks = [k for k in ("harness_error", "error", "named_gap")
             if isinstance(effects, dict) and k in effects]
    if cell.get("status") == -1:
        marks.append("status: -1")
    if not marks:
        continue
    declared = by_file.get(path.name)
    if declared and "harness_error" not in marks:
        bad.append(f"{path.name}: {', '.join(marks)} — cells.json DOES declare this cell a named gap "
                   f"(needs_fixture = {declared!r}), and a named gap is a SKIP row with NO cell "
                   f"file: this artifact recorded a cell while carrying the claim it could not")
    else:
        bad.append(f"{path.name}: {', '.join(marks)} — no cell in cells.json declares this cell a "
                   f"named gap, so this capture is the harness giving up")
print("\n".join(bad))
PY
)"
[ -z "$bad_cells" ] || die "the artifact carries a cell whose capture is a give-up, not an answer:
$bad_cells
  A harness failure that never reached the product is not a recording of the product. Merged, it
  becomes a golden every later candidate is compared against — and a candidate that fails the same
  way matches it exactly, which is a cell that is permanently green about nothing."

jget() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2],"") or "")' "$1" "$2"; }
src_ver="$(jget "$src/meta.json" version)"
src_sha="$(jget "$src/meta.json" binary_sha256)"
src_host="$(jget "$src/meta.json" host_triple)"
src_rev="$(jget "$src/meta.json" harness_rev)"
gold_ver="$(jget "$golden/meta.json" version)"
gold_sha="$(jget "$golden/meta.json" binary_sha256)"
gold_host="$(jget "$golden/meta.json" host_triple)"

# The digests are only REPORTED here; the tool refuses on them. Reporting is still worth doing: the
# operator should see which two builds are about to become one recording before the merge runs.
pin_of() {  # pin_of <sha> -> the busbar-<triple> row it is pinned as, or empty
  awk -F'\t' -v v="${src_ver##* }" -v s="$1" \
    '$1==v && $2 ~ /^busbar-/ && $2 !~ /\.(json|zip|tar\.gz)$/ && $3==s {print $2; exit}' "$digests"
}
src_pin="$(pin_of "$src_sha")"; gold_pin="$(pin_of "$gold_sha")"

echo "import-store-cells: merging into $golden"
echo "  golden    ${gold_ver}  ${gold_sha:0:12}  ${gold_pin:-NOT A PINNED ROW}  ${gold_host}"
echo "  artifact  ${src_ver}  ${src_sha:0:12}  ${src_pin:-NOT A PINNED ROW}  ${src_host}"

# ── THE OVERLAP ─────────────────────────────────────────────────────────────────────────────────
# The parts of a merge must be disjoint or the merged ledger carries two verdicts for one cell. The
# golden already holds a store-postgres PASS, recorded on the aarch64 host against a postgres that
# happened to be on that laptop; the artifact holds one recorded on the pinned postgres:16 image the
# CANDIDATE side of every CI replay also runs against. Those are not the same fact, and the second
# is the one a replay can be measured against — so the incoming row wins, and the outgoing one is
# named here rather than disappearing into a diff nobody reads.
superseded=""
for id in $(printf '%s\n' "$want_ids"); do
  if grep -Fq "$(printf '%s\t' "$id")" "$golden/ledger.tsv"; then superseded="${superseded} ${id}"; fi
done
if [ -n "$superseded" ]; then
  echo "  SUPERSEDED in the golden by this import (recorded against the pinned service images instead):"
  for id in $superseded; do
    printf '    %s  was: %s\n' "$id" "$(awk -F'\t' -v i="$id" '$1==i{print $2" "$3}' "$golden/ledger.tsv")"
  done
fi
if [ "$assume_yes" != 1 ]; then
  printf 'Proceed? [y/N] '
  read -r reply
  case "$reply" in y|Y|yes|YES) ;; *) die "stopped at the operator's request; the golden is untouched" ;; esac
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/import-store-cells.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# The golden becomes a PART, minus whatever the artifact supersedes. Copied, never edited in place:
# if the merge refuses, the committed golden has not been touched at all.
cp -R "$golden" "$work/golden-part"
if [ -n "$superseded" ]; then
  keep="$work/golden-part/ledger.tsv.keep"
  cp "$work/golden-part/ledger.tsv" "$keep"
  dropped_recordings=0
  for id in $superseded; do
    awk -F'\t' -v i="$id" '$1!=i' "$keep" >"$keep.new" && mv "$keep.new" "$keep"
    # a cell file is its id with every `|` written `__` — the same spelling record.sh writes.
    # A SKIP row has no cell file, and a named gap is the commonest thing this import supersedes,
    # so an absent file is only a problem when the row claimed a comparison was made.
    f="$(printf '%s' "$id" | sed 's/|/__/g')"
    was="$(awk -F'\t' -v i="$id" '$1==i{print $2}' "$golden/ledger.tsv")"
    case "$was" in
      PASS|FAIL) [ -f "$work/golden-part/cells/$f.json" ] \
        || die "the golden's ledger records $id as $was but cells/$f.json is not there — a verdict with no cell behind it" ;;
    esac
    [ -f "$work/golden-part/cells/$f.json" ] && dropped_recordings=$((dropped_recordings + 1))
    rm -f "$work/golden-part/cells/$f.json"
    rm -rf "$work/golden-part/raw/$f"
  done
  mv "$keep" "$work/golden-part/ledger.tsv"
  # `recorded` counts RECORDINGS, not ledger rows: a SKIP is a named gap with a row and no cell.
  # So it drops by the number of superseded rows that actually had a cell behind them, and a
  # superseded gap does not move it at all. Counting rows here instead would have stamped the
  # merged golden with the size of its ledger, a number nothing on disk supports.
  python3 - "$work/golden-part/meta.json" "$dropped_recordings" <<'PY'
import json, sys
mp, dropped = sys.argv[1], int(sys.argv[2])
m = json.load(open(mp, encoding="utf-8"))
before = m.get("recorded", 0)
m["recorded"] = before - dropped
json.dump(m, open(mp, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
print(f"import-store-cells: the golden part drops {dropped} superseded recording(s): {before} -> {before - dropped}")
PY
fi
cp -R "$src" "$work/store-cells-part"

note="the three plugins.store-persist cells recorded on ${src_host} from the pinned ${src_pin:-?} build of ${src_ver}, against the postgres/mysql/valkey images testing/fleet-fixtures/service-images.tsv pins — the same images every CI candidate runs against, which is what makes the two sides comparable"
[ -n "$superseded" ] && note="${note}; supersedes the golden's earlier${superseded} recorded on ${gold_host}"

"$oracle" merge --out "$work/merged" \
  --cells "$data/cells.json" \
  --pinned-binaries "$digests" \
  --allow-host-skew --allow-harness-skew \
  --note "$note" \
  "$work/golden-part" "$work/store-cells-part"

# Swap wholesale. The merged tree is complete or the tool exited non-zero above, so there is no
# state in which the golden is half-replaced.
rm -rf "$golden"
mv "$work/merged" "$golden"

echo
echo "import-store-cells: the golden now holds $(awk 'NF' "$golden/ledger.tsv" | wc -l | tr -d ' ') ledger rows."
echo "harness_rev is the merge's, and it is NOT the tree's current revision: re-stamp it deliberately"
echo "(bin/oracle harness-rev prints the current one) and write down what moved it, or every replay"
echo "will refuse on skew. Nothing is committed — accepting a golden is a review:"
echo
git -C "$here" --no-pager diff --stat -- testing/shadow-oracle/golden
