#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Re-run normalize.py over a recording's raw captures WITHOUT re-recording: a normalizer change is
# reviewable against existing goldens in seconds.  renormalize.sh <recording-dir>
#
# Faithful to record.sh, or refused: the cell's `keep` / `body_lines` spec is read from cells.json
# by id and passed exactly as record.sh's call site FOR THAT CELL'S DRIVER passes it (record.sh has
# four normalize.py invocations, not one — see the driver table below), and a cell whose recorded
# capture carries a
# readback (folded in by record.sh AFTER normalization, from live requests that cannot be replayed
# here) keeps its readback verbatim. A cell id that cells.json no longer knows is left untouched
# and named, never silently re-normalized under someone else's spec.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
d="" CELLS="${here}/cells.json"; n=0; kept=0; unknown=0; failed=0
while [ $# -gt 0 ]; do
  case "$1" in
    # the corpus whose per-cell specs are replayed. Defaults to the shipped one; an explicit path
    # lets the selftest drive this file against a fixture corpus rather than the 2301-cell tree.
    --cells) CELLS="$2"; shift 2 ;;
    -*) echo "renormalize.sh: unknown arg $1" >&2; exit 2 ;;
    *) d="$1"; shift ;;
  esac
done
[ -n "$d" ] || { echo "usage: renormalize.sh [--cells cells.json] <recording-dir>" >&2; exit 2; }
command -v jq >/dev/null || { echo "renormalize.sh needs jq" >&2; exit 2; }
specs="$(mktemp "${TMPDIR:-/tmp}/renorm-specs.XXXXXX")" \
  || { echo "renormalize.sh: could not create a temp file for the cell specs" >&2; exit 2; }
# THE SPEC TABLE IS THE WHOLE CONTRACT, SO A FAILURE TO BUILD IT IS FATAL. Unchecked, a jq that
# failed here (an unreadable or malformed cells.json) left `$specs` EMPTY — every id then looked
# like "not in cells.json", every cell was skipped as unknown, and the script printed
# "renormalized 0 cells" and exited 0. A run that re-normalized nothing reported success.
jq -c '.cells[] | {id, driver: (.driver // "http"), keep: (.keep // null), body_lines: (.body_lines // null)}' "$CELLS" >"$specs" \
  || { echo "renormalize.sh: could not read the cell specs out of ${CELLS}" >&2; rm -f "$specs"; exit 2; }
[ -s "$specs" ] || { echo "renormalize.sh: ${CELLS} yielded no cells" >&2; rm -f "$specs"; exit 2; }
for raw in "$d"/raw/*/; do
  [ -f "$raw/captured.json" ] || continue
  safe="$(basename "$raw")"; kid="$(cat "$raw/key-id" 2>/dev/null || true)"
  cell="$d/cells/$safe.json"
  id="$(sed 's/__/|/g' <<<"$safe")"
  spec="$(jq -c --arg id "$id" 'select(.id == $id)' "$specs" | head -1)"
  if [ -z "$spec" ]; then unknown=$((unknown+1)); echo "renormalize: $id is not in cells.json; left as recorded" >&2; continue; fi
  keep_spec="$(jq -r '.keep // empty | tojson' <<<"$spec" 2>/dev/null)"; [ "$keep_spec" = null ] && keep_spec=""
  keep_lines="$(jq -r '.body_lines // empty' <<<"$spec")"
  driver="$(jq -r '.driver' <<<"$spec")"
  # ── FAITHFUL TO THIS CELL'S OWN RECORDER CALL SITE, OR REFUSED ────────────────────────────────
  # This file's whole claim is that it re-derives a cell "exactly as record.sh passes it". record.sh
  # does NOT have one normalize.py invocation; it has four, and they pass different flags:
  #
  #   driver      record.sh call site           passes
  #   http        record.sh:984                 --key-id, --keep-body-lines, --keep
  #   exec        record.sh:526                 --keep-body-lines, --keep      (no --key-id)
  #   concurrent  record.sh:740                 --key-id, --driver concurrent  (no keep spec)
  #   script      record.sh:825                 nothing at all
  #
  # Passing all three uniformly, as this loop did, means a `keep` or `body_lines` on a script or
  # concurrent cell is applied HERE and was never applied by the recorder: the re-normalized cell is
  # not the cell record.sh made, it is written over the golden in place, and the harness_rev
  # re-stamp at the bottom of this file then makes the rewrite look like a legitimate re-derivation.
  # Today no script or concurrent cell declares either spec, so the old code was faithful by luck
  # and not by rule; the day one does, the golden changes and nothing says so.
  #
  # So the flags are chosen by the cell's driver, and a spec the recorder's call site would have
  # IGNORED is a refusal naming the cell — never silently applied here, and never silently dropped
  # either, because "cells.json says keep this and the recording did not" is a discrepancy the
  # operator has to resolve in cells.json or in record.sh, not one this file may paper over.
  driver_flag=()
  case "$driver" in
    http) ;;
    exec)
      if [ -n "$kid" ]; then
        echo "renormalize: $id is an exec cell but its capture carries a key-id; record.sh:526 normalizes exec cells WITHOUT --key-id, so re-deriving it here would not reproduce the recorded cell" >&2
        failed=$((failed+1)); continue
      fi ;;
    concurrent)
      if [ -n "$keep_spec" ] || [ -n "$keep_lines" ]; then
        echo "renormalize: $id is a concurrent cell and cells.json gives it a keep/body_lines spec, but record.sh:740 normalizes concurrent cells with --key-id ALONE; applying the spec here would write a cell the recorder never made" >&2
        failed=$((failed+1)); continue
      fi
      keep_spec=""; keep_lines=""; driver_flag=(--driver concurrent) ;;
    script)
      if [ -n "$keep_spec" ] || [ -n "$keep_lines" ]; then
        echo "renormalize: $id is a script cell and cells.json gives it a keep/body_lines spec, but record.sh:825 normalizes script cells with NO flags at all; applying the spec here would write a cell the recorder never made" >&2
        failed=$((failed+1)); continue
      fi
      kid=""; keep_spec=""; keep_lines="" ;;
    *)
      echo "renormalize: $id has an unknown driver ${driver@Q}; refusing to guess which of record.sh's four normalize.py call sites made it" >&2
      failed=$((failed+1)); continue ;;
  esac
  readback="$(jq -c '.effects.readback // empty' "$cell" 2>/dev/null)"
  python3 "${here}/normalize.py" "$raw/captured.json" ${kid:+--key-id "$kid"} \
    ${keep_lines:+--keep-body-lines "$keep_lines"} ${keep_spec:+--keep "$keep_spec"} \
    ${driver_flag[0]+"${driver_flag[@]}"} >"$raw/renormalized.json" \
    || { echo "renormalize: normalize.py failed on $id" >&2; rm -f "$raw/renormalized.json"; failed=$((failed+1)); continue; }
  # NEVER WRITE A TRACKED GOLDEN CELL IN PLACE. `jq … >"$cell"` truncates the cell BEFORE jq runs:
  # a jq failure, a full disk or a Ctrl-C at that instant left a truncated (or empty) file where a
  # golden cell used to be — in the TRACKED tree — and the loop carried on and exited 0. Build the
  # new bytes beside it and rename only once jq has succeeded; a rename is atomic, so the cell is
  # either its old self or its new self and never half of one.
  if [ -n "$readback" ]; then
    if jq --argjson rb "$readback" '.effects.readback = $rb' "$raw/renormalized.json" >"$raw/with-readback.json"; then
      mv "$raw/with-readback.json" "$cell"; kept=$((kept+1))
    else
      echo "renormalize: could not fold ${id}'s recorded readback back in; left as recorded" >&2
      rm -f "$raw/with-readback.json" "$raw/renormalized.json"; failed=$((failed+1)); continue
    fi
  else
    mv "$raw/renormalized.json" "$cell"
  fi
  rm -f "$raw/renormalized.json"; n=$((n+1))
done
rm -f "$specs"
echo "renormalized $n cells in $d ($kept with their recorded readback kept; $unknown not in cells.json, untouched)"

# ZERO CELLS IS NOT SUCCESS, AND NEITHER IS A CELL THAT COULD NOT BE WRITTEN. The caller uses the
# exit status to decide whether the recording it just re-normalized can be reviewed as one; a run
# that touched nothing (wrong directory, a recording with no raw/ tree) or that skipped a cell it
# was asked to re-normalize must say so in the status, not only in a line of prose.
if [ "$n" -eq 0 ]; then
  echo "renormalize.sh: re-normalized NO cells in $d — is that a recording directory (does it have raw/<id>/captured.json)?" >&2
  exit 1
fi
if [ "$failed" -ne 0 ]; then
  echo "renormalize.sh: ${failed} cell(s) could not be re-normalized (named above); the recording is not fully re-normalized" >&2
  exit 1
fi

# ── THE RECORDING NOW SAYS WHICH HARNESS PRODUCED THE CELLS IT HOLDS ─────────────────────────────
# renormalize.sh is itself in the harness-rev file set (it decides what a recording's cells say), so
# a recording it has rewritten was NOT produced by the harness its meta.json still names. Left
# unstamped, the recording carries the rev of the run that recorded it while holding cells this
# revision of normalize.py wrote — and diff-cells' skew guard, whose entire job is to refuse a pair
# of recordings made under different harnesses, compares the two stale stamps, finds them equal and
# says nothing. The rewrite is invisible in exactly the field that exists to make it visible.
#
# So the rev is re-stamped here, and the OLD one is pushed onto harness_rev_history (the same place
# a re-record puts it) with a note naming this script and how many cells it rewrote. Nothing else in
# meta.json is touched: `recorded`, `at`, `binary_sha256` and `binary` still describe the recording
# run, because that run is still what produced the raw captures.
if [ -f "$d/meta.json" ]; then
  # shellcheck source=harness-rev.sh
  source "${here}/harness-rev.sh"
  if ! python3 - "$d/meta.json" "$(harness_rev)" "$n" <<'PY'
import json, sys, datetime
p, rev, n = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(p, encoding="utf-8") as f:
        m = json.load(f)
except Exception as e:
    sys.exit(f"renormalize.sh: {p} is not readable JSON ({e}); refusing to leave it half-stamped")
old = m.get("harness_rev")
if old == rev:
    sys.exit(0)
if old:
    m.setdefault("harness_rev_history", []).append(old)
m["harness_rev"] = rev
note = (f"RE-NORMALIZED {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d')} by renormalize.sh: "
        f"{n} cell(s) rewritten from the recorded raw captures under this harness revision. No cell was "
        f"re-recorded and the binary is unchanged; the rev moved because the code that decides what a "
        f"normalized cell SAYS did.")
m["harness_rev_note"] = f"{note} | {m['harness_rev_note']}" if m.get("harness_rev_note") else note
with open(p + ".tmp", "w", encoding="utf-8") as f:
    json.dump(m, f, indent=2)
    f.write("\n")
import os
os.replace(p + ".tmp", p)
print(f"renormalize: re-stamped harness_rev {(old or 'none')[:12]} -> {rev[:12]} in {p}")
PY
  then
    echo "renormalize.sh: could not re-stamp harness_rev in $d/meta.json — the recording's cells were rewritten but it still claims the old harness" >&2
    exit 1
  fi
else
  echo "renormalize.sh: $d has no meta.json, so the rewritten cells carry no harness revision at all" >&2
  exit 1
fi
