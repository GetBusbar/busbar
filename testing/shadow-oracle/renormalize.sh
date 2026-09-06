#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Re-run normalize.py over a recording's raw captures WITHOUT re-recording: a normalizer change is
# reviewable against existing goldens in seconds.  renormalize.sh <recording-dir>
#
# Faithful to record.sh, or refused: the cell's `keep` / `body_lines` spec is read from cells.json
# by id and passed exactly as record.sh passes it, and a cell whose recorded capture carries a
# readback (folded in by record.sh AFTER normalization, from live requests that cannot be replayed
# here) keeps its readback verbatim. A cell id that cells.json no longer knows is left untouched
# and named, never silently re-normalized under someone else's spec.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
d="${1:?recording dir}"; n=0; kept=0; unknown=0; failed=0
command -v jq >/dev/null || { echo "renormalize.sh needs jq" >&2; exit 2; }
specs="$(mktemp "${TMPDIR:-/tmp}/renorm-specs.XXXXXX")" \
  || { echo "renormalize.sh: could not create a temp file for the cell specs" >&2; exit 2; }
# THE SPEC TABLE IS THE WHOLE CONTRACT, SO A FAILURE TO BUILD IT IS FATAL. Unchecked, a jq that
# failed here (an unreadable or malformed cells.json) left `$specs` EMPTY — every id then looked
# like "not in cells.json", every cell was skipped as unknown, and the script printed
# "renormalized 0 cells" and exited 0. A run that re-normalized nothing reported success.
jq -c '.cells[] | {id, keep: (.keep // null), body_lines: (.body_lines // null)}' "${here}/cells.json" >"$specs" \
  || { echo "renormalize.sh: could not read the cell specs out of ${here}/cells.json" >&2; rm -f "$specs"; exit 2; }
[ -s "$specs" ] || { echo "renormalize.sh: ${here}/cells.json yielded no cells" >&2; rm -f "$specs"; exit 2; }
for raw in "$d"/raw/*/; do
  [ -f "$raw/captured.json" ] || continue
  safe="$(basename "$raw")"; kid="$(cat "$raw/key-id" 2>/dev/null || true)"
  cell="$d/cells/$safe.json"
  id="$(sed 's/__/|/g' <<<"$safe")"
  spec="$(jq -c --arg id "$id" 'select(.id == $id)' "$specs" | head -1)"
  if [ -z "$spec" ]; then unknown=$((unknown+1)); echo "renormalize: $id is not in cells.json; left as recorded" >&2; continue; fi
  keep_spec="$(jq -r '.keep // empty | tojson' <<<"$spec" 2>/dev/null)"; [ "$keep_spec" = null ] && keep_spec=""
  keep_lines="$(jq -r '.body_lines // empty' <<<"$spec")"
  readback="$(jq -c '.effects.readback // empty' "$cell" 2>/dev/null)"
  python3 "${here}/normalize.py" "$raw/captured.json" ${kid:+--key-id "$kid"} \
    ${keep_lines:+--keep-body-lines "$keep_lines"} ${keep_spec:+--keep "$keep_spec"} >"$raw/renormalized.json" \
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
