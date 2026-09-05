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
d="${1:?recording dir}"; n=0; kept=0; unknown=0
command -v jq >/dev/null || { echo "renormalize.sh needs jq" >&2; exit 2; }
specs="$(mktemp "${TMPDIR:-/tmp}/renorm-specs.XXXXXX")"
jq -c '.cells[] | {id, keep: (.keep // null), body_lines: (.body_lines // null)}' "${here}/cells.json" >"$specs"
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
    ${keep_lines:+--keep-body-lines "$keep_lines"} ${keep_spec:+--keep "$keep_spec"} >"$raw/renormalized.json" || { echo "renormalize: normalize.py failed on $id" >&2; rm -f "$raw/renormalized.json"; continue; }
  if [ -n "$readback" ]; then
    jq --argjson rb "$readback" '.effects.readback = $rb' "$raw/renormalized.json" >"$cell" && kept=$((kept+1))
  else
    mv "$raw/renormalized.json" "$cell"
  fi
  rm -f "$raw/renormalized.json"; n=$((n+1))
done
rm -f "$specs"
echo "renormalized $n cells in $d ($kept with their recorded readback kept; $unknown not in cells.json, untouched)"
