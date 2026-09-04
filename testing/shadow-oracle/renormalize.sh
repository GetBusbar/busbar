#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Re-run normalize.py over a recording's raw captures WITHOUT re-recording: a normalizer change is
# reviewable against existing goldens in seconds.  renormalize.sh <recording-dir>
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
d="${1:?recording dir}"; n=0
for raw in "$d"/raw/*/; do
  [ -f "$raw/captured.json" ] || continue
  id="$(basename "$raw")"; kid="$(cat "$raw/key-id" 2>/dev/null || true)"
  python3 "${here}/normalize.py" "$raw/captured.json" ${kid:+--key-id "$kid"} >"$d/cells/$id.json" && n=$((n+1))
done
echo "renormalized $n cells in $d"
