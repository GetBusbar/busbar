#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
# Script-driver cell: `--list-plugins` with ONE published 1.5.5-era plugin in the dir. The STATUS
# column (ready | SKIPPED: … | INVALID: …) is the contract (PB-11). Writes $RAW/captured.json.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
PLUGIN="${1:?plugin name}"; BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"
W="$RAW/plugin-work"; mkdir -p "$W/plugins"
# EVERY STEP AFTER THE FETCH USED TO BE UNCHECKED. A `cp` that never happened, or a capture pipeline
# whose python half died, still left this driver exiting on the last command's status while the
# recorder's file-only verdict recorded PASS — the STATUS column contract (PB-11) proved by an empty
# plugins dir. `fail` marks a harness error so a broken setup is FAILed rather than recorded.
fail() { jq -n --arg body "$1" '{status:0, headers:{}, body:$body, effects:{harness_error:$body}}' >"$RAW/captured.json"; exit 70; }
tarball="$(bash "${BUSBAR_ORACLE_TOOL_DIR:-$here}/fetch-plugin.sh" "$PLUGIN")" || oracle_harness_give_up "plugin fetch failed"
[ -s "$tarball" ] || fail "fetch-plugin.sh reported success but $PLUGIN's tarball is empty or missing"
cp "$tarball" "$W/plugins/" || fail "could not copy $PLUGIN's tarball into the cell's plugins dir"
cat >"$W/config.yaml" <<YAML
listen: "127.0.0.1:48851"
admin_listen: "127.0.0.1:48852"
plugins:
  enabled: true
  dir: "${W}/plugins"
providers:
  p: { api_key: { env: ORACLE_UPSTREAM_KEY } }
models:
  m: { provider: p }
YAML
printf 'p:\n  protocol: openai\n  base_url: "http://127.0.0.1:1"\n' >"$W/providers.yaml"
BUSBAR_CONFIG="$W/config.yaml" BUSBAR_PROVIDERS="$W/providers.yaml" ORACLE_UPSTREAM_KEY=x "$BIN" --list-plugins >"$W/stdout" 2>"$W/stderr"; rc=$?
# the table's FILE column carries the host triple; keep everything else verbatim
python3 "${BUSBAR_ORACLE_TOOL_DIR:-$here}/capture-exec.py" "$rc" "$W/stdout" "$W/stderr" --strip-path "$W" --strip-path "$BIN" \
  | python3 -c "import sys,json,re; d=json.load(sys.stdin); d['body']=re.sub(r'-(aarch64|x86_64)-(apple-darwin|unknown-linux-gnu|pc-windows-msvc)', '-<TRIPLE>', d['body']); print(json.dumps(d,separators=(',',':'),sort_keys=True))" >"$RAW/captured.json" \
  || fail "the capture pipeline failed (capture-exec.py or the triple-scrubber exited non-zero)"
[ -s "$RAW/captured.json" ] || fail "the capture pipeline wrote an empty captured.json"

# The script-cell verdict reads the DRIVER'S EXIT STATUS, not just the file it left behind. Say 0
# out loud on the success path rather than inheriting whatever the last command happened to return.
exit 0
