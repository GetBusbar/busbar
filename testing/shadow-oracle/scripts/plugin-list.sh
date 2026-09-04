#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
# Script-driver cell: `--list-plugins` with ONE published 1.5.5-era plugin in the dir. The STATUS
# column (ready | SKIPPED: … | INVALID: …) is the contract (PB-11). Writes $RAW/captured.json.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
PLUGIN="${1:?plugin name}"; BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"
W="$RAW/plugin-work"; mkdir -p "$W/plugins"
tarball="$(bash "${here}/fetch-plugin.sh" "$PLUGIN")" || { echo '{"status":-1,"headers":{},"body":"","effects":{"error":"plugin fetch failed"}}' >"$RAW/captured.json"; exit 0; }
cp "$tarball" "$W/plugins/"
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
python3 "${here}/capture-exec.py" "$rc" "$W/stdout" "$W/stderr" --strip-path "$W" --strip-path "$BIN" \
  | python3 -c "import sys,json,re; d=json.load(sys.stdin); d['body']=re.sub(r'-(aarch64|x86_64)-(apple-darwin|unknown-linux-gnu|pc-windows-msvc)', '-<TRIPLE>', d['body']); print(json.dumps(d,separators=(',',':'),sort_keys=True))" >"$RAW/captured.json"
