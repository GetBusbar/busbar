#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
# Script-driver cell: `--list-plugins` with ONE published 1.5.5-era plugin in the dir. The STATUS
# column (ready | SKIPPED: … | INVALID: …) is the contract (PB-11). Writes $RAW/captured.json.
#
# PORTS COME FROM THE RECORDER'S BLOCK, like every other script cell. They were hardcoded 48851/48852
# here — which are also key-revoke.sh's defaults, and are three above record.sh's own 48811/48812
# rather than derived from them. A caller that moves the recording off the default block
# (ORACLE_LISTEN_PORT/ORACLE_ADMIN_PORT, which record.sh passes down as SCRIPT_LISTEN_PORT/
# SCRIPT_ADMIN_PORT — selftest.sh does exactly this, giving each parallel recording `48851 + n*3`)
# moved every other cell and not this one, so this cell went on binding the block it was moved OFF,
# which is either a bind failure or, worse, an adoption of whatever else is there.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
PLUGIN="${1:?plugin name}"; BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"
LP="${PLUGINLIST_LISTEN_PORT:-${SCRIPT_LISTEN_PORT:-48851}}" AP="${PLUGINLIST_ADMIN_PORT:-${SCRIPT_ADMIN_PORT:-48852}}"
W="$RAW/plugin-work"; mkdir -p "$W/plugins"
tarball="$(bash "${here}/fetch-plugin.sh" "$PLUGIN")" || { echo '{"status":-1,"headers":{},"body":"","effects":{"error":"plugin fetch failed"}}' >"$RAW/captured.json"; exit 0; }
cp "$tarball" "$W/plugins/"
cat >"$W/config.yaml" <<YAML
listen: "127.0.0.1:${LP}"
admin_listen: "127.0.0.1:${AP}"
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
