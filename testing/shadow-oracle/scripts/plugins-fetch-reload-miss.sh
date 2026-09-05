#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell: BOOT-W24 (main.rs/appbuild.rs `plugins.fetch: miss on reload; keeping current
# artifact`) is explicitly RELOAD-ONLY — `fetch_plugins(..., prior.is_none(), ...)` passes
# `fatal_on_miss = prior.is_none()`, so the SAME fetch failure that is a hard boot error is only a
# WARN on `POST /plugins/reload`. No single-exec mutation can produce that distinction; this needs a
# BOOTED process to reload against.
#
#   1. serve a REAL, digest-pinned published plugin tarball (store-sqlite) over a throwaway local
#      HTTP file server; boot busbar with `plugins.fetch: [{ url: http://127.0.0.1:<port>/<asset> }]`
#      pointed at it — the boot-time fetch succeeds (fatal_on_miss, so it MUST for busbar to come up).
#   2. kill the file server (the next fetch attempt now gets connection-refused), then
#      `POST /plugins/reload` — the SAME url now misses, but reload's `fatal_on_miss=false` turns it
#      into a WARN ("keeping current artifact") instead of rejecting the reload.
#
# Writes $RAW/captured.json in capture-exec.py's shape (status/headers/body/effects.stderr): status
# is the reload response's HTTP status (200 — the reload itself is NOT rejected by a fetch miss),
# body is the reload response, effects.stderr is the busbar log tail carrying the warn line.
#
# Env from the recorder: BUSBAR_BIN RAW WORK ORACLE_ADMIN_TOKEN; SCRIPT_LISTEN_PORT/SCRIPT_ADMIN_PORT
# for busbar itself, SCRIPT_MOCK_PORT for the throwaway tarball file server.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"

BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"; ADMIN="${ORACLE_ADMIN_TOKEN:-shadow-oracle-admin}"
LP="${FETCH_LISTEN_PORT:-${SCRIPT_LISTEN_PORT:-49751}}" AP="${FETCH_ADMIN_PORT:-${SCRIPT_ADMIN_PORT:-49752}}" FP="${FETCH_FILE_PORT:-${SCRIPT_MOCK_PORT:-49761}}"
fail() { echo "{\"status\":-1,\"headers\":{},\"body\":\"\",\"effects\":{\"error\":\"$1\"}}" >"$RAW/captured.json"; exit 0; }
for p in "$LP" "$AP" "$FP"; do assert_port_free "$p" || fail "port $p busy"; done

W="$RAW/fetch-work"; mkdir -p "$W/plugins" "$W/serve" "$W/tmp"
# see durable-governance-precondition.sh's header comment: isolate `sweep_dead_staging`'s host-wide
# `$TMPDIR` scan so its opportunistic `[info] removed N orphaned ...` line never fires here.
export TMPDIR="$W/tmp"
tarball="$(bash "${here}/fetch-plugin.sh" store-sqlite)" || fail "store-sqlite plugin fetch failed"
asset="$(basename "$tarball")"
cp "$tarball" "$W/serve/"
"$BIN" --generate-signing-key >"$W/signing.key" 2>/dev/null
[ -s "$W/signing.key" ] || fail "--generate-signing-key produced no key"

cat >"$W/providers.yaml" <<EOF
openai-chat:
  protocol: openai
  base_url: "http://127.0.0.1:1"
EOF
cat >"$W/config.yaml" <<EOF
listen: "127.0.0.1:${LP}"
admin_listen: "127.0.0.1:${AP}"
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: { env: BUSBAR_ADMIN_TOKEN }
auth:
  chain: [keys]
  signing_key: { file: "${W}/signing.key" }
  admin_auth: [admin-tokens]
plugins:
  enabled: true
  dir: "${W}/plugins"
  fetch:
    - url: "http://127.0.0.1:${FP}/${asset}"
groups:
  oracle:
    limits:
      - { budget: 1000000, per: day }
providers:
  openai-chat:
    api_key: { env: ORACLE_UPSTREAM_KEY }
models:
  m-openai-chat:
    provider: openai-chat
rate_card:
  m-openai-chat: { input_utok: 100000, output_utok: 200000 }
EOF

( cd "$W/serve" && exec python3 -m http.server "$FP" --bind 127.0.0.1 ) >"$W/fileserver.log" 2>&1 &
fs_pid=$!; track_pid "$fs_pid"
wait_for_http "http://127.0.0.1:${FP}/${asset}" 8 || fail "throwaway file server did not come up"

spawn_() { ( exec env BUSBAR_CONFIG="$W/config.yaml" BUSBAR_PROVIDERS="$W/providers.yaml" ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN="$ADMIN" RUST_LOG=warn "$BIN" ) >>"$W/busbar.log" 2>&1 & echo $!; }
pid="$(spawn_)"; track_pid "$pid"
wait_for_http "http://127.0.0.1:${LP}/healthz" 30 || fail "busbar did not come up (boot-time fetch must succeed): $(tail -c 400 "$W/busbar.log")"
grep -q "plugins.fetch: downloaded" "$W/busbar.log" 2>/dev/null || true  # informational only

# kill the file server: the NEXT fetch attempt (the reload below) now misses.
kill "$fs_pid" 2>/dev/null; wait "$fs_pid" 2>/dev/null
i=0; while [ $i -lt 50 ] && curl -sS -m1 -o /dev/null "http://127.0.0.1:${FP}/${asset}" 2>/dev/null; do sleep 0.1; i=$((i+1)); done

st="$(curl -sS -m 20 -o "$RAW/body" -D "$RAW/headers" -w '%{http_code}' -X POST "http://127.0.0.1:${AP}/api/v1/admin/plugins/reload" -H "Authorization: Bearer $ADMIN" 2>"$RAW/reload.err")"
sleep 0.2
kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done

: >"$RAW/stdout"
grep -a "plugins.fetch" "$W/busbar.log" >"$RAW/stderr" || cp "$W/busbar.log" "$RAW/stderr"
python3 "${here}/capture-exec.py" "$st" "$RAW/body" "$RAW/stderr" \
  --strip-path "$W" --strip-path "$RAW" --strip-path "$repo" --strip-path "$BIN" >"$RAW/captured.json" 2>"$RAW/capture.err" \
  || fail "capture-exec.py failed: $(tail -c 300 "$RAW/capture.err")"
