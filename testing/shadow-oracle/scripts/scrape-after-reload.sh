#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell `ops.scrape|reload|sink-removed` (ARCHITECT 2026-10-05, Q-U2-4 follow-up, from the
# D4 lane): ACROSS A RELOAD the two scrape routes on the DATA listener answer as 1.5.5's did.
#
#   1. boot with the prometheus exporter (`export: metrics: {module: prometheus}`) and mint a key;
#      scrape `/metrics` and `/metrics/hooks` with it (both 200);
#   2. rewrite config.yaml WITHOUT the exporter and `POST /api/v1/admin/config/reload`;
#   3. scrape both again with the same key. 1.5.5: `/metrics` (the exporter's plugin route) follows
#      the configuration and 404s; `/metrics/hooks` (a core route mounted with the recorder at boot)
#      keeps answering 200 for the process's life.
#
# Recorded per scrape: the HTTP status and the content type (the bodies carry live process counters,
# so they are not compared). The reload's own status is the cell's status; busbar's stderr lands
# under `effects.stderr` so the register's D-1 transform reaches it as for every other script cell.
#
# Writes $RAW/captured.json. Env from the recorder: BUSBAR_BIN RAW WORK ORACLE_ADMIN_TOKEN
# BUSBAR_ORACLE_BIN; SCRIPT_LISTEN_PORT/SCRIPT_ADMIN_PORT for busbar itself.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"
BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"; ADMIN="${ORACLE_ADMIN_TOKEN:-shadow-oracle-admin}"
ORACLE_BIN="${BUSBAR_ORACLE_BIN:?the Rust oracle engine must be published as BUSBAR_ORACLE_BIN}"
LP="${SCRAPE_LISTEN_PORT:-${SCRIPT_LISTEN_PORT:-48931}}" AP="${SCRAPE_ADMIN_PORT:-${SCRIPT_ADMIN_PORT:-48932}}"

eff='{}'
step() { eff="$(jq -c --arg k "$1" --arg v "$2" '. + {($k): $v}' <<<"$eff")"; }
# A `fail` is the harness giving up, never an outcome of the binary (see documented-docker-defaults.sh).
fail() { jq -n --argjson eff "$eff" --arg body "$1" '{status:-1, headers:{}, body:$body, effects:($eff + {harness_error: $body})}' >"$RAW/captured.json"; exit 0; }
for p in "$LP" "$AP"; do assert_port_free "$p" || fail "port $p busy"; done

W="$RAW/scrape-reload-work"
rm -rf "$W"; mkdir -p "$W/tmp"
export TMPDIR="$W/tmp"
"$BIN" --generate-signing-key >"$W/signing.key" 2>/dev/null
[ -s "$W/signing.key" ] || fail "--generate-signing-key produced no key"
cat >"$W/providers.yaml" <<EOF
openai-chat:
  protocol: openai
  base_url: "http://127.0.0.1:1"
EOF
config() {  # config <with-exporter: yes|no>
  cat <<EOF
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
  if [ "$1" = yes ]; then
    printf 'export:\n  metrics:\n    module: prometheus\n    settings: { buffer_seconds: 60 }\n'
  fi
}
config yes >"$W/config.yaml"
# The operator upgrade step and the oracle's run-time inputs (store, mock allowlist), as every script cell.
"$ORACLE_BIN" upgrade-config "$BIN" "$W/config.yaml" || fail "upgrade-config refused the boot config"

( exec env BUSBAR_CONFIG="$W/config.yaml" BUSBAR_PROVIDERS="$W/providers.yaml" ORACLE_UPSTREAM_KEY=unused \
    BUSBAR_ADMIN_TOKEN="$ADMIN" RUST_LOG=warn "$BIN" ) >"$W/stdout.log" 2>"$W/stderr.log" &
pid=$!; track_pid "$pid"
wait_for_http "http://127.0.0.1:${LP}/healthz" 30 || fail "busbar did not come up: $(tail -c 600 "$W/stderr.log")"

key="$(curl -sS -m 10 -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys" -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json' -d '{"name":"scrape","group":"oracle"}' | jq -r '.token // empty')"
[ -n "$key" ] || fail "no key was minted"

scrape() {  # scrape <label> <path> — records <label>_status and <label>_content_type
  local hdr="$W/$1.headers" st
  st="$(curl -sS -m 10 -o /dev/null -D "$hdr" -w '%{http_code}' "http://127.0.0.1:${LP}$2" -H "Authorization: Bearer $key")"
  step "$1_status" "$st"
  step "$1_content_type" "$(grep -i '^content-type:' "$hdr" | head -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//')"
}
scrape before_metrics /metrics
scrape before_metrics_hooks /metrics/hooks

# The reload: the exporter leaves the file, then the config is re-read from disk.
config no >"$W/config.yaml"
"$ORACLE_BIN" upgrade-config "$BIN" "$W/config.yaml" || fail "upgrade-config refused the reloaded config"
st="$(curl -sS -m 20 -o "$W/reload.body" -w '%{http_code}' -X POST "http://127.0.0.1:${AP}/api/v1/admin/config/reload" \
  -H "Authorization: Bearer $ADMIN")"
step reload_status "$st"
sleep 0.3

scrape after_metrics /metrics
scrape after_metrics_hooks /metrics/hooks

kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done
eff="$(jq -c --arg v "$(cat "$W/stderr.log" 2>/dev/null)" '. + {stderr: $v}' <<<"$eff")"
jq -n --argjson st "${st:-0}" --argjson eff "$eff" --arg body "$(jq -c 'del(.stderr)' <<<"$eff")" \
  '{status:$st, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"

# The script-cell verdict reads the DRIVER'S EXIT STATUS: say 0 on the success path.
exit 0
