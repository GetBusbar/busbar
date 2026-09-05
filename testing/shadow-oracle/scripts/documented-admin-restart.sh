#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell for the PB-71 `documented` family: CHANGELOG.md:309-310 (1.5.0) — "POST
# /api/v1/admin/restart applies the settings that need a restart (listeners, TLS, store backend)
# without shell access." The admin.ops family already pins the shape of ONE restart response
# (restart_epoch, its own final epoch); this cell instead proves the DURABLE-SETTINGS half: a
# restart-scoped setting PUT through the admin API survives into the overlay file BEFORE the
# restart is even requested (so the operator never touched a shell or the binary), and a fresh
# process launched against the same config+overlay picks it up — the "without shell access" half
# of the claim, not just the 202 response shape.
#
# Each boot's stdout/stderr are captured separately (never merged with `2>&1`); the two boots' raw
# stderr are concatenated (labeled) into ONE combined `effects.stderr` — the standard path
# accepted-differences.json's D-1/D-2 transforms already reach (MULTILINE regexes, so both boots'
# lines are still individually matched inside the one blob).
#
#   documented-admin-restart.sh
#
# Writes $RAW/captured.json. Env from the recorder: BUSBAR_BIN RAW WORK ORACLE_ADMIN_TOKEN.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"
BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"; ADMIN="${ORACLE_ADMIN_TOKEN:-shadow-oracle-admin}"
LP="${RESTART_LISTEN_PORT:-${SCRIPT_LISTEN_PORT:-48931}}" AP="${RESTART_ADMIN_PORT:-${SCRIPT_ADMIN_PORT:-48932}}"
W="$RAW/restart-work"; mkdir -p "$W"

for p in "$LP" "$AP"; do
  assert_port_free "$p" || { echo "{\"status\":-1,\"headers\":{},\"body\":\"\",\"effects\":{\"error\":\"port $p busy\"}}" >"$RAW/captured.json"; exit 0; }
done

"$BIN" --generate-signing-key >"$W/signing.key" 2>/dev/null
cat >"$W/providers.yaml" <<YAML
openai-chat:
  protocol: openai
  base_url: "http://127.0.0.1:1"
YAML
cat >"$W/config.yaml" <<YAML
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
YAML

eff='{}'
step() { eff="$(jq -c --arg k "$1" --arg v "$2" '. + {($k): $v}' <<<"$eff")"; }
fail() { jq -n --argjson st "$1" --argjson eff "$eff" --arg body "$2" '{status:$st, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"; exit 0; }

boot() {  # <stdout-file> <stderr-file>
  ( exec env BUSBAR_CONFIG="$W/config.yaml" BUSBAR_PROVIDERS="$W/providers.yaml" \
      ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN="$ADMIN" RUST_LOG=warn "$BIN" ) \
    >"$1" 2>"$2" &
  echo $!
}

pid="$(boot "$W/boot1.stdout" "$W/boot1.stderr")"; track_pid "$pid"
wait_for_http "http://127.0.0.1:${LP}/healthz" 30 || fail 1 "$(tail -c 800 "$W/boot1.stdout")$(tail -c 800 "$W/boot1.stderr")"
step booted "true"

# advanced.response_headers.server_timing (PB-73): RESTART-scoped, default false — the config
# plane's own example of a setting that must round-trip through a restart to take effect.
put_status="$(curl -sS -m 10 -o "$W/put.body" -w '%{http_code}' -X PUT "http://127.0.0.1:${AP}/api/v1/admin/config/settings" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"advanced":{"response_headers":{"server_timing":true}}}')"
step put_settings_status "$put_status"
step put_settings_body "$(cat "$W/put.body" 2>/dev/null | tr -d '\n')"

restart_status="$(curl -sS -m 10 -o "$W/restart.body" -w '%{http_code}' -X POST "http://127.0.0.1:${AP}/api/v1/admin/restart" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d '{"confirm":true}')"
step restart_status "$restart_status"
step restart_body "$(cat "$W/restart.body" 2>/dev/null | tr -d '\n')"

# the restart drains and exits the process itself (no supervisor here) — wait for the port to free
i=0; while [ $i -lt 100 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done
step process_exited "$(assert_port_free "$LP" && echo true || echo false)"

# a fresh launch against the SAME config + overlay (the "supervisor" restarting it) must come back
# up clean AND now emit the Server-Timing header the pre-restart PUT staged — proving the setting
# survived the restart it required, without any shell access to the box in between.
pid2="$(boot "$W/boot2.stdout" "$W/boot2.stderr")"; track_pid "$pid2"
relaunch_ok="false"
wait_for_http "http://127.0.0.1:${LP}/healthz" 30 && relaunch_ok="true"
step relaunch_after_restart_healthy "$relaunch_ok"
if [ "$relaunch_ok" = "true" ]; then
  hdrs="$(curl -sS -m 5 -D - -o /dev/null "http://127.0.0.1:${LP}/healthz")"
  step server_timing_header_after_relaunch "$(echo "$hdrs" | grep -qi '^server-timing:' && echo true || echo false)"
fi
kill "$pid2" 2>/dev/null; wait "$pid2" 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done

combined_stderr="--- boot1 ---
$(cat "$W/boot1.stderr" 2>/dev/null)
--- boot2 ---
$(cat "$W/boot2.stderr" 2>/dev/null)
"
eff="$(jq -c --arg v "$combined_stderr" '. + {stderr: $v}' <<<"$eff")"
jq -n --argjson eff "$eff" --arg body "$(jq -c 'del(.stderr)' <<<"$eff")" '{status:0, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"
