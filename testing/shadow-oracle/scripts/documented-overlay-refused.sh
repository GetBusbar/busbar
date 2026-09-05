#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell for the PB-71 `documented` family. Proves the ACTUAL 1.5.5 behaviour behind
# two documented-behaviour claims about a config with no writable overlay (`config.locked: true`,
# or a writable-by-declaration config whose overlay backend cannot actually be written):
#   - README.md:272 (CONTRADICTED — the code does NOT refuse to boot; PB-71 pins the code)
#   - CHANGELOG.md:40-46 (1.5.4 entry, CONFIRMED — boots, serves, WARNs, refuses admin mutations)
# One arg selects which config shape is under test; both land on the SAME `overlay_path == None`
# code path (config/overlay.rs; main.rs:1053-1073 in the 1.5.5 tag), so the observable facts —
# boots to /healthz, then refuses a PUT /api/v1/admin/config/settings with the fixed
# NO_WRITABLE_OVERLAY_MSG — are identical for both variants; only the boot-time WARN/INFO line text
# differs, which the harvested log tail preserves for the differ to compare byte-for-byte.
#
#   documented-overlay-refused.sh <locked|overlay-unwritable>
#
# Writes $RAW/captured.json: status = 0 once the boot + mutation attempt both ran (else the failing
# step number). Env from the recorder: BUSBAR_BIN RAW WORK ORACLE_ADMIN_TOKEN.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"
BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"; ADMIN="${ORACLE_ADMIN_TOKEN:-shadow-oracle-admin}"
VARIANT="${1:-overlay-unwritable}"
LP="${OVRL_LISTEN_PORT:-${SCRIPT_LISTEN_PORT:-48901}}" AP="${OVRL_ADMIN_PORT:-${SCRIPT_ADMIN_PORT:-48902}}"
W="$RAW/overlay-work"; mkdir -p "$W"

for p in "$LP" "$AP"; do
  assert_port_free "$p" || { echo "{\"status\":-1,\"headers\":{},\"body\":\"\",\"effects\":{\"error\":\"port $p busy\"}}" >"$RAW/captured.json"; exit 0; }
done

"$BIN" --generate-signing-key >"$W/signing.key" 2>/dev/null
cat >"$W/providers.yaml" <<YAML
openai-chat:
  protocol: openai
  base_url: "http://127.0.0.1:1"
YAML

case "$VARIANT" in
  locked) config_block='config:
  locked: true' ;;
  overlay-unwritable) config_block='config:
  overlay:
    file: "/dev/null/oracle-overlay.json"' ;;
  *) echo "{\"status\":-1,\"headers\":{},\"body\":\"\",\"effects\":{\"error\":\"unknown variant $VARIANT\"}}" >"$RAW/captured.json"; exit 0 ;;
esac

cat >"$W/config.yaml" <<YAML
listen: "127.0.0.1:${LP}"
admin_listen: "127.0.0.1:${AP}"
${config_block}
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
stepbool() { eff="$(jq -c --arg k "$1" --argjson v "$2" '. + {($k): $v}' <<<"$eff")"; }
fail() { jq -n --argjson st "$1" --argjson eff "$eff" --arg body "$2" '{status:$st, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"; exit 0; }

( exec env BUSBAR_CONFIG="$W/config.yaml" BUSBAR_PROVIDERS="$W/providers.yaml" \
    ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN="$ADMIN" RUST_LOG=warn "$BIN" ) >"$W/busbar.log" 2>&1 &
pid=$!; track_pid $pid
if wait_for_http "http://127.0.0.1:${LP}/healthz" 30; then
  stepbool booted true
else
  stepbool booted false
  fail 1 "$(tail -c 800 "$W/busbar.log")"
fi

step boot_log_tail "$(tail -c 1200 "$W/busbar.log" | tr -d '\000')"

mut_status="$(curl -sS -m 10 -o "$W/mut.body" -w '%{http_code}' -X PUT "http://127.0.0.1:${AP}/api/v1/admin/config/settings" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"limits":{"request_body_max_bytes":33554432}}')"
step mutation_status "$mut_status"
stepjson_body="$(cat "$W/mut.body" 2>/dev/null || echo '{}')"
eff="$(jq -c --arg v "$stepjson_body" '. + {mutation_body: ($v | try fromjson catch {raw: $v})}' <<<"$eff")"

kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done

jq -n --argjson eff "$eff" --arg body "$(jq -c . <<<"$eff")" '{status:0, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"
