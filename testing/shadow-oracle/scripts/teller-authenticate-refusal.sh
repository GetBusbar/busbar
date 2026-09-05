#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell: `teller|authenticate-refusal` -- H2 (ARCHITECTURE.md #2.2 step 1, AUTHENTICATE).
# Proves the Teller order at step 1: a bad credential is refused BEFORE step 2 (VERIFY) is ever
# reached, so no upstream egress is dialled and no admission slot is drawn. 1.5.5 has no "Teller"
# vocabulary, but it already realises the order (auth middleware runs before routing/admission), so
# this cell must PASS unmodified on the published 1.5.5 binary.
#
# Steps, on our own throwaway boot (mirrors key-revoke.sh's shape):
#   1. request the data plane with a garbage bearer token           -> expect the ingress-native 401
#   2. read the mock upstream's own capture directory                -> expect ZERO files (no egress)
#   3. read /usage for the `oracle` group's key                      -> expect no requests recorded
#
# Writes $RAW/captured.json: status = 0 once all steps ran (else the failing step number).
#
# Env from the recorder: BUSBAR_BIN RAW WORK ORACLE_ADMIN_TOKEN SCRIPT_LISTEN_PORT SCRIPT_ADMIN_PORT
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"
BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"; ADMIN="${ORACLE_ADMIN_TOKEN:-shadow-oracle-admin}"
LP="${TELLER_LISTEN_PORT:-${SCRIPT_LISTEN_PORT:-49611}}" AP="${TELLER_ADMIN_PORT:-${SCRIPT_ADMIN_PORT:-49612}}" MP="${TELLER_MOCK_PORT:-${SCRIPT_MOCK_PORT:-49621}}"
W="$RAW/teller-work"; mkdir -p "$W" "$W/egress"

for p in "$LP" "$AP" "$MP"; do
  assert_port_free "$p" || { echo "{\"status\":-1,\"headers\":{},\"body\":\"\",\"effects\":{\"error\":\"port $p busy\"}}" >"$RAW/captured.json"; exit 0; }
done

ORACLE_MOCK_CAPTURE_DIR="$W/egress" python3 "${here}/mock-upstream.py" "$MP" oracle-marker "$W/mock.control" >"$W/mock.log" 2>&1 & track_pid $!
wait_for_http "http://127.0.0.1:${MP}/" 5

"$BIN" --generate-signing-key >"$W/signing.key" 2>/dev/null
cat >"$W/providers.yaml" <<YAML
openai-chat:
  protocol: openai
  base_url: "http://127.0.0.1:${MP}"
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
stepjson() { eff="$(jq -c --arg k "$1" --argjson v "$2" '. + {($k): $v}' <<<"$eff")"; }
fail() { jq -n --argjson st "$1" --argjson eff "$eff" --arg body "$2" '{status:$st, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"; exit 0; }

( exec env BUSBAR_CONFIG="$W/config.yaml" BUSBAR_PROVIDERS="$W/providers.yaml" \
    ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN="$ADMIN" RUST_LOG=warn "$BIN" ) >"$W/busbar.log" 2>&1 &
pid=$!; track_pid $pid
wait_for_http "http://127.0.0.1:${LP}/healthz" 30 || fail 1 "$(tail -c 500 "$W/busbar.log")"

mint="$(curl -sS -m 10 -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d '{"name":"teller-oracle","group":"oracle"}')"
kid="$(jq -r '.id // empty' <<<"$mint")"
[ -n "$kid" ] || fail 2 "$mint"
step mint_status "201"

# step 1: a garbage bearer token -> expect the ingress-native 401, never routed
auth_status="$(curl -sS -m 20 -o "$W/auth.body" -w '%{http_code}' -X POST "http://127.0.0.1:${LP}/v1/chat/completions" \
  -H 'Authorization: Bearer not-a-real-token' -H 'Content-Type: application/json' \
  -d '{"model":"m-openai-chat","messages":[{"role":"user","content":"ping"}]}')"
step auth_status "$auth_status"
stepjson auth_body "$(jq -c . "$W/auth.body" 2>/dev/null || jq -n --arg raw "$(cat "$W/auth.body" 2>/dev/null)" '{raw:$raw}')"

# step 2: the mock's own capture dir -- zero files means zero egress reached the upstream
egress_count="$(find "$W/egress" -type f 2>/dev/null | wc -l | tr -d ' ')"
step egress_count "$egress_count"

# step 3: usage for the mint'd key -- must show nothing drawn for a refusal this early
sleep 0.3
usage="$(curl -sS -m 10 -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/keys/${kid}/usage" | jq -c 'del(.as_of)')"
stepjson usage "$usage"

kill $pid 2>/dev/null; wait $pid 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done

result="$(jq -n \
  --argjson mint_status "$(jq -r .mint_status <<<"$eff")" \
  --argjson auth_status "$(jq -r .auth_status <<<"$eff")" \
  --argjson auth_body "$(jq -c .auth_body <<<"$eff")" \
  --argjson egress_count "$(jq -r .egress_count <<<"$eff")" \
  --argjson usage "$(jq -c .usage <<<"$eff")" \
  '{mint_status:$mint_status, auth_status:$auth_status, auth_body:$auth_body,
    egress_count:$egress_count, usage:$usage}')"

jq -n --argjson eff "$eff" --arg body "$result" '{status:0, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"
