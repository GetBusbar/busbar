#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell: `teller|exit-terminal` -- H2 (ARCHITECTURE.md #2.2 `exit`). Proves the ONE exit
# path contract: a unit that relays MULTIPLE response frames (a streamed answer -- several SSE
# events before the terminal one) still settles to exactly ONE terminal and ONE usage posting, never
# a post per frame and never a second post at the stream's terminal event. 1.5.5 has no "Teller"
# vocabulary but its own single finish-accounting path already realises this, so this cell must PASS
# unmodified on the published 1.5.5 binary.
#
# Steps, on our own throwaway boot:
#   1. mint a key
#   2. read /usage before
#   3. one STREAMED request (the mock's fixed multi-event SSE sequence: several deltas + a terminal
#      usage event) -- count the SSE frames actually relayed to the client
#   4. read /usage after                    -> expect requests +1 (not +N frames), one settle only
#
# Env from the recorder: BUSBAR_BIN RAW WORK ORACLE_ADMIN_TOKEN SCRIPT_LISTEN_PORT SCRIPT_ADMIN_PORT
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"
BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"; ADMIN="${ORACLE_ADMIN_TOKEN:-shadow-oracle-admin}"
LP="${TELLER_LISTEN_PORT:-${SCRIPT_LISTEN_PORT:-49611}}" AP="${TELLER_ADMIN_PORT:-${SCRIPT_ADMIN_PORT:-49612}}" MP="${TELLER_MOCK_PORT:-${SCRIPT_MOCK_PORT:-49621}}"
W="$RAW/teller-work"; mkdir -p "$W"

for p in "$LP" "$AP" "$MP"; do
  assert_port_free "$p" || { echo "{\"status\":-1,\"headers\":{},\"body\":\"\",\"effects\":{\"error\":\"port $p busy\"}}" >"$RAW/captured.json"; exit 0; }
done

python3 "${here}/mock-upstream.py" "$MP" oracle-marker "$W/mock.control" >"$W/mock.log" 2>&1 & track_pid $!
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

mint="$(curl -sS -m 10 -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d '{"name":"teller-exit","group":"oracle"}')"
kid="$(jq -r '.id // empty' <<<"$mint")"; tok="$(jq -r '.token // empty' <<<"$mint")"
[ -n "$kid" ] && [ -n "$tok" ] || fail 2 "$mint"
step mint_status "201"

usage_of() { curl -sS -m 10 -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/keys/${kid}/usage" | jq -c 'del(.as_of)'; }
sleep 0.3
u_before="$(usage_of)"; stepjson usage_before "$u_before"

stream_status="$(curl -sS -m 20 -N -o "$W/stream.body" -w '%{http_code}' -X POST "http://127.0.0.1:${LP}/v1/chat/completions" \
  -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' \
  -d '{"model":"m-openai-chat","stream":true,"messages":[{"role":"user","content":"ping"}]}')"
step stream_status "$stream_status"
frame_count="$(grep -c '^data:' "$W/stream.body" 2>/dev/null || echo 0)"
step sse_frame_count "$frame_count"

sleep 0.5
u_after="$(usage_of)"; stepjson usage_after "$u_after"
req_delta="$(jq -n --argjson a "$(jq -r '.requests // 0' <<<"$u_before")" --argjson b "$(jq -r '.requests // 0' <<<"$u_after")" '$b - $a')"
step usage_requests_delta "$req_delta"

# read again after a further pause: a duplicate/late settle would show up as further drift here
sleep 0.5
u_settled="$(usage_of)"
req_delta2="$(jq -n --argjson a "$(jq -r '.requests // 0' <<<"$u_after")" --argjson b "$(jq -r '.requests // 0' <<<"$u_settled")" '$b - $a')"
step usage_requests_delta_after_settle_pause "$req_delta2"

kill $pid 2>/dev/null; wait $pid 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done

result="$(jq -n \
  --argjson mint_status "$(jq -r .mint_status <<<"$eff")" \
  --argjson stream_status "$(jq -r .stream_status <<<"$eff")" \
  --argjson sse_frame_count "$(jq -r .sse_frame_count <<<"$eff")" \
  --argjson usage_requests_delta "$(jq -r .usage_requests_delta <<<"$eff")" \
  --argjson usage_requests_delta_after_settle_pause "$(jq -r .usage_requests_delta_after_settle_pause <<<"$eff")" \
  '{mint_status:$mint_status, stream_status:$stream_status, sse_frame_count:$sse_frame_count,
    usage_requests_delta:$usage_requests_delta,
    usage_requests_delta_after_settle_pause:$usage_requests_delta_after_settle_pause}')"

jq -n --argjson eff "$eff" --arg body "$result" '{status:0, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"
