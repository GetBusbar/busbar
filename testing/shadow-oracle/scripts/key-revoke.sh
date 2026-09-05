#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell: proves that revocation actually stops the data plane, not just the admin
# response. The gap this closes: every earlier revoke/rotate cell only checked the SHAPE of the
# revoke/rotate admin response; nothing spent through the data plane with the affected token
# afterward. Steps, on our own throwaway boot (auth chain only, no store plugin needed):
#   1. mint a key in the `oracle` group
#   2. spend once with its token through the mock upstream           -> expect 200
#   3. revoke the key via the admin API
#   4. spend again with the SAME (now revoked) token                  -> expect the ingress-native
#      401 (busbar never hands out a busbar-specific revoked-key error; the data plane always
#      answers with the dialect's own auth-failure shape, here OpenAI's)
#   5. read /usage before and after step 4 and diff it: a revoked spend must bill NOTHING
#
# Writes $RAW/captured.json: status = 0 once all steps ran (else the failing step number), body =
# the whole result object below (so the cell body IS the contract), effects = the same fields
# individually (forensics/diffing convenience).
#
# Env from the recorder: BUSBAR_BIN RAW WORK ORACLE_ADMIN_TOKEN
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"
BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"; ADMIN="${ORACLE_ADMIN_TOKEN:-shadow-oracle-admin}"
LP="${REVOKE_LISTEN_PORT:-${SCRIPT_LISTEN_PORT:-48851}}" AP="${REVOKE_ADMIN_PORT:-${SCRIPT_ADMIN_PORT:-48852}}" MP="${REVOKE_MOCK_PORT:-${SCRIPT_MOCK_PORT:-48795}}"
W="$RAW/revoke-work"; mkdir -p "$W"

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

# `exec` inside the backgrounded subshell so $! is busbar's OWN pid, not a wrapper subshell's — a
# plain `env VAR=val "$BIN" &` backgrounds a subshell running that command, and killing the
# subshell orphans busbar (it keeps the listen port and the next boot on this port hangs forever).
( exec env BUSBAR_CONFIG="$W/config.yaml" BUSBAR_PROVIDERS="$W/providers.yaml" \
    ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN="$ADMIN" RUST_LOG=warn "$BIN" ) >"$W/busbar.log" 2>&1 &
pid=$!; track_pid $pid
wait_for_http "http://127.0.0.1:${LP}/healthz" 30 || fail 1 "$(tail -c 500 "$W/busbar.log")"

mint="$(curl -sS -m 10 -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d '{"name":"revoke-oracle","group":"oracle"}')"
kid="$(jq -r '.id // empty' <<<"$mint")"; tok="$(jq -r '.token // empty' <<<"$mint")"
[ -n "$kid" ] && [ -n "$tok" ] || fail 2 "$mint"
step mint_status "201"

spend() {  # spend <token> -> writes $W/spend.body, prints status
  curl -sS -m 20 -o "$W/spend.body" -w '%{http_code}' -X POST "http://127.0.0.1:${LP}/v1/chat/completions" \
    -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
    -d '{"model":"m-openai-chat","messages":[{"role":"user","content":"ping"}]}'
}
usage_of() { curl -sS -m 10 -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/keys/${kid}/usage" | jq -c 'del(.as_of)'; }

st1="$(spend "$tok")"; step spend1_status "$st1"

sleep 0.5   # let write-behind metering settle before the "before" snapshot
u_before="$(usage_of)"; stepjson usage_before "$u_before"

rev_status="$(curl -sS -m 10 -o "$W/revoke.body" -w '%{http_code}' -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys/${kid}/revoke" -H "Authorization: Bearer $ADMIN")"
step revoke_status "$rev_status"

st2="$(spend "$tok")"; step spend2_status "$st2"
spend2_body="$(cat "$W/spend.body" 2>/dev/null || echo '{}')"
stepjson spend2_body "$(jq -c . <<<"$spend2_body" 2>/dev/null || jq -n --arg raw "$spend2_body" '{raw:$raw}')"

sleep 0.5
u_after="$(usage_of)"; stepjson usage_after "$u_after"

req_delta="$(jq -n --argjson a "$(jq -r '.requests // 0' <<<"$u_before")" --argjson b "$(jq -r '.requests // 0' <<<"$u_after")" '$b - $a')"
spend_delta="$(jq -n --argjson a "$(jq -r '.spend_cents // 0' <<<"$u_before")" --argjson b "$(jq -r '.spend_cents // 0' <<<"$u_after")" '$b - $a')"
step usage_requests_delta "$req_delta"
step usage_spend_cents_delta "$spend_delta"

kill $pid 2>/dev/null; wait $pid 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done

result="$(jq -n \
  --argjson mint_status "$(jq -r .mint_status <<<"$eff")" \
  --argjson spend1_status "$(jq -r .spend1_status <<<"$eff")" \
  --argjson revoke_status "$(jq -r .revoke_status <<<"$eff")" \
  --argjson spend2_status "$(jq -r .spend2_status <<<"$eff")" \
  --argjson spend2_body "$(jq -c .spend2_body <<<"$eff")" \
  --argjson usage_requests_delta "$(jq -r .usage_requests_delta <<<"$eff")" \
  --argjson usage_spend_cents_delta "$(jq -r .usage_spend_cents_delta <<<"$eff")" \
  '{mint_status:$mint_status, spend1_status:$spend1_status, revoke_status:$revoke_status,
    spend2_status:$spend2_status, spend2_body:$spend2_body,
    usage_requests_delta:$usage_requests_delta, usage_spend_cents_delta:$usage_spend_cents_delta}')"

jq -n --argjson eff "$eff" --arg body "$result" '{status:0, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"
