#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell: proves rotation actually cuts the OLD token over on the DATA plane, with no
# grace period, and that the NEW token is live right away — on the same node that did the rotate.
# The gap this closes: earlier rotate cells only checked the shape of the admin rotate response;
# nothing spent through the data plane with the pre-rotation token afterward. Steps, on our own
# throwaway boot (auth chain only, no store plugin needed):
#   1. mint a key in the `oracle` group
#   2. spend once with the original token through the mock upstream       -> expect 200
#   3. rotate the key via the admin API (mints a fresh token, same key id)
#   4. spend again with the OLD token                                      -> expect 401, immediately,
#      no grace period (this is a same-node rotate: the design says the old token dies at once here)
#   5. spend with the NEW token                                            -> expect 200
#   6. read /usage before step 2 and after step 5: the diff must show exactly two billed requests
#      (the two 200s; the rejected old-token spend bills nothing)
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
LP="${ROTATE_LISTEN_PORT:-${SCRIPT_LISTEN_PORT:-48861}}" AP="${ROTATE_ADMIN_PORT:-${SCRIPT_ADMIN_PORT:-48862}}" MP="${ROTATE_MOCK_PORT:-${SCRIPT_MOCK_PORT:-48796}}"
W="$RAW/rotate-work"; mkdir -p "$W"

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

mint="$(curl -sS -m 10 -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d '{"name":"rotate-oracle","group":"oracle"}')"
kid="$(jq -r '.id // empty' <<<"$mint")"; old_tok="$(jq -r '.token // empty' <<<"$mint")"
[ -n "$kid" ] && [ -n "$old_tok" ] || fail 2 "$mint"
step mint_status "201"

spend() {  # spend <token> -> writes $W/spend.body, prints status
  curl -sS -m 20 -o "$W/spend.body" -w '%{http_code}' -X POST "http://127.0.0.1:${LP}/v1/chat/completions" \
    -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
    -d '{"model":"m-openai-chat","messages":[{"role":"user","content":"ping"}]}'
}
usage_of() { curl -sS -m 10 -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/keys/${kid}/usage" | jq -c 'del(.as_of)'; }

sleep 0.3
u_before="$(usage_of)"; stepjson usage_before "$u_before"

st1="$(spend "$old_tok")"; step spend1_status "$st1"

rotate="$(curl -sS -m 10 -w '\n%{http_code}' -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys/${kid}/rotate" -H "Authorization: Bearer $ADMIN")"
rotate_status="$(tail -1 <<<"$rotate")"; rotate_body="$(sed '$d' <<<"$rotate")"
new_tok="$(jq -r '.token // empty' <<<"$rotate_body")"
[ -n "$new_tok" ] || fail 3 "$rotate_body"
step rotate_status "$rotate_status"

# NO grace period: the old token must be refused IMMEDIATELY, not after some delay.
st2="$(spend "$old_tok")"; step spend2_old_status "$st2"
spend2_body="$(cat "$W/spend.body" 2>/dev/null || echo '{}')"
stepjson spend2_old_body "$(jq -c . <<<"$spend2_body" 2>/dev/null || jq -n --arg raw "$spend2_body" '{raw:$raw}')"

st3="$(spend "$new_tok")"; step spend3_new_status "$st3"

sleep 0.5
u_after="$(usage_of)"; stepjson usage_after "$u_after"

req_delta="$(jq -n --argjson a "$(jq -r '.requests // 0' <<<"$u_before")" --argjson b "$(jq -r '.requests // 0' <<<"$u_after")" '$b - $a')"
step usage_requests_delta "$req_delta"

kill $pid 2>/dev/null; wait $pid 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done

result="$(jq -n \
  --argjson mint_status "$(jq -r .mint_status <<<"$eff")" \
  --argjson spend1_status "$(jq -r .spend1_status <<<"$eff")" \
  --argjson rotate_status "$(jq -r .rotate_status <<<"$eff")" \
  --argjson spend2_old_status "$(jq -r .spend2_old_status <<<"$eff")" \
  --argjson spend2_old_body "$(jq -c .spend2_old_body <<<"$eff")" \
  --argjson spend3_new_status "$(jq -r .spend3_new_status <<<"$eff")" \
  --argjson usage_requests_delta "$(jq -r .usage_requests_delta <<<"$eff")" \
  '{mint_status:$mint_status, spend1_status:$spend1_status, rotate_status:$rotate_status,
    spend2_old_status:$spend2_old_status, spend2_old_body:$spend2_old_body,
    spend3_new_status:$spend3_new_status, usage_requests_delta:$usage_requests_delta}')"

jq -n --argjson eff "$eff" --arg body "$result" '{status:0, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"
