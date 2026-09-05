#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell: proves what actually happens when a key is minted with `expires_at` set in
# the past, on the DATA plane — not just the shape of the mint response. The design binding this
# checks is that 1.5.5 never enforced a stored key-level expiry field on the request path (only a
# signed token's own `exp` claim is a live expiry check); this script records the REAL outcome
# rather than assuming it, because the admin API also independently rejects an `expires_at` that
# is not in the future for the token-expiry parameter of the SAME name, and the two facts must be
# told apart on the actual binary rather than guessed from the design doc.
#   1. mint a key in the `oracle` group with `expires_at` far in the past (Unix epoch + 1)
#   2. if the mint succeeded (2xx, a token came back): spend once through the mock upstream
#      3. if the mint was refused (4xx): spend is not attempted; spend_status stays null
#
# Writes $RAW/captured.json: status = 0 once the script ran to completion (else the failing step
# number for infra failures only — a REFUSED mint is not an infra failure, it is the recorded
# outcome), body = the whole result object below (so the cell body IS the contract), effects = the
# same fields individually (forensics/diffing convenience).
#
# Env from the recorder: BUSBAR_BIN RAW WORK ORACLE_ADMIN_TOKEN
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"
BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"; ADMIN="${ORACLE_ADMIN_TOKEN:-shadow-oracle-admin}"
LP="${EXPIRY_LISTEN_PORT:-48871}" AP="${EXPIRY_ADMIN_PORT:-48872}" MP="${EXPIRY_MOCK_PORT:-48797}"
W="$RAW/expiry-work"; mkdir -p "$W"

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

# Unix epoch + 1 second: unambiguously in the past on any clock, and not "mutually exclusive with
# expires_in" since we never set that field.
mint="$(curl -sS -m 10 -w '\n%{http_code}' -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"name":"expiry-oracle","group":"oracle","expires_at":1}')"
mint_status="$(tail -1 <<<"$mint")"; mint_body="$(sed '$d' <<<"$mint")"
step mint_status "$mint_status"
stepjson mint_body "$(jq -c . <<<"$mint_body" 2>/dev/null || jq -n --arg raw "$mint_body" '{raw:$raw}')"

tok="$(jq -r '.token // empty' <<<"$mint_body" 2>/dev/null || true)"
spend_status="null"; spend_body="null"
if [ -n "$tok" ]; then
  spend_status="$(curl -sS -m 20 -o "$W/spend.body" -w '%{http_code}' -X POST "http://127.0.0.1:${LP}/v1/chat/completions" \
    -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' \
    -d '{"model":"m-openai-chat","messages":[{"role":"user","content":"ping"}]}')"
  spend_body="$(jq -c . "$W/spend.body" 2>/dev/null || jq -n --arg raw "$(cat "$W/spend.body" 2>/dev/null)" '{raw:$raw}')"
fi
step spend_status "$spend_status"
stepjson spend_body "$spend_body"

kill $pid 2>/dev/null; wait $pid 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done

result="$(jq -n \
  --argjson mint_status "$(jq -r .mint_status <<<"$eff")" \
  --argjson mint_body "$(jq -c .mint_body <<<"$eff")" \
  --argjson spend_status "$(jq -r .spend_status <<<"$eff")" \
  --argjson spend_body "$(jq -c .spend_body <<<"$eff")" \
  '{mint_status:$mint_status, mint_body:$mint_body, spend_status:$spend_status, spend_body:$spend_body}')"

jq -n --argjson eff "$eff" --arg body "$result" '{status:0, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"
