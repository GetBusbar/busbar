#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell: `teller|audit-record` -- H2 (ARCHITECTURE.md #2.2 step 7, AUDIT). Proves the
# Teller order at step 7: a governed unit that mutates state seals ITS OWN audit record -- the chain
# gains EXACTLY one entry, naming the right action and outcome, with the link-integrity contract
# (first entry's prev_hash is empty; hash is a function of the entry). The data-plane `llm` request
# path in 1.5.5 emits no audit entry of its own (confirmed empirically: a plain chat completion,
# refused or served, leaves the chain untouched) -- the KernelVerb / admin path is where 1.5.5
# already realises step 7's contract, so THIS is the cell that proves it, one action at a time,
# smaller than admin.ops|GetAudit's four-action chain (which already pins the fuller chain-of-four).
#
# Steps, on our own throwaway boot:
#   1. read /api/v1/admin/audit                          -> expect zero entries (fresh boot)
#   2. one admin mutation (mint a key)
#   3. read /api/v1/admin/audit again                     -> expect EXACTLY one new entry, action
#      `key.create`, outcome `applied`, resource naming the minted key, prev_hash empty
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

audit_of() { curl -sS -m 10 -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/audit?limit=10"; }
a_before="$(audit_of)"; stepjson audit_before "$a_before"
n_before="$(jq '.items | length' <<<"$a_before")"

mint="$(curl -sS -m 10 -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d '{"name":"teller-audit","group":"oracle"}')"
kid="$(jq -r '.id // empty' <<<"$mint")"
[ -n "$kid" ] || fail 2 "$mint"
step mint_status "201"

sleep 0.3
a_after="$(audit_of)"; stepjson audit_after "$a_after"
n_after="$(jq '.items | length' <<<"$a_after")"
step audit_entry_delta "$((n_after - n_before))"

newest="$(jq -c '.items[0]' <<<"$a_after")"
stepjson newest_entry "$newest"
step newest_action "$(jq -r '.action // ""' <<<"$newest")"
step newest_outcome "$(jq -r '.outcome // ""' <<<"$newest")"
step newest_resource_names_key "$(jq -r --arg kid "$kid" 'if (.resource // "") | contains($kid) then "true" else "false" end' <<<"$newest")"
step first_entry_prev_hash_empty "$(jq -r 'if (.prev_hash // "x") == "" then "true" else "false" end' <<<"$newest")"

kill $pid 2>/dev/null; wait $pid 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done

result="$(jq -n \
  --argjson mint_status "$(jq -r .mint_status <<<"$eff")" \
  --argjson audit_entry_delta "$(jq -r .audit_entry_delta <<<"$eff")" \
  --arg newest_action "$(jq -r .newest_action <<<"$eff")" \
  --arg newest_outcome "$(jq -r .newest_outcome <<<"$eff")" \
  --arg newest_resource_names_key "$(jq -r .newest_resource_names_key <<<"$eff")" \
  --arg first_entry_prev_hash_empty "$(jq -r .first_entry_prev_hash_empty <<<"$eff")" \
  '{mint_status:$mint_status, audit_entry_delta:$audit_entry_delta,
    newest_action:$newest_action, newest_outcome:$newest_outcome,
    newest_resource_names_key:$newest_resource_names_key,
    first_entry_prev_hash_empty:$first_entry_prev_hash_empty}')"

jq -n --argjson eff "$eff" --arg body "$result" '{status:0, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"
