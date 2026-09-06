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
# CHECKED: an unchecked wait here let the cell run with NO upstream and record whatever busbar
# answers to that as the contract. fail() is defined further down (it needs $eff), so refuse in
# the same -1 shape the port-busy guard above uses -- record.sh reads it as UNSUPPORTED, not a pass.
wait_for_http "http://127.0.0.1:${MP}/" 5 || { echo '{"status":-1,"headers":{},"body":"","effects":{"error":"mock upstream did not come up"}}' >"$RAW/captured.json"; exit 0; }

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
# A `fail` IS THE HARNESS GIVING UP, NOT AN OUTCOME OF THE BINARY. It writes a captured.json like
# any other result, and the recorder used to read `status` alone — so `fail 1 "openssl produced no
# cert"` was recorded as a golden that says "this cell is exit 1", with a PASS row behind it, and
# the candidate agreed because it failed the same way. `harness_error` says which of the two this
# is; record.sh refuses any cell that carries it (a status of -1 stays a named gap, as before).
fail() { jq -n --argjson st "$1" --argjson eff "$eff" --arg body "$2" '{status:$st, headers:{}, body:$body, effects:($eff + {harness_error: $body})}' >"$RAW/captured.json"; exit 0; }

( exec env BUSBAR_CONFIG="$W/config.yaml" BUSBAR_PROVIDERS="$W/providers.yaml" \
    ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN="$ADMIN" RUST_LOG=warn "$BIN" ) >"$W/busbar.log" 2>&1 &
pid=$!; track_pid $pid
wait_for_http "http://127.0.0.1:${LP}/healthz" 30 || fail 1 "$(tail -c 500 "$W/busbar.log")"

audit_of() { curl -sS -m 10 -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/audit?limit=10"; }
a_before="$(audit_of)"; stepjson audit_before "$a_before"
n_before="$(jq '.items | length' <<<"$a_before")"

# THE CODE IS READ, NOT ASSERTED. `-w` appends the real status as a last line, so

# `mint_status` below is what this binary answered rather than what the harness

# assumed; a mint that stopped being a 201 is then a diff on this cell.

mint_raw="$(curl -sS -m 10 -w '\n%{http_code}' -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d '{"name":"teller-audit","group":"oracle"}')"

mint_code="$(printf '%s' "$mint_raw" | tail -1)"

mint="$(printf '%s' "$mint_raw" | sed '$d')"
kid="$(jq -r '.id // empty' <<<"$mint")"
[ -n "$kid" ] || fail 2 "$mint"
step mint_status "$mint_code"

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

if ! result="$(jq -n \
  --argjson mint_status "$(jq -r .mint_status <<<"$eff")" \
  --argjson audit_entry_delta "$(jq -r .audit_entry_delta <<<"$eff")" \
  --arg newest_action "$(jq -r .newest_action <<<"$eff")" \
  --arg newest_outcome "$(jq -r .newest_outcome <<<"$eff")" \
  --arg newest_resource_names_key "$(jq -r .newest_resource_names_key <<<"$eff")" \
  --arg first_entry_prev_hash_empty "$(jq -r .first_entry_prev_hash_empty <<<"$eff")" \
  '{mint_status:$mint_status, audit_entry_delta:$audit_entry_delta,
    newest_action:$newest_action, newest_outcome:$newest_outcome,
    newest_resource_names_key:$newest_resource_names_key,
    first_entry_prev_hash_empty:$first_entry_prev_hash_empty}' 2>"$W/result.err")"; then
  # CHECKED. Every value above is a number this run measured; if any of them is not one, the cell
  # measured something it cannot state and the body would go out EMPTY — and an empty body with
  # status 0 compares clean against a golden that failed the same way, which is the vacuous green
  # the ledger exists to refuse. Record the -1 UNSUPPORTED shape record.sh reads as a named gap.
  jq -n --argjson eff "$eff" --arg e "$(tr '\n' ' ' <"$W/result.err" | tail -c 200)" \
    '{status:-1, headers:{}, body:"", effects:($eff + {error: ("the cell body could not be assembled from its own measurements: " + $e)})}' \
    >"$RAW/captured.json"
  exit 0
fi

jq -n --argjson eff "$eff" --arg body "$result" '{status:0, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"
