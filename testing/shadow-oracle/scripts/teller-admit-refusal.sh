#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell: `teller|admit-refusal` -- H2 (ARCHITECTURE.md #2.2 step 4, ADMIT). Proves the
# Teller order at step 4: a principal already past AUTHENTICATE/VERIFY/APPROVE but over budget is
# refused at ADMIT (native 429, `OverBudget`), and the refusal never reaches ROUTE -- no egress is
# dialled. ARCHITECTURE.md's kernel-floor `estimated` line is a 1.6.0-internal record with no 1.5.5
# surface; what 1.5.5 already realises, and what this cell can prove against the published binary,
# is the OBSERVABLE half of that contract: the refusal precedes any egress, and posts no billable
# usage (1.5.5's check-then-charge returns on the first blocking bucket BEFORE charging).
#
# Steps, on our own throwaway boot:
#   1. mint a key in a group with a 1-cent/day budget (mirrors the oracle's own BROKE key)
#   2. request the data plane with that key                          -> expect the native 429
#   3. read the mock upstream's own capture directory                 -> expect ZERO files (no egress)
#   4. read /usage before and after                                   -> expect no spend/requests delta
#
# Env from the recorder: BUSBAR_BIN RAW WORK ORACLE_ADMIN_TOKEN SCRIPT_LISTEN_PORT SCRIPT_ADMIN_PORT
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"
BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"; ADMIN="${ORACLE_ADMIN_TOKEN:-shadow-oracle-admin}"
LP="${TELLER_LISTEN_PORT:-${SCRIPT_LISTEN_PORT:-49611}}" AP="${TELLER_ADMIN_PORT:-${SCRIPT_ADMIN_PORT:-49612}}" MP="${TELLER_MOCK_PORT:-${SCRIPT_MOCK_PORT:-49621}}"
W="$RAW/teller-work"; mkdir -p "$W"
# EMPTY, not just present: the mock drops one capture file per upstream request in here and
# this cell COUNTS them, so a re-record into an existing raw tree would count the last run's
# requests as well as its own.
rm -rf "$W/egress"; mkdir -p "$W/egress"

for p in "$LP" "$AP" "$MP"; do
  assert_port_free "$p" || { echo "{\"status\":-1,\"headers\":{},\"body\":\"\",\"effects\":{\"error\":\"port $p busy\"}}" >"$RAW/captured.json"; exit 0; }
done

ORACLE_MOCK_CAPTURE_DIR="$W/egress" python3 "${here}/mock-upstream.py" "$MP" oracle-marker "$W/mock.control" >"$W/mock.log" 2>&1 & track_pid $!
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
  broke:
    limits:
      - { budget: 1, per: day }
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

# THE CODE IS READ, NOT ASSERTED. `-w` appends the real status as a last line, so

# `mint_status` below is what this binary answered rather than what the harness

# assumed; a mint that stopped being a 201 is then a diff on this cell.

mint_raw="$(curl -sS -m 10 -w '\n%{http_code}' -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d '{"name":"teller-broke","group":"broke"}')"

mint_code="$(printf '%s' "$mint_raw" | tail -1)"

mint="$(printf '%s' "$mint_raw" | sed '$d')"
kid="$(jq -r '.id // empty' <<<"$mint")"; tok="$(jq -r '.token // empty' <<<"$mint")"
[ -n "$kid" ] && [ -n "$tok" ] || fail 2 "$mint"
step mint_status "$mint_code"

usage_of() { curl -sS -m 10 -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/keys/${kid}/usage" | jq -c 'del(.as_of)'; }
sleep 0.3
u_before="$(usage_of)"; stepjson usage_before "$u_before"

# step 2: a 1-cent/day budget is already spent by the fee lookahead on the FIRST call -- but the very
# first call, before anything is charged, still has zero spend recorded so it may legitimately admit;
# the SECOND call on the same exhausted budget is the one this cell judges -- refused at ADMIT.
curl -sS -m 20 -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${LP}/v1/chat/completions" \
  -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' \
  -d '{"model":"m-openai-chat","messages":[{"role":"user","content":"ping"}]}' >/dev/null
sleep 0.3
u_mid="$(usage_of)"; stepjson usage_mid "$u_mid"
mid_egress="$(find "$W/egress" -type f 2>/dev/null | wc -l | tr -d ' ')"

admit_status="$(curl -sS -m 20 -o "$W/admit.body" -w '%{http_code}' -X POST "http://127.0.0.1:${LP}/v1/chat/completions" \
  -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' \
  -d '{"model":"m-openai-chat","messages":[{"role":"user","content":"ping"}]}')"
step admit_status "$admit_status"
stepjson admit_body "$(jq -c . "$W/admit.body" 2>/dev/null || jq -n --arg raw "$(cat "$W/admit.body" 2>/dev/null)" '{raw:$raw}')"

after_egress="$(find "$W/egress" -type f 2>/dev/null | wc -l | tr -d ' ')"
egress_delta="$((after_egress - mid_egress))"
step egress_delta_on_refusal "$egress_delta"

sleep 0.3
u_after="$(usage_of)"; stepjson usage_after "$u_after"
spend_delta="$(jq -n --argjson a "$(jq -r '.spend_cents // 0' <<<"$u_mid")" --argjson b "$(jq -r '.spend_cents // 0' <<<"$u_after")" '$b - $a')"
req_delta="$(jq -n --argjson a "$(jq -r '.requests // 0' <<<"$u_mid")" --argjson b "$(jq -r '.requests // 0' <<<"$u_after")" '$b - $a')"
step usage_spend_cents_delta_on_refusal "$spend_delta"
step usage_requests_delta_on_refusal "$req_delta"

kill $pid 2>/dev/null; wait $pid 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done

if ! result="$(jq -n \
  --argjson mint_status "$(jq -r .mint_status <<<"$eff")" \
  --argjson admit_status "$(jq -r .admit_status <<<"$eff")" \
  --argjson admit_body "$(jq -c .admit_body <<<"$eff")" \
  --argjson egress_delta_on_refusal "$(jq -r .egress_delta_on_refusal <<<"$eff")" \
  --argjson usage_spend_cents_delta_on_refusal "$(jq -r .usage_spend_cents_delta_on_refusal <<<"$eff")" \
  --argjson usage_requests_delta_on_refusal "$(jq -r .usage_requests_delta_on_refusal <<<"$eff")" \
  '{mint_status:$mint_status, admit_status:$admit_status, admit_body:$admit_body,
    egress_delta_on_refusal:$egress_delta_on_refusal,
    usage_spend_cents_delta_on_refusal:$usage_spend_cents_delta_on_refusal,
    usage_requests_delta_on_refusal:$usage_requests_delta_on_refusal}' 2>"$W/result.err")"; then
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
