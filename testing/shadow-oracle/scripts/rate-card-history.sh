#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell `billing|rate-card|history-mid-window` (tracker M7; design
# the first cell the rate-card-history design lists for the oracle).
#
# WHAT IT ASKS. `billing|rate-card|epoch-mid-window` already recorded what ONE mid-window card edit
# does to ONE read: the whole ledger comes back at the new card. This cell asks the question that
# one cannot: what happens to the SAME request as the window goes on. Two complete cards are written
# into one window with a chat either side of each, and /api/v1/admin/usage is read after EVERY
# write — so the first request's price is observed three times, under three different current cards.
#
#   chat1                       (boot card:  input 100000 / output 200000 per token)
#   PUT /config/settings        card A: 10x the boot card, complete, no per-request fee
#   GET /admin/usage            -> usage_after_a
#   chat2
#   PUT /config/settings        card B: 100x the boot card + a 3-cent per_request_fee
#   GET /admin/usage            -> usage_after_b
#   chat3
#   GET /admin/usage            -> usage_final
#
# WHY THE SCRIPT DRIVER AND NOT `pre`. record.sh's run_pre_request is UNRECORDED by construction: it
# checks only that busbar answered, never what it answered. The finding here is the RELATION between
# the three reads, so an http cell could record only the last one and would have to assert the other
# two in prose — which is exactly the kind of claim the oracle exists to replace with bytes.
#
# WHY THE FIGURES ARE THESE FIGURES. The mock answers every request with the same 11 in / 7 out, so
# one request costs 11*100000 + 7*200000 = 2,500,000 micro-units under the BOOT card, 25,000,000
# under card A, and 11*10,000,000 + 7*20,000,000 + a 3-cent fee (30,000 micro-units) = 250,030,000
# under card B. The three hypotheses therefore separate arithmetically at each read rather than
# merely differing:
#
#   usage_after_a   read-time reprice: 25,000,000  |  priced-at-charge: 2,500,000
#   usage_after_b   read-time reprice: 500,060,000 |  priced-at-charge: 27,500,000
#   usage_final     read-time reprice: 750,090,000 |  priced-at-charge: 277,530,000
#                                                  |  1.6.0 history:    277,530,000
#
# The priced-at-charge column IS the 1.6.0 answer for this sequence, which is the point: the cell is
# recorded from 1.5.5 now so that when M6 lands, the move is a diff on a golden that predates it.
#
# UNITS, since they are not the same field to field: `rate_card`'s *_utok are MICRO-units per token,
# `spend_micros` is micro-units, and `per_request_fee` is an i64 in CENTS (1 cent = 10,000 micros).
# The `oracle` group's 1,000,000/day budget is in cents; the largest read here is 750,090,000 micros
# = 75,009 cents, so no request in this cell is ever refused at Admit for budget. That is checked,
# not assumed: every chat's status is recorded, so a 429 would be visible in the cell body rather
# than quietly costing the window a row.
#
# COMPLETE CARDS ON PURPOSE. 1.5.5 refuses a partial card with a 400 ("rate_card is AUTHORITATIVE
# and COMPLETE") — see the sibling cell `config|rate-card|append-not-replace`, which records that
# refusal — and a history cell whose writes were refused would record the boot card three times and
# call that a finding. Both PUT statuses are in the body for exactly that reason.
#
# Writes $RAW/captured.json: status = 0 once all steps ran, body = the whole result object (so the
# cell body IS the contract), effects = the same fields individually.
#
# Env from the recorder: BUSBAR_BIN RAW WORK ORACLE_ADMIN_TOKEN SCRIPT_{LISTEN,ADMIN,MOCK}_PORT
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"
BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"; ADMIN="${ORACLE_ADMIN_TOKEN:-shadow-oracle-admin}"
LP="${RCH_LISTEN_PORT:-${SCRIPT_LISTEN_PORT:-48861}}"
AP="${RCH_ADMIN_PORT:-${SCRIPT_ADMIN_PORT:-48862}}"
MP="${RCH_MOCK_PORT:-${SCRIPT_MOCK_PORT:-48796}}"
W="$RAW/rch-work"; mkdir -p "$W"

for p in "$LP" "$AP" "$MP"; do
  assert_port_free "$p" || { echo "{\"status\":-1,\"headers\":{},\"body\":\"\",\"effects\":{\"error\":\"port $p busy\"}}" >"$RAW/captured.json"; exit 0; }
done

python3 "${BUSBAR_ORACLE_TOOL_DIR:-$here}/mock-upstream.py" "$MP" oracle-marker "$W/mock.control" >"$W/mock.log" 2>&1 & track_pid $!
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
fail() { jq -n --argjson st "$1" --argjson eff "$eff" --arg body "$2" '{status:$st, headers:{}, body:$body, effects:($eff + {harness_error: $body})}' >"$RAW/captured.json"; exit 0; }

( exec env BUSBAR_CONFIG="$W/config.yaml" BUSBAR_PROVIDERS="$W/providers.yaml" \
    ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN="$ADMIN" RUST_LOG=warn "$BIN" ) >"$W/busbar.log" 2>&1 &
pid=$!; track_pid $pid
wait_for_busbar "${LP}" "${AP}" 30 || fail 1 "$(tail -c 500 "$W/busbar.log")"

mint_raw="$(curl -sS -m 10 -w '\n%{http_code}' -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d '{"name":"rch-oracle","group":"oracle"}')"
mint_code="$(printf '%s' "$mint_raw" | tail -1)"; mint="$(printf '%s' "$mint_raw" | sed '$d')"
tok="$(jq -r '.token // empty' <<<"$mint")"
[ -n "$tok" ] || fail 2 "$mint"
step mint_status "$mint_code"

chat() {  # chat -> prints the status; the body is not the contract here, the price is
  curl -sS -m 20 -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${LP}/v1/chat/completions" \
    -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' \
    -d '{"model":"m-openai-chat","messages":[{"role":"user","content":"ping"}]}'
}

# THE WHOLE-WINDOW VIEW, not the per-key one: this cell is about what an INVOICE reads back as, and
# /admin/usage is the endpoint an invoice is read off. `window` and `as_of` are dropped because they
# carry the wall-clock day boundary the recording happened to fall on (normalize.py's ts.usage-window
# rule does the same for the http cells); everything that is money stays.
usage_of() {
  curl -sS -m 10 -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/usage" \
    | jq -c 'del(.window, .as_of) | del(.by_key[]?.id)'
}

# A card write. Complete on purpose (see the header): a partial card is a 400 and would leave the
# previous card in force with nothing to show for it.
put_card() {  # put_card <json-body> -> prints the status
  curl -sS -m 10 -o "$W/put.body" -w '%{http_code}' -X PUT "http://127.0.0.1:${AP}/api/v1/admin/config/settings" \
    -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d "$1"
}

CARD_A='{"rate_card":{"m-openai-chat":{"input_utok":1000000,"output_utok":2000000}}}'
CARD_B='{"per_request_fee":3,"rate_card":{"m-openai-chat":{"input_utok":10000000,"output_utok":20000000}}}'

sleep 0.3
stepjson usage_before "$(usage_of)"

step chat1_status "$(chat)"
sleep 0.3

step put_a_status "$(put_card "$CARD_A")"
stepjson put_a_body "$(jq -c . <"$W/put.body" 2>/dev/null || jq -n --arg raw "$(cat "$W/put.body")" '{raw:$raw}')"
sleep 0.3
stepjson usage_after_a "$(usage_of)"

step chat2_status "$(chat)"
sleep 0.3

step put_b_status "$(put_card "$CARD_B")"
stepjson put_b_body "$(jq -c . <"$W/put.body" 2>/dev/null || jq -n --arg raw "$(cat "$W/put.body")" '{raw:$raw}')"
sleep 0.3
stepjson usage_after_b "$(usage_of)"

step chat3_status "$(chat)"
sleep 0.5
stepjson usage_final "$(usage_of)"

kill $pid 2>/dev/null; wait $pid 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done

# THE BODY IS ASSEMBLED FROM MEASUREMENTS, AND THE ASSEMBLY IS CHECKED. If any field above is not
# the thing this run measured, the body would go out EMPTY and an empty body with status 0 compares
# clean against a golden that failed the same way — the vacuous green the ledger exists to refuse.
if ! result="$(jq -n \
  --argjson mint_status "$(jq -r .mint_status <<<"$eff")" \
  --argjson chat1_status "$(jq -r .chat1_status <<<"$eff")" \
  --argjson chat2_status "$(jq -r .chat2_status <<<"$eff")" \
  --argjson chat3_status "$(jq -r .chat3_status <<<"$eff")" \
  --argjson put_a_status "$(jq -r .put_a_status <<<"$eff")" \
  --argjson put_b_status "$(jq -r .put_b_status <<<"$eff")" \
  --argjson usage_before "$(jq -c .usage_before <<<"$eff")" \
  --argjson usage_after_a "$(jq -c .usage_after_a <<<"$eff")" \
  --argjson usage_after_b "$(jq -c .usage_after_b <<<"$eff")" \
  --argjson usage_final "$(jq -c .usage_final <<<"$eff")" \
  '{mint_status:$mint_status, chat1_status:$chat1_status, put_a_status:$put_a_status,
    usage_after_a:$usage_after_a, chat2_status:$chat2_status, put_b_status:$put_b_status,
    usage_after_b:$usage_after_b, chat3_status:$chat3_status, usage_final:$usage_final,
    usage_before:$usage_before,
    spend_after_a:($usage_after_a.total.spend_micros // null),
    spend_after_b:($usage_after_b.total.spend_micros // null),
    spend_final:($usage_final.total.spend_micros // null)}' 2>"$W/result.err")"; then
  jq -n --argjson eff "$eff" --arg e "$(tr '\n' ' ' <"$W/result.err" | tail -c 200)" \
    '{status:-1, headers:{}, body:"", effects:($eff + {error: ("the cell body could not be assembled from its own measurements: " + $e)})}' \
    >"$RAW/captured.json"
  exit 0
fi

jq -n --argjson eff "$eff" --arg body "$result" '{status:0, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"

# The script-cell verdict reads the DRIVER'S EXIT STATUS, not just the file it left behind. Say 0
# out loud on the success path rather than inheriting whatever the last command happened to return.
exit 0
