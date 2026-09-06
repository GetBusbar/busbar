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
# awk, not `grep -c ... || echo 0`: grep -c on a file with no match PRINTS 0 and EXITS 1, so the
# `|| echo 0` fires too and the count becomes the two-line string "0\n0". That is not a JSON number,
# so the --argjson assembly below died, `result` was empty, and the cell still wrote a captured.json
# with status 0 and an empty body — a PASS on a stream whose frames were never counted, which is
# exactly the outcome this cell exists to detect. Same idiom verdict.sh uses for its ledger rows.
frame_count="$(awk '/^data:/{n++} END{print n+0}' "$W/stream.body" 2>/dev/null || echo 0)"
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

if ! result="$(jq -n \
  --argjson mint_status "$(jq -r .mint_status <<<"$eff")" \
  --argjson stream_status "$(jq -r .stream_status <<<"$eff")" \
  --argjson sse_frame_count "$(jq -r .sse_frame_count <<<"$eff")" \
  --argjson usage_requests_delta "$(jq -r .usage_requests_delta <<<"$eff")" \
  --argjson usage_requests_delta_after_settle_pause "$(jq -r .usage_requests_delta_after_settle_pause <<<"$eff")" \
  '{mint_status:$mint_status, stream_status:$stream_status, sse_frame_count:$sse_frame_count,
    usage_requests_delta:$usage_requests_delta,
    usage_requests_delta_after_settle_pause:$usage_requests_delta_after_settle_pause}' 2>"$W/result.err")"; then
  # CHECKED. Every value above is a number this run measured; if any of them is not one, the cell
  # measured something it cannot state and the body would go out empty. An empty body with status 0
  # compares clean against a golden that also failed this way — the vacuous green the ledger exists
  # to refuse. Record the -1 UNSUPPORTED shape record.sh reads as a named gap instead.
  jq -n --argjson eff "$eff" --arg e "$(tr '\n' ' ' <"$W/result.err" | tail -c 200)" \
    '{status:-1, headers:{}, body:"", effects:($eff + {error: ("the cell body could not be assembled from its own measurements: " + $e)})}' \
    >"$RAW/captured.json"
  exit 0
fi

jq -n --argjson eff "$eff" --arg body "$result" '{status:0, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"
