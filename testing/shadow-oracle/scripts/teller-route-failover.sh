#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell: `teller|route-failover` -- H2 (ARCHITECTURE.md #2.2 step 5, ROUTE). Proves the
# Teller order at step 5: when the FIRST lane in a pool is down, the egress unit's walk fails over to
# the next verified destination within the same unit -- the client sees ONE successful terminal, the
# dead lane is dialled and abandoned, the live lane serves and is billed. 1.5.5 has no "Teller"
# vocabulary but already realises the walk-and-failover order, so this cell must PASS unmodified on
# the published 1.5.5 binary.
#
# Steps, on our own throwaway boot:
#   1. a pool with two members: lane-dead (nothing listening on its port) weight 1,
#      lane-live (a real mock upstream) weight 1, breaker trip on the first failure so the SECOND
#      call would skip straight to lane-live -- but this cell judges the FIRST call's own failover,
#      not the breaker's memory
#   2. one request against the pool                                    -> expect 200
#   3. the live mock's own capture directory                            -> expect exactly ONE file
#   4. /usage requests delta                                            -> expect exactly 1 (one bill,
#      not two, even though two lanes were attempted)
#
# Env from the recorder: BUSBAR_BIN RAW WORK ORACLE_ADMIN_TOKEN SCRIPT_LISTEN_PORT SCRIPT_ADMIN_PORT
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"
BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"; ADMIN="${ORACLE_ADMIN_TOKEN:-shadow-oracle-admin}"
LP="${TELLER_LISTEN_PORT:-${SCRIPT_LISTEN_PORT:-49611}}" AP="${TELLER_ADMIN_PORT:-${SCRIPT_ADMIN_PORT:-49612}}" MP="${TELLER_MOCK_PORT:-${SCRIPT_MOCK_PORT:-49621}}"
DEADP=$((MP + 1))
W="$RAW/teller-work"; mkdir -p "$W"
# EMPTY, not just present: the mock drops one capture file per upstream request in here and
# this cell COUNTS them, so a re-record into an existing raw tree would count the last run's
# requests as well as its own.
rm -rf "$W/egress"; mkdir -p "$W/egress"

for p in "$LP" "$AP" "$MP" "$DEADP"; do
  assert_port_free "$p" || { echo "{\"status\":-1,\"headers\":{},\"body\":\"\",\"effects\":{\"error\":\"port $p busy\"}}" >"$RAW/captured.json"; exit 0; }
done
# lane-dead's port is deliberately left with nothing listening -- a connection refused, not a mock.

ORACLE_MOCK_CAPTURE_DIR="$W/egress" python3 "${here}/mock-upstream.py" "$MP" oracle-marker "$W/mock.control" >"$W/mock.log" 2>&1 & track_pid $!
# CHECKED: an unchecked wait here let the cell run with NO upstream and record whatever busbar
# answers to that as the contract. fail() is defined further down (it needs $eff), so refuse in
# the same -1 shape the port-busy guard above uses -- record.sh reads it as UNSUPPORTED, not a pass.
wait_for_http "http://127.0.0.1:${MP}/" 5 || { echo '{"status":-1,"headers":{},"body":"","effects":{"error":"mock upstream did not come up"}}' >"$RAW/captured.json"; exit 0; }

"$BIN" --generate-signing-key >"$W/signing.key" 2>/dev/null
cat >"$W/providers.yaml" <<YAML
lane-dead:
  protocol: openai
  base_url: "http://127.0.0.1:${DEADP}"
lane-live:
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
  lane-dead:
    api_key: { env: ORACLE_UPSTREAM_KEY }
  lane-live:
    api_key: { env: ORACLE_UPSTREAM_KEY }
models:
  m-lane-dead:
    provider: lane-dead
  m-lane-live:
    provider: lane-live
rate_card:
  m-lane-dead: { input_utok: 100000, output_utok: 200000 }
  m-lane-live: { input_utok: 100000, output_utok: 200000 }
pools:
  oracle:
    members:
      - { model: m-lane-dead, weight: 1 }
      - { model: m-lane-live, weight: 1 }
    breaker: { base_cooldown_secs: 15, max_cooldown_secs: 120, trip: { mode: consecutive, consecutive_n: 1 } }
    failover: { timeout_secs: 30, max_hops: 3 }
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

mint_raw="$(curl -sS -m 10 -w '\n%{http_code}' -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d '{"name":"teller-route","group":"oracle"}')"

mint_code="$(printf '%s' "$mint_raw" | tail -1)"

mint="$(printf '%s' "$mint_raw" | sed '$d')"
kid="$(jq -r '.id // empty' <<<"$mint")"; tok="$(jq -r '.token // empty' <<<"$mint")"
[ -n "$kid" ] && [ -n "$tok" ] || fail 2 "$mint"
step mint_status "$mint_code"

# step 2: one request against the pool -- either lane's model name is accepted (pool routes by model)
route_status="$(curl -sS -m 25 -o "$W/route.body" -w '%{http_code}' -X POST "http://127.0.0.1:${LP}/v1/chat/completions" \
  -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' \
  -d '{"model":"oracle","messages":[{"role":"user","content":"ping"}]}')"
step route_status "$route_status"
stepjson route_body "$(jq -c . "$W/route.body" 2>/dev/null || jq -n --arg raw "$(cat "$W/route.body" 2>/dev/null)" '{raw:$raw}')"

egress_count="$(find "$W/egress" -type f 2>/dev/null | wc -l | tr -d ' ')"
step live_egress_count "$egress_count"

sleep 0.3
usage="$(curl -sS -m 10 -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/keys/${kid}/usage" | jq -c 'del(.as_of)')"
stepjson usage "$usage"

kill $pid 2>/dev/null; wait $pid 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done

if ! result="$(jq -n \
  --argjson mint_status "$(jq -r .mint_status <<<"$eff")" \
  --argjson route_status "$(jq -r .route_status <<<"$eff")" \
  --argjson route_body "$(jq -c .route_body <<<"$eff")" \
  --argjson live_egress_count "$(jq -r .live_egress_count <<<"$eff")" \
  --argjson usage "$(jq -c .usage <<<"$eff")" \
  '{mint_status:$mint_status, route_status:$route_status, route_body:$route_body,
    live_egress_count:$live_egress_count, usage:$usage}' 2>"$W/result.err")"; then
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
