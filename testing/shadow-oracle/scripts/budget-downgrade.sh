#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell: `billing|budget|downgrade`. A group budget scoped to pool `frontier` declares
# `on_exhaust: downgrade, downgrade_to: value`: once the budget is spent, a request naming
# `frontier` is not refused; it is re-admitted through `value`, its charge lands on `value`, and it
# is dispatched there (1.5.5 `ingress::admit_check` and `ingress::dispatch`). The cell records where
# each request went and where each charge and count landed.
#
# Steps, on our own throwaway boot (per_request_fee 10, no rate card: a request costs its fee):
#   1. mint a key in group `oracle`, whose `frontier` budget is 25 a day
#   2. three chats naming pool `frontier`: the first two spend 20; the third would spend 30 > 25, so
#      it is downgraded to `value`
#   3. read what each pool's upstream received (one mock per pool, each counting its requests), the
#      key and group usage views, and the request and attempt counters on `/metrics`
#
# Env from the recorder: BUSBAR_BIN RAW WORK ORACLE_ADMIN_TOKEN SCRIPT_LISTEN_PORT SCRIPT_ADMIN_PORT
# SCRIPT_MOCK_PORT BUSBAR_ORACLE_BIN
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"
BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"; ADMIN="${ORACLE_ADMIN_TOKEN:-shadow-oracle-admin}"
ORACLE_BIN="${BUSBAR_ORACLE_BIN:?the Rust oracle engine must be published as BUSBAR_ORACLE_BIN}"
LP="${SCRIPT_LISTEN_PORT:-49611}" AP="${SCRIPT_ADMIN_PORT:-49612}" MP="${SCRIPT_MOCK_PORT:-49621}"
VP=$((MP + 1))
W="$RAW/budget-downgrade-work"; rm -rf "$W"; mkdir -p "$W/frontier" "$W/value"

# A harness failure is never an outcome of the binary: the -1 shape record.sh reads as a named gap.
gap() { jq -n --arg e "$1" '{status:-1, headers:{}, body:"", effects:{error:$e}}' >"$RAW/captured.json"; exit 0; }

for p in "$LP" "$AP" "$MP" "$VP"; do assert_port_free "$p" || gap "port $p busy"; done

# One mock per pool, each dropping one capture file per upstream request it answers, so the cell
# counts where every request was dispatched without reading the mock's capture format.
ORACLE_MOCK_CAPTURE_DIR="$W/frontier" "$ORACLE_BIN" mock "$MP" oracle-marker "$W/frontier.control" >"$W/frontier.log" 2>&1 & track_pid $!
ORACLE_MOCK_CAPTURE_DIR="$W/value" "$ORACLE_BIN" mock "$VP" oracle-marker "$W/value.control" >"$W/value.log" 2>&1 & track_pid $!
wait_for_http "http://127.0.0.1:${MP}/" 5 || gap "the frontier mock upstream did not come up"
wait_for_http "http://127.0.0.1:${VP}/" 5 || gap "the value mock upstream did not come up"

"$BIN" --generate-signing-key >"$W/signing.key" 2>/dev/null
[ -s "$W/signing.key" ] || gap "--generate-signing-key produced no key"
cat >"$W/providers.yaml" <<YAML
up-frontier:
  protocol: openai
  base_url: "http://127.0.0.1:${MP}"
up-value:
  protocol: openai
  base_url: "http://127.0.0.1:${VP}"
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
      - { budget: 25, per: day, pool: frontier, on_exhaust: downgrade, downgrade_to: value }
providers:
  up-frontier:
    api_key: { env: ORACLE_UPSTREAM_KEY }
  up-value:
    api_key: { env: ORACLE_UPSTREAM_KEY }
models:
  m-frontier:
    provider: up-frontier
  m-value:
    provider: up-value
pools:
  frontier:
    members:
      - { model: m-frontier, weight: 1 }
  value:
    members:
      - { model: m-value, weight: 1 }
per_request_fee: 10
export:
  metrics:
    module: prometheus
    settings: { buffer_seconds: 60 }
YAML
# The operator upgrade step and the oracle's run-time inputs (store, mock allowlist), as every script cell.
"$ORACLE_BIN" upgrade-config "$BIN" "$W/config.yaml" || gap "upgrade-config refused the config"

eff='{}'
step() { eff="$(jq -c --arg k "$1" --arg v "$2" '. + {($k): $v}' <<<"$eff")"; }
stepjson() { eff="$(jq -c --arg k "$1" --argjson v "$2" '. + {($k): $v}' <<<"$eff")"; }
# A `fail` is the harness giving up, never an outcome: record.sh refuses a cell carrying it.
fail() { jq -n --argjson st "$1" --argjson eff "$eff" --arg body "$2" '{status:$st, headers:{}, body:$body, effects:($eff + {harness_error: $body})}' >"$RAW/captured.json"; exit 0; }

( exec env BUSBAR_CONFIG="$W/config.yaml" BUSBAR_PROVIDERS="$W/providers.yaml" \
    ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN="$ADMIN" RUST_LOG=warn "$BIN" ) >"$W/busbar.log" 2>&1 &
pid=$!; track_pid $pid
wait_for_http "http://127.0.0.1:${LP}/healthz" 30 || fail 1 "$(tail -c 500 "$W/busbar.log")"

mint_raw="$(curl -sS -m 10 -w '\n%{http_code}' -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d '{"name":"budget-downgrade","group":"oracle"}')"
mint_code="$(printf '%s' "$mint_raw" | tail -1)"
mint="$(printf '%s' "$mint_raw" | sed '$d')"
kid="$(jq -r '.id // empty' <<<"$mint")"; tok="$(jq -r '.token // empty' <<<"$mint")"
[ -n "$kid" ] && [ -n "$tok" ] || fail 2 "$mint"
step mint_status "$mint_code"

chat() {  # chat <label>: one chat naming pool `frontier`; records its status and body under <label>
  local code
  code="$(curl -sS -m 25 -o "$W/$1.body" -w '%{http_code}' -X POST "http://127.0.0.1:${LP}/v1/chat/completions" \
    -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' \
    -d '{"model":"frontier","messages":[{"role":"user","content":"ping"}]}')"
  step "${1}_status" "$code"
}
chat first
chat second
chat downgraded
stepjson downgraded_body "$(jq -c 'del(.id, .created)' "$W/downgraded.body" 2>/dev/null || jq -n --arg raw "$(cat "$W/downgraded.body" 2>/dev/null)" '{raw:$raw}')"

step frontier_upstream_requests "$(find "$W/frontier" -type f 2>/dev/null | wc -l | tr -d ' ')"
step value_upstream_requests "$(find "$W/value" -type f 2>/dev/null | wc -l | tr -d ' ')"

# Let the write-behind usage flush before reading the views back.
sleep 0.3
key_view="$(curl -sS -m 10 -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/keys/${kid}/usage" | jq -c 'del(.as_of)')"
group_view="$(curl -sS -m 10 -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/groups/oracle/usage" | jq -c 'del(.as_of)')"
stepjson key_usage "${key_view:-null}"
stepjson group_usage "${group_view:-null}"
# The request and attempt COUNTERS by pool (a duration family carries wall-clock values, so only the
# two counters are read), sorted so the exposition's series order does not move the cell.
metrics="$(curl -sS -m 10 -H "Authorization: Bearer $tok" "http://127.0.0.1:${LP}/metrics" \
  | grep -E '^busbar_(requests_total|upstream_attempts_total)\{' | LC_ALL=C sort)"
stepjson counters "$(jq -Rn '[inputs]' <<<"$metrics")"

kill $pid 2>/dev/null; wait $pid 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done

if ! result="$(jq -c '{mint_status, first_status, second_status, downgraded_status, downgraded_body,
    frontier_upstream_requests, value_upstream_requests, key_usage, group_usage, counters}' <<<"$eff" 2>"$W/result.err")"; then
  gap "the cell body could not be assembled from its own measurements: $(tr '\n' ' ' <"$W/result.err" | tail -c 200)"
fi

jq -n --argjson st "$(jq -r .downgraded_status <<<"$eff")" --argjson eff "$eff" --arg body "$result" \
  '{status:$st, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"
# The script-cell verdict reads the driver's exit status: say 0 on the success path.
exit 0
