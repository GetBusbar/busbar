#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell: `POST /api/v1/admin/keys {"issue_aws_credential": true}` on a node whose
# `auth.chain` does NOT name `keys` (`chain: []`, the admin on its token). 1.5.5 mints the AWS pair on
# the flag alone, whatever the chain (v1.5.5 crates/busbar/src/admin/mod.rs:919, :997-1000,
# :1103-1108, :1118); the oracle's shared config names `keys`, so no other cell reaches this
# (busbar status row 186). Steps, on our own throwaway boot (no upstream is dialed):
#   1. mint with `issue_aws_credential: true`  -> the status, the body's sorted field names, and the
#      SHAPES of the token, the AccessKeyId and the secret access key (their bytes are CSPRNG draws)
#   2. a plain mint on the same node            -> the status and whether it carries either AWS field
#
# Writes $RAW/captured.json: status = 0 once all steps ran (else the failing step number), body =
# the whole result object below (so the cell body IS the contract), effects = the same fields.
#
# Env from the recorder: BUSBAR_BIN RAW WORK ORACLE_ADMIN_TOKEN
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"
BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"; ADMIN="${ORACLE_ADMIN_TOKEN:-shadow-oracle-admin}"
LP="${AWSCRED_LISTEN_PORT:-${SCRIPT_LISTEN_PORT:-48941}}" AP="${AWSCRED_ADMIN_PORT:-${SCRIPT_ADMIN_PORT:-48942}}"
W="$RAW/awscred-work"; mkdir -p "$W"

for p in "$LP" "$AP"; do
  assert_port_free "$p" || { echo "{\"status\":-1,\"headers\":{},\"body\":\"\",\"effects\":{\"error\":\"port $p busy\"}}" >"$RAW/captured.json"; exit 0; }
done

"$BIN" --generate-signing-key >"$W/signing.key" 2>/dev/null
cat >"$W/providers.yaml" <<YAML
openai-chat:
  protocol: openai
  base_url: "http://127.0.0.1:9"
YAML
cat >"$W/config.yaml" <<YAML
listen: "127.0.0.1:${LP}"
admin_listen: "127.0.0.1:${AP}"
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: { env: BUSBAR_ADMIN_TOKEN }
auth:
  chain: []
  signing_key: { file: "${W}/signing.key" }
  admin_auth: [admin-tokens]
providers:
  openai-chat:
    api_key: { env: ORACLE_UPSTREAM_KEY }
models:
  m-openai-chat:
    provider: openai-chat
YAML
# The operator upgrade step (owner ruling Q42, docs/migration-1.6.md): the binary under test adds, at 0,
# each billable class it names as unconfigured on this card. The 1.5.5 golden names none: its config runs as written.
"${BUSBAR_ORACLE_BIN:?}" upgrade-config "$BIN" "$W/config.yaml" || exit 1

eff='{}'
fail() { jq -n --argjson st "$1" --argjson eff "$eff" --arg body "$2" '{status:$st, headers:{}, body:$body, effects:($eff + {harness_error: $body})}' >"$RAW/captured.json"; exit 0; }

( exec env BUSBAR_CONFIG="$W/config.yaml" BUSBAR_PROVIDERS="$W/providers.yaml" \
    ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN="$ADMIN" RUST_LOG=warn "$BIN" ) >"$W/busbar.log" 2>&1 &
pid=$!; track_pid $pid
wait_for_http "http://127.0.0.1:${LP}/healthz" 30 || fail 1 "$(tail -c 500 "$W/busbar.log")"

mint() {  # mint <json body> -> prints the body, then the status on its own last line
  curl -sS -m 10 -w '\n%{http_code}' -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys" \
    -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d "$1"
}

# THE CODE IS READ, NOT ASSERTED: a mint that stopped being a 201 is a diff on this cell.
aws_raw="$(mint '{"name":"oracle-aws-no-keys","issue_aws_credential":true}')" || fail 2 "the AWS mint did not answer"
aws_code="$(printf '%s' "$aws_raw" | tail -1)"
aws_body="$(printf '%s' "$aws_raw" | sed '$d')"
# The SHAPES only: each value is a fresh CSPRNG draw, so the bytes cannot be a golden; the shapes are
# 1.5.5's wire contract (AKIA + 16 of [A-Z0-9]; 40 of [A-Za-z0-9+/]; the signed token's bbk_ prefix).
aws_view="$(jq -c '{
    fields: (if type == "object" then (keys | sort) else null end),
    token_is_signed: ((.token // "") | test("^bbk_")),
    access_key_id_shape_ok: ((.aws_access_key_id // "") | test("^AKIA[A-Z0-9]{16}$")),
    secret_access_key_shape_ok: ((.aws_secret_access_key // "") | test("^[A-Za-z0-9+/]{40}$")),
    state: .state,
    group_provisioned: .group_provisioned
  }' <<<"$aws_body" 2>/dev/null)" || aws_view="$(jq -cn --arg raw "$aws_body" '{raw:$raw}')"

plain_raw="$(mint '{"name":"oracle-plain-no-keys"}')" || fail 3 "the plain mint did not answer"
plain_code="$(printf '%s' "$plain_raw" | tail -1)"
plain_body="$(printf '%s' "$plain_raw" | sed '$d')"
plain_aws="$(jq -c 'has("aws_access_key_id") or has("aws_secret_access_key")' <<<"$plain_body" 2>/dev/null || echo null)"

kill $pid 2>/dev/null; wait $pid 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done

if ! result="$(jq -cn \
  --argjson aws_mint_status "$aws_code" \
  --argjson aws_mint "$aws_view" \
  --argjson plain_mint_status "$plain_code" \
  --argjson plain_mint_carries_aws "$plain_aws" \
  '{aws_mint_status:$aws_mint_status, aws_mint:$aws_mint,
    plain_mint_status:$plain_mint_status, plain_mint_carries_aws:$plain_mint_carries_aws}' 2>"$W/result.err")"; then
  # CHECKED: a body the cell cannot assemble from its own measurements is the -1 UNSUPPORTED shape
  # record.sh reads as a named gap, never an empty status-0 body that compares clean.
  jq -n --argjson eff "$eff" --arg e "$(tr '\n' ' ' <"$W/result.err" | tail -c 200)" \
    '{status:-1, headers:{}, body:"", effects:($eff + {error: ("the cell body could not be assembled from its own measurements: " + $e)})}' \
    >"$RAW/captured.json"
  exit 0
fi
eff="$result"

jq -n --argjson eff "$eff" --arg body "$result" '{status:0, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"

# The script-cell verdict reads the DRIVER'S EXIT STATUS: say 0 out loud on the success path.
exit 0
