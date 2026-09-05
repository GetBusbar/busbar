#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell: settles, on the PUBLISHED binary, whether the data plane enforces a stored
# key's `expires_at` once it is in the past. key-expiry.sh already proved the admin API refuses to
# MINT a key with a past `expires_at` (400) on both binaries — so the only way a key row with a
# past `expires_at` can exist is by editing the store directly (an operator restoring a backup, a
# migration, a hand-edited row). This cell manufactures exactly that out-of-band state and asks the
# data plane the one question the design binding turns on: does a spend against that row come back
# 200 (never enforced) or 401 (enforced)?
#   1. boot busbar with the PUBLISHED store-sqlite plugin as `store:` (own ports, own db)
#   2. mint a key with `expires_at` far in the FUTURE (passes the admin API's own validation)
#   3. spend once through the mock upstream -> record status + usage
#   4. stop busbar, then edit the sqlite row's `expires_at` to a past Unix epoch with `sqlite3`
#      directly against the db file (out-of-band; no admin API involved)
#   5. restart busbar against the SAME db (same file, same row, now-past expires_at)
#   6. spend again with the SAME token -> record status + body + the usage delta
#
# Writes $RAW/captured.json: status = 0 once the script ran to completion (else the failing step
# number), body = the whole result object below (so the cell body IS the contract), effects = the
# same fields individually (forensics/diffing convenience).
#
# Env from the recorder: BUSBAR_BIN RAW WORK ORACLE_ADMIN_TOKEN
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
# shellcheck source=../../fleet-fixtures/lib.sh
source "${repo}/testing/fleet-fixtures/lib.sh"
BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"; ADMIN="${ORACLE_ADMIN_TOKEN:-shadow-oracle-admin}"
LP="${EXPIRED_OOB_LISTEN_PORT:-${SCRIPT_LISTEN_PORT:-49201}}" AP="${EXPIRED_OOB_ADMIN_PORT:-${SCRIPT_ADMIN_PORT:-49202}}" MP="${EXPIRED_OOB_MOCK_PORT:-${SCRIPT_MOCK_PORT:-49211}}"
W="$RAW/expired-oob-work"; mkdir -p "$W/plugins"

for p in "$LP" "$AP" "$MP"; do
  assert_port_free "$p" || { echo "{\"status\":-1,\"headers\":{},\"body\":\"\",\"effects\":{\"error\":\"port $p busy\"}}" >"$RAW/captured.json"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo '{"status":-1,"headers":{},"body":"","effects":{"error":"sqlite3 not installed"}}' >"$RAW/captured.json"; exit 0; }

tarball="$(bash "${here}/fetch-plugin.sh" store-sqlite)" || { echo '{"status":-1,"headers":{},"body":"","effects":{"error":"plugin fetch failed"}}' >"$RAW/captured.json"; exit 0; }
cp "$tarball" "$W/plugins/"
alias_="$(tar -xzOf "$tarball" manifest.json | jq -r .alias)"
DB="$W/governance.db"

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
plugins:
  enabled: true
  dir: "${W}/plugins"
  trust:
    allow_unsigned: true
store:
  module: ${alias_}
  settings: { db_path: "${DB}" }
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

spawn() {  # spawn <log-file>  -> prints pid (busbar's OWN pid, see note below)
  # `exec` inside the backgrounded subshell so $! is busbar's OWN pid, not a wrapper subshell's — a
  # plain `env VAR=val "$BIN" &` backgrounds a subshell running that command, and killing the
  # subshell orphans busbar (it keeps the listen port and the next boot on this port hangs forever).
  ( exec env BUSBAR_CONFIG="$W/config.yaml" BUSBAR_PROVIDERS="$W/providers.yaml" \
      ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN="$ADMIN" RUST_LOG=warn "$BIN" ) >>"$1" 2>&1 &
  echo $!
}
stop() {  # stop <pid> — kill and wait for the listen port to free before the next boot
  kill "$1" 2>/dev/null; wait "$1" 2>/dev/null
  local i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done
}
usage_of() { curl -sS -m 10 -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/keys/${1}/usage" | jq -c 'del(.as_of)'; }
spend() {  # spend <token> -> writes $W/spend.body, prints status
  curl -sS -m 20 -o "$W/spend.body" -w '%{http_code}' -X POST "http://127.0.0.1:${LP}/v1/chat/completions" \
    -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
    -d '{"model":"m-openai-chat","messages":[{"role":"user","content":"ping"}]}'
}

# ── boot 1: mint (future expires_at, passes admin validation) + spend once ──────────────────────
pid="$(spawn "$W/busbar1.log")"; track_pid "$pid"
wait_for_http "http://127.0.0.1:${LP}/healthz" 30 || fail 1 "$(tail -c 500 "$W/busbar1.log")"

future="$(( $(date +%s) + 3600 ))"
mint="$(curl -sS -m 10 -w '\n%{http_code}' -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d "{\"name\":\"expired-oob-oracle\",\"group\":\"oracle\",\"expires_at\":${future}}")"
mint_status="$(tail -1 <<<"$mint")"; mint_body="$(sed '$d' <<<"$mint")"
step mint_status "$mint_status"
kid="$(jq -r '.id // empty' <<<"$mint_body" 2>/dev/null)"; tok="$(jq -r '.token // empty' <<<"$mint_body" 2>/dev/null)"
[ -n "$kid" ] && [ -n "$tok" ] || fail 2 "$mint_body"

spend_before="$(spend "$tok")"; step spend_before "$spend_before"
sleep 0.5
usage_before="$(usage_of "$kid")"; stepjson usage_before "$usage_before"

stop "$pid"

# ── out-of-band edit: flip the stored row's expires_at into the past, bypassing the admin API ──
# Find the table that actually holds this key's row: it must have both an `id` column (matching
# the minted key id) and an `expires_at` column. `credentials` also has an expires_at column (a
# CHECK constraint on it, not a table named CHECK — a naive text-grep over `.schema` for
# "<name>(...expires_at...)" wrongly matches the CONSTRAINT clause, not the CREATE TABLE), so this
# walks sqlite_master + PRAGMA table_info instead of grepping the schema text.
table=""
for t in $(sqlite3 "$DB" "SELECT name FROM sqlite_master WHERE type='table';"); do
  cols="$(sqlite3 "$DB" "PRAGMA table_info(${t});" | cut -d'|' -f2)"
  if grep -qx id <<<"$cols" && grep -qx expires_at <<<"$cols"; then
    if [ "$(sqlite3 "$DB" "SELECT COUNT(*) FROM ${t} WHERE id = '${kid}';")" -gt 0 ]; then table="$t"; break; fi
  fi
done
step schema_table_found "${table:-none}"
[ -n "$table" ] || fail 3 "no table with id+expires_at columns holding key ${kid} found in schema"

# The store's own CHECK constraint requires expires_at > created_at, so we can't just slam in
# Unix-epoch 1 — that would violate the constraint (SQLite refuses the UPDATE). Set it to
# created_at + 1 instead: still satisfies expires_at > created_at, and by the time busbar restarts
# a few seconds later, created_at + 1 is already well in the past relative to wall-clock time —
# a genuinely PAST expires_at, honestly obtained.
created_at="$(sqlite3 "$DB" "SELECT created_at FROM ${table} WHERE id = '${kid}';")"
past_expires=$(( created_at + 1 ))
sqlite3 "$DB" "UPDATE ${table} SET expires_at = ${past_expires} WHERE id = '${kid}';" || fail 3 "sqlite3 UPDATE failed on table ${table}"
expires_now="$(sqlite3 "$DB" "SELECT expires_at FROM ${table} WHERE id = '${kid}';")"
step created_at "$created_at"
step expires_at_after_edit "$expires_now"
step now_at_edit "$(date +%s)"

# created_at (and so expires_at = created_at + 1) is a wall-clock second stamped just moments ago —
# without a margin the second boot could still land in the SAME second, and expires_at would not
# yet be in the past when the second spend fires (a false "not enforced" from a race, not a
# finding). Sleep past it so expires_at is unambiguously behind wall-clock time at spend #2.
while [ "$(date +%s)" -le "$past_expires" ]; do sleep 1; done

# ── boot 2: restart on the SAME db, spend again with the SAME token ────────────────────────────
pid="$(spawn "$W/busbar2.log")"; track_pid "$pid"
wait_for_http "http://127.0.0.1:${LP}/healthz" 30 || fail 4 "$(tail -c 500 "$W/busbar2.log")"

spend_after="$(spend "$tok")"; step spend_after "$spend_after"
body_after="$(jq -c . "$W/spend.body" 2>/dev/null || jq -n --arg raw "$(cat "$W/spend.body" 2>/dev/null)" '{raw:$raw}')"
stepjson body_after "$body_after"
sleep 0.5
usage_after="$(usage_of "$kid")"; stepjson usage_after "$usage_after"

stop "$pid"

req_before="$(jq -r '.requests // 0' <<<"$usage_before")"; req_after="$(jq -r '.requests // 0' <<<"$usage_after")"
usage_delta="$(jq -n --argjson a "$req_before" --argjson b "$req_after" '{requests: ($b - $a)}')"

result="$(jq -n \
  --argjson mint_status "$mint_status" \
  --argjson spend_before "$(jq -r .spend_before <<<"$eff")" \
  --argjson spend_after "$(jq -r .spend_after <<<"$eff")" \
  --argjson body_after "$(jq -c .body_after <<<"$eff")" \
  --argjson usage_delta "$usage_delta" \
  '{mint_status:$mint_status, spend_before:$spend_before, spend_after:$spend_after, body_after:$body_after, usage_delta:$usage_delta}')"

jq -n --argjson eff "$eff" --arg body "$result" '{status:0, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"
