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
# Same knob as record.sh's boot_busbar / scripts/store-persist.sh: this cell boots busbar TWICE, so
# a bound sized for an idle laptop reads a saturated host's second boot as "never came up".
BOOT_BOUND="${ORACLE_BOOT_BOUND_SECS:-60}"
W="$RAW/expired-oob-work"; mkdir -p "$W/plugins"

for p in "$LP" "$AP" "$MP"; do
  assert_port_free "$p" || oracle_harness_give_up "port $p busy"
done
# NOT A NAMED GAP, AND THE RULE IS WHY. A gap is an entitlement the CELL holds, declared in
# cells.json as `needs_fixture: "<ENV VAR>"`; no cell in that file drives this script at all (it is
# the one driver under scripts/ with no cell naming it today), so there is nothing to declare one.
# Undeclared, a box without sqlite3 is the harness unable to run what it was asked to run — which is
# a failure to report, not a cell to quietly stop owing.
command -v sqlite3 >/dev/null 2>&1 || oracle_harness_give_up "sqlite3 not installed"

tarball="$(bash "${BUSBAR_ORACLE_TOOL_DIR:-$here}/fetch-plugin.sh" store-sqlite)" || oracle_harness_give_up "plugin fetch failed"
cp "$tarball" "$W/plugins/"
alias_="$(tar -xzOf "$tarball" manifest.json | jq -r .alias)"
DB="$W/governance.db"

python3 "${BUSBAR_ORACLE_TOOL_DIR:-$here}/mock-upstream.py" "$MP" oracle-marker "$W/mock.control" >"$W/mock.log" 2>&1 & track_pid $!
# CHECKED: an unchecked wait here let the cell run with NO upstream and record whatever busbar
# answers to that as the contract. fail() is defined further down (it needs $eff), so refuse in
# the same way the port-busy guard above does: oracle_harness_give_up marks harness_error AND exits
# 70, so the recorder refuses the run instead of filing it SKIP and quietly dropping the cell.
wait_for_http "http://127.0.0.1:${MP}/" 5 || oracle_harness_give_up "mock upstream did not come up"

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
# A `fail` IS THE HARNESS GIVING UP, NOT AN OUTCOME OF THE BINARY. It writes a captured.json like
# any other result, and the recorder used to read `status` alone — so `fail 1 "openssl produced no
# cert"` was recorded as a golden that says "this cell is exit 1", with a PASS row behind it, and
# the candidate agreed because it failed the same way. `harness_error` says which of the two this
# is; record.sh refuses any cell that carries it, and this fail() exits 70 as well — AUDIT NOTE-36:
# a give-up marked only by `status: -1` was filed SKIP, which takes the cell out of the owed set.
fail() { jq -n --argjson st "$1" --argjson eff "$eff" --arg body "$2" '{status:$st, headers:{}, body:$body, effects:($eff + {harness_error: $body})}' >"$RAW/captured.json"; exit 70; }

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
wait_for_http "http://127.0.0.1:${LP}/healthz" "$BOOT_BOUND" || fail 1 "$(tail -c 500 "$W/busbar1.log")"

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
# NO WALL CLOCK IN `effects`. diff-cells.py compares EVERY effects key a driver writes under
# `effects.script`, rated MONEY — so a raw epoch second here differs on every replay by construction
# (the golden was recorded at one instant, the candidate runs at another) and normalize.py cannot
# save it: its TS_KEYS rewrite is an EXACT key-name match on an int/float, and `step` writes STRINGS
# under names of this driver's own choosing (`created_at` matched the name but not the type;
# `expires_at_after_edit` and `now_at_edit` matched neither). Three keys about nothing would have
# made this cell permanently, unforgivably-except-as-`breaking` red the moment a cell drove it.
# What the cell actually needs to assert is the RELATION the out-of-band edit was for: the row's
# expires_at now sits behind the clock. That is a boolean, and it is the same boolean every run.
# created_at (and so expires_at = created_at + 1) is a wall-clock second stamped just moments ago —
# without a margin the second boot could still land in the SAME second, and expires_at would not
# yet be in the past when the second spend fires (a false "not enforced" from a race, not a
# finding). Sleep past it so expires_at is unambiguously behind wall-clock time at spend #2.
while [ "$(date +%s)" -le "$past_expires" ]; do sleep 1; done
# ASSERTED AFTER THE WAIT, not before it: before the sleep this is still `false` by construction,
# and a `false` here would be the harness reporting its own impatience as a fact about the row.
step expires_at_moved_into_past "$([ -n "$expires_now" ] && [ "$expires_now" -lt "$(date +%s)" ] 2>/dev/null && echo true || echo false)"

# ── boot 2: restart on the SAME db, spend again with the SAME token ────────────────────────────
pid="$(spawn "$W/busbar2.log")"; track_pid "$pid"
wait_for_http "http://127.0.0.1:${LP}/healthz" "$BOOT_BOUND" || fail 4 "$(tail -c 500 "$W/busbar2.log")"

spend_after="$(spend "$tok")"; step spend_after "$spend_after"
body_after="$(jq -c . "$W/spend.body" 2>/dev/null || jq -n --arg raw "$(cat "$W/spend.body" 2>/dev/null)" '{raw:$raw}')"
stepjson body_after "$body_after"
sleep 0.5
usage_after="$(usage_of "$kid")"; stepjson usage_after "$usage_after"

stop "$pid"

req_before="$(jq -r '.requests // 0' <<<"$usage_before")"; req_after="$(jq -r '.requests // 0' <<<"$usage_after")"
usage_delta="$(jq -n --argjson a "$req_before" --argjson b "$req_after" '{requests: ($b - $a)}')"

if ! result="$(jq -n \
  --argjson mint_status "$mint_status" \
  --argjson spend_before "$(jq -r .spend_before <<<"$eff")" \
  --argjson spend_after "$(jq -r .spend_after <<<"$eff")" \
  --argjson body_after "$(jq -c .body_after <<<"$eff")" \
  --argjson usage_delta "$usage_delta" \
  '{mint_status:$mint_status, spend_before:$spend_before, spend_after:$spend_after, body_after:$body_after, usage_delta:$usage_delta}' 2>"$W/result.err")"; then
  # CHECKED. Every value above is a number this run measured; if any of them is not one, the cell
  # measured something it cannot state and the body would go out EMPTY — and an empty body with
  # status 0 compares clean against a golden that failed the same way, which is the vacuous green
  # the ledger exists to refuse. This is the HARNESS failing to assemble what it measured, not a
  # cell this host cannot host, so it gives up (harness_error, exit 70) instead of filing a gap.
  oracle_harness_give_up "the cell body could not be assembled from its own measurements: $(tr '\n' ' ' <"$W/result.err" | tail -c 200)" "$eff"
fi

jq -n --argjson eff "$eff" --arg body "$result" '{status:0, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"

# The script-cell verdict reads the DRIVER'S EXIT STATUS, not just the file it left behind. Say 0
# out loud on the success path rather than inheriting whatever the last command happened to return.
exit 0
