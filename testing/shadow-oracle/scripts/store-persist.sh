#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell: a PUBLISHED 1.5.5-era store plugin loaded by the binary under test.
#   1. --validate with the plugin wired as `store:`   (the load line)
#   2. boot, mint a key, spend through the mock, read /usage
#   3. KILL, boot again against the SAME store, read the key and its usage back (persistence)
# Writes $RAW/captured.json: status = 0 (all steps ran) else the failing step number; body = the
# usage view after restart; effects = every intermediate status and the survived/reset verdict,
# plus `usage_after_restart` (the whole /usage JSON read back on the second boot — the money the
# store was supposed to keep) and `store_errors` (how many `store error` lines the two boots
# logged). Those two are the ones that catch a binary whose store calls are the wrong SHAPE: every
# request still answers 200 and nothing else in this cell moves.
#
# Env from the recorder: BUSBAR_BIN RAW WORK ORACLE_ADMIN_TOKEN; args: <plugin-name> [<settings-json>]
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"
PLUGIN="${1:?plugin name}"; SETTINGS="${2:-}"
BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"; ADMIN="${ORACLE_ADMIN_TOKEN:-shadow-oracle-admin}"
LP="${STORE_LISTEN_PORT:-${SCRIPT_LISTEN_PORT:-48831}}" AP="${STORE_ADMIN_PORT:-${SCRIPT_ADMIN_PORT:-48832}}" MP="${STORE_MOCK_PORT:-${SCRIPT_MOCK_PORT:-48791}}"
W="$RAW/store-work"; mkdir -p "$W/plugins"
tarball="$(bash "${here}/fetch-plugin.sh" "$PLUGIN")" || { echo '{"status":-1,"headers":{},"body":"","effects":{"error":"plugin fetch failed"}}' >"$RAW/captured.json"; exit 0; }
cp "$tarball" "$W/plugins/"
alias_="$(tar -xzOf "$tarball" manifest.json | jq -r .alias)"
[ -n "$SETTINGS" ] || case "$alias_" in sqlite) SETTINGS="{ db_path: \"${W}/governance.db\" }" ;; *) SETTINGS="{}" ;; esac
for p in "$LP" "$AP" "$MP"; do assert_port_free "$p" || { echo "{\"status\":-1,\"headers\":{},\"body\":\"\",\"effects\":{\"error\":\"port $p busy\"}}" >"$RAW/captured.json"; exit 0; }; done
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
store:
  module: ${alias_}
  settings: ${SETTINGS}
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
env_() { BUSBAR_CONFIG="$W/config.yaml" BUSBAR_PROVIDERS="$W/providers.yaml" ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN="$ADMIN" RUST_LOG=warn "$@"; }
# Backgrounding a shell FUNCTION tracks the subshell's pid, and killing that orphans busbar on the
# port (the next recording then refuses to boot against the stale process). Spawn through a subshell
# that execs, so the pid tracked and killed IS busbar's.
spawn_() { local log="$1"; shift; ( exec env BUSBAR_CONFIG="$W/config.yaml" BUSBAR_PROVIDERS="$W/providers.yaml" ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN="$ADMIN" RUST_LOG=warn "$@" ) >>"$log" 2>&1 & echo $!; }
eff='{}'
step() { eff="$(jq -c --arg k "$1" --arg v "$2" '. + {($k): $v}' <<<"$eff")"; }
fail() { jq -n --argjson st "$1" --argjson eff "$eff" --arg body "$2" '{status:$st, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"; exit 0; }

env_ "$BIN" --validate >"$W/validate.log" 2>&1; step validate_exit "$?"
step validate_tail "$(tail -c 300 "$W/validate.log" | tr '\n' ' ')"
[ "$(jq -r .validate_exit <<<"$eff")" = 0 ] || fail 1 "$(cat "$W/validate.log")"
env_ "$BIN" --list-plugins >"$W/plugins.log" 2>&1; step list_plugins "$(grep -w "$alias_" "$W/plugins.log" | head -1 | tr '\n' ' ')"

pid="$(spawn_ "$W/busbar1.log" "$BIN")"; track_pid $pid
wait_for_http "http://127.0.0.1:${LP}/healthz" 30 || fail 2 "$(tail -c 500 "$W/busbar1.log")"
mint="$(curl -sS -m 10 -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d '{"name":"store-oracle","group":"oracle"}')"
kid="$(jq -r '.id // empty' <<<"$mint")"; tok="$(jq -r '.token // empty' <<<"$mint")"
[ -n "$kid" ] && [ -n "$tok" ] || fail 3 "$mint"
step mint_status "201"
st="$(curl -sS -m 20 -o "$W/chat.body" -w '%{http_code}' -X POST "http://127.0.0.1:${LP}/v1/chat/completions" -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' -d '{"model":"m-openai-chat","messages":[{"role":"user","content":"ping"}]}')"
step chat_status "$st"
sleep 0.5
u1="$(curl -sS -m 10 -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/keys/${kid}/usage" | jq -c 'del(.as_of)')"
step usage_before_restart "$u1"
kill $pid; wait $pid 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done

pid="$(spawn_ "$W/busbar2.log" "$BIN")"; track_pid $pid
wait_for_http "http://127.0.0.1:${LP}/healthz" 30 || fail 4 "$(tail -c 500 "$W/busbar2.log")"
k2="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/keys/${kid}")"
step key_after_restart "$k2"
u2="$(curl -sS -m 10 -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/keys/${kid}/usage" | jq -c 'del(.as_of)')"
step usage_after_restart "$u2"
st2="$(curl -sS -m 20 -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${LP}/v1/chat/completions" -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' -d '{"model":"m-openai-chat","messages":[{"role":"user","content":"ping"}]}')"
step chat_after_restart "$st2"
step survived "$([ "$k2" = 200 ] && [ "$(jq -r .requests <<<"$u2")" = "$(jq -r .requests <<<"$u1")" ] && echo yes || echo no)"
kill $pid; wait $pid 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done
# Every `store error` line across BOTH boots. A store the binary cannot actually write to still
# serves 200s and still answers /usage from whatever it holds in memory, so the request statuses
# alone can look healthy while nothing is being persisted — this is the count that says so. It is a
# COUNT, not the text: the message wording is the plugin's, but "more than zero" is the finding.
step store_errors "$(( $(grep -c 'store error' "$W/busbar1.log") + $(grep -c 'store error' "$W/busbar2.log") ))"
jq -n --argjson eff "$eff" --arg body "$u2" '{status:0, headers:{}, body:$body, effects:($eff | . + {warnings_boot1: $w1})}' --arg w1 "$(grep -ci 'warn' "$W/busbar1.log")" >"$RAW/captured.json"
