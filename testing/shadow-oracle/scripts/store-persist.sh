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
# ONE KNOB, shared with record.sh's own boot_busbar: this cell does a REAL double boot of a
# published plugin, and a bound sized for an idle laptop reads a saturated host's boot latency as
# "never came up" -- a harness timing limit recorded as a product divergence. record.sh already
# uses 60s for a hooks-variant boot (loading published plugins beside a build eating the CPU); this
# cell loads a published store plugin the same way, so it gets the same bound from the same env var
# instead of a second, independently-drifting hard-code.
BOOT_BOUND="${ORACLE_BOOT_BOUND_SECS:-60}"
LP="${STORE_LISTEN_PORT:-${SCRIPT_LISTEN_PORT:-48831}}" AP="${STORE_ADMIN_PORT:-${SCRIPT_ADMIN_PORT:-48832}}" MP="${STORE_MOCK_PORT:-${SCRIPT_MOCK_PORT:-48791}}"
W="$RAW/store-work"; mkdir -p "$W/plugins"
tarball="$(bash "${BUSBAR_ORACLE_TOOL_DIR:-$here}/fetch-plugin.sh" "$PLUGIN")" || oracle_harness_give_up "plugin fetch failed"
cp "$tarball" "$W/plugins/"
alias_="$(tar -xzOf "$tarball" manifest.json | jq -r .alias)"
# The store's fixture. sqlite's lives in the tree (a path under this cell's own work dir). Every
# other first-party store is a NETWORK backend whose fixture is a live service, addressed by a URL
# this harness will not invent: the var per plugin is the same map enumerate-cells.py gates the cell
# on, so a cell that ran cannot have been pointed at a different backend than the one it named.
# An explicit <settings-json> arg still wins, so a caller can drive a backend this map has never
# heard of. `{}` survives ONLY for a store with neither — it would boot on the plugin's own
# defaults, which is a real 1.5.5 shape, not a stand-in.
case "$PLUGIN" in
  store-postgres) URL_VAR=BUSBAR_TEST_POSTGRES_URL ;;
  store-mysql)    URL_VAR=BUSBAR_TEST_MYSQL_URL ;;
  store-valkey)   URL_VAR=VALKEY_URL ;;
  *)              URL_VAR="" ;;
esac
if [ -z "$SETTINGS" ] && [ -n "$URL_VAR" ]; then
  url="${!URL_VAR:-}"
  # record.sh gates these cells on the same var, so an unset one should never reach here. If it
  # does (a direct call), refuse as a NAMED GAP -- this host has no backend to record against, which
  # is not the harness breaking -- rather than booting on `{}` and
  # recording whatever a store with no backend answers as the 1.5.5 contract.
  [ -n "$url" ] || oracle_named_gap "$URL_VAR is unset: no live backend for $PLUGIN"
  SETTINGS="{ url: \"${url}\" }"
fi
[ -n "$SETTINGS" ] || case "$alias_" in sqlite) SETTINGS="{ db_path: \"${W}/governance.db\" }" ;; *) SETTINGS="{}" ;; esac
for p in "$LP" "$AP" "$MP"; do assert_port_free "$p" || oracle_harness_give_up "port $p busy"; done
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
# A `fail` IS THE HARNESS GIVING UP, NOT AN OUTCOME OF THE BINARY. It writes a captured.json like
# any other result, and the recorder used to read `status` alone — so `fail 1 "openssl produced no
# cert"` was recorded as a golden that says "this cell is exit 1", with a PASS row behind it, and
# the candidate agreed because it failed the same way. `harness_error` says which of the two this
# is; record.sh refuses any cell that carries it, and this fail() exits 70 as well — AUDIT NOTE-36:
# a give-up marked only by `status: -1` was filed SKIP, which takes the cell out of the owed set.
fail() { jq -n --argjson st "$1" --argjson eff "$eff" --arg body "$2" '{status:$st, headers:{}, body:$body, effects:($eff + {harness_error: $body})}' >"$RAW/captured.json"; exit 70; }

env_ "$BIN" --validate >"$W/validate.log" 2>&1; step validate_exit "$?"
# STRIP THIS RUN'S DIRS BEFORE TRUNCATING, not after. The window is a fixed number of BYTES, so
# cutting first leaves whatever fragment of an absolute path happens to fall inside it — and a
# fragment is no longer a path record.sh's own scrub can recognise. Two --out dirs whose names differ
# in length then yield two different 300-byte windows of the same log, which is a byte diff on this
# cell about where the recording was written.
step validate_tail "$(sed -e "s|${RAW}|<WORK>|g" -e "s|${BIN}|<WORK>|g" -e "s|${repo}|<WORK>|g" "$W/validate.log" | tr '\n' ' ' | tail -c 300)"
[ "$(jq -r .validate_exit <<<"$eff")" = 0 ] || fail 1 "$(cat "$W/validate.log")"
env_ "$BIN" --list-plugins >"$W/plugins.log" 2>&1; step list_plugins "$(grep -w "$alias_" "$W/plugins.log" | head -1 | tr '\n' ' ')"

pid="$(spawn_ "$W/busbar1.log" "$BIN")"; track_pid $pid
wait_for_http "http://127.0.0.1:${LP}/healthz" "$BOOT_BOUND" \
  || fail 2 "boot 1 (first, fresh) did not come up within ${BOOT_BOUND}s: $(tail -c 500 "$W/busbar1.log")"
# THE CODE IS READ, NOT ASSERTED. `-w` appends the real status as a last line, so
# `mint_status` below is what this binary answered rather than what the harness
# assumed; a mint that stopped being a 201 is then a diff on this cell.
mint_raw="$(curl -sS -m 10 -w '\n%{http_code}' -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d '{"name":"store-oracle","group":"oracle"}')"
mint_code="$(printf '%s' "$mint_raw" | tail -1)"
mint="$(printf '%s' "$mint_raw" | sed '$d')"
kid="$(jq -r '.id // empty' <<<"$mint")"; tok="$(jq -r '.token // empty' <<<"$mint")"
[ -n "$kid" ] && [ -n "$tok" ] || fail 3 "$mint"
step mint_status "$mint_code"
st="$(curl -sS -m 20 -o "$W/chat.body" -w '%{http_code}' -X POST "http://127.0.0.1:${LP}/v1/chat/completions" -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' -d '{"model":"m-openai-chat","messages":[{"role":"user","content":"ping"}]}')"
step chat_status "$st"
sleep 0.5
u1="$(curl -sS -m 10 -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/keys/${kid}/usage" | jq -c 'del(.as_of)')"
step usage_before_restart "$u1"
kill $pid; wait $pid 2>/dev/null
# THE OLD PROCESS MUST BE PROVEN GONE ON BOTH PORTS before the restart binds them, or the second
# boot's /healthz poll can be answered by the FIRST busbar still draining its listeners -- read as
# "persistence survived" for a process that never restarted. `kill`+`wait` only proves the pid was
# reaped, not that the sockets are free (same shape as probe-store.sh's post-400893bd restart spin
# and record.sh's own stop_busbar). Spin on BOTH ports, not just the data port.
i=0
while [ $i -lt 100 ] && { ! assert_port_free "$LP" || ! assert_port_free "$AP"; }; do sleep 0.1; i=$((i+1)); done
if ! assert_port_free "$LP" || ! assert_port_free "$AP"; then
  kill -9 "$pid" 2>/dev/null || true
  fail 4 "port ${LP}/${AP} still answers after boot 1 was killed (waited 10s): the second boot would bind a port the first process still holds, so the persistence verdict would come from the instance that never restarted: $(tail -c 500 "$W/busbar1.log")"
fi

pid="$(spawn_ "$W/busbar2.log" "$BIN")"; track_pid $pid
wait_for_http "http://127.0.0.1:${LP}/healthz" "$BOOT_BOUND" \
  || fail 4 "boot 2 (restart against the same store) did not come up within ${BOOT_BOUND}s: $(tail -c 500 "$W/busbar2.log")"
k2="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/keys/${kid}")"
step key_after_restart "$k2"
u2="$(curl -sS -m 10 -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/keys/${kid}/usage" | jq -c 'del(.as_of)')"
step usage_after_restart "$u2"
st2="$(curl -sS -m 20 -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${LP}/v1/chat/completions" -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' -d '{"model":"m-openai-chat","messages":[{"role":"user","content":"ping"}]}')"
step chat_after_restart "$st2"
# `survived` COMPARES TWO READS, SO IT MUST FIRST PROVE THERE WERE TWO READS. `"" = ""` is true in
# `[`, so a /usage call that came back empty on BOTH sides of the restart — an admin API that
# answered 500, a body jq could not parse, a curl that timed out twice — read as "the usage the
# store was supposed to keep is exactly what it was", i.e. the money class this cell exists for said
# `yes` on the strength of having measured nothing. Both reads must be real: a 200 whose body
# actually carries a `requests` number.
u1_req="$(jq -r '.requests // empty' <<<"$u1" 2>/dev/null)"
u2_req="$(jq -r '.requests // empty' <<<"$u2" 2>/dev/null)"
[ -n "$u1_req" ] && [ -n "$u2_req" ] \
  || fail 5 "the /usage read before ($u1) or after ($u2) the restart carried no requests count, so 'survived' would compare two absences and call them equal"
step survived "$([ "$k2" = 200 ] && [ "$u2_req" = "$u1_req" ] && echo yes || echo no)"
kill $pid; wait $pid 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done
# Every `store error` line across BOTH boots. A store the binary cannot actually write to still
# serves 200s and still answers /usage from whatever it holds in memory, so the request statuses
# alone can look healthy while nothing is being persisted — this is the count that says so. It is a
# COUNT, not the text: the message wording is the plugin's, but "more than zero" is the finding.
# awk, not `grep -c`: on a log with no match grep prints 0 and EXITS 1, so any `|| echo 0` guard
# doubles the value and a missing log leaves the arithmetic below with nothing at all. awk always
# prints exactly one number, including for a file that does not exist.
count_matching() { awk -v re="$1" '$0 ~ re {n++} END{print n+0}' "$2" 2>/dev/null || echo 0; }
step store_errors "$(( $(count_matching 'store error' "$W/busbar1.log") + $(count_matching 'store error' "$W/busbar2.log") ))"
jq -n --argjson eff "$eff" --arg body "$u2" '{status:0, headers:{}, body:$body, effects:($eff | . + {warnings_boot1: $w1})}' --arg w1 "$(count_matching '[Ww][Aa][Rr][Nn]' "$W/busbar1.log")" >"$RAW/captured.json"

# The script-cell verdict reads the DRIVER'S EXIT STATUS, not just the file it left behind. Say 0
# out loud on the success path rather than inheriting whatever the last command happened to return.
exit 0
