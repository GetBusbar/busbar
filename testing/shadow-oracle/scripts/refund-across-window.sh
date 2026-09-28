#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell: `billing|key-usage|refund-across-window`. A request that straddles a billing
# window roll: its arrival epoch sits in window D, but by the time it is admitted another request
# has already rolled the group's window cell to D+1, so its flat per-request fee is charged in
# place on the D+1 cell. The request then fails upstream (503), and the fee is refunded. The cell
# records WHICH cell that refund reaches, read back through the group usage view for window D+1
# (the key's own bucket is the all-time window, which never rolls, so it is recorded alongside as
# the control: its refund lands on both engines).
#
# A real straddle is a race between two requests' clock reads and their admissions. This cell
# reproduces the same order deterministically by moving the binary's wall clock between requests
# (fixtures/clock-shift.c, preloaded): request B is admitted at D+1 00:00:01, then request A arrives
# at D 23:59:30, which is exactly the state the race produces (A's arrival epoch is earlier than
# the window the live cell already holds). Fixed UTC instants, so the recording does not depend on
# when it is made. D+1 = 2030-01-02.
#
# Steps, on our own throwaway boot (per_request_fee 7, one group with a daily budget):
#   1. mint a key in the group                         (clock: D 23:58:00)
#   2. B: one served chat                              (clock: D+1 00:00:01) -> rolls the cell to D+1
#   3. A: one chat whose upstream is down (503)        (clock: D 23:59:30)   -> charged on the D+1 cell
#   4. read the group usage view and the key usage view (clock: D+1 00:00:40)
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
W="$RAW/refund-window-work"; rm -rf "$W"; mkdir -p "$W"

# A harness failure is never an outcome of the binary: the -1 shape record.sh reads as a named gap.
gap() { jq -n --arg e "$1" '{status:-1, headers:{}, body:"", effects:{error:$e}}' >"$RAW/captured.json"; exit 0; }

for p in "$LP" "$AP" "$MP"; do assert_port_free "$p" || gap "port $p busy"; done

# The clock shift is built for this host from the fixture's source. No compiler, or a host whose
# loader has no preload hook, is a named gap, never a recording made on an unshifted clock.
case "$(uname -s)" in
  Linux) preload_var=LD_PRELOAD; shim="$W/clock-shift.so"; shim_flags=(-shared -fPIC) ;;
  Darwin) preload_var=DYLD_INSERT_LIBRARIES; shim="$W/clock-shift.dylib"; shim_flags=(-dynamiclib) ;;
  *) gap "no clock-shift preload for $(uname -s)" ;;
esac
cc_bin="$(command -v cc || command -v gcc || command -v clang || true)"
[ -n "$cc_bin" ] || gap "no C compiler for the clock-shift fixture"
"$cc_bin" "${shim_flags[@]}" -o "$shim" "${here}/fixtures/clock-shift.c" -ldl 2>"$W/shim.err" \
  || "$cc_bin" "${shim_flags[@]}" -o "$shim" "${here}/fixtures/clock-shift.c" 2>"$W/shim.err" \
  || gap "the clock-shift fixture did not build: $(tr '\n' ' ' <"$W/shim.err" | tail -c 300)"

# UTC midnight 2030-01-02: the D -> D+1 day-window boundary.
BOUNDARY=1893542400
SHIFT="$W/clock.shift"
clock_at() {  # clock_at <epoch>: the binary's wall clock reads <epoch> from now on
  local tmp; tmp="$(mktemp "${SHIFT}.XXXXXX")" || return 1
  printf '%s\n' "$(( $1 - $(date +%s) ))" >"$tmp" && mv -f "$tmp" "$SHIFT"
}

"$ORACLE_BIN" mock "$MP" oracle-marker "$W/mock.control" >"$W/mock.log" 2>&1 & track_pid $!
wait_for_http "http://127.0.0.1:${MP}/" 5 || gap "mock upstream did not come up"

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
per_request_fee: 7
YAML
# The operator upgrade step (docs/migration-1.6.md): the binary under test adds, at 0,
# each billable class it names as unconfigured on this card. The 1.5.5 golden names none: its config runs as written.
"$ORACLE_BIN" upgrade-config "$BIN" "$W/config.yaml" || exit 1

eff='{}'
step() { eff="$(jq -c --arg k "$1" --arg v "$2" '. + {($k): $v}' <<<"$eff")"; }
fail() { jq -n --argjson st "$1" --argjson eff "$eff" --arg body "$2" '{status:$st, headers:{}, body:$body, effects:($eff + {harness_error: $body})}' >"$RAW/captured.json"; exit 0; }

clock_at $((BOUNDARY - 120)) || gap "could not write the clock shift"
( exec env "${preload_var}=${shim}" ORACLE_CLOCK_SHIFT_FILE="$SHIFT" \
    BUSBAR_CONFIG="$W/config.yaml" BUSBAR_PROVIDERS="$W/providers.yaml" \
    ORACLE_UPSTREAM_KEY=unused BUSBAR_ADMIN_TOKEN="$ADMIN" RUST_LOG=warn "$BIN" ) >"$W/busbar.log" 2>&1 &
pid=$!; track_pid $pid
wait_for_http "http://127.0.0.1:${LP}/healthz" 30 || fail 1 "$(tail -c 500 "$W/busbar.log")"

mint_raw="$(curl -sS -m 10 -w '\n%{http_code}' -X POST "http://127.0.0.1:${AP}/api/v1/admin/keys" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d '{"name":"refund-window","group":"oracle"}')"
mint_code="$(printf '%s' "$mint_raw" | tail -1)"
mint="$(printf '%s' "$mint_raw" | sed '$d')"
kid="$(jq -r '.id // empty' <<<"$mint")"; tok="$(jq -r '.token // empty' <<<"$mint")"
[ -n "$kid" ] && [ -n "$tok" ] || fail 2 "$mint"
step mint_status "$mint_code"

chat() {  # chat <label>: one chat on the key; records its status under <label>
  local code
  code="$(curl -sS -m 20 -o "$W/$1.body" -w '%{http_code}' -X POST "http://127.0.0.1:${LP}/v1/chat/completions" \
    -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' \
    -d '{"model":"m-openai-chat","messages":[{"role":"user","content":"ping"}]}')"
  step "$1" "$code"
}

# The proof the preload took: a binary that ignored it reads today's date, not 2030-01-01.
clock_probe="$(curl -sS -m 10 -D - -o /dev/null "http://127.0.0.1:${LP}/healthz" | tr -d '\r' | sed -n 's/^[Dd]ate: //p')"
case "$clock_probe" in *"01 Jan 2030"*) ;; *) fail 3 "the clock shift did not reach the binary (Date: ${clock_probe})" ;; esac

# B: served in window D+1, which rolls the group's day cell forward.
clock_at $((BOUNDARY + 1)) || fail 4 "could not step the clock"
oracle_clear_control "$W/mock.control" "$MP" || fail 4 "mock control did not clear"
chat rolling_status

# A: arrives in window D, after the roll; its upstream is down, so its fee is refunded.
clock_at $((BOUNDARY - 30)) || fail 4 "could not step the clock"
oracle_write_control "$W/mock.control" "$MP" "down" || fail 4 "mock control did not take"
chat straddling_status
oracle_clear_control "$W/mock.control" "$MP" || fail 4 "mock control did not clear"

# Read back in window D+1: the cell the charge reached.
clock_at $((BOUNDARY + 40)) || fail 4 "could not step the clock"
sleep 0.3
group_view="$(curl -sS -m 10 -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/groups/oracle/usage")"
key_view="$(curl -sS -m 10 -H "Authorization: Bearer $ADMIN" "http://127.0.0.1:${AP}/api/v1/admin/keys/${kid}/usage")"

kill $pid 2>/dev/null; wait $pid 2>/dev/null
i=0; while [ $i -lt 50 ] && ! assert_port_free "$LP"; do sleep 0.1; i=$((i+1)); done

if ! result="$(jq -n \
  --argjson mint_status "$(jq -r .mint_status <<<"$eff")" \
  --argjson rolling_status "$(jq -r .rolling_status <<<"$eff")" \
  --argjson straddling_status "$(jq -r .straddling_status <<<"$eff")" \
  --argjson group "$group_view" \
  --argjson key "$key_view" \
  '{mint_status:$mint_status, rolling_status:$rolling_status, straddling_status:$straddling_status,
    group_day_window:($group.buckets | map(select(.window == "day")) | .[0]
      | {requests, tokens, spend_cents, budget_remaining_cents}),
    key_all_time:($key | {requests, tokens, spend_cents})}' 2>"$W/result.err")"; then
  # Every value above is a number this run measured; one that is not means the cell cannot state
  # what it measured, and an empty body must never compare clean against a golden that failed the
  # same way.
  gap "the cell body could not be assembled from its own measurements: $(tr '\n' ' ' <"$W/result.err" | tail -c 200)"
fi

jq -n --argjson eff "$eff" --arg body "$result" '{status:0, headers:{}, body:$body, effects:$eff}' >"$RAW/captured.json"
exit 0
