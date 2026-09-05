#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell: the cooldown family. Pool `oracle-cd` has one member with base_cooldown_secs
# 1 and a consecutive-1 trip. This cell:
#   1. flips the mock `down` and sends a request -> the member 5xx-fails, the breaker trips Open
#   2. clears the mock control (settle) and sleeps past the jittered cooldown (+/-10% of 1s)
#   3. sends the SAME request again -> the breaker's own half-open probe succeeds -> served 200
# Writes $RAW/captured.json in the SAME shape capture.py uses everywhere else (status/headers/body
# of the LAST request, effects = before/after deltas spanning the whole sequence), so the recorded
# state-transition proof rides on quantities that survive a single before/after snapshot even though
# a scrape-time GAUGE like busbar_lane_state nets back to its starting value by the time the "after"
# snapshot is taken (0 -> 2 -> 0): the CUMULATIVE counters `busbar_breaker_trips_total` and
# `busbar_upstream_failures_total` go up by one and stay up, and the usage delta shows two admitted
# requests but only one billable one (the failed attempt is refunded, PB-16/26/27) — that pairing IS
# the trip-then-recover contract, and normalize.py's `metrics.cooldown` rule (keeps the key, blanks
# the jittered value) is what stops a pool/lane name that happens to contain "cooldown" from wiping
# those very metric lines (the bug this family exists to catch).
#
# Env from the recorder: BUSBAR_BIN RAW WORK ORACLE_ADMIN_TOKEN (WORK/ORACLE_ADMIN_TOKEN are ignored;
# this cell boots its own busbar on its own ports, like plugin-list.sh / store-persist.sh do).
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"
# shellcheck source=../oracle-config.sh
source "${here}/oracle-config.sh"

BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"
LISTEN_PORT="${COOLDOWN_LISTEN_PORT:-${SCRIPT_LISTEN_PORT:-48861}}" ADMIN_PORT="${COOLDOWN_ADMIN_PORT:-${SCRIPT_ADMIN_PORT:-48862}}" MOCK_PORT="${COOLDOWN_MOCK_PORT:-${SCRIPT_MOCK_PORT:-48796}}"
fail() { echo "{\"status\":-1,\"headers\":{},\"body\":\"\",\"effects\":{\"error\":\"$1\"}}" >"$RAW/captured.json"; exit 0; }
for p in "$LISTEN_PORT" "$ADMIN_PORT" "$MOCK_PORT"; do assert_port_free "$p" || fail "port $p busy"; done

W="$RAW/cooldown-work"; mkdir -p "$W"
export WORK="$W" BUSBAR_BIN="$BIN"
CONTROL="$W/mock.control"

python3 "${here}/mock-upstream.py" "$MOCK_PORT" oracle-marker "$CONTROL" >"$W/mock.log" 2>&1 & track_pid $!
wait_for_http "http://127.0.0.1:${MOCK_PORT}/" 8 || fail "mock upstream did not come up"

oracle_write_config "$W" "$LISTEN_PORT" "$ADMIN_PORT" "$MOCK_PORT" || fail "oracle config could not be written"

pid="$(oracle_spawn "$W/busbar.log" "$BIN")"; track_pid "$pid"
i=0
while [ $i -lt 200 ]; do
  curl -fsS -m 1 -o /dev/null "http://127.0.0.1:${LISTEN_PORT}/healthz" 2>/dev/null && break
  kill -0 "$pid" 2>/dev/null || break
  sleep 0.025; i=$((i + 1))
done
[ $i -lt 200 ] || fail "busbar did not come up ($(tr '\n' '|' <"$W/busbar.log" | tail -c 300))"

oracle_mint_keys "$ADMIN_PORT" || fail "could not mint oracle keys"

BODY='{"model":"oracle-cd","messages":[{"role":"user","content":"ping"}]}'
before_dir="$RAW/before"; after_dir="$RAW/after"
snap() {  # snap <dir>
  local d="$1"; mkdir -p "$d"
  curl -fsS -m 5 -H "Authorization: Bearer ${ORACLE_ADMIN_TOKEN}" \
    "http://127.0.0.1:${ADMIN_PORT}/api/v1/admin/keys/${ORACLE_KEY_OK}/usage" -o "$d/usage.json" 2>/dev/null || rm -f "$d/usage.json"
  curl -fsS -m 5 -H "Authorization: Bearer ${ORACLE_ADMIN_TOKEN}" \
    "http://127.0.0.1:${ADMIN_PORT}/api/v1/admin/audit?limit=1000" -o "$d/audit.json" 2>/dev/null || rm -f "$d/audit.json"
  curl -fsS -m 5 -H "Authorization: Bearer ${ORACLE_TOKEN_OK}" "http://127.0.0.1:${LISTEN_PORT}/metrics" -o "$d/metrics.txt" 2>/dev/null || rm -f "$d/metrics.txt"
}
snap "$before_dir"

# 1. trip: the mock answers `down` (503) for every model -> the walk's own attempt fails, the
#    consecutive-1 breaker on oracle-cd's one member opens on this first failure.
echo down >"$CONTROL"
curl -sS -m 20 -o "$RAW/trip.body" -w '%{http_code}' -X POST "http://127.0.0.1:${LISTEN_PORT}/v1/chat/completions" \
  -H "Authorization: Bearer ${ORACLE_TOKEN_OK}" -H 'Content-Type: application/json' -d "$BODY" >"$RAW/trip.status" 2>"$RAW/trip.err" || true

# 2. settle: the mock goes back to answering normally, then wait past the jittered cooldown
#    (base_cooldown_secs 1, +/-10% jitter -> worst case 1.1s; 1.6s leaves comfortable margin).
rm -f "$CONTROL"
sleep 1.6

# 3. serve again: the breaker's own half-open probe on the next attempt succeeds -> 200.
status="$(curl -sS -m 20 -N -o "$RAW/body" -D "$RAW/headers" -w '%{http_code}' -X POST "http://127.0.0.1:${LISTEN_PORT}/v1/chat/completions" \
  -H "Authorization: Bearer ${ORACLE_TOKEN_OK}" -H 'Content-Type: application/json' -d "$BODY" 2>"$RAW/serve.err")"

# let write-behind usage flush and the scrape-time gauges settle before the final snapshot
sleep 0.3
snap "$after_dir"

kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null

python3 "${here}/capture.py" "$RAW/headers" "$status" "$RAW/body" "$before_dir" "$after_dir" >"$RAW/captured.json" 2>"$RAW/capture.err" \
  || fail "capture.py failed: $(tail -c 300 "$RAW/capture.err")"
