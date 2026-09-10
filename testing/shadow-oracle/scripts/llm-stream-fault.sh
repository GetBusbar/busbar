#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Script-driver cell family: `llm.stream|<dialect>|<fault>` -- THE MID-STREAM UPSTREAM FAILURE.
#
# WHY THIS FAMILY EXISTS. Every other upstream-failure cell in the corpus refuses BEFORE a byte of
# the answer has left the door: `upstream_down` is a status code, and a status code is a thing you
# can still choose. Once the door has written `HTTP/1.1 200` and the first frame, the status is
# spent -- the failure has to be told in the stream's own dialect, the frames already delivered have
# to be billed or refunded, and the breaker has to decide whether a lane that answered and then died
# counts as a failure. NOT ONE RECORDED CELL SEES ANY OF THAT. busbar-unit-egress has never served a
# request, and the engine's egress half is about to move into it (L2 MOVE 7); a move onto the money
# path with the whole mid-stream arm unrecorded is a move that cannot be proven byte-identical.
#
# WHY IT IS A SCRIPT CELL AND NOT SIX MORE `llm|<d>|<d>|request|...` ROWS. It was meant to be: the
# corpus has declared `llm|<d>|<d>|request|stream_upstream_error` with `mock_control:
# {"stream-error": true}` since the day the mock grew the verb. Under the PINNED recorder those six
# rows cannot record what they name, for two independent reasons, and both fail SILENTLY GREEN:
#   1. record.sh's built-in `llm` driver writes the mock control for exactly one outcome
#      (`if [ "$outcome" = upstream_down ]` -> "down"). A cell's own `mock_control` is honoured by
#      the `http` and `concurrent` drivers only, so on an llm cell it is dead: the mock serves the
#      HEALTHY answer.
#   2. build-request.py decides streaming by `oc in ("ok_stream", "ok_stream_array")`. `stream_
#      upstream_error` is in neither, so the request it builds is BUFFERED -- not a stream at all.
# Measured, not argued: recording those six against 1.5.5 with `needs_fixture` lifted yields
# `usage Δ {"requests":1,"spend_cents":250,"tokens":18}` and a buffered `chat.completion` body --
# the happy path, frozen under the name of the failure, identically on both binaries. So those rows
# stay `needs_fixture` (a NAMED gap, owed to a tool release that teaches the llm driver
# `mock_control`), and the behaviour is pinned HERE, in the half of the harness busbar owns.
#
# WHAT THE CELL PINS, on the SAME baseline config, the SAME mock and the SAME request bytes the
# `ok_stream` golden already carries for this dialect (build-request.py, outcome `ok_stream`) -- so
# the ONLY difference from the recorded happy path is what the upstream did halfway through:
#   status + headers   what the caller was told, including that it was told 200 and content-type
#   body               the caller's bytes VERBATIM, terminal frame or the absence of one, decoded
#                      by normalize.py in the dialect's own framing (SSE / amazon eventstream)
#   effects.usage      THE LEDGER ROW: requests / tokens / spend_cents actually drawn for a stream
#                      that delivered text and then died
#   effects.metrics    the breaker's own record: busbar_breaker_trips_total,
#                      busbar_upstream_failures_total, busbar_requests_total{outcome=...} -- and
#                      their ABSENCE is pinned exactly as their presence is
#   effects.egress     what busbar SENT upstream, so a change of request is a diff here and not a
#                      mystery in the answer
#   effects.stream_fault  the surfaces a normalized body cannot carry: the client-side transport
#                      verdict (curl's rc: 0 = the door closed cleanly, 18/56 = the CALLER's socket
#                      died too), the frame count, and a second usage read after a settle pause --
#                      a late or doubled posting is drift here, not silence
#
# THE TWO FAULT SHAPES, both from the pinned mock's own verb vocabulary, both deterministic:
#   stream-error   the upstream sends the dialect's normal frames up to and including the text
#                  delta, then an IN-BAND error event in that dialect's own error shape, and NO
#                  terminal usage/[DONE] frame. The 5xx that arrives too late to be a status.
#   cut            headers, the first frame, then the socket dies with no error at all. The reset.
# Neither depends on a clock, a race or a retry: the mock is a pure function of the request and the
# control file, the control is written and READ BACK through /__control before the request is sent
# (oracle_write_control), and the door is addressed by its own lane, never by a pool, so no failover
# or jitter can reorder anything.
#
#   llm-stream-fault.sh <dialect> <fault>
#     <dialect>  anthropic | openai | responses | gemini | bedrock | cohere  (the corpus spelling;
#                build-request.py aliases openai -> openai-chat, responses -> openai-responses)
#     <fault>    stream-error | cut
#
# Env from the recorder: BUSBAR_BIN RAW SCRIPT_LISTEN_PORT SCRIPT_ADMIN_PORT SCRIPT_MOCK_PORT
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
repo="$(cd "${here}/../.." && pwd)"
source "${repo}/testing/fleet-fixtures/lib.sh"
# shellcheck source=../oracle-config.sh
source "${BUSBAR_ORACLE_TOOL_DIR:-$here}/oracle-config.sh"
TOOL="${BUSBAR_ORACLE_TOOL_DIR:-$here}"

BIN="${BUSBAR_BIN:?}"; RAW="${RAW:?}"
DIALECT="${1:?usage: llm-stream-fault.sh <dialect> <fault>}"
FAULT="${2:?usage: llm-stream-fault.sh <dialect> <fault>}"
LISTEN_PORT="${SCRIPT_LISTEN_PORT:-48861}" ADMIN_PORT="${SCRIPT_ADMIN_PORT:-48862}" MOCK_PORT="${SCRIPT_MOCK_PORT:-48796}"

# A give-up path is a NAMED GAP (status -1), never a pass: record.sh reads it as UNSUPPORTED.
fail() { jq -n --arg e "$1" '{status:-1,headers:{},body:"",effects:{error:$e}}' >"$RAW/captured.json"; exit 0; }
# `harness_error` is the OTHER give-up: record.sh refuses the cell outright.
broke() { jq -n --arg e "$1" '{status:-1,headers:{},body:"",effects:{harness_error:$e}}' >"$RAW/captured.json"; exit 0; }

case "$FAULT" in stream-error|cut) ;; *) broke "unknown fault '${FAULT}': the mock implements stream-error and cut" ;; esac
command -v jq >/dev/null || broke "llm-stream-fault.sh needs jq"
for p in "$LISTEN_PORT" "$ADMIN_PORT" "$MOCK_PORT"; do assert_port_free "$p" || fail "port $p busy"; done

W="$RAW/stream-fault-work"; rm -rf "$W"; mkdir -p "$W/egress"
export WORK="$W" BUSBAR_BIN="$BIN"
CONTROL="$W/mock.control"

ORACLE_MOCK_CAPTURE_DIR="$W/egress" python3 "${TOOL}/mock-upstream.py" "$MOCK_PORT" oracle-marker "$CONTROL" >"$W/mock.log" 2>&1 & track_pid $!
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

# THE REQUEST IS THE `ok_stream` GOLDEN'S REQUEST, BYTE FOR BYTE. Built by the same builder, from a
# cell that names the same diagonal and the same outcome, with the same principal -- so this cell
# and the recorded happy-path stream differ in exactly one variable: what the upstream did. A
# request written by hand here would put a second variable in the comparison and quietly become the
# thing that explains a diff.
cellspec="$(jq -nc --arg d "$DIALECT" '{ingress_dialect:$d, egress_dialect:$d, outcome:"ok_stream"}')"
req="$(ORACLE_AWS_AKID="$ORACLE_AWS_AKID_OK" ORACLE_AWS_SECRET="$ORACLE_AWS_SECRET_OK" \
       ORACLE_HOST="127.0.0.1:${LISTEN_PORT}" python3 "${TOOL}/build-request.py" --cell "$cellspec" 2>"$W/build.err")" \
  || broke "build-request.py failed for ${DIALECT}: $(tail -c 200 "$W/build.err")"
auth="$(jq -r .auth <<<"$req")"
case "$auth" in
  bearer|sigv4-signed) ;;
  *) fail "UNSUPPORTED: $(jq -r .note <<<"$req")" ;;
esac
path="$(jq -r .path <<<"$req")"
jq -j .body <<<"$req" >"$W/request.body"
hdr_args=()
while IFS= read -r kv; do hdr_args+=(-H "$kv"); done < <(jq -r '.headers | to_entries[] | "\(.key): \(.value)"' <<<"$req")
[ "$auth" = sigv4-signed ] || hdr_args+=(-H "Authorization: Bearer ${ORACLE_TOKEN_OK}")

snap() {  # snap <dir> -- the three files capture.py reads on each side
  local d="$1"; mkdir -p "$d"
  curl -fsS -m 5 -H "Authorization: Bearer ${ORACLE_ADMIN_TOKEN}" \
    "http://127.0.0.1:${ADMIN_PORT}/api/v1/admin/keys/${ORACLE_KEY_OK}/usage" -o "$d/usage.json" 2>/dev/null || rm -f "$d/usage.json"
  curl -fsS -m 5 -H "Authorization: Bearer ${ORACLE_ADMIN_TOKEN}" \
    "http://127.0.0.1:${ADMIN_PORT}/api/v1/admin/audit?limit=1000" -o "$d/audit.json" 2>/dev/null || rm -f "$d/audit.json"
  oracle_scrape_metrics "$LISTEN_PORT" "$ORACLE_TOKEN_OK" "$d/metrics.txt" || true
}
usage_now() { curl -sS -m 5 -H "Authorization: Bearer ${ORACLE_ADMIN_TOKEN}" \
  "http://127.0.0.1:${ADMIN_PORT}/api/v1/admin/keys/${ORACLE_KEY_OK}/usage" | jq -c 'del(.as_of)'; }

snap "$RAW/before"
ls "$W/egress" 2>/dev/null | LC_ALL=C sort >"$W/egress.before"

# The fault is ordered OUT OF BAND and read back through /__control before a byte is sent, so
# busbar's own request is byte-identical to the healthy cell this one is compared against.
oracle_write_control "$CONTROL" "$MOCK_PORT" "$FAULT" || fail "mock control write (${FAULT}) never landed"

status="$(curl -sS -m 25 -N -X POST "http://127.0.0.1:${LISTEN_PORT}${path}" "${hdr_args[@]}" \
  --data-binary "@$W/request.body" -D "$RAW/headers" -o "$RAW/body" -w '%{http_code}' 2>"$W/curl.err")"; curl_rc=$?
# A CUT MID-BODY IS THE RESPONSE, NOT A HARNESS FAILURE -- record.sh's own rule, restated here
# because this cell is the one that provokes it. 18 (partial transfer) and 56 (recv failure) still
# carry the status line and every byte that arrived; anything else means no response at all.
case "$curl_rc:$status" in
  0:*|18:[1-5]??|56:[1-5]??) ;;
  *) fail "no HTTP response from the door (curl rc ${curl_rc}, status '${status}'): $(tr '\n' ' ' <"$W/curl.err" | tail -c 200)" ;;
esac

oracle_clear_control "$CONTROL" "$MOCK_PORT" || fail "mock control clear never landed"

# Let the write-behind meter flush before the "after" snapshot: a settle read that happens too early
# records "not billed yet" as "not billed", which is the one thing this cell must not get wrong.
sleep 0.6
usage_settled="$(usage_now)"
snap "$RAW/after"
# ...and once more, after a further pause: a LATE or DOUBLED posting shows up as drift between these
# two reads, which a single before/after delta can never see.
sleep 0.6
usage_late="$(usage_now)"

ls "$W/egress" 2>/dev/null | LC_ALL=C sort >"$W/egress.after"
egress_files=()
while IFS= read -r f; do [ -n "$f" ] && egress_files+=("$W/egress/$f"); done < <(LC_ALL=C comm -13 "$W/egress.before" "$W/egress.after")
egress_settle "llm.stream|${DIALECT}|${FAULT}" "${egress_files[@]}"

kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null

python3 "${TOOL}/capture.py" "$RAW/headers" "$status" "$RAW/body" "$RAW/before" "$RAW/after" "${egress_files[@]}" \
  >"$W/captured.json" 2>"$W/capture.err" || broke "capture.py failed: $(tail -c 300 "$W/capture.err")"

# THE SURFACES A NORMALIZED BODY CANNOT CARRY. Counted here, on the raw bytes, before normalize.py
# ever sees them: a frame count taken after normalization would be a property of the normalizer.
frames="$(awk '/^(data|event):/{n++} END{print n+0}' "$RAW/body" 2>/dev/null)"
[ -n "$frames" ] || frames=0
bytes="$(wc -c <"$RAW/body" | tr -d ' ')"
late_delta="$(jq -n --argjson a "$usage_settled" --argjson b "$usage_late" \
  '{requests: (($b.requests//0) - ($a.requests//0)), tokens: (($b.tokens//0) - ($a.tokens//0)),
    spend_cents: (($b.spend_cents//0) - ($a.spend_cents//0))}' 2>/dev/null)" || late_delta='null'
[ -n "$late_delta" ] || late_delta='null'

if ! jq --arg d "$DIALECT" --arg f "$FAULT" --argjson rc "$curl_rc" --argjson fr "$frames" \
      --argjson by "$bytes" --argjson late "$late_delta" \
      '.effects.stream_fault = {dialect:$d, fault:$f, client_curl_rc:$rc, body_frames:$fr,
                                body_bytes:$by, usage_delta_after_settle_pause:$late}' \
      "$W/captured.json" >"$RAW/captured.json" 2>"$W/fold.err"; then
  broke "the mid-stream evidence could not be folded into the capture: $(tail -c 200 "$W/fold.err")"
fi

# The script-cell verdict reads the DRIVER'S EXIT STATUS, not just the file it left behind. Say 0
# out loud on the success path rather than inheriting whatever the last command happened to return.
exit 0
