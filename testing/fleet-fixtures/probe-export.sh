#!/usr/bin/env bash
# testing/fleet-fixtures/probe-export.sh — the FUNCTIONAL probe for an export (telemetry-egress)
# plugin/module.
#
# THE BAR: an exporter is verified only when a real busbar has loaded it, a request has been driven,
# and the SINK actually received the export. "busbar booted with the exporter configured" is the
# it-loaded claim; delivery is the it-works claim, and only a receiver outside busbar tells them
# apart. docker.yml once recorded a bundle rebuild that "succeeded" having shipped only `test` — the
# same it-built-≠-it-works gap, one layer down.
#
#   1. an export instance (module under test) points at a sink fixture URL
#   2. drive a real chat request through busbar
#   3. poll the sink: it must have received at least one export POST
#
# Usage: BUSBAR_BIN=<busbar> PLUGIN_DIR=<dir> LEDGER=<tsv> \
#          [EXPORT_MODULE=request-log-webhook] probe-export.sh <alias>
set -uo pipefail
cd "$(dirname "$0")" || exit 1
# shellcheck source=testing/fleet-fixtures/lib.sh
. ./lib.sh

ALIAS="${1:?usage: probe-export.sh <alias>}"
BUSBAR_BIN="${BUSBAR_BIN:?BUSBAR_BIN must point at a busbar binary}"
PLUGIN_DIR="${PLUGIN_DIR:?PLUGIN_DIR must point at a directory of packed plugin tarballs}"
EXPORT_MODULE="${EXPORT_MODULE:-$ALIAS}"
LISTEN_PORT="${LISTEN_PORT:-18080}"
MOCK_PORT="${MOCK_PORT:-18079}"
SINK_PORT="${SINK_PORT:-18073}"
ID="export:${ALIAS}"

fail_here() { record "$ID" FAIL "$1" "$2"; exit 0; }
command -v jq >/dev/null 2>&1 || fail_here "jq is required and missing" "install jq on the runner"
declaw "$BUSBAR_BIN"

WORK="$(mktemp -d "${RUNNER_TEMP:-/tmp}/probe-export-XXXXXX")"
MARKER="fleet-fixture-export-${ALIAS}-$$-${RANDOM}"
for p in "$LISTEN_PORT" "$MOCK_PORT" "$SINK_PORT"; do
  assert_port_free "$p" || fail_here "port ${p} already in use before the probe starts" "refusing a possibly-false PASS."
done

python3 mock-upstream.py "$MOCK_PORT" "$MARKER" >/dev/null 2>&1 &
track_pid $!
python3 export-sink.py "$SINK_PORT" >/dev/null 2>&1 &
track_pid $!
wait_for_http "http://127.0.0.1:${SINK_PORT}/received" 5 || fail_here "the export sink fixture did not come up" "port ${SINK_PORT}."

# ── THE SINK IS PROVEN SHARP BEFORE THE EXPORTER IS JUDGED BY IT. ────────────────────────────────
# The sink counted any POST with no look at the body, so "the exporter delivered" meant no more than
# "something POSTed to this port" — an exporter shipping `{}`, an empty body, or another process's
# telemetry all read as delivery. These calls happen BEFORE busbar exists, so the counter is known to
# be 0 and every increment below is attributable.
sink_json() { curl -fsS -m 10 "http://127.0.0.1:${SINK_PORT}/received" 2>/dev/null; }
sink_post() { curl -sS -m 10 -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${SINK_PORT}/" \
                -H 'Content-Type: application/json' --data-binary "$1" 2>/dev/null || echo 000; }
# One malformed body per way a body can be wrong and still be a POST.
for _bad in '' '{}' 'not json at all' '[{"ts":1,"ingress_protocol":"anthropic","pool":"p","outcome":"ok","latency_ms":1}]' \
            '{"ts":1,"ingress_protocol":"anthropic","pool":"p","outcome":"ok"}' \
            '{"ts":"soon","ingress_protocol":"anthropic","pool":"p","outcome":"ok","latency_ms":1}' \
            '{"ts":1,"ingress_protocol":"anthropic","pool":"p","outcome":"probably_fine","latency_ms":1}'; do
  sink_post "$_bad" >/dev/null
done
BLUNT="$(sink_json | jq -r '.count // 0' 2>/dev/null)"
BLUNT_REJ="$(sink_json | jq -r '.rejected // 0' 2>/dev/null)"
if [ "${BLUNT:-0}" -ne 0 ]; then
  fail_here "the export sink counts bodies that are not request-log records, so this probe cannot prove the exporter delivered anything" \
    "7 deliberately malformed bodies (empty, {}, non-JSON, an array, a missing field, a wrong type, an outcome outside the vocabulary) produced ${BLUNT} counted delivery(s). A sink that counts any POST turns 'the exporter shipped a request log' into 'something reached this port'."
fi
if [ "${BLUNT_REJ:-0}" -lt 7 ]; then
  fail_here "the export sink did not account for the malformed bodies it was sent" \
    "sent 7, rejected ${BLUNT_REJ}. The sink cannot say what it received, so a later count cannot be attributed."
fi

cat >"${WORK}/providers.yaml" <<EOF
mock:
  protocol: anthropic
  base_url: "http://127.0.0.1:${MOCK_PORT}"
EOF

# export: is a NAMED map of instances; one instance of the module under test, pointed at the sink.
cat >"${WORK}/config.yaml" <<EOF
listen: "127.0.0.1:${LISTEN_PORT}"
auth:
  chain: []
plugins:
  enabled: true
  dir: "${PLUGIN_DIR}"
  trust:
    allow_unsigned: true
export:
  probe:
    module: ${EXPORT_MODULE}
    settings: { url: "http://127.0.0.1:${SINK_PORT}/" }
providers:
  mock:
    api_key: { env: MOCK_KEY }
models:
  test-model:
    provider: mock
pools:
  default:
    members:
      - model: test-model
EOF

busbar_env() {
  BUSBAR_CONFIG="${WORK}/config.yaml" BUSBAR_PROVIDERS="${WORK}/providers.yaml" \
    MOCK_KEY=unused RUST_LOG=warn "$@"
}

if ! busbar_env "$BUSBAR_BIN" --validate >"${WORK}/validate.log" 2>&1; then
  fail_here "busbar --validate rejects the export config" \
    "$(tr '\n' '|' <"${WORK}/validate.log" | tail -c 500). The ${ALIAS} exporter does not load into this busbar."
fi

busbar_env "$BUSBAR_BIN" >"${WORK}/busbar.log" 2>&1 &
PID=$!; track_pid "$PID"
if ! wait_for_http "http://127.0.0.1:${LISTEN_PORT}/healthz" 30; then
  fail_here "busbar did not come up with the ${ALIAS} exporter" "$(tr '\n' '|' <"${WORK}/busbar.log" | tail -c 500)"
fi

# Drive a real request so there is something to export.
CHAT="$(curl -fsS -m 30 "http://127.0.0.1:${LISTEN_PORT}/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d '{"model":"test-model","messages":[{"role":"user","content":"hi"}]}' 2>/dev/null || true)"
GOT="$(printf '%s' "$CHAT" | jq -r '.choices[0].message.content // empty' 2>/dev/null)"
[ "$GOT" = "$MARKER" ] || fail_here "the request to be exported did not round-trip" \
  "expected marker '${MARKER}', observed '$(printf '%s' "$CHAT" | tr '\n' ' ' | tail -c 200)'."

# Poll the sink: exports may be buffered, so give it a bounded window rather than one shot.
RECV=0
for _ in $(seq 1 15); do
  RECV="$(curl -fsS -m 30 "http://127.0.0.1:${SINK_PORT}/received" 2>/dev/null | jq -r '.count // 0' 2>/dev/null)"
  [ "${RECV:-0}" -ge 1 ] && break
  sleep 2
done
if [ "${RECV:-0}" -lt 1 ]; then
  REJ="$(sink_json | jq -r '.rejected // 0' 2>/dev/null)"
  LAST="$(sink_json | jq -r '.last_reject // empty' 2>/dev/null)"
  if [ "${REJ:-0}" -gt "${BLUNT_REJ:-0}" ]; then
    # The two failures are NOT the same and must not read the same. Something DID arrive; it was not
    # a request-log record, and the sink can say why.
    fail_here "the ${ALIAS} exporter delivered, but not a request-log record" \
      "$(( REJ - BLUNT_REJ )) body(ies) reached the sink and none validated; the last was rejected because: ${LAST}. Expected one flat object {ts, ingress_protocol, pool, outcome, latency_ms} per completed request."
  fi
  fail_here "the exporter did not deliver: the sink received nothing" \
    "busbar booted with the ${ALIAS} exporter and served a request, but no export reached the sink. The exporter is configured but inert."
fi

record "$ID" PASS "export ${ALIAS}: a driven request was delivered to the sink fixture as a valid request-log record (${RECV} received)" \
  "the sink validates the shape busbar's build_request_log emits and refused 7 malformed bodies before busbar started."
