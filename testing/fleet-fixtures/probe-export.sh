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
CHAT="$(curl -fsS "http://127.0.0.1:${LISTEN_PORT}/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d '{"model":"test-model","messages":[{"role":"user","content":"hi"}]}' 2>/dev/null || true)"
GOT="$(printf '%s' "$CHAT" | jq -r '.choices[0].message.content // empty' 2>/dev/null)"
[ "$GOT" = "$MARKER" ] || fail_here "the request to be exported did not round-trip" \
  "expected marker '${MARKER}', observed '$(printf '%s' "$CHAT" | tr '\n' ' ' | tail -c 200)'."

# Poll the sink: exports may be buffered, so give it a bounded window rather than one shot.
RECV=0
for _ in $(seq 1 15); do
  RECV="$(curl -fsS "http://127.0.0.1:${SINK_PORT}/received" 2>/dev/null | jq -r '.count // 0' 2>/dev/null)"
  [ "${RECV:-0}" -ge 1 ] && break
  sleep 2
done
if [ "${RECV:-0}" -lt 1 ]; then
  fail_here "the exporter did not deliver: the sink received nothing" \
    "busbar booted with the ${ALIAS} exporter and served a request, but no export reached the sink. The exporter is configured but inert."
fi

record "$ID" PASS "export ${ALIAS}: a driven request was delivered to the sink fixture (${RECV} received)" ""
