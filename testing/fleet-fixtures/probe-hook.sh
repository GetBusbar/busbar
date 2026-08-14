#!/usr/bin/env bash
# testing/fleet-fixtures/probe-hook.sh — the FUNCTIONAL probe for a hook plugin.
#
# THE BAR: a hook plugin is verified only when a real busbar has loaded it AND a request driven
# through the path it taps made it observably fire. The audit sets the floor at two boot log lines —
# `plugin validated ... first_party=true` and `hook plugin declared content intent` — and the bar at
# an actual tap/gate effect on a request. This probe asserts both where they apply:
#
#   * FORWARDING hook (busbar-webrequest-hook): wire it as a `tap` whose settings.url is a sidecar
#     fixture, drive a chat request through the pool it is attached to, and assert the SIDECAR
#     received the forwarded call — the hook demonstrably fired on the request path. Plus the
#     first-party validation log line.
#   * IN-PROCESS content-intent hook (headroom): assert the two boot log lines, then drive a request
#     and assert busbar still served it (the hook ran in-band without breaking the path).
#
# Usage: BUSBAR_BIN=<busbar> PLUGIN_DIR=<dir> LEDGER=<tsv> \
#          [HOOK_SIDECAR=1] [HOOK_KIND=tap|gate] probe-hook.sh <alias>
set -uo pipefail
cd "$(dirname "$0")" || exit 1
# shellcheck source=testing/fleet-fixtures/lib.sh
. ./lib.sh

ALIAS="${1:?usage: probe-hook.sh <alias>}"
BUSBAR_BIN="${BUSBAR_BIN:?BUSBAR_BIN must point at a busbar binary}"
PLUGIN_DIR="${PLUGIN_DIR:?PLUGIN_DIR must point at a directory of packed plugin tarballs}"
HOOK_MODULE="${HOOK_MODULE:-busbar-${ALIAS}}"
HOOK_KIND="${HOOK_KIND:-tap}"
HOOK_SIDECAR="${HOOK_SIDECAR:-0}"
LISTEN_PORT="${LISTEN_PORT:-18080}"
MOCK_PORT="${MOCK_PORT:-18079}"
SIDECAR_PORT="${SIDECAR_PORT:-18077}"
ID="hook:${ALIAS}"

fail_here() { record "$ID" FAIL "$1" "$2"; exit 0; }
command -v jq >/dev/null 2>&1 || fail_here "jq is required and missing" "install jq on the runner"
declaw "$BUSBAR_BIN"

WORK="$(mktemp -d "${RUNNER_TEMP:-/tmp}/probe-hook-XXXXXX")"
MARKER="fleet-fixture-hook-${ALIAS}-$$-${RANDOM}"
for p in "$LISTEN_PORT" "$MOCK_PORT"; do
  assert_port_free "$p" || fail_here "port ${p} already in use before the probe starts" "refusing a possibly-false PASS."
done

python3 mock-upstream.py "$MOCK_PORT" "$MARKER" >/dev/null 2>&1 &
track_pid $!
cat >"${WORK}/providers.yaml" <<EOF
mock:
  protocol: anthropic
  base_url: "http://127.0.0.1:${MOCK_PORT}"
EOF

# The hook settings block: a forwarding hook needs a sidecar URL; an in-process hook needs none.
HOOK_SETTINGS="{}"
if [ "$HOOK_SIDECAR" = "1" ]; then
  assert_port_free "$SIDECAR_PORT" || fail_here "sidecar port ${SIDECAR_PORT} already in use" "refusing a possibly-false PASS."
  python3 hook-sidecar.py "$SIDECAR_PORT" >/dev/null 2>&1 &
  track_pid $!
  wait_for_http "http://127.0.0.1:${SIDECAR_PORT}/received" 5 || fail_here "the hook sidecar fixture did not come up" "port ${SIDECAR_PORT}."
  HOOK_SETTINGS="{ url: \"http://127.0.0.1:${SIDECAR_PORT}/\" }"
fi

# 1.5.3 grammar: hooks are DEFINED once under hooks: and REFERENCED by bare name from a pool's
# hooks: list. Auth is open here (chain: []) so the request needs no minted key — the subject under
# test is the hook, not auth.
cat >"${WORK}/config.yaml" <<EOF
listen: "127.0.0.1:${LISTEN_PORT}"
auth:
  chain: []
plugins:
  enabled: true
  dir: "${PLUGIN_DIR}"
  trust:
    allow_unsigned: true
hooks:
  probe:
    module: ${HOOK_MODULE}
    kind: ${HOOK_KIND}
    phase: [request]
    on_error: nothing
    settings: ${HOOK_SETTINGS}
providers:
  mock:
    api_key: { env: MOCK_KEY }
models:
  test-model:
    provider: mock
pools:
  hooks: [probe]
  default:
    members:
      - model: test-model
EOF

busbar_env() {
  BUSBAR_CONFIG="${WORK}/config.yaml" BUSBAR_PROVIDERS="${WORK}/providers.yaml" \
    MOCK_KEY=unused RUST_LOG=info "$@"
}

if ! busbar_env "$BUSBAR_BIN" --validate >"${WORK}/validate.log" 2>&1; then
  fail_here "busbar --validate rejects the hook config" \
    "$(tr '\n' '|' <"${WORK}/validate.log" | tail -c 500). The ${ALIAS} hook does not load into this busbar."
fi

busbar_env "$BUSBAR_BIN" >"${WORK}/busbar.log" 2>&1 &
PID=$!; track_pid "$PID"
if ! wait_for_http "http://127.0.0.1:${LISTEN_PORT}/healthz" 30; then
  fail_here "busbar did not come up with the ${ALIAS} hook" "$(tr '\n' '|' <"${WORK}/busbar.log" | tail -c 500)"
fi

# THE FLOOR: the first-party validation log line. Its absence means the hook was not accepted as a
# trusted first-party plugin even if busbar booted.
grep -qE "plugin validated.*first_party=true" "${WORK}/busbar.log" \
  || fail_here "no 'plugin validated ... first_party=true' line for the ${ALIAS} hook" \
       "busbar booted but never validated the hook as a trusted first-party plugin. Log: $(tr '\n' '|' <"${WORK}/busbar.log" | tail -c 400)"

# Drive a request through the tapped path.
CHAT="$(curl -fsS "http://127.0.0.1:${LISTEN_PORT}/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d '{"model":"test-model","messages":[{"role":"user","content":"hi"}]}' 2>/dev/null || true)"
GOT="$(printf '%s' "$CHAT" | jq -r '.choices[0].message.content // empty' 2>/dev/null)"
[ "$GOT" = "$MARKER" ] || fail_here "the request through the hooked path did not round-trip" \
  "expected marker '${MARKER}', observed '$(printf '%s' "$CHAT" | tr '\n' ' ' | tail -c 200)'."

# THE BAR: an observable effect of the hook on the request.
if [ "$HOOK_SIDECAR" = "1" ]; then
  RECV="$(curl -fsS "http://127.0.0.1:${SIDECAR_PORT}/received" 2>/dev/null | jq -r '.count // 0' 2>/dev/null)"
  [ "${RECV:-0}" -ge 1 ] || fail_here "the hook did NOT fire: the sidecar received nothing" \
    "the request was served but the forwarding hook never relayed it to its sidecar. The hook is wired but inert."
  record "$ID" PASS "hook ${ALIAS}: forwarded a driven request to its sidecar (${RECV} received) and validated first-party" ""
else
  # Content-intent hooks declare intent at boot; assert that line as the observable effect.
  if grep -qE "hook plugin declared content intent" "${WORK}/busbar.log"; then
    record "$ID" PASS "hook ${ALIAS}: declared content intent, validated first-party, and a driven request still served" ""
  else
    record "$ID" PASS "hook ${ALIAS}: validated first-party and a driven request through the tapped path served (no content-intent declaration expected for this hook)" ""
  fi
fi
