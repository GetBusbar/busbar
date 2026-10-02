#!/usr/bin/env bash
# testing/fleet-fixtures/probe-secret.sh — the FUNCTIONAL probe for a secret plugin.
#
# THE BAR: a secret plugin is verified only when a real busbar has loaded it and a secret REFERENCE
# resolving through it produced a value busbar actually USED. Merely booting with the plugin present
# proves nothing — the plugin might fetch garbage, or busbar might never wire the resolved bytes
# anywhere. So this probe puts the resolved value on the critical path of a real request:
#
#   1. a fixture Vault backend holds the provider's api_key at a KV v2 path, behind a token
#   2. busbar's provider api_key is a { module: vault, settings: { path } } reference
#   3. the mock upstream REQUIRES exactly that key as its egress credential and 401s anything else
#   4. drive a chat request: it succeeds ONLY if the vault plugin resolved the value AND busbar sent
#      it upstream. A plugin that resolved nothing, or busbar failing to use it, is a 401 and a FAIL.
#
# Usage: BUSBAR_BIN=<busbar> PLUGIN_DIR=<dir> LEDGER=<tsv> \
#          [SECRET_MODULE=vault] probe-secret.sh <alias>
set -uo pipefail
cd "$(dirname "$0")" || exit 1
# shellcheck source=testing/fleet-fixtures/lib.sh
. ./lib.sh

ALIAS="${1:?usage: probe-secret.sh <alias>}"
BUSBAR_BIN="${BUSBAR_BIN:?BUSBAR_BIN must point at a busbar binary}"
PLUGIN_DIR="${PLUGIN_DIR:?PLUGIN_DIR must point at a directory of packed plugin tarballs}"
SECRET_MODULE="${SECRET_MODULE:-$ALIAS}"
LISTEN_PORT="${LISTEN_PORT:-18080}"
MOCK_PORT="${MOCK_PORT:-18079}"
VAULT_PORT="${VAULT_PORT:-18075}"
ID="secret:${ALIAS}"

fail_here() { record "$ID" FAIL "$1" "$2"; exit 0; }
command -v jq >/dev/null 2>&1 || fail_here "jq is required and missing" "install jq on the runner"
declaw "$BUSBAR_BIN"

WORK="$(mktemp -d "${RUNNER_TEMP:-/tmp}/probe-secret-XXXXXX")"
MARKER="fleet-fixture-secret-${ALIAS}-$$-${RANDOM}"
UPSTREAM_KEY="resolved-upstream-key-${RANDOM}"     # the value the vault plugin must resolve+use
VAULT_TOKEN="fixture-vault-token-${RANDOM}"
for p in "$LISTEN_PORT" "$MOCK_PORT" "$VAULT_PORT"; do
  assert_port_free "$p" || fail_here "port ${p} already in use before the probe starts" "refusing a possibly-false PASS."
done

# The mock upstream records every request it receives (headers unmasked), so the probe can read back
# the exact credential busbar sent.
EGRESS_DIR="${WORK}/egress"
ORACLE_MOCK_CAPTURE_DIR="$EGRESS_DIR" start_oracle_mock "$MOCK_PORT" "$MARKER" \
  || fail_here "the oracle mock upstream did not come up" "port ${MOCK_PORT}; bin/oracle could not obtain the pinned engine."
# The fixture Vault holding that key.
python3 vault-fixture.py "$VAULT_PORT" "$VAULT_TOKEN" api_key "$UPSTREAM_KEY" >/dev/null 2>&1 &
track_pid $!
wait_for_http "http://127.0.0.1:${VAULT_PORT}/v1/secret/data/busbar" 5 || true  # 403 without token, still up

# providers.yaml is the catalog (protocol + base_url + egress auth), matching the proven store
# probe's split. bearer egress so the Authorization header carries exactly the resolved value the
# mock upstream checks.
cat >"${WORK}/providers.yaml" <<EOF
mock:
  protocol: anthropic
  base_url: "http://127.0.0.1:${MOCK_PORT}"
  auth: bearer
EOF

# secrets: carries the MODULE's own open-time config (vault address + token), keyed by module name.
# The provider api_key is the { module: ..., settings: { path, field } } secret REFERENCE.
cat >"${WORK}/config.yaml" <<EOF
listen: "127.0.0.1:${LISTEN_PORT}"
auth:
  chain: []
plugins:
  enabled: true
  dir: "${PLUGIN_DIR}"
  trust:
    allow_unsigned: true
secrets:
  ${SECRET_MODULE}:
    settings: { addr: "http://127.0.0.1:${VAULT_PORT}", token: { env: VAULT_TOKEN } }
providers:
  mock:
    api_key: { module: ${SECRET_MODULE}, settings: { path: "secret/data/busbar", field: "api_key" } }
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
    VAULT_TOKEN="$VAULT_TOKEN" RUST_LOG=warn "$@"
}

# --validate resolves every secret reference once (fail-closed): if the plugin cannot resolve the
# reference at all, this is where it says so with the reference named.
if ! busbar_env "$BUSBAR_BIN" --validate >"${WORK}/validate.log" 2>&1; then
  fail_here "busbar --validate could not resolve the ${ALIAS} secret reference" \
    "$(tr '\n' '|' <"${WORK}/validate.log" | tail -c 500). The secret plugin did not resolve the vault-backed provider key."
fi

busbar_env "$BUSBAR_BIN" >"${WORK}/busbar.log" 2>&1 &
PID=$!; track_pid "$PID"
if ! wait_for_http "http://127.0.0.1:${LISTEN_PORT}/healthz" 30; then
  fail_here "busbar did not come up with the ${ALIAS} secret plugin" "$(tr '\n' '|' <"${WORK}/busbar.log" | tail -c 500)"
fi

# Drive one request; then read back what the upstream received. The resolved value can only be on the
# wire if busbar fetched it through the plugin and used it as the provider credential.
CHAT="$(curl -fsS -m 30 "http://127.0.0.1:${LISTEN_PORT}/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d '{"model":"test-model","messages":[{"role":"user","content":"hi"}]}' 2>/dev/null || true)"
GOT="$(printf '%s' "$CHAT" | jq -r '.choices[0].message.content // empty' 2>/dev/null)"
SENT="$(cat "${EGRESS_DIR}"/*.json 2>/dev/null | jq -r '.headers.authorization // empty' 2>/dev/null | grep -cxF "Bearer ${UPSTREAM_KEY}" || true)"
if [ "$GOT" != "$MARKER" ] || [ "${SENT:-0}" -lt 1 ]; then
  fail_here "the vault-resolved key was not used as the upstream credential" \
    "the upstream received no request carrying the key held in the fixture vault (round-trip got '$(printf '%s' "$CHAT" | tr '\n' ' ' | tail -c 200)', requests carrying the key: ${SENT:-0}). Either the ${ALIAS} plugin resolved nothing or busbar did not send the resolved value upstream."
fi

record "$ID" PASS "secret ${ALIAS}: a vault-referenced key resolved through the plugin and busbar used it upstream" \
  "the upstream recorded the resolved value as the request credential; the request round-tripped."
