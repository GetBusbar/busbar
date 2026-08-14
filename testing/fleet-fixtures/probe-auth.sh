#!/usr/bin/env bash
# testing/fleet-fixtures/probe-auth.sh — the FUNCTIONAL probe for an auth (identity-provider) plugin.
#
# THE BAR: an auth plugin is verified only when a real busbar has loaded it as an identity provider,
# a real credential exchange has happened against a stub IdP, and a USABLE busbar key came back. Not
# "the plugin's tests pass" — a full credential-to-key round trip through the running binary:
#
#   1. a stub IdP fixture serves OIDC discovery + JWKS and mints a signed id_token for a test sub
#   2. busbar is booted with the provider (module under test) in auth.chain, issuer -> the stub,
#      and a role_binding mapping the token's group to a budgeted team
#   3. POST /auth/token with the id_token as a bearer -> busbar mints a self-scoped key { api_key }
#   4. use that api_key to drive a real chat request through busbar -> the mock upstream
#   A usable key that authorizes a real request is the proof; a 401 at the exchange or the request
#   is a FAIL.
#
# Usage: BUSBAR_BIN=<busbar> PLUGIN_DIR=<dir> LEDGER=<tsv> \
#          [AUTH_MODULE=oidc] probe-auth.sh <alias>
set -uo pipefail
cd "$(dirname "$0")" || exit 1
# shellcheck source=testing/fleet-fixtures/lib.sh
. ./lib.sh

ALIAS="${1:?usage: probe-auth.sh <alias>}"
BUSBAR_BIN="${BUSBAR_BIN:?BUSBAR_BIN must point at a busbar binary}"
PLUGIN_DIR="${PLUGIN_DIR:?PLUGIN_DIR must point at a directory of packed plugin tarballs}"
AUTH_MODULE="${AUTH_MODULE:-$ALIAS}"
LISTEN_PORT="${LISTEN_PORT:-18080}"
ADMIN_PORT="${ADMIN_PORT:-18081}"
MOCK_PORT="${MOCK_PORT:-18079}"
IDP_PORT="${IDP_PORT:-18071}"
ID="auth:${ALIAS}"

fail_here() { record "$ID" FAIL "$1" "$2"; exit 0; }
command -v jq >/dev/null 2>&1 || fail_here "jq is required and missing" "install jq on the runner"
command -v openssl >/dev/null 2>&1 || fail_here "openssl is required for the stub IdP and missing" "install openssl on the runner"
declaw "$BUSBAR_BIN"

WORK="$(mktemp -d "${RUNNER_TEMP:-/tmp}/probe-auth-XXXXXX")"
MARKER="fleet-fixture-auth-${ALIAS}-$$-${RANDOM}"
SUB="probe-user-${RANDOM}"
ISSUER="http://127.0.0.1:${IDP_PORT}/"
AUDIENCE="busbar-fleet-fixture"
GROUP_VALUE="fixture-eng"
for p in "$LISTEN_PORT" "$ADMIN_PORT" "$MOCK_PORT" "$IDP_PORT"; do
  assert_port_free "$p" || fail_here "port ${p} already in use before the probe starts" "refusing a possibly-false PASS."
done

python3 mock-upstream.py "$MOCK_PORT" "$MARKER" >/dev/null 2>&1 &
track_pid $!
python3 stub-idp.py "$IDP_PORT" "http://127.0.0.1:${IDP_PORT}" "$ISSUER" "$AUDIENCE" "$SUB" groups "$GROUP_VALUE" >/dev/null 2>&1 &
track_pid $!
wait_for_http "http://127.0.0.1:${IDP_PORT}/jwks" 8 || fail_here "the stub IdP fixture did not come up" "port ${IDP_PORT}; openssl key generation may have failed."

"$BUSBAR_BIN" --generate-signing-key >"${WORK}/signing.key" 2>/dev/null
[ -s "${WORK}/signing.key" ] || fail_here "busbar --generate-signing-key produced no key" "the keys verifier cannot be configured."

cat >"${WORK}/providers.yaml" <<EOF
mock:
  protocol: anthropic
  base_url: "http://127.0.0.1:${MOCK_PORT}"
EOF

# The provider under test in auth.chain, issuer pointed at the stub, role_binding mapping the token's
# group to a budgeted team so /auth/token can mint a self-scoped key. keys stays in the chain so the
# minted key is then usable on the data plane.
cat >"${WORK}/config.yaml" <<EOF
listen: "127.0.0.1:${LISTEN_PORT}"
admin_listen: "127.0.0.1:${ADMIN_PORT}"
public_url: "http://127.0.0.1:${LISTEN_PORT}"
plugins:
  enabled: true
  dir: "${PLUGIN_DIR}"
  trust:
    allow_unsigned: true
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: { env: BUSBAR_ADMIN_TOKEN }
  ${ALIAS}:
    module: ${AUTH_MODULE}
    settings:
      issuer: "${ISSUER}"
      audience: "${AUDIENCE}"
auth:
  chain: [keys, ${ALIAS}]
  admin_auth: [admin-tokens]
  signing_key: { file: "${WORK}/signing.key" }
  role_bindings:
    ${ALIAS}:
      "${GROUP_VALUE}": { group: engineering }
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
groups:
  engineering:
    child_default:
      limits:
        - { requests: 1000, per: minute }
EOF

busbar_env() {
  BUSBAR_CONFIG="${WORK}/config.yaml" BUSBAR_PROVIDERS="${WORK}/providers.yaml" \
    MOCK_KEY=unused BUSBAR_ADMIN_TOKEN=fleet-fixture-admin RUST_LOG=warn "$@"
}

if ! busbar_env "$BUSBAR_BIN" --validate >"${WORK}/validate.log" 2>&1; then
  fail_here "busbar --validate rejects the ${ALIAS} auth config" \
    "$(tr '\n' '|' <"${WORK}/validate.log" | tail -c 500). The auth provider does not load into this busbar."
fi

busbar_env "$BUSBAR_BIN" >"${WORK}/busbar.log" 2>&1 &
PID=$!; track_pid "$PID"
if ! wait_for_http "http://127.0.0.1:${LISTEN_PORT}/healthz" 30; then
  fail_here "busbar did not come up with the ${ALIAS} auth provider" "$(tr '\n' '|' <"${WORK}/busbar.log" | tail -c 500)"
fi

# Get a fresh signed id_token from the stub IdP and present it to busbar's exchange.
IDTOKEN="$(curl -fsS "http://127.0.0.1:${IDP_PORT}/mint" 2>/dev/null || true)"
[ -n "$IDTOKEN" ] || fail_here "the stub IdP did not mint an id_token" "the credential exchange has nothing to present."

EXCH="$(curl -fsS -X POST "http://127.0.0.1:${LISTEN_PORT}/auth/token" \
  -H "Authorization: Bearer ${IDTOKEN}" 2>/dev/null || true)"
APIKEY="$(printf '%s' "$EXCH" | jq -r '.api_key // empty' 2>/dev/null)"
if [ -z "$APIKEY" ]; then
  fail_here "the credential exchange did not return a usable busbar key" \
    "POST /auth/token with a stub-IdP token returned '$(printf '%s' "$EXCH" | tr '\n' ' ' | tail -c 300)'. The ${ALIAS} provider did not verify the credential into a minted key."
fi

# The minted key must actually authorize a real data-plane request.
CHAT="$(curl -fsS "http://127.0.0.1:${LISTEN_PORT}/v1/chat/completions" \
  -H "Authorization: Bearer ${APIKEY}" -H "Content-Type: application/json" \
  -d '{"model":"test-model","messages":[{"role":"user","content":"hi"}]}' 2>/dev/null || true)"
GOT="$(printf '%s' "$CHAT" | jq -r '.choices[0].message.content // empty' 2>/dev/null)"
if [ "$GOT" != "$MARKER" ]; then
  fail_here "the exchanged key does not authorize a real request" \
    "the key minted from the credential exchange was rejected on the data plane (got '$(printf '%s' "$CHAT" | tr '\n' ' ' | tail -c 200)'). A key that cannot be used is not a usable key."
fi

record "$ID" PASS "auth ${ALIAS}: credential exchange against a stub IdP returned a busbar key that authorized a real request" ""
