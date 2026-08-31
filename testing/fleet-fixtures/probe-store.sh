#!/usr/bin/env bash
# testing/fleet-fixtures/probe-store.sh — the FUNCTIONAL probe for a store plugin.
#
# THE BAR, STATED ONCE: a store plugin is verified only when a real busbar binary has loaded it and
# it has demonstrably done its ONE job — persistence. "The plugin's own tests pass" and "cargo test
# is green" are different claims and neither dlopens the plugin into busbar. This does:
#
#   1. boot the real busbar binary with the plugin wired as `store:`
#   2. mint a real virtual key over the real admin API (POST .../keys)
#   3. drive a real chat-completion through busbar -> the mock upstream, asserting the body
#   4. read the key's usage counters back (they must be nonzero)
#   5. KILL the process, restart it against the SAME store, and assert the key AND its usage
#      counters SURVIVED — persistence is the entire job, so the restart is the entire test
#
# This is scripts/release-check.sh's run_store_backend_e2e, lifted out of the ~2h release gate into
# a standalone probe so it can (a) run in the reusable plugin-functional.yml against ANY busbar and
# (b) be dry-run on a laptop against the real published artifacts. It was validated exactly that
# way against busbar 1.5.4 + store-sqlite 1.0.4 before being trusted.
#
# Usage: BUSBAR_BIN=<busbar> PLUGIN_DIR=<dir of packed+extracted plugin> LEDGER=<tsv> \
#          probe-store.sh <alias>
#
# Every probe RECORDS to the ledger and returns; it does not decide the verdict. verdict.sh does.
set -uo pipefail
cd "$(dirname "$0")" || exit 1
# shellcheck source=testing/fleet-fixtures/lib.sh
. ./lib.sh

ALIAS="${1:?usage: probe-store.sh <alias>}"
BUSBAR_BIN="${BUSBAR_BIN:?BUSBAR_BIN must point at a busbar binary}"
PLUGIN_DIR="${PLUGIN_DIR:?PLUGIN_DIR must point at a directory of packed plugin tarballs/manifests}"
STORE_MODULE="${STORE_MODULE:-$ALIAS}"
STORE_SETTINGS="${STORE_SETTINGS:-}"        # e.g. '{ db_path: "/tmp/gov.db" }'; empty for in-config default
LISTEN_PORT="${LISTEN_PORT:-18080}"
ADMIN_PORT="${ADMIN_PORT:-18081}"
MOCK_PORT="${MOCK_PORT:-18079}"
ID="store:${ALIAS}"

fail_here() { record "$ID" FAIL "$1" "$2"; exit 0; }   # exit 0: the ledger row IS the result

command -v jq >/dev/null 2>&1 || fail_here "jq is required and missing" "install jq on the runner"
declaw "$BUSBAR_BIN"

# A store db_path that must survive the restart. When STORE_SETTINGS is passed we honour it; the
# sqlite default here mirrors how an operator would configure a file-backed store.
WORK="$(mktemp -d "${RUNNER_TEMP:-/tmp}/probe-store-XXXXXX")"
DB="${WORK}/governance.db"
if [ -z "$STORE_SETTINGS" ]; then
  case "$STORE_MODULE" in
    sqlite) STORE_SETTINGS="{ db_path: \"${DB}\" }" ;;
    *)      STORE_SETTINGS="{}" ;;
  esac
fi
MARKER="fleet-fixture-${ALIAS}-$$-${RANDOM}"

# Port hygiene up front: a probe that binds a busy port proves nothing.
for p in "$LISTEN_PORT" "$ADMIN_PORT" "$MOCK_PORT"; do
  assert_port_free "$p" || fail_here "port ${p} is already in use before the probe starts" \
    "a health probe against it would report the wrong process. Refusing to risk a false PASS."
done

# The mock upstream busbar will forward chat traffic to.
python3 mock-upstream.py "$MOCK_PORT" "$MARKER" >/dev/null 2>&1 &
track_pid $!
wait_for_http "http://127.0.0.1:${MOCK_PORT}/" 5 || true   # no GET route; just settle

cat >"${WORK}/providers.yaml" <<EOF
mock:
  protocol: anthropic
  base_url: "http://127.0.0.1:${MOCK_PORT}"
EOF

# 1.5.1+: the built-in \`keys\` verifier requires an explicit signing key (busbar no longer
# auto-generates one). Mint one via the shipping command exactly as an operator would.
"$BUSBAR_BIN" --generate-signing-key >"${WORK}/signing.key" 2>/dev/null
[ -s "${WORK}/signing.key" ] || fail_here "busbar --generate-signing-key produced no key" \
  "the probe cannot configure the keys verifier without a signing key; the busbar binary may be broken."

# 1.5.3+ config grammar: identity-providers + admin-tokens module, referenced by bare name from
# auth.admin_auth. The retired inline \`admin_auth: [- admin-tokens: {...}]\` shape is a legacy
# marker that refuses to boot, which would fail this probe for the wrong reason.
cat >"${WORK}/config.yaml" <<EOF
listen: "127.0.0.1:${LISTEN_PORT}"
admin_listen: "127.0.0.1:${ADMIN_PORT}"
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: { env: BUSBAR_ADMIN_TOKEN }
auth:
  chain:
    - keys
  signing_key: { file: "${WORK}/signing.key" }
  admin_auth: [admin-tokens]
plugins:
  enabled: true
  dir: "${PLUGIN_DIR}"
  trust:
    allow_unsigned: true
store:
  module: ${STORE_MODULE}
  settings: ${STORE_SETTINGS}
providers:
  mock:
    api_key: { env: MOCK_KEY }
models:
  test-model:
    provider: mock
EOF

busbar_env() {
  BUSBAR_CONFIG="${WORK}/config.yaml" BUSBAR_PROVIDERS="${WORK}/providers.yaml" \
    MOCK_KEY=unused BUSBAR_ADMIN_TOKEN=fleet-fixture-admin RUST_LOG=warn "$@"
}

# --validate first: the same fail-closed preflight boot performs, with zero side effects. If the
# plugin cannot be loaded at all this is where it says so, cleanly.
if ! busbar_env "$BUSBAR_BIN" --validate >"${WORK}/validate.log" 2>&1; then
  fail_here "busbar --validate rejects the store plugin config" \
    "$(tr '\n' '|' <"${WORK}/validate.log" | tail -c 500). The ${ALIAS} plugin does not load into this busbar at all."
fi

boot() {
  busbar_env "$BUSBAR_BIN" >"${WORK}/busbar.log" 2>&1 &
  local pid=$!
  track_pid "$pid"
  echo "$pid"
}

PID="$(boot)"
if ! wait_for_http "http://127.0.0.1:${LISTEN_PORT}/healthz" 30; then
  fail_here "busbar did not come up with the ${ALIAS} store plugin" \
    "$(tr '\n' '|' <"${WORK}/busbar.log" | tail -c 500)"
fi
echo "  busbar up (pid ${PID}) with store=${STORE_MODULE}"

# The load line is the floor; persistence is the bar. Confirm the plugin actually validated as a
# first-party/loaded store, not merely that busbar booted (it would boot on the in-RAM default too).
if busbar_env "$BUSBAR_BIN" --list-plugins >"${WORK}/plugins.log" 2>&1; then
  grep -qw "$ALIAS" "${WORK}/plugins.log" \
    && echo "  --list-plugins shows ${ALIAS}: $(grep -w "$ALIAS" "${WORK}/plugins.log" | head -1)"
fi

# Mint a real virtual key over the real admin API.
MINT="$(curl -fsS -X POST "http://127.0.0.1:${ADMIN_PORT}/api/v1/admin/keys" \
  -H "Authorization: Bearer fleet-fixture-admin" -H "Content-Type: application/json" \
  -d '{"name":"fleet-fixture"}' 2>/dev/null || true)"
TOKEN="$(printf '%s' "$MINT" | jq -r '.token // empty' 2>/dev/null)"
KEY_ID="$(printf '%s' "$MINT" | jq -r '.id // empty' 2>/dev/null)"
if [ -z "$TOKEN" ] || [ -z "$KEY_ID" ]; then
  fail_here "the admin API did not mint a usable key" \
    "POST /api/v1/admin/keys returned '$(printf '%s' "$MINT" | tr '\n' ' ' | tail -c 300)'. Writing through the admin plane is step one of the store's job."
fi
echo "  minted key id=${KEY_ID}"

# Drive a real chat-completion through busbar -> mock and assert the body.
CHAT="$(curl -fsS "http://127.0.0.1:${LISTEN_PORT}/v1/chat/completions" \
  -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
  -d '{"model":"test-model","messages":[{"role":"user","content":"hello"}]}' 2>/dev/null || true)"
GOT="$(printf '%s' "$CHAT" | jq -r '.choices[0].message.content // empty' 2>/dev/null)"
if [ "$GOT" != "$MARKER" ]; then
  fail_here "a request authorized by the minted key did not round-trip" \
    "expected body marker '${MARKER}', observed '$(printf '%s' "$CHAT" | tr '\n' ' ' | tail -c 300)'. The minted key is not usable, so the write did not take effect in the running plane."
fi

USAGE="$(curl -fsS "http://127.0.0.1:${ADMIN_PORT}/api/v1/admin/keys/${KEY_ID}/usage" \
  -H "Authorization: Bearer fleet-fixture-admin" 2>/dev/null || true)"
REQ_BEFORE="$(printf '%s' "$USAGE" | jq -r '.requests // 0' 2>/dev/null)"
TOK_BEFORE="$(printf '%s' "$USAGE" | jq -r '.tokens // 0' 2>/dev/null)"
if [ "${REQ_BEFORE:-0}" -lt 1 ] || [ "${TOK_BEFORE:-0}" -lt 1 ]; then
  fail_here "usage counters were not recorded before the restart" \
    "GET keys/${KEY_ID}/usage returned requests=${REQ_BEFORE} tokens=${TOK_BEFORE}; there is nothing whose survival the restart could prove."
fi
echo "  usage before restart: requests=${REQ_BEFORE} tokens=${TOK_BEFORE}"

# THE DURABILITY PROOF: kill, restart against the SAME store, assert the key + usage survived.
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
boot >/dev/null   # its pid is tracked inside boot() for the reaper; we only need it up again
if ! wait_for_http "http://127.0.0.1:${LISTEN_PORT}/healthz" 30; then
  fail_here "busbar did not restart against the ${ALIAS} store" \
    "$(tr '\n' '|' <"${WORK}/busbar.log" | tail -c 500)"
fi

GET_KEY="$(curl -fsS "http://127.0.0.1:${ADMIN_PORT}/api/v1/admin/keys/${KEY_ID}" \
  -H "Authorization: Bearer fleet-fixture-admin" 2>/dev/null || true)"
if ! printf '%s' "$GET_KEY" | jq -e --arg id "$KEY_ID" '.id == $id' >/dev/null 2>&1; then
  fail_here "the minted key did NOT survive a restart (${ALIAS} store is not persisting)" \
    "GET keys/${KEY_ID} after restart returned '$(printf '%s' "$GET_KEY" | tr '\n' ' ' | tail -c 300)'. Persistence is the store plugin's entire job and it did not persist."
fi
USAGE2="$(curl -fsS "http://127.0.0.1:${ADMIN_PORT}/api/v1/admin/keys/${KEY_ID}/usage" \
  -H "Authorization: Bearer fleet-fixture-admin" 2>/dev/null || true)"
REQ_AFTER="$(printf '%s' "$USAGE2" | jq -r '.requests // 0' 2>/dev/null)"
TOK_AFTER="$(printf '%s' "$USAGE2" | jq -r '.tokens // 0' 2>/dev/null)"
if [ "${REQ_AFTER:-0}" -lt "${REQ_BEFORE}" ] || [ "${TOK_AFTER:-0}" -lt "${TOK_BEFORE}" ]; then
  fail_here "usage counters regressed across the restart (${ALIAS} store lost data)" \
    "before requests=${REQ_BEFORE} tokens=${TOK_BEFORE}; after requests=${REQ_AFTER} tokens=${TOK_AFTER}."
fi

# One more request post-restart, so the restarted instance is proven a live working lane through the
# same store rather than just serving stale reads.
CHAT2="$(curl -fsS "http://127.0.0.1:${LISTEN_PORT}/v1/chat/completions" \
  -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
  -d '{"model":"test-model","messages":[{"role":"user","content":"again"}]}' 2>/dev/null || true)"
GOT2="$(printf '%s' "$CHAT2" | jq -r '.choices[0].message.content // empty' 2>/dev/null)"
if [ "$GOT2" != "$MARKER" ]; then
  fail_here "the restarted busbar cannot serve traffic through the ${ALIAS} store" \
    "post-restart request body was '$(printf '%s' "$CHAT2" | tr '\n' ' ' | tail -c 200)'."
fi

record "$ID" PASS "store ${ALIAS}: minted key + usage persisted across a real restart" \
  "requests ${REQ_BEFORE}->${REQ_AFTER}, tokens ${TOK_BEFORE}->${TOK_AFTER}; post-restart traffic live."
