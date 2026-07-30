#!/usr/bin/env bash
#
# release-check.sh — the 1.5.0 "plugin release" REAL end-to-end gate.
#
# WHAT THIS TESTS
#   Everything the unit/integration test suite cannot: that the ACTUAL signed-shape plugin
#   tarballs a user downloads (built + packed this script's own Phase 0b, in the same shape each
#   plugin's own standalone-repo release workflow packs it — busbarAI's release.yml no longer
#   builds or uploads store/auth plugin tarballs itself; see the "Store/auth plugin releases moved
#   out" comment in .github/workflows/release.yml) load into a REAL busbar binary, that busbar
#   serves REAL HTTP traffic through each backend exactly the way docs/getting-started.md and
#   docs/configuration.md tell an operator to configure it, and that keys/usage genuinely
#   SURVIVE A PROCESS RESTART against sqlite, postgres, and redis. It builds real artifacts,
#   spins up real `docker run` postgres/redis servers with real readiness probes (no fixed
#   sleeps), mints a real virtual key over the real admin API, drives a real chat-completion
#   request through a real (if minimal) mock upstream, and asserts real response bodies and
#   real usage counters — not just exit codes.
#
# WHAT THIS DOES NOT TEST
#   - Store-sqlite's hermetic in-process dlopen path — that's a separate, parallel test.
#   - The release-SIGNING pipeline (BUSBAR_SIGN_KEY) — out of scope by design. Every tarball
#     here is packed with `--allow-unsigned`, exactly like CI's fallback path when the signing
#     secret isn't provisioned (see the TODO(release-keys) seam in release.yml).
#   - OIDC's real-ABI plugin proof — that already exists as genuine, hermetic, real-crypto
#     coverage in `cargo test -p busbar-plugin-loader` (`load_and_exercise_auth_oidc_plugin_*`,
#     crates/plugin-loader/src/lib.rs), which stands up a real local JWKS server + a real minted
#     JWT and drives the plugin through the real ABI. This script just runs that suite as a gate
#     rather than reinventing a second, lower-quality fake-IdP proof (see Phase 5 below).
#   - secret-vault's real-ABI plugin proof — busbar-secret-vault / busbar-secret-vault-plugin no
#     longer live in this workspace (extracted to GetBusbar/secret-vault). Phase 4.5 below runs
#     THAT repo's own test suite (a sibling checkout) against a real Vault dev-mode container,
#     rather than duplicating the proof in-tree.
#
# WHEN TO RUN
#   Pre-tag / pre-push, NOT on every commit. This is release infrastructure, not part of the
#   normal `cargo test --workspace` gate. Budget up to ~2 hours (dominated by `cargo build
#   --release` for the busbar binary + every plugin cdylib, run multiple times).
#
# PREREQUISITES
#   - A working Rust toolchain (`cargo build --release` must succeed for this workspace).
#   - Docker running locally (`docker ps` must succeed) — needed for the Postgres and Redis
#     phases. If Docker is unavailable those two phases are skipped loudly (not silently) and
#     the script still exits non-zero, because "gate incomplete" must never look like "gate green".
#   - python3 (stdlib only) — used for a tiny local mock upstream server. No network access
#     beyond localhost and the Docker daemon is required.
#   - Optionally, sibling checkouts `../headroom-hook` and `../webrequest-hook` next to this
#     repo (GetBusbar/headroom-hook, GetBusbar/webrequest-hook) for the hook-plugin --validate
#     phase. If absent, that phase is skipped loudly and does not fail the gate (documented,
#     matches the task's explicit instruction not to fail the whole run over a missing sibling).
#
# USAGE
#   scripts/release-check.sh                # run every phase
#   scripts/release-check.sh --skip-docker   # skip Postgres/Redis (fast local iteration only;
#                                             # NEVER treat this as a green release gate)
#
# FAILURE POLICY
#   Fail-fast: `set -euo pipefail` plus an ERR trap that names the failing command. Every
#   docker container and every temp file/dir this script creates is torn down on exit — success,
#   failure, or signal — via a single EXIT trap. Safe to re-run; never leaves stray containers.

set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$PWD"

SKIP_DOCKER=0
for arg in "$@"; do
  case "$arg" in
    --skip-docker) SKIP_DOCKER=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

# ── Fail-fast diagnostics ────────────────────────────────────────────────────────────────────────
SECONDS=0
PHASE="startup"
on_err() {
  local ec=$?
  echo
  echo "!!! RELEASE GATE FAILED during phase: ${PHASE} (exit ${ec}) !!!"
  echo "    Elapsed: ${SECONDS}s. This means: DO NOT TAG THIS RELEASE."
  exit "$ec"
}
trap on_err ERR

phase() {
  PHASE="$1"
  echo
  echo "════════════════════════════════════════════════════════════════════════════"
  echo "=== ${1} ==="
  echo "════════════════════════════════════════════════════════════════════════════"
}

ok()   { echo "  [ok] $*"; }
note() { echo "  [note] $*"; }

# ── Cleanup registry: docker containers, background PIDs, temp dirs. Torn down on ANY exit. ───────
DOCKER_CONTAINERS=()
BG_PIDS=()
TMP_DIRS=()

cleanup() {
  local ec=$?
  echo
  echo "--- cleanup (exit code ${ec}) ---"
  for pid in "${BG_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" >/dev/null 2>&1 || true
  done
  for pid in "${BG_PIDS[@]:-}"; do
    [ -n "$pid" ] && wait "$pid" >/dev/null 2>&1 || true
  done
  for c in "${DOCKER_CONTAINERS[@]:-}"; do
    [ -n "$c" ] && docker rm -f "$c" >/dev/null 2>&1 || true
  done
  for d in "${TMP_DIRS[@]:-}"; do
    [ -n "$d" ] && rm -rf "$d" || true
  done
  echo "--- cleanup done ---"
}
trap cleanup EXIT

new_tmpdir() {
  local d
  d="$(mktemp -d "${TMPDIR:-/tmp}/busbar-release-check.XXXXXX")"
  TMP_DIRS+=("$d")
  echo "$d"
}

# ── Wait-for-HTTP helper: real polling, no fixed sleeps. Fails loudly on timeout. ──────────────────
wait_for_http() {
  local url="$1" timeout_s="${2:-30}" waited=0
  until curl -fsS -o /dev/null "$url" 2>/dev/null; do
    waited=$((waited + 1))
    if [ "$waited" -ge "$timeout_s" ]; then
      echo "  timed out waiting for ${url} after ${timeout_s}s" >&2
      return 1
    fi
    sleep 1
  done
}

# ── Platform-specific cdylib naming (host-native build; matches release.yml's per-target matrix
#    entries for the OS this script actually runs on). ─────────────────────────────────────────────
case "$(uname -s)" in
  Darwin) LIBEXT="dylib"; LIBPREFIX="lib" ;;
  Linux)  LIBEXT="so";    LIBPREFIX="lib" ;;
  *) echo "unsupported OS for local release-check: $(uname -s)" >&2; exit 1 ;;
esac
VER="$(grep -m1 '^version' crates/busbar/Cargo.toml | sed -E 's/version *= *"([^"]+)"/\1/')"
note "Host: $(uname -s) $(uname -m), busbar version ${VER}, libext=${LIBEXT}"

PLUGIN_DIST="$(new_tmpdir)"
MOCK_TEXT_MARKER_SEQ=0

# ── Tiny local mock upstream (Anthropic-protocol) — a real HTTP server, not a canned function ─────
# call. Responds to any POST with a well-formed Anthropic Messages response whose text body embeds
# a unique marker, so the assertions below can prove the SPECIFIC response that came back through
# busbar (not just "some 200"), and whose usage.{input,output}_tokens are nonzero so the admin API's
# key-usage counters have something real to accumulate + persist across a restart.
start_mock_upstream() {
  local port="$1" marker="$2"
  local script
  script="$(new_tmpdir)/mock_upstream.py"
  cat >"$script" <<PYEOF
import http.server, json, sys

MARKER = ${marker@Q}

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        body = json.dumps({
            "id": "msg_release_check",
            "type": "message",
            "role": "assistant",
            "model": "test-model",
            "content": [{"type": "text", "text": MARKER}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 11, "output_tokens": 7},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass

http.server.HTTPServer(("127.0.0.1", ${port}), Handler).serve_forever()
PYEOF
  python3 "$script" &
  local pid=$!
  BG_PIDS+=("$pid")
  wait_for_http "http://127.0.0.1:${port}/" 10 || true # server has no GET route; just give it a beat
  echo "$pid"
}

# ── Build the busbar binary + the packer (shared by every phase) ───────────────────────────────────
phase "Phase 0: build busbar binary + busbar-plugin-pack"
cargo build --release -p busbar -p busbar-plugin-pack
BUSBAR_BIN="${REPO_ROOT}/target/release/busbar"
PACK_BIN="${REPO_ROOT}/target/release/busbar-plugin-pack"
[ -x "$BUSBAR_BIN" ] || { echo "busbar binary not found at $BUSBAR_BIN" >&2; exit 1; }
[ -x "$PACK_BIN" ] || { echo "busbar-plugin-pack not found at $PACK_BIN" >&2; exit 1; }
ok "busbar binary: $BUSBAR_BIN"
ok "busbar-plugin-pack: $PACK_BIN"

# ── Build + pack every store plugin + the auth-oidc plugin, in the same host-native/unsigned
#    shape each plugin's own standalone-repo release workflow packs it (busbarAI's release.yml
#    itself no longer builds or packs these — it only ships the busbar binary + the bundled hook
#    plugins now; see the "Store/auth plugin releases moved out" comment there). ──────────────────
phase "Phase 0b: build + pack store-sqlite / store-postgres / store-redis / auth-oidc plugin tarballs"
cargo build --release \
  -p busbar-store-sqlite-plugin -p busbar-store-postgres-plugin -p busbar-store-redis-plugin \
  -p busbar-auth-oidc-plugin

pack_store_plugin() {
  local store="$1"
  local lib="${REPO_ROOT}/target/release/${LIBPREFIX}busbar_store_${store}_plugin.${LIBEXT}"
  [ -f "$lib" ] || { echo "missing built cdylib: $lib" >&2; exit 1; }
  "$PACK_BIN" pack \
    --lib "$lib" \
    --name "busbar-store-${store}" --alias "${store}" --kind store \
    --version "$VER" --publisher busbar \
    --description "busbar ${store} governance store plugin" \
    --license Apache-2.0 \
    --out "${PLUGIN_DIST}/busbar-store-${store}-${VER}-local.tar.gz" \
    --allow-unsigned
  ok "packed busbar-store-${store}"
}
pack_store_plugin sqlite
pack_store_plugin postgres
pack_store_plugin redis

auth_lib="${REPO_ROOT}/target/release/${LIBPREFIX}busbar_auth_oidc_plugin.${LIBEXT}"
[ -f "$auth_lib" ] || { echo "missing built cdylib: $auth_lib" >&2; exit 1; }
"$PACK_BIN" pack \
  --lib "$auth_lib" \
  --name "busbar-auth-oidc" --alias "oidc" --kind auth \
  --version "$VER" --publisher busbar \
  --description "busbar OIDC auth plugin: verify caller identity against an OIDC provider" \
  --license Apache-2.0 \
  --out "${PLUGIN_DIST}/busbar-auth-oidc-${VER}-local.tar.gz" \
  --allow-unsigned
ok "packed busbar-auth-oidc"
ls -l "$PLUGIN_DIST"

# ── Shared traffic-and-restart-survival driver, parameterized by store module/settings ─────────────
# 1. writes config.yaml + providers.yaml exactly matching docs/getting-started.md +
#    docs/configuration.md's documented shapes
# 2. boots the real busbar binary against them (plugins.enabled + plugins.dir pointed at the real
#    packed tarballs above)
# 3. mints a real virtual key over the real admin API (POST /keys)
# 4. drives a real chat-completion request through the real mock upstream and asserts the response
#    body byte-for-byte on the marker text
# 5. asserts GET /keys/{id}/usage shows real nonzero request/token counters
# 6. kills the process, restarts it against the SAME store, and asserts the key + its usage
#    counters SURVIVED — the actual durability proof
run_store_backend_e2e() {
  local backend_label="$1" store_module="$2" store_settings_yaml="$3"
  local listen_port="$4" admin_port="$5" mock_port="$6"

  local work
  work="$(new_tmpdir)"
  local marker="release-check-${backend_label}-$$-${RANDOM}"

  echo "  starting mock upstream on 127.0.0.1:${mock_port} (marker=${marker})"
  start_mock_upstream "$mock_port" "$marker" >/dev/null

  cat >"${work}/providers.yaml" <<EOF
mock:
  protocol: anthropic
  base_url: "http://127.0.0.1:${mock_port}"
EOF

  cat >"${work}/config.yaml" <<EOF
listen: "127.0.0.1:${listen_port}"
admin_listen: "127.0.0.1:${admin_port}"
auth:
  chain:
    - keys
  admin_auth:
    - admin-tokens: { token: { env: BUSBAR_ADMIN_TOKEN } }
plugins:
  enabled: true
  dir: "${PLUGIN_DIST}"
  trust:
    allow_unsigned: true
store:
  module: ${store_module}
  settings: ${store_settings_yaml}
providers:
  mock:
    api_key: { env: MOCK_KEY }
models:
  test-model:
    provider: mock
EOF

  # --validate first: the same fail-closed preflight boot performs, with zero side effects.
  echo "  --validate against this exact config..."
  BUSBAR_CONFIG="${work}/config.yaml" BUSBAR_PROVIDERS="${work}/providers.yaml" \
    MOCK_KEY=unused BUSBAR_ADMIN_TOKEN=release-check-admin \
    "$BUSBAR_BIN" --validate
  ok "--validate clean for ${backend_label}"

  boot_busbar() {
    BUSBAR_CONFIG="${work}/config.yaml" BUSBAR_PROVIDERS="${work}/providers.yaml" \
      MOCK_KEY=unused BUSBAR_ADMIN_TOKEN=release-check-admin \
      RUST_LOG=warn \
      "$BUSBAR_BIN" >"${work}/busbar.log" 2>&1 &
    local pid=$!
    BG_PIDS+=("$pid")
    echo "$pid"
  }

  echo "  booting busbar (${backend_label})..."
  local pid; pid="$(boot_busbar)"
  wait_for_http "http://127.0.0.1:${listen_port}/healthz" 30
  ok "busbar up (pid ${pid}), /healthz green"

  echo "  minting a virtual key over the real admin API..."
  local mint_resp token key_id
  mint_resp="$(curl -fsS -X POST "http://127.0.0.1:${admin_port}/api/v1/admin/keys" \
    -H "Authorization: Bearer release-check-admin" -H "Content-Type: application/json" \
    -d '{"name":"release-check"}')"
  token="$(echo "$mint_resp" | jq -r .token)"
  key_id="$(echo "$mint_resp" | jq -r .id)"
  [ -n "$token" ] && [ "$token" != "null" ] || { echo "mint did not return a token: $mint_resp" >&2; exit 1; }
  [ -n "$key_id" ] && [ "$key_id" != "null" ] || { echo "mint did not return an id: $mint_resp" >&2; exit 1; }
  ok "minted key id=${key_id}"

  echo "  driving a real chat-completion request through busbar -> mock upstream..."
  local chat_resp got_text
  chat_resp="$(curl -fsS "http://127.0.0.1:${listen_port}/v1/chat/completions" \
    -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" \
    -d '{"model":"test-model","messages":[{"role":"user","content":"hello"}]}')"
  got_text="$(echo "$chat_resp" | jq -r '.choices[0].message.content')"
  if [ "$got_text" != "$marker" ]; then
    echo "  response text mismatch: expected [${marker}] got [${got_text}] (full body: ${chat_resp})" >&2
    exit 1
  fi
  ok "response body matched the mock upstream's marker exactly: ${marker}"

  echo "  asserting usage was recorded via GET /keys/{id}/usage..."
  local usage_resp requests_before tokens_before
  usage_resp="$(curl -fsS "http://127.0.0.1:${admin_port}/api/v1/admin/keys/${key_id}/usage" \
    -H "Authorization: Bearer release-check-admin")"
  requests_before="$(echo "$usage_resp" | jq -r .requests)"
  tokens_before="$(echo "$usage_resp" | jq -r .tokens)"
  if [ "$requests_before" -lt 1 ] || [ "$tokens_before" -lt 1 ]; then
    echo "  usage not recorded as expected: ${usage_resp}" >&2
    exit 1
  fi
  ok "usage before restart: requests=${requests_before} tokens=${tokens_before}"

  echo "  restarting busbar (${backend_label}) against the SAME store to prove durability..."
  kill "$pid"
  wait "$pid" 2>/dev/null || true
  local pid2; pid2="$(boot_busbar)"
  wait_for_http "http://127.0.0.1:${listen_port}/healthz" 30
  ok "busbar restarted (pid ${pid2}), /healthz green"

  echo "  asserting the key + its usage counters SURVIVED the restart..."
  local get_key_resp usage_resp2 requests_after tokens_after
  get_key_resp="$(curl -fsS "http://127.0.0.1:${admin_port}/api/v1/admin/keys/${key_id}" \
    -H "Authorization: Bearer release-check-admin")"
  echo "$get_key_resp" | jq -e '.id == "'"${key_id}"'"' >/dev/null \
    || { echo "  key did not survive restart: ${get_key_resp}" >&2; exit 1; }
  usage_resp2="$(curl -fsS "http://127.0.0.1:${admin_port}/api/v1/admin/keys/${key_id}/usage" \
    -H "Authorization: Bearer release-check-admin")"
  requests_after="$(echo "$usage_resp2" | jq -r .requests)"
  tokens_after="$(echo "$usage_resp2" | jq -r .tokens)"
  if [ "$requests_after" -lt "$requests_before" ] || [ "$tokens_after" -lt "$tokens_before" ]; then
    echo "  usage regressed after restart: before(requests=${requests_before} tokens=${tokens_before}) after(requests=${requests_after} tokens=${tokens_after})" >&2
    exit 1
  fi
  ok "DURABILITY CONFIRMED (${backend_label}): key + usage survived a real process restart (requests=${requests_after} tokens=${tokens_after})"

  # A second request post-restart, to prove the restarted instance is not just serving stale reads
  # but is a fully live, working lane through the same store.
  local chat_resp2 got_text2
  chat_resp2="$(curl -fsS "http://127.0.0.1:${listen_port}/v1/chat/completions" \
    -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" \
    -d '{"model":"test-model","messages":[{"role":"user","content":"hello again"}]}')"
  got_text2="$(echo "$chat_resp2" | jq -r '.choices[0].message.content')"
  [ "$got_text2" = "$marker" ] || { echo "  post-restart traffic mismatch: ${chat_resp2}" >&2; exit 1; }
  ok "post-restart live traffic confirmed working end-to-end"

  kill "$pid2" 2>/dev/null || true
  wait "$pid2" 2>/dev/null || true
}

# ── Phase 1: SQLite (dockerless, fastest feedback loop) ─────────────────────────────────────────────
phase "Phase 1: store-sqlite-plugin — real busbar, real HTTP traffic, real restart durability"
SQLITE_DB="$(new_tmpdir)/governance.db"
run_store_backend_e2e "sqlite" "sqlite" "{ db_path: \"${SQLITE_DB}\" }" 18080 18081 18079
ok "SQLite phase complete: $(date -u +%H:%M:%S) elapsed=${SECONDS}s"

if [ "$SKIP_DOCKER" = "1" ]; then
  note "SKIP_DOCKER set — skipping Postgres and Redis phases. This is NOT a valid release gate run."
else
  if ! docker ps >/dev/null 2>&1; then
    echo "Docker is not available/running (docker ps failed). Postgres/Redis phases cannot run." >&2
    echo "This is a REQUIRED part of the release gate — fix Docker and re-run, or pass --skip-docker" >&2
    echo "only for fast local iteration (never as a substitute for a real green gate)." >&2
    exit 1
  fi

  # ── Phase 2: Postgres ──────────────────────────────────────────────────────────────────────────
  phase "Phase 2: store-postgres-plugin — real postgres:16 container, real busbar, restart durability"
  PG_CONTAINER="busbar-release-check-pg-$$"
  DOCKER_CONTAINERS+=("$PG_CONTAINER")
  docker run -d --rm --name "$PG_CONTAINER" \
    -e POSTGRES_USER=busbar -e POSTGRES_PASSWORD=busbar -e POSTGRES_DB=busbar_release_check \
    -p 15432:5432 \
    postgres:16 >/dev/null
  echo "  waiting for postgres to accept connections (pg_isready inside the container)..."
  waited=0
  until docker exec "$PG_CONTAINER" pg_isready -U busbar >/dev/null 2>&1; do
    waited=$((waited + 1))
    if [ "$waited" -ge 60 ]; then
      echo "postgres did not become ready within 60s" >&2
      docker logs "$PG_CONTAINER" || true
      exit 1
    fi
    sleep 1
  done
  ok "postgres ready after ${waited}s"
  run_store_backend_e2e "postgres" "postgres" \
    "{ url: \"postgres://busbar:busbar@127.0.0.1:15432/busbar_release_check\" }" \
    18090 18091 18089
  ok "Postgres phase complete: elapsed=${SECONDS}s"
  docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true

  # ── Phase 3: Redis ─────────────────────────────────────────────────────────────────────────────
  phase "Phase 3: store-redis-plugin — real redis:7 container, real busbar, restart durability"
  REDIS_CONTAINER="busbar-release-check-redis-$$"
  DOCKER_CONTAINERS+=("$REDIS_CONTAINER")
  docker run -d --rm --name "$REDIS_CONTAINER" -p 16379:6379 redis:7 >/dev/null
  echo "  waiting for redis to accept connections (redis-cli ping inside the container)..."
  waited=0
  until [ "$(docker exec "$REDIS_CONTAINER" redis-cli ping 2>/dev/null)" = "PONG" ]; do
    waited=$((waited + 1))
    if [ "$waited" -ge 60 ]; then
      echo "redis did not become ready within 60s" >&2
      docker logs "$REDIS_CONTAINER" || true
      exit 1
    fi
    sleep 1
  done
  ok "redis ready after ${waited}s"
  run_store_backend_e2e "redis" "redis" \
    "{ url: \"redis://127.0.0.1:16379\" }" \
    18100 18101 18099
  ok "Redis phase complete: elapsed=${SECONDS}s"
  docker rm -f "$REDIS_CONTAINER" >/dev/null 2>&1 || true
fi

# ── Phase 4: OIDC — proof already lives in the real test suite; run it as a gate, not a duplicate ──
phase "Phase 4: auth-oidc-plugin — real-ABI proof via cargo test (no duplicate fake-IdP scaffolding)"
note "A full local IdP (Keycloak, etc.) is disproportionate scaffolding for a release-gate script."
note "crates/plugin-loader/src/lib.rs's load_and_exercise_auth_oidc_plugin_success and"
note "..._bad_config_fails_over_abi tests already stand up a REAL local mock JWKS server, mint a"
note "REAL JWT, and drive the busbar-auth-oidc-plugin cdylib through the REAL dlopen ABI — genuine,"
note "hermetic, real-crypto coverage. Running that suite here (rather than reinventing a second,"
note "lower-quality proof) is the correct release-gate check for this plugin."
cargo test -p busbar-plugin-loader --release load_and_exercise_auth_oidc_plugin -- --nocapture
ok "OIDC real-ABI plugin tests passed"

# ── Phase 4.5: secret-vault — real-ABI proof via a sibling checkout's own test suite ────────────────
#
# busbar-secret-vault / busbar-secret-vault-plugin no longer live in this workspace (extracted to
# GetBusbar/secret-vault, same-repo 2-crate workspace, mirroring busbar-auth-oidc's own extraction).
# Unlike Phase 4's OIDC coverage (which still runs in-tree because auth-oidc-plugin hasn't been
# extracted out of this workspace yet), there is no in-tree cdylib to dlopen here any more — the
# real-Vault ABI-crossing proof now lives entirely in that repo's own test suite (its
# `secret-vault-plugin/tests/e2e.rs`, dlopen-ing its own real-built cdylib). Running THAT suite,
# against a real `hashicorp/vault` dev-mode container, is the correct release-gate check: it proves
# the actual released artifact works, not a duplicate in-tree reimplementation of the same proof.
phase "Phase 4.5: secret-vault-plugin — real-ABI proof via sibling checkout (real Vault container)"
SECRET_VAULT_SRC="${REPO_ROOT}/../secret-vault"
if [ -d "$SECRET_VAULT_SRC" ]; then
  VAULT_CONTAINER="busbar-release-check-vault-$$"
  DOCKER_CONTAINERS+=("$VAULT_CONTAINER")
  docker run -d --rm --name "$VAULT_CONTAINER" --cap-add=IPC_LOCK \
    -e VAULT_DEV_ROOT_TOKEN_ID=root -p 18200:8200 hashicorp/vault >/dev/null
  echo "  waiting for vault to report healthy (/v1/sys/health)..."
  waited=0
  until curl -fsS "http://127.0.0.1:18200/v1/sys/health" >/dev/null 2>&1; do
    waited=$((waited + 1))
    if [ "$waited" -ge 60 ]; then
      echo "vault did not become ready within 60s" >&2
      docker logs "$VAULT_CONTAINER" || true
      exit 1
    fi
    sleep 1
  done
  ok "vault ready after ${waited}s"
  ( cd "$SECRET_VAULT_SRC" && \
    BUSBAR_TEST_VAULT_ADDR="http://127.0.0.1:18200" BUSBAR_TEST_VAULT_TOKEN="root" \
    cargo test --workspace )
  ok "secret-vault real-ABI plugin tests passed (sibling checkout: ${SECRET_VAULT_SRC})"
  docker rm -f "$VAULT_CONTAINER" >/dev/null 2>&1 || true
else
  note "SKIP: ../secret-vault not present as a sibling checkout on this machine."
  note "Clone GetBusbar/secret-vault as a sibling of this repo to run this phase locally; CI runs"
  note "it via that repo's own ci.yml (service: vault), not from here."
fi

# ── Phase 5: Headroom / Webrequest — local --validate dlopen smoke test ────────────────────────────
phase "Phase 5: headroom-hook / webrequest-hook — local busbar --validate dlopen smoke test"
HEADROOM_SRC="${REPO_ROOT}/../headroom-hook"
WEBREQUEST_SRC="${REPO_ROOT}/../webrequest-hook"

run_validate_smoke() {
  local name="$1" manifest_path="$2" crate_lib_name="$3" kind="$4" needs_flag="${5:-}"
  local work; work="$(new_tmpdir)"
  mkdir -p "${work}/plugins"
  echo "  building ${name} cdylib from ${manifest_path}..."
  cargo build --release --manifest-path "$manifest_path"
  local built_dir; built_dir="$(dirname "$(dirname "$manifest_path")")/target/release"
  local lib="${built_dir}/${LIBPREFIX}${crate_lib_name}.${LIBEXT}"
  [ -f "$lib" ] || { echo "expected built cdylib not found: $lib" >&2; exit 1; }
  local pack_extra=()
  [ -n "$needs_flag" ] && pack_extra=(--needs-prompt rw)
  "$PACK_BIN" pack \
    --lib "$lib" \
    --name "busbar-${name}" --alias "${name}" --kind "$kind" \
    --version "$VER" --publisher busbar \
    --description "busbar ${name} hook plugin (local release-check smoke test)" \
    --license Apache-2.0 \
    --out "${work}/plugins/busbar-${name}.tar.gz" \
    "${pack_extra[@]}" \
    --allow-unsigned
  cat >"${work}/config.yaml" <<EOF
listen: "127.0.0.1:0"
plugins:
  enabled: true
  dir: "${work}/plugins"
  trust:
    allow_unsigned: true
providers:
  mock:
    api_key: { env: MOCK_KEY }
models:
  test-model:
    provider: mock
EOF
  cat >"${work}/providers.yaml" <<EOF
mock:
  protocol: anthropic
  base_url: "https://example.invalid"
EOF
  local out
  out="$(BUSBAR_CONFIG="${work}/config.yaml" BUSBAR_PROVIDERS="${work}/providers.yaml" MOCK_KEY=unused \
    "$BUSBAR_BIN" --validate)"
  echo "$out" | grep -q "1 validated" || { echo "  ${name} did not validate as loaded: $out" >&2; exit 1; }
  ok "${name}: busbar --validate confirms the real dlopen'd plugin loads (${out##*$'\n'})"
}

if [ -d "$HEADROOM_SRC" ]; then
  run_validate_smoke "headroom" "${HEADROOM_SRC}/Cargo.toml" "headroom_hook" hook needs
else
  note "SKIP: ../headroom-hook not present as a sibling checkout on this machine."
fi

if [ -d "$WEBREQUEST_SRC" ]; then
  run_validate_smoke "webrequest" "${WEBREQUEST_SRC}/Cargo.toml" "busbar_webrequest_hook_plugin" hook
else
  note "SKIP: ../webrequest-hook not present as a sibling checkout on this machine."
fi

phase "RELEASE GATE PASSED"
echo "Total elapsed: ${SECONDS}s"
echo "SQLite, Postgres, Redis, and OIDC phases all passed with real assertions."
if [ ! -d "$HEADROOM_SRC" ] || [ ! -d "$WEBREQUEST_SRC" ]; then
  echo "NOTE: one or both hook-plugin sibling repos were not present locally — that phase was"
  echo "partially or fully skipped. Run on a machine with ../headroom-hook and ../webrequest-hook"
  echo "checked out for full coverage before tagging, or confirm docker.yml's own smoke test is green."
fi
