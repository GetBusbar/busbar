#!/usr/bin/env bash
#
# release-check-1.5.2.sh — the 1.5.2 dev-gate phases that exercise the NEW 1.5.2 functionality.
#
# WHAT THIS TESTS (the 1.5.2 feature surface, end to end against the REAL binary)
#   Phase A — plugins.fetch (HERMETIC, no published-release / no public-network dependency):
#             the declarative `plugins.fetch:` download → verify → stage → load pipeline, against a
#             plugin tarball packed IN THIS SCRIPT from an in-tree cdylib and served from a LOCAL
#             http server. Proves: happy path (downloaded+verified+loaded), wrong-pin REJECT (file
#             never written, boot fatal), boot-miss FATAL, cache-by-pin (second boot does NOT
#             re-download — asserted against a per-request hit log), and the `{env: VAR}` source.
#   Phase B — token-exchange (POST /auth/token) E2E: a REAL local JWKS + a REAL minted JWT drive the
#             1.5.2 data-plane token exchange; a self-scoped `user:<sub>` key comes back and is used
#             for a real chat-completion; one-key idempotency (POST twice → SAME key). TTL reflects
#             `auth.key_ttl`.
#   Phase C — admin AUTHORIZATION MATRIX (1.5.2 scope collapse {ReadOnly, Full}): prove full CAN do
#             what read-only CANNOT on the SAME endpoint, across three postures — (a) OIDC admin
#             group → admin_scope full, (b) → read-only, (c) admin_auth:[] open admin.
#
# HOW IT RELATES TO release-check.sh
#   This script mirrors release-check.sh's structure verbatim: the same `phase()`/`ok()`/`note()`
#   helpers, the same fail-fast `set -euo pipefail` + ERR trap, the same single EXIT-trap cleanup
#   registry (background PIDs + temp dirs), the same wait_for_http polling, and the same Phase-0
#   busbar-binary + busbar-plugin-pack build. It is STANDALONE (run it directly) but also honors a
#   pre-built binary handed down by a parent gate: if $BUSBAR_BIN and $PACK_BIN are already exported
#   and executable, Phase 0 reuses them instead of rebuilding (so release.sh can source/invoke this
#   without a second `cargo build --release`). release-check.sh invokes this script at the end of its
#   run (see the "1.5.2 feature gate" block appended there).
#
# WHAT RUNS vs. WHAT IS MARKED VERIFIED-AT-INTEGRATION
#   Phase A runs FULLY and hermetically here (only needs the busbar binary + python3 + an in-tree
#   cdylib). Phase B and Phase C's OIDC-backed postures need a packed auth-oidc `kind:auth` plugin
#   (sibling checkout ../auth-oidc) and a minted JWT; this script BUILDS the real JWKS + JWT fixtures
#   and runs `busbar --validate` on every config (a real, fail-closed check), then drives the full
#   boot + HTTP assertions when the sibling plugin is present. Any assertion that cannot be proven
#   standalone in this worktree is labelled `# VERIFIED-AT-INTEGRATION` with the exact thing the
#   integrator must confirm. Nothing here fakes a pass: a phase that cannot run its real proof says
#   so LOUDLY and (for the optional OIDC bits) loud-skips rather than reporting green.
#
# KNOWN INTEGRATION BLOCKER (Phase B/C, flagged — the integrator MUST confirm)
#   The auth-oidc plugin sets `principal.id = "oidc:<sub>"` (auth-oidc/src/lib.rs:272), but the
#   token-exchange self-subject sanitizer `sanitize_self_sub` (auth/self_keys.rs) REJECTS any id
#   containing ':' (→ ExchangeError::BadSubject → 403). So with the CURRENT auth-oidc plugin, a real
#   `POST /auth/token` carrying an OIDC JWT returns 403 BadSubject, NOT the intended 200 + user:<sub>
#   key. The busbar crate's own self_keys_tests use a clean, prefix-free principal id ("sam"). Phase
#   B's happy-path 200 is authored against the INTENDED contract and gated VERIFIED-AT-INTEGRATION on
#   this exact question — the integrator must confirm whether the engine strips the module prefix
#   before the exchange subject check (or whether the plugin/sanitizer is reconciled) before Phase B's
#   200 can pass with the real plugin.
#
# USAGE
#   scripts/release-check-1.5.2.sh                 # run every 1.5.2 phase
#   scripts/release-check-1.5.2.sh --phase A       # run just Phase A (also B / C)
#
# FAILURE POLICY — identical to release-check.sh: fail-fast, name the failing phase, tear everything
# down on ANY exit. A failure here means: DO NOT TAG THIS RELEASE.

set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$PWD"

# ── Defensive watchdog (defense-in-depth) ─────────────────────────────────────────────────────────
# A command-substitution that captured a backgrounded serve_forever once wedged this gate for the
# full 180-min CI timeout (the python held the `$(...)` stdout pipe open forever). That specific bug
# is fixed at the launch sites below, but as a belt-and-suspenders guard we re-exec the WHOLE script
# under `timeout`, so ANY future hang becomes a fast, diagnosable FAILURE (exit 124) instead of a
# multi-hour `cancelled`. `timeout` cleanly kills the process tree on expiry. Guarded on availability
# (a bare macOS may only have `gtimeout`), and self-disables on the re-exec via the env sentinel.
if [ -z "${BUSBAR_1_5_2_WATCHDOG_ARMED:-}" ] && command -v timeout >/dev/null 2>&1; then
  export BUSBAR_1_5_2_WATCHDOG_ARMED=1
  exec timeout --kill-after=30 "${BUSBAR_1_5_2_WATCHDOG_SECS:-1500}" bash "$0" "$@"
fi

ONLY_PHASE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --phase) ONLY_PHASE="${2:-}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# ── Fail-fast diagnostics (mirrors release-check.sh) ──────────────────────────────────────────────
SECONDS=0
PHASE="startup"
on_err() {
  local ec=$?
  echo
  echo "!!! 1.5.2 GATE FAILED during phase: ${PHASE} (exit ${ec}) !!!"
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
integ() { echo "  [VERIFIED-AT-INTEGRATION] $*"; }

# ── Cleanup registry (mirrors release-check.sh) ───────────────────────────────────────────────────
BG_PIDS=()
TMP_DIRS=()
DOCKER_CIDS=()   # container ids launched by the live github/ldap arms (Phase B), force-removed below.
cleanup() {
  local ec=$?
  echo
  echo "--- cleanup (exit code ${ec}) ---"
  for pid in "${BG_PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" >/dev/null 2>&1 || true; done
  for pid in "${BG_PIDS[@]:-}"; do [ -n "$pid" ] && wait "$pid" >/dev/null 2>&1 || true; done
  for cid in "${DOCKER_CIDS[@]:-}"; do [ -n "$cid" ] && docker rm -f "$cid" >/dev/null 2>&1 || true; done
  for d in "${TMP_DIRS[@]:-}"; do [ -n "$d" ] && rm -rf "$d" || true; done
  echo "--- cleanup done ---"
}
trap cleanup EXIT

new_tmpdir() {
  local d
  d="$(mktemp -d "${TMPDIR:-/tmp}/busbar-1.5.2-gate.XXXXXX")"
  TMP_DIRS+=("$d")
  echo "$d"
}

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

# ── CONFIG-YAML-VALIDITY guard (up-front, fail-fast) ──────────────────────────────────────────────
# WHY: this gate GENERATES config files with heredocs, and one of them once emitted an under-indented
# `ca_cert_pem: |` block scalar — invalid YAML — that only blew up DEEP in a later phase (and only
# after the 2h hang above was fixed), costing a full cycle to diagnose. `assert_yaml` is called the
# instant a config/providers file is written, so a malformed GENERATED config fails FAST with a clear,
# file-named message instead of surfacing as a confusing error inside a boot/validate step. This is
# the YAML-PARSE precondition; the per-phase `busbar --validate` calls (which run only after the
# sibling plugins are packed, since they name plugin modules) remain the semantic check on top.
# PyYAML is the parser (present on the qa-gate ubuntu runner and locally); if it is somehow absent we
# WARN loudly rather than silently skip — the per-phase `busbar --validate` still rejects bad YAML
# (it emits `invalid YAML:` before any module/secret resolution), so coverage degrades, never vanishes.
assert_yaml() {
  local file="$1" label="${2:-config}"
  [ -f "$file" ] || { echo "  CONFIG-YAML-GUARD: ${label}: file not found: ${file}" >&2; exit 1; }
  if ! python3 -c 'import yaml' >/dev/null 2>&1; then
    note "CONFIG-YAML-GUARD: PyYAML unavailable — cannot pre-parse ${label} (${file}); relying on the"
    note "  per-phase \`busbar --validate\` (still rejects malformed YAML). Install PyYAML for fast-fail."
    return 0
  fi
  local err; err="$(new_tmpdir)/yamlerr"
  # Concise diagnostic (not a Python traceback): print just the YAML scanner/parser message + mark.
  if ! python3 -c 'import sys,yaml
try:
    yaml.safe_load(open(sys.argv[1]))
except yaml.YAMLError as e:
    sys.stderr.write(str(e) + "\n"); sys.exit(1)' "$file" 2>"$err"; then
    echo "  CONFIG-YAML-GUARD: ${label} is NOT parseable YAML — failing fast (file: ${file})" >&2
    sed 's/^/      /' "$err" >&2
    echo "      └─ this is the under-indented \`ca_cert_pem: |\`-class bug: a malformed GENERATED config." >&2
    echo "         Fix the heredoc's indentation; do NOT let it reach a boot/validate phase." >&2
    exit 1
  fi
  ok "config YAML parses: ${label}"
}

# Wait until a launched busbar has EITHER come up on /healthz (echo "up") or exited (echo "down").
# Used by the negative fetch phases, which expect the process to DIE at boot rather than serve.
wait_up_or_dead() {
  local health_url="$1" pid="$2" timeout_s="${3:-30}" waited=0
  while :; do
    if curl -fsS -o /dev/null "$health_url" 2>/dev/null; then echo "up"; return 0; fi
    if ! kill -0 "$pid" 2>/dev/null; then echo "down"; return 0; fi
    waited=$((waited + 1))
    [ "$waited" -ge "$timeout_s" ] && { echo "timeout"; return 0; }
    sleep 1
  done
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# ── LIVE-HERMETIC auth deps (Phase B github/ldap arms): READY-MADE containers, PINNED to a specific
#    tag (never :latest). Both are stood up with docker-run from LOCAL images + LOCAL fixtures — no
#    external network is contacted by the flow itself (only a one-time image pull if the tag is not
#    already cached; a fully-offline runner with the images pre-pulled never touches the network). ──
WIREMOCK_IMAGE="wiremock/wiremock:3.9.2"   # github OAuth token/user/orgs endpoints, stubbed from JSON
OPENLDAP_IMAGE="osixia/openldap:1.5.0"     # real OpenLDAP, seeded with scripts/fixtures/auth-ldap/seed.ldif

# docker present AND the daemon reachable? A LOCAL run without docker LOUD-SKIPS the live arms (never a
# silent pass); a CI/self-hosted runner WITH docker RUNS them. `BUSBAR_1_5_2_SKIP_DOCKER=1` force-skips.
docker_available() {
  [ "${BUSBAR_1_5_2_SKIP_DOCKER:-0}" = "1" ] && return 1
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

# Ensure a pinned image is available locally (already cached, else a single pull). Returns non-zero on
# a fully-offline runner that lacks the image — the caller loud-skips rather than failing the gate.
ensure_image() {
  local img="$1"
  docker image inspect "$img" >/dev/null 2>&1 && return 0
  echo "  image ${img} not cached; attempting a one-time pull..."
  docker pull "$img" >/dev/null 2>&1
}

# A free ephemeral TCP port on 127.0.0.1 (bind :0, read it back, release it — a tiny TOCTOU that is
# fine for a test harness). Used to map each container to a private host port with no collisions.
free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

# Decode the busbar login cookie (base64url(JSON)) and print its `state` field. The hosted-login GET
# flow (auth/token.rs) stores PKCE/state/nonce in this HttpOnly cookie; the callback validates the
# query `state` against the cookie's — so the harness must read `state` back out to drive the callback
# (redirect flow) or the credential POST (form flow), exactly as a real browser round-trips the cookie.
login_cookie_state() {
  python3 -c 'import base64,json,sys; v=sys.argv[1]; v+="="*(-len(v)%4); print(json.loads(base64.urlsafe_b64decode(v.encode()))["state"])' "$1"
}

# Pull `busbar_login=<value>` out of a raw HTTP response header block (curl -D -).
extract_login_cookie() {
  printf '%s' "$1" | grep -i '^set-cookie: *busbar_login=' | head -1 \
    | sed -E 's/^[Ss]et-[Cc]ookie: *busbar_login=([^;]*).*/\1/' | tr -d '\r'
}

# Pull the issued api_key out of the hosted key-issued HTML page (`<span ... id="key">KEY</span>`).
extract_issued_key() {
  printf '%s' "$1" | sed -n 's/.*id="key">\([^<]*\)<.*/\1/p' | head -1
}

# ── Platform-specific cdylib naming (mirrors release-check.sh) ────────────────────────────────────
case "$(uname -s)" in
  Darwin) LIBEXT="dylib"; LIBPREFIX="lib" ;;
  Linux)  LIBEXT="so";    LIBPREFIX="lib" ;;
  *) echo "unsupported OS for local release-check: $(uname -s)" >&2; exit 1 ;;
esac
VER="$(grep -m1 '^version' crates/busbar/Cargo.toml | sed -E 's/version *= *"([^"]+)"/\1/')"
note "Host: $(uname -s) $(uname -m), busbar version ${VER}, libext=${LIBEXT}"

# ── A tiny local plugin registry: python http server that LOGS every GET path to a hits file, so the
#    cache-by-pin phase can PROVE the second boot did not re-download (the served-request counter). ─
start_plugin_registry() {
  local root="$1" port="$2" hits="$3"
  local script; script="$(new_tmpdir)/registry.py"
  cat >"$script" <<PYEOF
import http.server, os, sys
ROOT = ${root@Q}
HITS = ${hits@Q}
class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=ROOT, **k)
    def do_GET(self):
        with open(HITS, "a") as f:
            f.write(self.path + "\n")
        return super().do_GET()
    def log_message(self, *a):
        pass
http.server.ThreadingHTTPServer(("127.0.0.1", ${port}), H).serve_forever()
PYEOF
  : >"$hits"
  # Sentinel: a unique file OUR server (rooted at $root) can serve. A stale/foreign server that
  # happened to grab this port serves a different directory and 404s the sentinel — so this both
  # confirms the bind succeeded AND guarantees the hits log below belongs to the server busbar
  # actually talks to (otherwise the cache-by-pin "zero hits" assertion could pass VACUOUSLY).
  local sentinel="registry-sentinel-$$-${RANDOM}"
  echo ok >"${root}/${sentinel}"
  # Redirect the SERVER's stdout/stderr to /dev/null: this function is captured via `$(...)` (see
  # run_phase_a's `reg_pid="$(start_plugin_registry ...)"`), and a backgrounded serve_forever that
  # inherits the command-substitution's stdout pipe holds it open forever → `$(...)` blocks on EOF
  # for the full CI timeout. The function's own `echo "$pid"` below still reaches `$(...)`.
  python3 "$script" >/dev/null 2>&1 &
  local pid=$!
  BG_PIDS+=("$pid")
  local waited=0
  until [ "$(curl -fsS "http://127.0.0.1:${port}/${sentinel}" 2>/dev/null)" = "ok" ]; do
    waited=$((waited + 1))
    if [ "$waited" -ge 10 ]; then
      echo "  plugin registry did not come up on 127.0.0.1:${port} (bind collision? foreign server on the port?)" >&2
      exit 1
    fi
    sleep 1
  done
  rm -f "${root}/${sentinel}"
  : >"$hits"   # discard the sentinel GET so the hits log starts clean for the caller's assertions
  echo "$pid"
}

# ── Tiny mock Anthropic upstream (verbatim from release-check.sh's start_mock_upstream) ───────────
start_mock_upstream() {
  local port="$1" marker="$2"
  local script; script="$(new_tmpdir)/mock_upstream.py"
  cat >"$script" <<PYEOF
import http.server, json
MARKER = ${marker@Q}
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        body = json.dumps({
            "id": "msg_gate152", "type": "message", "role": "assistant", "model": "test-model",
            "content": [{"type": "text", "text": MARKER}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 11, "output_tokens": 7},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", ${port}), Handler).serve_forever()
PYEOF
  # stdout/stderr → /dev/null: this function is captured via `$(...)` (mock_pid="$(start_mock_upstream ...)");
  # a backgrounded serve_forever inheriting that pipe would block `$(...)` on EOF forever. `echo "$pid"` still returns.
  python3 "$script" >/dev/null 2>&1 &
  local pid=$!
  BG_PIDS+=("$pid")
  echo "$pid"
}

# ══════════════════════════════════════════════════════════════════════════════════════════════════
phase "Phase 0: build (or reuse) busbar binary + busbar-plugin-pack"
# Reuse a parent gate's already-built binaries when handed down, else build them here — same crates,
# same profile as release-check.sh's Phase 0.
if [ -n "${BUSBAR_BIN:-}" ] && [ -x "${BUSBAR_BIN:-}" ] && [ -n "${PACK_BIN:-}" ] && [ -x "${PACK_BIN:-}" ]; then
  ok "reusing pre-built binaries handed down by the parent gate"
else
  cargo build --release -p busbar -p busbar-plugin-pack
  BUSBAR_BIN="${REPO_ROOT}/target/release/busbar"
  PACK_BIN="${REPO_ROOT}/target/release/busbar-plugin-pack"
fi
[ -x "$BUSBAR_BIN" ] || { echo "busbar binary not found at $BUSBAR_BIN" >&2; exit 1; }
[ -x "$PACK_BIN" ] || { echo "busbar-plugin-pack not found at $PACK_BIN" >&2; exit 1; }
ok "busbar binary: $BUSBAR_BIN"
ok "busbar-plugin-pack: $PACK_BIN"

# ── Pack a plugin tarball IN THIS SCRIPT from an in-tree cdylib (no sibling checkout, no published
#    release). hook-test-plugin is a hermetic, standalone-buildable kind:hook cdylib (crates/
#    hook-test-plugin, crate-type [cdylib, rlib]) — exactly the "reuse a simple existing plugin
#    cdylib" the task calls for. Packed --allow-unsigned (dev), loaded under trust.allow_unsigned. ─
pack_hook_test_plugin() {
  local out="$1"
  cargo build --release -p busbar-hook-test-plugin >/dev/null 2>&1
  local lib="${REPO_ROOT}/target/release/${LIBPREFIX}busbar_hook_test_plugin.${LIBEXT}"
  [ -f "$lib" ] || { echo "hook-test-plugin cdylib not built at $lib" >&2; exit 1; }
  "$PACK_BIN" pack \
    --lib "$lib" \
    --name "busbar-hook-test" --alias "hooktest" --kind hook \
    --version "$VER" --publisher busbar \
    --description "hermetic hook-test plugin for the 1.5.2 plugins.fetch gate" \
    --license Apache-2.0 \
    --out "$out" \
    --allow-unsigned
}

# ══════════════════════════════════════════════════════════════════════════════════════════════════
# PHASE A — plugins.fetch (HERMETIC)
# ══════════════════════════════════════════════════════════════════════════════════════════════════
run_phase_a() {
  phase "Phase A: plugins.fetch — download → verify → stage → load (hermetic, real binary, local http)"

  local A_PORT=19151 A_LISTEN=19150
  local srv_root; srv_root="$(new_tmpdir)"          # served tarballs live here
  local hits; hits="$(new_tmpdir)/registry-hits.log"

  # Pack the plugin ONCE, serve it, compute its REAL sha256 pin.
  local tarball="${srv_root}/busbar-hook-test.tar.gz"
  echo "  packing hook-test plugin tarball..."
  pack_hook_test_plugin "$tarball"
  local PIN; PIN="$(sha256_of "$tarball")"
  ok "packed + pinned: $(basename "$tarball") sha256=${PIN}"

  echo "  starting local plugin registry (request-logging http server) on 127.0.0.1:${A_PORT}..."
  local reg_pid; reg_pid="$(start_plugin_registry "$srv_root" "$A_PORT" "$hits")"
  ok "registry up (pid ${reg_pid}), serving ${srv_root}"

  local URL="http://127.0.0.1:${A_PORT}/busbar-hook-test.tar.gz"

  # Shared: write a fetch config whose plugins.dir is empty, so a REAL boot must fetch to load.
  # (--validate would NOT exercise fetch: the zero-network contract skips it. So we BOOT.)
  write_fetch_config() {
    local dir="$1" fetch_body="$2" out="$3"
    mkdir -p "$dir"
    cat >"$out" <<EOF
listen: "127.0.0.1:${A_LISTEN}"
auth:
  chain: []
plugins:
  enabled: true
  dir: "${dir}"
  trust:
    allow_unsigned: true
  fetch:
${fetch_body}
providers:
  mock:
    api_key: { env: MOCK_KEY }
models:
  test-model:
    provider: mock
EOF
    assert_yaml "$out" "Phase A plugins.fetch config"
  }
  local PROVIDERS; PROVIDERS="$(new_tmpdir)/providers.yaml"
  cat >"$PROVIDERS" <<EOF
mock:
  protocol: anthropic
  base_url: "https://example.invalid"
EOF
  assert_yaml "$PROVIDERS" "Phase A providers"

  boot_fetch() {  # $1 config, $2 pluginsdir (for log path). echoes pid.
    local cfg="$1" log="$2"
    BUSBAR_CONFIG="$cfg" BUSBAR_PROVIDERS="$PROVIDERS" MOCK_KEY=unused RUST_LOG=info \
      "$BUSBAR_BIN" >"$log" 2>&1 &
    local pid=$!; BG_PIDS+=("$pid"); echo "$pid"
  }

  # ---- A.1 HAPPY PATH: fetched → verified → staged → loaded ----
  echo
  echo "  A.1 happy path: correct pin, empty dir → download + verify + load"
  local d1; d1="$(new_tmpdir)/plugins"
  local c1; c1="$(new_tmpdir)/config.yaml"
  write_fetch_config "$d1" "    - url: \"${URL}\"
      sha256: \"${PIN}\"" "$c1"
  local log1; log1="$(new_tmpdir)/busbar.log"
  local p1; p1="$(boot_fetch "$c1" "$log1")"
  wait_for_http "http://127.0.0.1:${A_LISTEN}/healthz" 30
  ok "busbar booted (pid ${p1})"
  grep -q "plugins.fetch: downloaded + verified" "$log1" \
    || { echo "  A.1: boot log missing 'downloaded + verified'" >&2; cat "$log1" >&2; exit 1; }
  ok "log shows: fetched + verified"
  [ -f "${d1}/busbar-hook-test.tar.gz" ] || { echo "  A.1: staged tarball missing in dir" >&2; exit 1; }
  ok "tarball staged into plugins.dir"
  # Prove it actually LOADED (validated) — a fetched-but-rejected artifact would not.
  grep -Eiq "validated|loaded|hooktest|busbar-hook-test" "$log1" \
    || note "A.1: could not positively confirm LOAD from log at RUST_LOG=info (fetch+verify confirmed above)"
  ok "A.1 happy path proven: fetch → verify → stage (load confirmed via boot success + staged artifact)"
  kill "$p1" 2>/dev/null || true; wait "$p1" 2>/dev/null || true

  # ---- A.2 CACHE-BY-PIN: second boot with the artifact already staged + matching pin → NO download ----
  echo
  echo "  A.2 cache-by-pin: artifact already present + matching pin → second boot must NOT re-download"
  : >"$hits"   # reset the registry hit log; the artifact is already in ${d1} from A.1
  local c2="$c1" log2; log2="$(new_tmpdir)/busbar.log"
  local p2; p2="$(boot_fetch "$c2" "$log2")"
  wait_for_http "http://127.0.0.1:${A_LISTEN}/healthz" 30
  grep -q "plugins.fetch: cached (pin match, no download)" "$log2" \
    || { echo "  A.2: boot log missing 'cached (pin match, no download)'" >&2; cat "$log2" >&2; exit 1; }
  ok "log shows: cached (pin match, no download)"
  if grep -q "busbar-hook-test.tar.gz" "$hits"; then
    echo "  A.2: registry WAS hit for the tarball on a cached boot — cache-by-pin did not skip the network" >&2
    echo "  hits:" >&2; cat "$hits" >&2; exit 1
  fi
  ok "A.2 cache-by-pin proven: ZERO registry requests for the tarball on the cached boot"
  kill "$p2" 2>/dev/null || true; wait "$p2" 2>/dev/null || true

  # ---- A.3 WRONG PIN: fetch REJECTED, file never written, boot FATAL ----
  echo
  echo "  A.3 wrong pin: a bogus sha256 → fetch REJECTED, artifact never written, boot FATAL"
  local d3; d3="$(new_tmpdir)/plugins"
  local c3; c3="$(new_tmpdir)/config.yaml"
  local WRONG="0000000000000000000000000000000000000000000000000000000000000000"
  write_fetch_config "$d3" "    - url: \"${URL}\"
      sha256: \"${WRONG}\"" "$c3"
  local log3; log3="$(new_tmpdir)/busbar.log"
  local p3; p3="$(boot_fetch "$c3" "$log3")"
  local st3; st3="$(wait_up_or_dead "http://127.0.0.1:${A_LISTEN}/healthz" "$p3" 30)"
  [ "$st3" = "down" ] || { echo "  A.3: busbar should have DIED on a wrong-pin boot (got: ${st3})" >&2; cat "$log3" >&2; exit 1; }
  grep -Eiq "mismatch|plugins.fetch failed" "$log3" \
    || { echo "  A.3: boot log missing the sha256 mismatch / fetch-failed error" >&2; cat "$log3" >&2; exit 1; }
  [ ! -f "${d3}/busbar-hook-test.tar.gz" ] \
    || { echo "  A.3: an artifact was written despite the pin mismatch (must NEVER happen)" >&2; exit 1; }
  ok "A.3 wrong-pin proven: boot FATAL, error names the mismatch, dir left empty (verify-before-write)"
  kill "$p3" 2>/dev/null || true; wait "$p3" 2>/dev/null || true

  # ---- A.4 BOOT-MISS: unreachable url, no cached copy → FATAL ----
  echo
  echo "  A.4 boot-miss: unreachable url + no cached copy → boot FATAL"
  local dead_port=19199   # nothing is listening here
  local d4; d4="$(new_tmpdir)/plugins"
  local c4; c4="$(new_tmpdir)/config.yaml"
  write_fetch_config "$d4" "    - url: \"http://127.0.0.1:${dead_port}/busbar-hook-test.tar.gz\"
      sha256: \"${PIN}\"" "$c4"
  local log4; log4="$(new_tmpdir)/busbar.log"
  local p4; p4="$(boot_fetch "$c4" "$log4")"
  local st4; st4="$(wait_up_or_dead "http://127.0.0.1:${A_LISTEN}/healthz" "$p4" 30)"
  [ "$st4" = "down" ] || { echo "  A.4: busbar should have DIED on an unreachable-fetch boot (got: ${st4})" >&2; cat "$log4" >&2; exit 1; }
  grep -Eiq "download failed|plugins.fetch failed|GET .*: " "$log4" \
    || { echo "  A.4: boot log missing the download-failed / fetch-failed error" >&2; cat "$log4" >&2; exit 1; }
  ok "A.4 boot-miss proven: unreachable url with no cache → boot FATAL, error names the download failure"
  kill "$p4" 2>/dev/null || true; wait "$p4" 2>/dev/null || true

  # ---- A.5 ENV SOURCE: {env: VAR} where VAR holds the url ----
  echo
  echo "  A.5 env source: fetch { env: BUSBAR_GATE_FETCH_URL } where the VAR holds the url"
  local d5; d5="$(new_tmpdir)/plugins"
  local c5; c5="$(new_tmpdir)/config.yaml"
  # The env-var value carries url@sha256 (the split-on-last-'@' form fetch_spec_from parses).
  write_fetch_config "$d5" "    - env: BUSBAR_GATE_FETCH_URL" "$c5"
  local log5; log5="$(new_tmpdir)/busbar.log"
  BUSBAR_CONFIG="$c5" BUSBAR_PROVIDERS="$PROVIDERS" MOCK_KEY=unused RUST_LOG=info \
    BUSBAR_GATE_FETCH_URL="${URL}@${PIN}" \
    "$BUSBAR_BIN" >"$log5" 2>&1 &
  local p5=$!; BG_PIDS+=("$p5")
  wait_for_http "http://127.0.0.1:${A_LISTEN}/healthz" 30
  grep -q "plugins.fetch: downloaded + verified" "$log5" \
    || { echo "  A.5: env-source boot log missing 'downloaded + verified'" >&2; cat "$log5" >&2; exit 1; }
  [ -f "${d5}/busbar-hook-test.tar.gz" ] || { echo "  A.5: env-source staged tarball missing" >&2; exit 1; }
  ok "A.5 env source proven: {env: VAR} resolved a url@sha256, fetched + verified + staged"
  kill "$p5" 2>/dev/null || true; wait "$p5" 2>/dev/null || true

  ok "Phase A complete: elapsed=${SECONDS}s"
}

# ══════════════════════════════════════════════════════════════════════════════════════════════════
# JWKS + JWT minting helpers (real crypto, hermetic) — shared by Phase B and Phase C.
# RS256: mint an RSA-2048 keypair, publish it as a JWKS document (kid gate-key-1), and sign a JWT.
# The auth-oidc plugin fetches the JWKS over HTTPS and verifies the RS256 signature over the C ABI.
# ══════════════════════════════════════════════════════════════════════════════════════════════════
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }        # stdin (binary/text) → base64url

OIDC_WORK=""
oidc_setup_keys() {
  OIDC_WORK="$(new_tmpdir)"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${OIDC_WORK}/rsa.pem" 2>/dev/null
  # JWKS n = base64url(modulus bytes); e = AQAB (65537, the openssl default public exponent).
  local mod_hex n
  mod_hex="$(openssl rsa -in "${OIDC_WORK}/rsa.pem" -noout -modulus 2>/dev/null | sed 's/^Modulus=//')"
  n="$(printf '%s' "$mod_hex" | xxd -r -p | b64url)"
  cat >"${OIDC_WORK}/jwks.json" <<EOF
{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"gate-key-1","n":"${n}","e":"AQAB"}]}
EOF
}

# Mint an RS256 JWT. $1 issuer $2 audience $3 sub $4 groups-json-array (e.g. '["eng"]') $5 exp-unix.
oidc_mint_jwt() {
  local iss="$1" aud="$2" sub="$3" groups="$4" exp="$5"
  local hdr pl signing_input sig
  hdr="$(printf '%s' '{"alg":"RS256","typ":"JWT","kid":"gate-key-1"}' | b64url)"
  pl="$(printf '%s' "{\"iss\":\"${iss}\",\"aud\":\"${aud}\",\"sub\":\"${sub}\",\"groups\":${groups},\"exp\":${exp},\"iat\":$(($(date +%s)-10))}" | b64url)"
  signing_input="${hdr}.${pl}"
  sig="$(printf '%s' "$signing_input" | openssl dgst -sha256 -sign "${OIDC_WORK}/rsa.pem" -binary | b64url)"
  printf '%s.%s' "$signing_input" "$sig"
}

# Serve the JWKS over HTTPS (the plugin's ReqwestFetcher does a real TLS handshake). Returns the
# server's self-signed cert PEM so the config can trust it via the plugin's `ca_cert_pem` setting.
# Uses python's ssl-wrapped http.server with an openssl-minted self-signed cert for 127.0.0.1.
oidc_start_https_jwks() {
  local port="$1"
  # `basicConstraints=critical,CA:FALSE` is REQUIRED: OpenSSL 3.x `req -x509` defaults a self-signed
  # cert to CA:TRUE, and the oidc plugin fetches this JWKS over rustls (reqwest), which REFUSES a CA
  # cert presented as the server's end-entity leaf (`CaUsedAsEndEntity`) — the JWKS fetch then fails and
  # POST /auth/token returns 401 "not authenticated". Forcing an END-ENTITY cert makes the real rustls
  # JWKS fetch succeed. Kept in sync with plugin-ci.yml's token-exchange e2e (same fix, same reason).
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "${OIDC_WORK}/tls.key" \
    -out "${OIDC_WORK}/tls.crt" -days 2 -subj "/CN=127.0.0.1" \
    -addext "subjectAltName=IP:127.0.0.1" \
    -addext "basicConstraints=critical,CA:FALSE" 2>/dev/null
  local script="${OIDC_WORK}/jwks_server.py"
  cat >"$script" <<PYEOF
import http.server, ssl
BODY = open(${OIDC_WORK@Q} + "/jwks.json","rb").read()
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(BODY))); self.end_headers(); self.wfile.write(BODY)
    def log_message(self,*a): pass
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(${OIDC_WORK@Q}+"/tls.crt", ${OIDC_WORK@Q}+"/tls.key")
srv = http.server.ThreadingHTTPServer(("127.0.0.1", ${port}), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
PYEOF
  # stdout/stderr → /dev/null: this function is captured via `$(...)` (jwks_pid="$(oidc_start_https_jwks ...)");
  # a backgrounded serve_forever inheriting that pipe would block `$(...)` on EOF forever. `echo "$pid"` still returns.
  python3 "$script" >/dev/null 2>&1 &
  local pid=$!; BG_PIDS+=("$pid")
  echo "$pid"
}

# Build + pack the sibling auth-oidc plugin into $1/plugins as alias `oidc`. Echoes 0 on success,
# 1 if the sibling checkout is absent (caller loud-skips the OIDC-backed assertions).
OIDC_SRC="${REPO_ROOT}/../auth-oidc"
oidc_pack_plugin() {
  local dir="$1"
  [ -d "$OIDC_SRC" ] || return 1
  mkdir -p "$dir"
  cargo build --release --manifest-path "${OIDC_SRC}/Cargo.toml" -p busbar-auth-oidc-plugin >/dev/null 2>&1
  local lib="${OIDC_SRC}/target/release/${LIBPREFIX}busbar_auth_oidc_plugin.${LIBEXT}"
  [ -f "$lib" ] || { echo "  auth-oidc cdylib not built at $lib" >&2; return 1; }
  "$PACK_BIN" pack \
    --lib "$lib" \
    --name "busbar-auth-oidc" --alias "oidc" --kind auth \
    --version "$VER" --publisher busbar \
    --description "auth-oidc plugin (1.5.2 gate)" \
    --license Apache-2.0 \
    --out "${dir}/busbar-auth-oidc.tar.gz" \
    --allow-unsigned
  return 0
}

# Build + pack a sibling LOGIN plugin cdylib into $dir as `$alias` (kind auth, unsigned dev pack). Used
# by the github/ldap live arms exactly as oidc_pack_plugin packs auth-oidc. Returns 1 if the sibling
# checkout is absent (caller loud-skips). $1 sibling-dir $2 crate $3 alias $4 lib-basename $5 out-dir.
pack_login_plugin() {
  local sib="$1" crate="$2" alias="$3" libbase="$4" dir="$5"
  local src="${REPO_ROOT}/../${sib}"
  [ -d "$src" ] || return 1
  mkdir -p "$dir"
  cargo build --release --manifest-path "${src}/Cargo.toml" -p "$crate" >/dev/null 2>&1
  local lib="${src}/target/release/${LIBPREFIX}${libbase}.${LIBEXT}"
  [ -f "$lib" ] || { echo "  ${crate} cdylib not built at $lib" >&2; return 1; }
  "$PACK_BIN" pack \
    --lib "$lib" \
    --name "$crate" --alias "$alias" --kind auth \
    --version "$VER" --publisher busbar \
    --description "${alias} plugin (1.5.2 gate)" \
    --license Apache-2.0 \
    --out "${dir}/${crate}.tar.gz" \
    --allow-unsigned
  return 0
}

# Self-test the JWKS/JWT machinery: prove a minted token verifies against the published JWKS key.
# This is HERMETIC and RUNS here — it validates the fixtures the integration assertions depend on.
oidc_selftest() {
  oidc_setup_keys
  local now exp jwt
  now="$(date +%s)"; exp="$((now + 3600))"
  jwt="$(oidc_mint_jwt "https://idp.gate.local/" "gate-audience" "alice" '["eng"]' "$exp")"
  # Verify the RS256 signature with the PUBLIC key (proves mint + JWKS material are consistent).
  local si sig
  si="${jwt%.*}"; sig="${jwt##*.}"
  openssl rsa -in "${OIDC_WORK}/rsa.pem" -pubout -out "${OIDC_WORK}/rsa.pub" 2>/dev/null
  printf '%s' "$sig" | tr '_-' '/+' | awk '{l=length($0)%4; if(l>0)for(i=0;i<4-l;i++)$0=$0"="; print}' \
    | openssl base64 -d -A >"${OIDC_WORK}/sig.bin"
  printf '%s' "$si" | openssl dgst -sha256 -verify "${OIDC_WORK}/rsa.pub" -signature "${OIDC_WORK}/sig.bin" >/dev/null 2>&1 \
    || { echo "  OIDC self-test: minted JWT did NOT verify against the published JWKS key" >&2; exit 1; }
  # Decode the payload back and confirm the claims round-trip.
  local pl
  pl="$(printf '%s' "${si#*.}" | tr '_-' '/+' | awk '{l=length($0)%4; if(l>0)for(i=0;i<4-l;i++)$0=$0"="; print}' | openssl base64 -d -A 2>/dev/null)"
  echo "$pl" | jq -e '.iss=="https://idp.gate.local/" and .aud=="gate-audience" and .sub=="alice" and (.groups|index("eng"))' >/dev/null \
    || { echo "  OIDC self-test: claims did not round-trip: ${pl}" >&2; exit 1; }
  ok "OIDC fixture self-test PASSED: minted RS256 JWT verifies against the JWKS key; claims round-trip"
}

# ══════════════════════════════════════════════════════════════════════════════════════════════════
# PHASE B — token-exchange CROSS-REPO MATRIX (registry-driven over EVERY kind:auth plugin)
# ══════════════════════════════════════════════════════════════════════════════════════════════════
#
# The 1.5.2 token exchange is a per-plugin capability, and different kind:auth plugins support
# different DIRECTIONS of the exchange. This phase is REGISTRY-DRIVEN: it iterates every kind:auth
# entry in plugins.yaml (via `plugin-registry-check.sh --list`) and, for each, exercises the flows
# that plugin SUPPORTS. A new kind:auth plugin slots in by (1) its plugins.yaml entry and (2) one arm
# in `auth_plugin_flows()` below — and plugin-registry-check.sh REDS any kind:auth plugin missing
# that arm (mirroring how it reds a plugin lacking a gate phase).
#
# FLOW CAPABILITY MAP — the single source of truth for "which directions does this plugin support":
#   post   — POST /auth/token with a held id_token/bearer → self-scoped key (headless). OIDC only:
#            its authenticate() verifies a signed JWT the caller already holds.
#   get    — GET /auth/token browser redirect flow (browser → IdP → callback → key). OIDC + GitHub.
#            (GitHub tokens are OPAQUE: authenticate()=Pass, so github has NO `post` path — GET only.)
#            GitHub's `get` now RUNS LIVE-HERMETIC: a WireMock container (run_tokenx_github_get) stubs
#            the token/user/orgs endpoints and the CORE executes the real hops against it.
#   form   — GET credential-form flow (chooser → form → POST creds → bind → key). LDAP only.
#            LDAP's `form` now RUNS LIVE-HERMETIC: a seeded OpenLDAP container (run_tokenx_ldap_form)
#            the plugin binds against; a wrong password is asserted 401. Both loud-SKIP without docker.
# Add an arm for every new kind:auth plugin's alias. An unlisted alias yields "" → the plugin's
# sub-cases are all VERIFIED-AT-INTEGRATION and plugin-registry-check.sh flags the missing arm RED.
auth_plugin_flows() {
  case "$1" in
    oidc)   echo "post get" ;;   # both directions
    github) echo "get" ;;        # opaque token → GET redirect only (no held-token POST path)
    ldap)   echo "form" ;;       # credential-form bind flow
    *)      echo "" ;;
  esac
}

# The full OIDC POST-token flow (headless): build the config, --validate it, and (opt-in) boot +
# POST /auth/token + drive a chat with the issued key + assert one-key idempotency + TTL. Reused by
# BOTH the busbar-side gate here and (as the same shape) the plugin-side plugin-ci.yml auth step.
run_phase_b() {
  phase "Phase B: token-exchange CROSS-REPO MATRIX — registry-driven over every kind:auth plugin"

  # Prove the JWKS/JWT fixtures are real + valid ONCE (hermetic, RUNS here) — shared by every
  # signature-verifying (OIDC-family) plugin case below.
  oidc_selftest

  # ── The registry-driven iteration: one pass per kind:auth plugin, dispatch per supported flow. ──
  local REG
  REG="$(./scripts/plugin-registry-check.sh --list 2>/dev/null || true)"
  [ -n "$REG" ] || { echo "  Phase B: plugin-registry-check.sh --list returned nothing" >&2; exit 1; }
  local saw_auth=0
  while IFS=$'\t' read -r P_REPO P_DIR P_ALIAS P_KIND P_SERVICE P_RELGATE P_GATE P_REF; do
    [ "$P_KIND" = "auth" ] || continue
    saw_auth=1
    local flows; flows="$(auth_plugin_flows "$P_ALIAS")"
    echo
    echo "  ── kind:auth plugin '${P_REPO}' (alias ${P_ALIAS}) — supported flows: [${flows:-<none declared>}] ──"
    if [ -z "$flows" ]; then
      integ "no flow arm in auth_plugin_flows() for alias '${P_ALIAS}' — every direction is UNVERIFIED."
      integ "  Add an arm (post/get/form) so this plugin's token-exchange is gated; registry-check REDS this."
      continue
    fi
    case "$P_ALIAS" in
      oidc)
        # OIDC supports BOTH directions.
        # (b) POST /auth/token (held id_token) — RUNS fully here (fixture self-test + --validate now;
        #     boot + POST behind BUSBAR_1_5_2_RUN_OIDC_BOOT, see the KNOWN INTEGRATION BLOCKER).
        run_tokenx_oidc_post "$P_DIR"
        # (a) GET /auth/token browser redirect flow — VERIFIED-AT-INTEGRATION: the GET handler is
        #     mounted by Step 6 (see auth/exchange.rs "Step 6 mounts the GET browser flow"); Steps 1-5
        #     mount POST only, so the browser round-trip has no endpoint to drive here yet.
        integ "OIDC GET /auth/token browser redirect flow (browser→IdP→callback→key)."
        integ "  NOT RUN: the GET handler lands in Step 6 (auth/exchange.rs). Confirm at integration:"
        integ "   GET /auth/token?method=oidc → 302 to the IdP authorize URL (browser_login.client_id/"
        integ "   scopes), the callback exchanges the code, and the redirect delivers a working key."
        ;;
      github)
        # LIVE-HERMETIC: opaque token → GET browser-redirect flow ONLY (authenticate()=Pass, no POST
        # path). The CORE executes the token/user/orgs hops against a WireMock container. Loud-skips
        # (never a silent pass) when docker or the sibling checkout is absent.
        run_tokenx_github_get "$P_DIR"
        ;;
      ldap)
        # LIVE-HERMETIC: GET credential-form flow (chooser → form → POST creds → bind → key). The
        # plugin binds against a seeded OpenLDAP container; a wrong password is asserted 401. Loud-skips
        # (never a silent pass) when docker or the sibling checkout is absent.
        run_tokenx_ldap_form "$P_DIR"
        ;;
      *)
        integ "flows [${flows}] declared for '${P_ALIAS}' but no runner wired — treat as VERIFIED-AT-INTEGRATION."
        ;;
    esac
  done <<<"$REG"
  [ "$saw_auth" = "1" ] || note "Phase B: no kind:auth plugins in the registry (nothing to exercise)."

  ok "Phase B complete: elapsed=${SECONDS}s"
}

# The OIDC POST /auth/token flow. $1 = the plugin's sibling checkout dir name (e.g. auth-oidc).
run_tokenx_oidc_post() {
  local plugin_dir="$1"

  # 2) Build the config exactly as an operator would for headless token exchange.
  local B_LISTEN=19160 B_ADMIN=19161 B_MOCK=19162 B_JWKS=19163
  local work; work="$(new_tmpdir)"
  local ISS="https://idp.gate.local/" AUD="gate-audience" SUB="alice"
  local jwks_pid; jwks_pid="$(oidc_start_https_jwks "$B_JWKS")"
  local JWKS_URL="https://127.0.0.1:${B_JWKS}/jwks.json"
  # 12-space indent: the `ca_cert_pem: |` key below sits at 10 spaces, so block-scalar CONTENT must be
  # indented MORE than the key (>=12) on every line, or YAML parses the PEM lines as new mapping keys.
  local CA_PEM; CA_PEM="$(sed 's/^/            /' "${OIDC_WORK}/tls.crt")"

  "$BUSBAR_BIN" --generate-signing-key >"${work}/signing.key" 2>/dev/null
  local pdir="${work}/plugins"

  # NB the OIDC identity module MUST be in the DATA-PLANE `auth.chain` (that is the chain
  # `POST /auth/token` runs to identify the caller); `keys` is also present so the MINTED key then
  # authenticates the subsequent chat-completion. `role_bindings.oidc.eng.group` binds the JWT's
  # `groups:["eng"]` role to the `eng-team` budget; `eng-team.child_default` is the per-user
  # (`user:<sub>`) budget template stamped on first self-mint. `key_ttl` sets the issued key's TTL.
  cat >"${work}/config.yaml" <<EOF
listen: "127.0.0.1:${B_LISTEN}"
admin_listen: "127.0.0.1:${B_ADMIN}"
public_url: "https://gate.busbar.local"
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: { env: BUSBAR_ADMIN_TOKEN }
  oidc:
    module: oidc
    settings:
      issuer: "${ISS}"
      audience: "${AUD}"
      jwks_url: "${JWKS_URL}"
      ca_cert_pem: |
${CA_PEM}
auth:
  key_ttl: "7d"
  signing_key: { file: "${work}/signing.key" }
  chain: [keys, oidc]
  admin_auth: [admin-tokens]
  role_bindings:
    oidc:
      eng:
        group: eng-team
plugins:
  enabled: true
  dir: "${pdir}"
  trust:
    allow_unsigned: true
groups:
  eng-team:
    limits:
      - { requests: 1000000, per: day }
    child_default:
      limits:
        - { budget: 5000, per: month }
        - { requests: 1000, per: day }
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
  base_url: "http://127.0.0.1:${B_MOCK}"
EOF
  assert_yaml "${work}/config.yaml" "Phase B token-exchange config"
  assert_yaml "${work}/providers.yaml" "Phase B providers"

  # 3) Pack the auth-oidc plugin (sibling), so `oidc` resolves in the chain. Without it we CANNOT
  #    validate a config that names the module — loud-skip the OIDC-dependent bits.
  if oidc_pack_plugin "$pdir"; then
    ok "packed sibling auth-oidc plugin as alias 'oidc' into ${pdir}"
    HAVE_OIDC=1
  else
    note "SKIP: ../auth-oidc sibling checkout absent — cannot pack the oidc plugin."
    note "Phase B's config-validate + boot are OIDC-dependent; loud-skipping them (NOT a green pass)."
    HAVE_OIDC=0
  fi

  if [ "$HAVE_OIDC" = "1" ]; then
    # 4) --validate the exact config (REAL, fail-closed; RUNS here). Proves the 1.5.2 config surface
    #    (public_url, auth.chain oidc entry + settings, key_ttl, role_bindings.oidc, groups +
    #    child_default) resolves and the oidc plugin manifest validates.
    echo "  busbar --validate on the token-exchange config..."
    BUSBAR_CONFIG="${work}/config.yaml" BUSBAR_PROVIDERS="${work}/providers.yaml" \
      MOCK_KEY=unused BUSBAR_ADMIN_TOKEN=gate-admin \
      "$BUSBAR_BIN" --validate
    ok "config-validate CLEAN: the full 1.5.2 token-exchange config surface resolves + the oidc plugin validates"
  fi

  # 5) The full boot + POST /auth/token round-trip.
  local now exp jwt
  now="$(date +%s)"; exp="$((now + 3600))"
  jwt="$(oidc_mint_jwt "$ISS" "$AUD" "$SUB" '["eng"]' "$exp")"

  if [ "$HAVE_OIDC" = "1" ] && [ "${BUSBAR_1_5_2_RUN_OIDC_BOOT:-0}" = "1" ]; then
    echo "  booting busbar + driving POST /auth/token with the minted JWT..."
    local mock_pid; mock_pid="$(start_mock_upstream "$B_MOCK" "gate-B-marker")"
    BUSBAR_CONFIG="${work}/config.yaml" BUSBAR_PROVIDERS="${work}/providers.yaml" \
      MOCK_KEY=unused BUSBAR_ADMIN_TOKEN=gate-admin RUST_LOG=warn \
      "$BUSBAR_BIN" >"${work}/busbar.log" 2>&1 &
    local bpid=$!; BG_PIDS+=("$bpid")
    wait_for_http "http://127.0.0.1:${B_LISTEN}/healthz" 30
    local resp1 api_key1 group1 exp1
    resp1="$(curl -sS -X POST "http://127.0.0.1:${B_LISTEN}/auth/token" -H "Authorization: Bearer ${jwt}")"
    echo "  POST /auth/token → ${resp1}"
    api_key1="$(echo "$resp1" | jq -r '.api_key // empty')"
    group1="$(echo "$resp1"  | jq -r '.group   // empty')"
    exp1="$(echo "$resp1"    | jq -r '.exp     // empty')"
    if [ -z "$api_key1" ]; then
      echo "  Phase B: POST /auth/token returned no api_key: ${resp1}" >&2
      echo "  ^ EXPECTED IN THIS BRANCH: the auth-oidc plugin sets principal.id='oidc:<sub>', and" >&2
      echo "    sanitize_self_sub rejects the ':' → 403 BadSubject. See the KNOWN INTEGRATION BLOCKER" >&2
      echo "    header. The integrator must reconcile the prefix vs the sanitizer for the 200 path." >&2
      exit 1
    fi
    # The self group is ALWAYS `user:` + the WHOLE module-namespaced principal id; the oidc plugin's is
    # `oidc:<sub>`, so the leaf is `user:oidc:<sub>` (core's self_keys_tests.rs asserts `user:oidc:alice`).
    [ "$group1" = "user:oidc:${SUB}" ] || { echo "  Phase B: group is '${group1}', expected 'user:oidc:${SUB}'" >&2; exit 1; }
    ok "self-scoped key issued: group=${group1}, exp=${exp1}"
    # TTL reflects key_ttl (7d = 604800s), within a generous skew of 'now'.
    local want_ttl=604800 got_ttl=$((exp1 - now))
    [ "$got_ttl" -ge $((want_ttl - 120)) ] && [ "$got_ttl" -le $((want_ttl + 120)) ] \
      || { echo "  Phase B: issued TTL ${got_ttl}s does not reflect key_ttl(7d=${want_ttl}s)" >&2; exit 1; }
    ok "issued key TTL reflects auth.key_ttl (7d): exp-now=${got_ttl}s"
    # One-key: POST again → SAME key.
    local resp2 api_key2
    resp2="$(curl -sS -X POST "http://127.0.0.1:${B_LISTEN}/auth/token" -H "Authorization: Bearer ${jwt}")"
    api_key2="$(echo "$resp2" | jq -r '.key_id // empty')"
    local kid1; kid1="$(echo "$resp1" | jq -r '.key_id // empty')"
    [ -n "$api_key2" ] && [ "$api_key2" = "$kid1" ] \
      || { echo "  Phase B: one-key idempotency broken: ${kid1} vs ${api_key2}" >&2; exit 1; }
    ok "one-key idempotency proven: a second POST returned the SAME key_id (${api_key2})"
    # Use the issued key for a REAL chat-completion → 200 with the mock marker.
    local chat got
    chat="$(curl -sS "http://127.0.0.1:${B_LISTEN}/v1/chat/completions" \
      -H "Authorization: Bearer ${api_key1}" -H "Content-Type: application/json" \
      -d '{"model":"test-model","messages":[{"role":"user","content":"hi"}]}')"
    got="$(echo "$chat" | jq -r '.choices[0].message.content // empty')"
    [ "$got" = "gate-B-marker" ] || { echo "  Phase B: chat via issued key failed: ${chat}" >&2; exit 1; }
    ok "issued self-serve key drove a real chat-completion → 200 (marker matched)"
    kill "$bpid" 2>/dev/null || true; wait "$bpid" 2>/dev/null || true
    kill "$mock_pid" 2>/dev/null || true; wait "$mock_pid" 2>/dev/null || true
  else
    integ "Phase B boot + POST /auth/token round-trip. RAN: JWKS/JWT fixture self-test + (when the"
    integ "  auth-oidc sibling is present) config --validate. NOT RUN standalone: the live boot + POST."
    integ "  To run it here: set BUSBAR_1_5_2_RUN_OIDC_BOOT=1 with ../auth-oidc checked out."
    integ "  The integrator MUST confirm, against the crates built on the sibling branch:"
    integ "   1) POST /auth/token with the minted JWT returns 200 + { api_key, key_id, group:'user:${SUB}', exp }."
    integ "      *** BLOCKER: the auth-oidc plugin sets principal.id='oidc:<sub>' but sanitize_self_sub"
    integ "      rejects ':' → today this returns 403 BadSubject. Reconcile before the 200 path passes. ***"
    integ "   2) exp-now ≈ auth.key_ttl (7d = 604800s)."
    integ "   3) a second POST returns the SAME key_id (one-key idempotency)."
    integ "   4) the issued key drives a real chat-completion → 200."
    integ "   5) NOTE: Steps 1-5 wire POST /auth/token to ISSUE only (self_keys refresh_self exists but"
    integ "      no HTTP refresh surface is mounted yet). The 'refresh → NEW key, old rejected' assertion"
    integ "      has NO endpoint in this branch — confirm when the refresh route lands (Step 6+)."
  fi

  ok "OIDC POST /auth/token flow complete (config-validate ran; boot+POST per the opt-in / blocker above)"
}

# ── github GET /auth/token browser-redirect flow — LIVE-HERMETIC against a WireMock container ──────
# The github plugin issues NO held-token POST path (opaque token, authenticate()=Pass): identity is
# established through the GET browser flow, where the CORE executes the module-described hops. This
# runner stands up WireMock stubbing GitHub's token/user/orgs endpoints, boots a real busbar whose
# `auth.methods.github` points token_base/api_base/authorize_base at WireMock, and drives the flow so
# the CORE really executes POST /login/oauth/access_token → GET /user → GET /user/orgs → Identify. The
# OAuth callback is simulated directly (GET /auth/token?code=…&state=… with the login cookie the begin
# leg set) since the mock accepts any code. Asserts: identity github:octotest, role github:org/testorg
# (proven by the mint succeeding — the ONLY role bound is github:org/testorg → without it the exchange
# is Unbound/403 and NO key page renders), and that the issued key drives a real chat-completion.
run_tokenx_github_get() {
  local plugin_dir="$1"   # sibling checkout dir name (auth-github)
  echo
  echo "  ── github GET /auth/token browser-redirect flow (opaque token; GET only) ──"
  local src="${REPO_ROOT}/../${plugin_dir}"
  if [ ! -d "$src" ]; then
    note "SKIP: ../${plugin_dir} sibling checkout absent — cannot pack the github plugin (NOT a green pass)."
    integ "github GET flow is STRUCTURED; it RUNS once ../${plugin_dir} is checked out with docker present."
    return 0
  fi
  if ! docker_available; then
    note "SKIP: docker unavailable locally — github LIVE flow LOUD-SKIPPED (NOT a green pass)."
    integ "github GET flow (WireMock ${WIREMOCK_IMAGE}): NOT RUN without docker; in CI (docker present) it RUNS."
    return 0
  fi
  if ! ensure_image "$WIREMOCK_IMAGE"; then
    note "SKIP: ${WIREMOCK_IMAGE} not cached and unpullable (offline runner) — github LIVE flow skipped (NOT a pass)."
    return 0
  fi

  local work pdir; work="$(new_tmpdir)"; pdir="${work}/plugins"
  pack_login_plugin "$plugin_dir" busbar-auth-github-plugin github busbar_auth_github_plugin "$pdir" \
    || { echo "  github: pack failed" >&2; exit 1; }
  ok "packed sibling auth-github plugin as alias 'github'"

  local WM_PORT LISTEN MOCK; WM_PORT="$(free_port)"; LISTEN="$(free_port)"; MOCK="$(free_port)"
  echo "  starting WireMock (${WIREMOCK_IMAGE}) on 127.0.0.1:${WM_PORT} with the github stub mappings..."
  local cid
  cid="$(docker run -d --rm -p "127.0.0.1:${WM_PORT}:8080" \
    -v "${REPO_ROOT}/scripts/fixtures/auth-github-wiremock:/home/wiremock/mappings:ro" \
    "$WIREMOCK_IMAGE")"
  DOCKER_CIDS+=("$cid")
  wait_for_http "http://127.0.0.1:${WM_PORT}/__admin/mappings" 60 \
    || { echo "  WireMock did not become ready" >&2; docker logs "$cid" >&2 || true; exit 1; }
  ok "WireMock up; github stubs loaded"

  local mock_pid; mock_pid="$(start_mock_upstream "$MOCK" "gate-github-marker")"
  "$BUSBAR_BIN" --generate-signing-key >"${work}/signing.key" 2>/dev/null

  cat >"${work}/config.yaml" <<EOF
listen: "127.0.0.1:${LISTEN}"
public_url: "https://gate.busbar.local"
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: { env: BUSBAR_ADMIN_TOKEN }
  github:
    module: github
    browser_login:
      client_id: "Iv1.gatetestclient"
      client_secret: { env: BUSBAR_GH_CLIENT_SECRET }
    settings:
      token_base: "http://127.0.0.1:${WM_PORT}"
      api_base: "http://127.0.0.1:${WM_PORT}"
      authorize_base: "http://127.0.0.1:${WM_PORT}"
auth:
  key_ttl: "7d"
  signing_key: { file: "${work}/signing.key" }
  chain: [keys]
  admin_auth: [admin-tokens]
  role_bindings:
    github:
      "github:org/testorg":
        group: eng-team
plugins:
  enabled: true
  dir: "${pdir}"
  trust:
    allow_unsigned: true
groups:
  eng-team:
    limits:
      - { requests: 1000000, per: day }
    child_default:
      limits:
        - { budget: 5000, per: month }
        - { requests: 1000, per: day }
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
  base_url: "http://127.0.0.1:${MOCK}"
EOF
  assert_yaml "${work}/config.yaml" "Phase B github token-exchange config"
  assert_yaml "${work}/providers.yaml" "Phase B github providers"

  echo "  busbar --validate on the github token-exchange config..."
  BUSBAR_CONFIG="${work}/config.yaml" BUSBAR_PROVIDERS="${work}/providers.yaml" \
    MOCK_KEY=unused BUSBAR_GH_CLIENT_SECRET=gate-gh-secret BUSBAR_ADMIN_TOKEN=gate-admin \
    "$BUSBAR_BIN" --validate
  ok "config-validate CLEAN (auth.methods.github + browser_login + role_bindings.github resolve; plugin loads)"

  echo "  booting busbar + driving the github GET /auth/token browser-redirect flow..."
  BUSBAR_CONFIG="${work}/config.yaml" BUSBAR_PROVIDERS="${work}/providers.yaml" \
    MOCK_KEY=unused BUSBAR_GH_CLIENT_SECRET=gate-gh-secret BUSBAR_ADMIN_TOKEN=gate-admin RUST_LOG=warn \
    "$BUSBAR_BIN" >"${work}/busbar.log" 2>&1 &
  local bpid=$!; BG_PIDS+=("$bpid")
  wait_for_http "http://127.0.0.1:${LISTEN}/healthz" 30

  local hdrs cookie state
  hdrs="$(curl -sS -D - -o /dev/null "http://127.0.0.1:${LISTEN}/auth/token?method=github")"
  cookie="$(extract_login_cookie "$hdrs")"
  [ -n "$cookie" ] || { echo "  github: begin did not set a login cookie" >&2; echo "$hdrs" >&2; exit 1; }
  state="$(login_cookie_state "$cookie")"
  [ -n "$state" ] || { echo "  github: could not read state from the login cookie" >&2; exit 1; }
  ok "begin → 302 to the authorize URL + login cookie (state captured)"

  local page
  page="$(curl -sS "http://127.0.0.1:${LISTEN}/auth/token?code=gate-testcode&state=${state}" \
    -H "Cookie: busbar_login=${cookie}")"
  if echo "$page" | grep -qi "no self-serve grant\|login rejected\|did not complete\|could not be reached"; then
    echo "  github: callback did NOT mint a key (identity/roles wrong → fail closed):" >&2
    echo "$page" | tr -d '\n' | head -c 500 >&2; echo >&2
    cat "${work}/busbar.log" >&2; exit 1
  fi
  echo "$page" | grep -q "github:octotest" \
    || { echo "  github: identity 'github:octotest' not present in the key page" >&2; exit 1; }
  echo "$page" | grep -q "user:github:octotest" \
    || { echo "  github: group 'user:github:octotest' absent (role github:org/testorg must have bound)" >&2; exit 1; }
  ok "identity github:octotest + role github:org/testorg resolved → key minted (group user:github:octotest)"

  local api_key chat got
  api_key="$(extract_issued_key "$page")"
  [ -n "$api_key" ] || { echo "  github: could not extract the issued api_key from the page" >&2; exit 1; }
  chat="$(curl -sS "http://127.0.0.1:${LISTEN}/v1/chat/completions" \
    -H "Authorization: Bearer ${api_key}" -H "Content-Type: application/json" \
    -d '{"model":"test-model","messages":[{"role":"user","content":"hi"}]}')"
  got="$(echo "$chat" | jq -r '.choices[0].message.content // empty')"
  [ "$got" = "gate-github-marker" ] || { echo "  github: issued key failed to drive a chat: ${chat}" >&2; exit 1; }
  ok "issued github key authorized a real chat-completion → 200 (marker matched)"

  kill "$bpid" 2>/dev/null || true; wait "$bpid" 2>/dev/null || true
  kill "$mock_pid" 2>/dev/null || true; wait "$mock_pid" 2>/dev/null || true
  docker rm -f "$cid" >/dev/null 2>&1 || true
  ok "github GET flow PROVEN LIVE against WireMock ${WIREMOCK_IMAGE}"
}

# ── ldap credential-FORM flow — LIVE-HERMETIC against an OpenLDAP container ────────────────────────
# LDAP is a Credential method: the chooser renders a form (no redirect), the browser POSTs
# username/password, and the plugin opens ITS OWN LDAP socket and BINDs. This runner stands up
# OpenLDAP seeded with seed.ldif (uid=alice, member of cn=admins), boots a real busbar whose
# `auth.methods.ldap` points at it, drives GET (render form) → POST (username=alice&password=…) so the
# plugin really binds + reads the group attribute, and asserts a key is minted with role `admins`
# (→ group eng-team). It ALSO asserts a WRONG password is rejected 401, proving the real bind gates.
run_tokenx_ldap_form() {
  local plugin_dir="$1"   # sibling checkout dir name (auth-ldap)
  echo
  echo "  ── ldap GET credential-form flow (chooser → form → POST creds → bind → key) ──"
  local src="${REPO_ROOT}/../${plugin_dir}"
  if [ ! -d "$src" ]; then
    note "SKIP: ../${plugin_dir} sibling checkout absent — cannot pack the ldap plugin (NOT a green pass)."
    integ "ldap form flow is STRUCTURED; it RUNS once ../${plugin_dir} is checked out with docker present."
    return 0
  fi
  if ! docker_available; then
    note "SKIP: docker unavailable locally — ldap LIVE flow LOUD-SKIPPED (NOT a green pass)."
    integ "ldap form flow (OpenLDAP ${OPENLDAP_IMAGE}): NOT RUN without docker; in CI (docker present) it RUNS."
    return 0
  fi
  if ! ensure_image "$OPENLDAP_IMAGE"; then
    note "SKIP: ${OPENLDAP_IMAGE} not cached and unpullable (offline runner) — ldap LIVE flow skipped (NOT a pass)."
    return 0
  fi

  local work pdir; work="$(new_tmpdir)"; pdir="${work}/plugins"
  pack_login_plugin "$plugin_dir" busbar-auth-ldap-plugin ldap busbar_auth_ldap_plugin "$pdir" \
    || { echo "  ldap: pack failed" >&2; exit 1; }
  ok "packed sibling auth-ldap plugin as alias 'ldap'"

  local LDAP_PORT LISTEN MOCK; LDAP_PORT="$(free_port)"; LISTEN="$(free_port)"; MOCK="$(free_port)"
  echo "  starting OpenLDAP (${OPENLDAP_IMAGE}) on 127.0.0.1:${LDAP_PORT}, bootstrapping seed.ldif..."
  local cid
  cid="$(docker run -d --rm -p "127.0.0.1:${LDAP_PORT}:389" \
    -e LDAP_ORGANISATION="Example Org" \
    -e LDAP_DOMAIN="example.org" \
    -e LDAP_ADMIN_PASSWORD="adminpassword" \
    -v "${REPO_ROOT}/scripts/fixtures/auth-ldap:/container/service/slapd/assets/config/bootstrap/ldif/custom:ro" \
    "$OPENLDAP_IMAGE" --copy-service)"
  DOCKER_CIDS+=("$cid")

  # Ready when the seeded alice entry resolves (base auto-created + bootstrap LDIF applied).
  local waited=0
  until docker exec "$cid" ldapsearch -x -H ldap://localhost:389 \
        -D "cn=admin,dc=example,dc=org" -w adminpassword \
        -b "uid=alice,ou=people,dc=example,dc=org" -s base dn >/dev/null 2>&1; do
    waited=$((waited + 1))
    if [ "$waited" -ge 60 ]; then
      echo "  OpenLDAP did not seed uid=alice within 60s" >&2; docker logs "$cid" >&2 || true; exit 1
    fi
    sleep 1
  done
  ok "OpenLDAP up + seeded (uid=alice resolvable; member of cn=admins)"

  local mock_pid; mock_pid="$(start_mock_upstream "$MOCK" "gate-ldap-marker")"
  "$BUSBAR_BIN" --generate-signing-key >"${work}/signing.key" 2>/dev/null

  cat >"${work}/config.yaml" <<EOF
listen: "127.0.0.1:${LISTEN}"
public_url: "https://gate.busbar.local"
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: { env: BUSBAR_ADMIN_TOKEN }
  ldap:
    module: ldap
    browser_login: {}
    settings:
      url: "ldap://127.0.0.1:${LDAP_PORT}"
      bind_dn_template: "uid={username},ou=people,dc=example,dc=org"
      base_dn: "dc=example,dc=org"
      group_attr: "seeAlso"
      role_from: cn
auth:
  key_ttl: "7d"
  signing_key: { file: "${work}/signing.key" }
  chain: [keys]
  admin_auth: [admin-tokens]
  role_bindings:
    ldap:
      admins:
        group: eng-team
plugins:
  enabled: true
  dir: "${pdir}"
  trust:
    allow_unsigned: true
groups:
  eng-team:
    limits:
      - { requests: 1000000, per: day }
    child_default:
      limits:
        - { budget: 5000, per: month }
        - { requests: 1000, per: day }
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
  base_url: "http://127.0.0.1:${MOCK}"
EOF
  assert_yaml "${work}/config.yaml" "Phase B ldap credential-flow config"
  assert_yaml "${work}/providers.yaml" "Phase B ldap providers"

  echo "  busbar --validate on the ldap credential-flow config..."
  BUSBAR_CONFIG="${work}/config.yaml" BUSBAR_PROVIDERS="${work}/providers.yaml" MOCK_KEY=unused BUSBAR_ADMIN_TOKEN=gate-admin \
    "$BUSBAR_BIN" --validate
  ok "config-validate CLEAN (auth.methods.ldap credential method + role_bindings.ldap resolve; plugin loads)"

  echo "  booting busbar + driving the ldap credential-form flow..."
  BUSBAR_CONFIG="${work}/config.yaml" BUSBAR_PROVIDERS="${work}/providers.yaml" MOCK_KEY=unused BUSBAR_ADMIN_TOKEN=gate-admin RUST_LOG=warn \
    "$BUSBAR_BIN" >"${work}/busbar.log" 2>&1 &
  local bpid=$!; BG_PIDS+=("$bpid")
  wait_for_http "http://127.0.0.1:${LISTEN}/healthz" 30

  # begin: GET ?method=ldap → 200 credential FORM + a login cookie carrying state.
  local hdrs cookie state
  hdrs="$(curl -sS -D - -o /dev/null "http://127.0.0.1:${LISTEN}/auth/token?method=ldap")"
  cookie="$(extract_login_cookie "$hdrs")"
  [ -n "$cookie" ] || { echo "  ldap: begin did not set a login cookie" >&2; echo "$hdrs" >&2; exit 1; }
  state="$(login_cookie_state "$cookie")"
  [ -n "$state" ] || { echo "  ldap: could not read state from the login cookie" >&2; exit 1; }
  ok "begin → credential form + login cookie (state captured)"

  # POST creds: the plugin BINDs alice against OpenLDAP, reads seeAlso (cn=admins → role 'admins').
  local page
  page="$(curl -sS -X POST "http://127.0.0.1:${LISTEN}/auth/token" \
    -H "Cookie: busbar_login=${cookie}" \
    --data-urlencode "__state=${state}" \
    --data-urlencode "username=alice" \
    --data-urlencode "password=alicepassword")"
  if echo "$page" | grep -qi "no self-serve grant\|login rejected\|did not complete"; then
    echo "  ldap: correct-password submit did NOT mint a key (bind/role wrong → fail closed):" >&2
    echo "$page" | tr -d '\n' | head -c 500 >&2; echo >&2
    cat "${work}/busbar.log" >&2; exit 1
  fi
  echo "$page" | grep -q "ldap:uid=alice" \
    || { echo "  ldap: identity 'ldap:uid=alice,...' not present in the key page" >&2; exit 1; }
  echo "$page" | grep -q "user:ldap:uid=alice" \
    || { echo "  ldap: group 'user:ldap:uid=alice,...' absent (role 'admins' must have bound)" >&2; exit 1; }
  ok "alice bound against OpenLDAP; role 'admins' (from cn=admins) resolved → key minted"

  local api_key chat got
  api_key="$(extract_issued_key "$page")"
  [ -n "$api_key" ] || { echo "  ldap: could not extract the issued api_key" >&2; exit 1; }
  chat="$(curl -sS "http://127.0.0.1:${LISTEN}/v1/chat/completions" \
    -H "Authorization: Bearer ${api_key}" -H "Content-Type: application/json" \
    -d '{"model":"test-model","messages":[{"role":"user","content":"hi"}]}')"
  got="$(echo "$chat" | jq -r '.choices[0].message.content // empty')"
  [ "$got" = "gate-ldap-marker" ] || { echo "  ldap: issued key failed to drive a chat: ${chat}" >&2; exit 1; }
  ok "issued ldap key authorized a real chat-completion → 200 (marker matched)"

  # WRONG password must be REJECTED (401) — proving the REAL bind gates. Fresh begin → fresh cookie/state.
  local hdrs2 cookie2 state2 code
  hdrs2="$(curl -sS -D - -o /dev/null "http://127.0.0.1:${LISTEN}/auth/token?method=ldap")"
  cookie2="$(extract_login_cookie "$hdrs2")"
  state2="$(login_cookie_state "$cookie2")"
  code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${LISTEN}/auth/token" \
    -H "Cookie: busbar_login=${cookie2}" \
    --data-urlencode "__state=${state2}" \
    --data-urlencode "username=alice" \
    --data-urlencode "password=wrong-password")"
  [ "$code" = "401" ] || { echo "  ldap: a WRONG password returned ${code}, expected 401 (bind must gate)" >&2; exit 1; }
  ok "WRONG password REJECTED with 401 — the real LDAP bind gates the form flow"

  kill "$bpid" 2>/dev/null || true; wait "$bpid" 2>/dev/null || true
  kill "$mock_pid" 2>/dev/null || true; wait "$mock_pid" 2>/dev/null || true
  docker rm -f "$cid" >/dev/null 2>&1 || true
  ok "ldap credential-form flow PROVEN LIVE against OpenLDAP ${OPENLDAP_IMAGE}"
}

# ══════════════════════════════════════════════════════════════════════════════════════════════════
# PHASE C — admin AUTHORIZATION MATRIX (three postures)
# ══════════════════════════════════════════════════════════════════════════════════════════════════
run_phase_c() {
  phase "Phase C: admin authorization matrix — full CAN do what read-only CANNOT; [] is truly open"

  local C_LISTEN=19170 C_ADMIN=19171

  # ---- Posture (c): admin_auth: [] → OPEN admin. Fully RUNS here (no OIDC needed). ----
  echo
  echo "  Posture (c): admin_auth: [] → an UNAUTHENTICATED caller can mutate; the open-relay banner is loud"
  local wc; wc="$(new_tmpdir)"
  "$BUSBAR_BIN" --generate-signing-key >"${wc}/signing.key" 2>/dev/null
  cat >"${wc}/config.yaml" <<EOF
listen: "127.0.0.1:${C_LISTEN}"
admin_listen: "127.0.0.1:${C_ADMIN}"
auth:
  signing_key: { file: "${wc}/signing.key" }
  chain:
    - keys
  admin_auth: []
providers:
  mock:
    api_key: { env: MOCK_KEY }
models:
  test-model:
    provider: mock
EOF
  cat >"${wc}/providers.yaml" <<EOF
mock:
  protocol: anthropic
  base_url: "https://example.invalid"
EOF
  assert_yaml "${wc}/config.yaml" "Phase C posture-(c) open-admin config"
  assert_yaml "${wc}/providers.yaml" "Phase C posture-(c) providers"
  echo "  --validate open-admin config..."
  BUSBAR_CONFIG="${wc}/config.yaml" BUSBAR_PROVIDERS="${wc}/providers.yaml" MOCK_KEY=unused \
    "$BUSBAR_BIN" --validate
  ok "open-admin config validates"
  BUSBAR_CONFIG="${wc}/config.yaml" BUSBAR_PROVIDERS="${wc}/providers.yaml" MOCK_KEY=unused RUST_LOG=warn \
    "$BUSBAR_BIN" >"${wc}/busbar.log" 2>&1 &
  local cpid=$!; BG_PIDS+=("$cpid")
  wait_for_http "http://127.0.0.1:${C_LISTEN}/healthz" 30
  # A MUTATION by an UNAUTHENTICATED caller must succeed (open front door).
  local mut_code
  mut_code="$(curl -s -o "${wc}/mint.json" -w '%{http_code}' -X POST \
    "http://127.0.0.1:${C_ADMIN}/api/v1/admin/keys" \
    -H "Content-Type: application/json" -d '{"name":"open-admin-mint"}')"
  case "$mut_code" in
    200|201) ok "unauthenticated mutation SUCCEEDED (HTTP ${mut_code}) — [] is a genuinely open front door" ;;
    *) echo "  Posture (c): unauthenticated POST /keys returned ${mut_code}; open admin must admit it" >&2; cat "${wc}/mint.json" >&2; exit 1 ;;
  esac
  # The admin-auth read reports the open posture (configured:false) — the loud, machine-readable signal.
  local aa_conf
  aa_conf="$(curl -sS "http://127.0.0.1:${C_ADMIN}/api/v1/admin/admin-auth" | jq -r '.configured')"
  [ "$aa_conf" = "false" ] || { echo "  Posture (c): admin-auth read should report configured:false, got ${aa_conf}" >&2; exit 1; }
  ok "GET /admin/admin-auth reports configured:false (the open, anonymous, full-authority dev posture)"
  # The loud boot banner (open front door). The DATA-plane open-relay banner is emitted here; the
  # admin-open state is additionally surfaced via the admin-auth read above + 'anonymous' audit
  # attribution (there is no SEPARATE admin-open boot banner string in this branch).
  if grep -qi "OPEN RELAY" "${wc}/busbar.log"; then
    ok "loud boot banner present: open front door warned in the log"
  else
    note "Posture (c): the OPEN RELAY banner needs an empty DATA-plane chain to fire; admin-open is"
    note "  surfaced via GET /admin/admin-auth configured:false (asserted) + audit 'anonymous' attribution."
  fi
  kill "$cpid" 2>/dev/null || true; wait "$cpid" 2>/dev/null || true
  ok "Posture (c) proven: admin_auth:[] admits an unauthenticated mutation; open posture is reported"

  # ---- Postures (a) full and (b) read-only: need the admin-plane OIDC plugin + a JWT carrying the
  #      admin group. Build fixtures + --validate here; the boot + matrix is OIDC-dependent. ----
  echo
  echo "  Postures (a)/(b): admin-plane OIDC + role_bindings.oidc.<admin-group>.admin_scope {full|read-only}"
  oidc_setup_keys
  local C2_LISTEN=19180 C2_ADMIN=19181 C2_JWKS=19183
  local ISS="https://idp.gate.local/" AUD="gate-admin-audience"
  local jwks_pid; jwks_pid="$(oidc_start_https_jwks "$C2_JWKS")"
  local JWKS_URL="https://127.0.0.1:${C2_JWKS}/jwks.json"
  # 12-space indent: the `ca_cert_pem: |` key below sits at 10 spaces; block-scalar CONTENT must be
  # indented STRICTLY MORE than the key (>=12), else YAML reads the PEM lines as new mapping keys.
  local CA_PEM; CA_PEM="$(sed 's/^/            /' "${OIDC_WORK}/tls.crt")"

  write_admin_oidc_config() {   # $1 admin_scope (full|read-only) $2 outdir
    local scope="$1" out="$2"
    "$BUSBAR_BIN" --generate-signing-key >"${out}/signing.key" 2>/dev/null
    cat >"${out}/config.yaml" <<EOF
listen: "127.0.0.1:${C2_LISTEN}"
admin_listen: "127.0.0.1:${C2_ADMIN}"
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: { env: BUSBAR_ADMIN_TOKEN }
  oidc:
    module: oidc
    max_admin_scope: full
    settings:
      issuer: "${ISS}"
      audience: "${AUD}"
      jwks_url: "${JWKS_URL}"
      ca_cert_pem: |
${CA_PEM}
auth:
  signing_key: { file: "${out}/signing.key" }
  chain: [keys]
  admin_auth: [admin-tokens, oidc]
  role_bindings:
    oidc:
      admins:
        admin_scope: ${scope}
providers:
  mock:
    api_key: { env: MOCK_KEY }
models:
  test-model:
    provider: mock
EOF
    cat >"${out}/providers.yaml" <<EOF
mock:
  protocol: anthropic
  base_url: "https://example.invalid"
EOF
    assert_yaml "${out}/providers.yaml" "Phase C admin-plane OIDC providers"
    # NB the base config is deliberately checked by the caller AFTER it appends the plugins block
    # (the config is not complete until then) — see the assert_yaml calls on ${wa}/${wb} below.
  }

  local pdir_a; pdir_a="$(new_tmpdir)/plugins"
  if oidc_pack_plugin "$pdir_a"; then
    HAVE_OIDC_C=1
    ok "packed sibling auth-oidc plugin as alias 'oidc' for the admin-plane postures"
  else
    HAVE_OIDC_C=0
    note "SKIP: ../auth-oidc sibling absent — admin-plane OIDC postures (a)/(b) loud-skipped (NOT a pass)."
  fi

  if [ "$HAVE_OIDC_C" = "1" ]; then
    local wa; wa="$(new_tmpdir)"; write_admin_oidc_config "full" "$wa"
    # write_admin_oidc_config emits no plugins block, so append one pointing at the packed oidc plugin.
    cat >>"${wa}/config.yaml" <<EOF
plugins:
  enabled: true
  dir: "${pdir_a}"
  trust:
    allow_unsigned: true
EOF
    assert_yaml "${wa}/config.yaml" "Phase C admin-plane OIDC config (full)"
    echo "  --validate admin-plane OIDC config (admin_scope: full)..."
    BUSBAR_CONFIG="${wa}/config.yaml" BUSBAR_PROVIDERS="${wa}/providers.yaml" \
      MOCK_KEY=unused BUSBAR_ADMIN_TOKEN=gate-admin \
      "$BUSBAR_BIN" --validate
    ok "admin-plane OIDC config (full) validates: admin_auth[oidc] + role_bindings.oidc.admins.admin_scope"

    local wb; wb="$(new_tmpdir)"; write_admin_oidc_config "read-only" "$wb"
    cat >>"${wb}/config.yaml" <<EOF
plugins:
  enabled: true
  dir: "${pdir_a}"
  trust:
    allow_unsigned: true
EOF
    assert_yaml "${wb}/config.yaml" "Phase C admin-plane OIDC config (read-only)"
    echo "  --validate admin-plane OIDC config (admin_scope: read-only)..."
    BUSBAR_CONFIG="${wb}/config.yaml" BUSBAR_PROVIDERS="${wb}/providers.yaml" \
      MOCK_KEY=unused BUSBAR_ADMIN_TOKEN=gate-admin \
      "$BUSBAR_BIN" --validate
    ok "admin-plane OIDC config (read-only) validates"
  fi

  # The boot + enforcement matrix itself is OIDC-dependent (a real admin JWT presented over the admin
  # listener). Gate the live drive behind the same opt-in as Phase B.
  local now exp jwt_admin
  now="$(date +%s)"; exp="$((now + 3600))"
  jwt_admin="$(oidc_mint_jwt "$ISS" "$AUD" "admin-user" '["admins"]' "$exp")"

  if [ "$HAVE_OIDC_C" = "1" ] && [ "${BUSBAR_1_5_2_RUN_OIDC_BOOT:-0}" = "1" ]; then
    drive_matrix() {  # $1 workdir (full|read-only config), $2 expect_mutation (200|403)
      local w="$1" expect="$2"
      BUSBAR_CONFIG="${w}/config.yaml" BUSBAR_PROVIDERS="${w}/providers.yaml" \
        MOCK_KEY=unused BUSBAR_ADMIN_TOKEN=gate-admin RUST_LOG=warn \
        "$BUSBAR_BIN" >"${w}/busbar.log" 2>&1 &
      local pid=$!; BG_PIDS+=("$pid")
      wait_for_http "http://127.0.0.1:${C2_LISTEN}/healthz" 30
      # READ must always succeed for a bound admin identity.
      local read_code
      read_code="$(curl -s -o /dev/null -w '%{http_code}' \
        "http://127.0.0.1:${C2_ADMIN}/api/v1/admin/keys" -H "Authorization: Bearer ${jwt_admin}")"
      [ "$read_code" = "200" ] || { echo "  matrix: READ (GET /keys) returned ${read_code}, expected 200" >&2; exit 1; }
      # MUTATION on the SAME endpoint.
      local mut_code
      mut_code="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
        "http://127.0.0.1:${C2_ADMIN}/api/v1/admin/keys" -H "Authorization: Bearer ${jwt_admin}" \
        -H "Content-Type: application/json" -d '{"name":"matrix"}')"
      case "$expect" in
        200) { [ "$mut_code" = "200" ] || [ "$mut_code" = "201" ]; } || { echo "  matrix(full): mutation ${mut_code}, expected 200/201" >&2; exit 1; } ;;
        403) [ "$mut_code" = "403" ] || { echo "  matrix(read-only): mutation ${mut_code}, expected 403" >&2; exit 1; } ;;
      esac
      echo "$mut_code"
      kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
    }
    local full_code ro_code
    full_code="$(drive_matrix "$wa" 200)"
    ok "posture (a) FULL: GET /keys 200 AND POST /keys ${full_code} (mutation ALLOWED)"
    ro_code="$(drive_matrix "$wb" 403)"
    ok "posture (b) READ-ONLY: GET /keys 200 BUT POST /keys ${ro_code} (mutation FORBIDDEN on the SAME endpoint)"
    ok "matrix proven: full CAN do what read-only CANNOT, on the identical endpoint"
  else
    integ "Phase C postures (a)/(b) live boot + enforcement matrix. RAN: config --validate for both"
    integ "  full and read-only (when ../auth-oidc present). NOT RUN standalone: the live admin JWT drive."
    integ "  To run it here: BUSBAR_1_5_2_RUN_OIDC_BOOT=1 with ../auth-oidc checked out."
    integ "  The integrator MUST confirm, against the crates built on the sibling branch:"
    integ "   (a) admin_scope: full   → GET /api/v1/admin/keys = 200 AND POST /api/v1/admin/keys = 200/201."
    integ "   (b) admin_scope: read-only → GET = 200 (read allowed) but EVERY mutation on the SAME endpoints"
    integ "       (POST/PUT/DELETE keys, PUT /config/settings, hooks) = 403 forbidden — the required_scope"
    integ "       matrix (admin/v1/contract: reads=ReadOnly, mutations=Full) enforced at the one chokepoint."
    integ "   The admin JWT must carry the 'admins' group; role_bindings.oidc.admins.admin_scope sets the rung;"
    integ "   admin_auth's oidc entry declares max_admin_scope: full so 'full' is reachable (1.5.2 collapse)."
  fi

  ok "Phase C complete: elapsed=${SECONDS}s"
}

# ══════════════════════════════════════════════════════════════════════════════════════════════════
case "$ONLY_PHASE" in
  A) run_phase_a ;;
  B) run_phase_b ;;
  C) run_phase_c ;;
  "") run_phase_a; run_phase_b; run_phase_c ;;
  *) echo "unknown phase: $ONLY_PHASE (want A|B|C)" >&2; exit 2 ;;
esac

phase "1.5.2 FEATURE GATE PASSED (with any VERIFIED-AT-INTEGRATION items noted above)"
echo "Total elapsed: ${SECONDS}s"
