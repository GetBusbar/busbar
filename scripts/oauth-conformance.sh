#!/usr/bin/env bash
# oauth-conformance.sh - runs the INDEPENDENT OAuth 2.1 conformance harness
# (crates/oauth-as-conformance) against the live AS (crates/oauth-as) as a black box.
#
# Modes:
#   --selftest   Prove the gate can go RED before anyone trusts a green (house discipline:
#                a check is not trusted until it has been shown red first):
#                  RED-A   the hermetic RFC-vector suite MUST FAIL when the expected PKCE
#                          challenge is deliberately corrupted via
#                          OAUTH_CONFORMANCE_SELFTEST_BREAK=pkce;
#                  GREEN-A the same suite MUST PASS clean;
#                  RED-B   the black-box suite MUST FAIL against a deliberately
#                          nonconformant stub AS (a python http server whose RFC 8414
#                          metadata document is an empty JSON object).
#   --check      Run the real thing: start crates/oauth-as, wait for its RFC 8414 metadata,
#                run the black-box + third-party-client suites against it. FAILS LOUDLY
#                (exit 1 with a clear message) when crates/oauth-as does not exist; this
#                gate must never pass vacuously.
#
# AS launch contract (assumptions are documented in crates/oauth-as-conformance/src/lib.rs):
#   * `cargo run --locked -p oauth-as` starts the HTTP server;
#   * OAUTH_AS_ADDR gives the bind address (we use 127.0.0.1:8914);
#   * OAUTH_AS_CONFORMANCE_SEED=1 seeds the deterministic conformance clients and
#     auto-approval behavior.
#   If the AS crate prefers a different launch, it may provide an executable
#   crates/oauth-as/conformance-serve.sh which this script will use instead; that script
#   must serve on OAUTH_AS_ADDR and block until killed.
#
# Backgrounded servers ALWAYS get their stdout/stderr redirected to a log file, never
# captured via command substitution (see scripts/release-script-lint.sh for the 1.5.2
# lesson this encodes).

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ADDR="127.0.0.1:8914"
BASE_URL="http://${ADDR}"
TMPDIR_CONF="$(mktemp -d "${TMPDIR:-/tmp}/oauth-conf.XXXXXX")"
AS_PID=""
STUB_PID=""

cleanup() {
  [ -n "$AS_PID" ] && kill "$AS_PID" 2>/dev/null
  [ -n "$STUB_PID" ] && kill "$STUB_PID" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$TMPDIR_CONF"
}
trap cleanup EXIT INT TERM

fail() { echo "oauth-conformance: FAIL: $*" >&2; exit 1; }
note() { echo "oauth-conformance: $*"; }

wait_for_metadata() {
  # $1 = base url, $2 = timeout seconds
  local url="$1/.well-known/oauth-authorization-server" deadline=$(( $(date +%s) + $2 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -sf -o /dev/null --max-time 2 "$url"; then return 0; fi
    sleep 1
  done
  return 1
}

run_vectors() {
  ( cd "$ROOT" && cargo test --locked -p oauth-as-conformance --test rfc_vectors )
}

run_blackbox() {
  # Single-threaded: the flows share seeded state and interleaving would blur failures.
  ( cd "$ROOT" && OAUTH_AS_BASE_URL="$BASE_URL" \
      cargo test --locked -p oauth-as-conformance --test blackbox_http --test client_drive \
      -- --ignored --test-threads=1 )
}

start_stub_as() {
  # A deliberately NONCONFORMANT AS: answers every path with an empty JSON object, so the
  # RFC 8414 metadata validation must reject it. Used only by --selftest RED-B.
  python3 - "$ADDR" >"$TMPDIR_CONF/stub.log" 2>&1 <<'PYEOF' &
import http.server, sys
host, port = sys.argv[1].rsplit(":", 1)
class H(http.server.BaseHTTPRequestHandler):
    def _serve(self):
        body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_GET = _serve
    do_POST = _serve
    def log_message(self, *a):  # quiet
        pass
http.server.HTTPServer((host, int(port)), H).serve_forever()
PYEOF
  STUB_PID=$!
}

run_selftest() {
  local rc

  note "SELFTEST RED-A: corrupting the expected RFC 7636 App B challenge; vector suite must FAIL"
  ( cd "$ROOT" && OAUTH_CONFORMANCE_SELFTEST_BREAK=pkce \
      cargo test --locked -p oauth-as-conformance --test rfc_vectors ) \
      >"$TMPDIR_CONF/red-a.log" 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then
    cat "$TMPDIR_CONF/red-a.log"
    fail "RED-A: vector suite PASSED with a corrupted expectation; the gate cannot go red"
  fi
  note "SELFTEST RED-A: failed as required (exit $rc)"

  note "SELFTEST GREEN-A: clean vector suite must PASS"
  run_vectors >"$TMPDIR_CONF/green-a.log" 2>&1 || {
    cat "$TMPDIR_CONF/green-a.log"
    fail "GREEN-A: clean vector suite failed"
  }
  note "SELFTEST GREEN-A: passed"

  note "SELFTEST RED-B: black-box suite must FAIL against a nonconformant stub AS"
  command -v python3 >/dev/null 2>&1 || fail "RED-B needs python3 for the stub AS"
  start_stub_as
  wait_for_metadata "$BASE_URL" 15 || fail "RED-B: stub AS did not come up on $ADDR"
  run_blackbox >"$TMPDIR_CONF/red-b.log" 2>&1
  rc=$?
  kill "$STUB_PID" 2>/dev/null; wait "$STUB_PID" 2>/dev/null; STUB_PID=""
  if [ "$rc" -eq 0 ]; then
    cat "$TMPDIR_CONF/red-b.log"
    fail "RED-B: black-box suite PASSED against a nonconformant AS; the gate is worthless"
  fi
  if ! grep -q "RFC 8414 metadata violations" "$TMPDIR_CONF/red-b.log"; then
    cat "$TMPDIR_CONF/red-b.log"
    fail "RED-B: suite failed, but not for the planted metadata violations; investigate"
  fi
  note "SELFTEST RED-B: failed as required (exit $rc), naming the planted RFC 8414 violations"
  note "selftest OK: the gate has been shown red on both the vector and black-box axes"
}

run_check() {
  if [ ! -d "$ROOT/crates/oauth-as" ]; then
    fail "crates/oauth-as does not exist in this tree. The OAuth 2.1 AS is NOT present, so \
independent conformance CANNOT run and this gate refuses to pass vacuously. Land the AS crate \
(branch feat/oauth-as) or merge it into this branch, then re-run."
  fi

  note "vector suite (hermetic RFC vectors)"
  run_vectors || fail "RFC vector suite failed"

  note "starting crates/oauth-as on $ADDR"
  if [ -x "$ROOT/crates/oauth-as/conformance-serve.sh" ]; then
    OAUTH_AS_ADDR="$ADDR" OAUTH_AS_CONFORMANCE_SEED=1 \
      "$ROOT/crates/oauth-as/conformance-serve.sh" >"$TMPDIR_CONF/as.log" 2>&1 &
    AS_PID=$!
  else
    ( cd "$ROOT" && OAUTH_AS_ADDR="$ADDR" OAUTH_AS_CONFORMANCE_SEED=1 \
        cargo run --locked -p oauth-as ) >"$TMPDIR_CONF/as.log" 2>&1 &
    AS_PID=$!
  fi
  if ! wait_for_metadata "$BASE_URL" 120; then
    echo "---- AS log ----"; cat "$TMPDIR_CONF/as.log"; echo "----------------"
    fail "AS never served RFC 8414 metadata at $BASE_URL/.well-known/oauth-authorization-server \
within 120s. The launch contract is documented in crates/oauth-as-conformance/src/lib.rs."
  fi

  note "black-box + third-party client drive against $BASE_URL"
  if ! run_blackbox; then
    echo "---- AS log ----"; cat "$TMPDIR_CONF/as.log"; echo "----------------"
    fail "black-box conformance failed against the live AS"
  fi
  note "conformance PASS"
}

case "${1:-}" in
  --selftest) run_selftest ;;
  --check)    run_check ;;
  --help|-h)  sed -n '2,30p' "$0"; exit 0 ;;
  *) echo "usage: scripts/oauth-conformance.sh --selftest | --check" >&2; exit 2 ;;
esac
