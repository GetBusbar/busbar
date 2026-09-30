#!/usr/bin/env bash
# THE SESSION-REVISION INTEROP MATRIX against REAL, PINNED MCP SDK peers.
#
# OWNER 2026-09-29 compat scope: busbar interoperates with MCP session Streamable HTTP
# (2025-06-18, 2025-11-25) and the HTTP+SSE transport (2024-11-05), in both directions, beside the
# stateless 2026-07-28 revision it already speaks. This script is the proof against third-party
# implementations rather than busbar's own reading of the spec. It is kept out of `cargo test`
# (ARCHITECT approval 2026-09-29, condition 7): it needs node, python and the network for the
# pinned installs.
#
# USAGE
#   MCP_SUBJECT_BUSBAR_BIN=<busbar binary built from this commit> \
#     testing/mcp-conformance/compat/run-compat.sh [--serve | --client | --all]
#
#   --serve   SDK CLIENTS -> busbar. busbar is booted exactly as the conformance subject leg boots
#             it (scripts/mcp-subject/boot.sh: loopback, a real audience-bound credential, the
#             boundary proven intact first), and each pinned client drives it:
#               TS SDK 1.0.4  (2024-11-05, HTTP+SSE)
#               TS SDK 1.17.5 (2025-06-18, Streamable HTTP)
#               TS SDK 1.24.3 (2025-11-25, Streamable HTTP)
#               python mcp 1.23.3 (2025-11-25, Streamable HTTP)
#   --client  busbar -> SDK SERVERS (TS 1.0.4 / 1.17.5 / 1.24.3, python mcp 1.12.4). ARMED OR RED:
#             busbar's client leg for the session revisions reads the upstream's Mcp-Session-Id
#             off the egress response head, which the egress seam carries only once the
#             keep_response_headers declaration lands (ARCHITECT ruling 2026-09-29). Until then
#             this leg says NOT ARMED and exits 1, rather than reporting a pass it never measured.
#   --all     both (the default).
#
# PINS: package.json + package-lock.json (installed with `npm ci`, never a floating range) and
# py/requirements-{client,server}.txt (the whole closure, installed with --no-deps).
#
# EXIT: 0 only when every armed leg ran every peer and every check passed.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"
COMPAT=testing/mcp-conformance/compat
MODE="${1:---all}"

say() { printf '%s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

SUBJECT_PIDS=""
REAP_PIDS=""
reap() { for p in $REAP_PIDS ${SUBJECT_PIDS:-}; do kill "$p" 2>/dev/null || true; done; }
trap reap EXIT INT TERM

setup_peers() {
  command -v node >/dev/null || die "node is required (>= 20)."
  command -v python3 >/dev/null || die "python3 is required."
  (cd "$COMPAT" && npm ci --ignore-scripts --no-audit --no-fund >/dev/null) \
    || die "npm ci of the pinned SDK peers failed."
  local which
  for which in client server; do
    local venv="$COMPAT/.venv-$which"
    [ -d "$venv" ] || python3 -m venv "$venv"
    "$venv/bin/pip" install --quiet --no-deps -r "$COMPAT/py/requirements-$which.txt" \
      || die "pip install of py/requirements-$which.txt failed."
  done
}

RESULTS=()
run_peer() {
  # run_peer <label> <command...>: one JSON line out; the exit status is the verdict.
  local label="$1"; shift
  local out
  if out="$("$@" 2>"$WORK/$label.err")"; then
    say "   PASS $label"
  else
    say "   FAIL $label"
    FAILED=$((FAILED + 1))
  fi
  RESULTS+=("$out")
  printf '%s\n' "$out" >>"$WORK/results.jsonl"
}

serve_leg() {
  say "== --serve: pinned SDK clients -> busbar"
  # shellcheck source=scripts/mcp-subject/boot.sh
  . scripts/mcp-subject/boot.sh
  MCP_SUBJECT_WORKDIR="$WORK/subject" boot_busbar_subject
  local url="$SUBJECT_URL"
  local rev
  for rev in 2024-11-05 2025-06-18 2025-11-25; do
    run_peer "ts-sdk-$rev" node "$COMPAT/clients/sdk-client.mjs" "$rev" "$url"
  done
  run_peer "python-sdk-client" "$COMPAT/.venv-client/bin/python" "$COMPAT/clients/py_client.py" "$url"
  reap
  SUBJECT_PIDS=""
}

client_leg() {
  say "== --client: busbar -> pinned SDK servers"
  say "   NOT ARMED: busbar's client leg for the session revisions waits on the egress response"
  say "   head (keep_response_headers: mcp-session-id). Nothing was measured, so this leg is RED."
  FAILED=$((FAILED + 1))
}

WORK="$(mktemp -d "${TMPDIR:-/tmp}/mcp-compat.XXXXXX")"
: >"$WORK/results.jsonl"
FAILED=0
setup_peers
case "$MODE" in
  --serve) serve_leg ;;
  --client) client_leg ;;
  --all) serve_leg; client_leg ;;
  --help|-h) sed -n '2,33p' "$0"; exit 0 ;;
  *) die "unknown mode $MODE (use --serve, --client or --all)" ;;
esac

say "== results: $WORK/results.jsonl"
cat "$WORK/results.jsonl"
[ "$FAILED" -eq 0 ] || die "$FAILED leg(s) or peer(s) failed."
say "== every armed leg passed"
