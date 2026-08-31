#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# RUN THE SUPPLEMENTARY SUITE AGAINST A THIRD-PARTY CONTROL.
#
# WHY THIS FILE IS THE MOST IMPORTANT ONE IN THE DIRECTORY.
#
# A test that busbar wrote, run against busbar, that passes, is worth almost nothing. It is
# consistent with the test being correct AND with the test asserting whatever busbar happens to do.
# The only way to tell those apart is to run the same test against an implementation NOBODY here
# wrote and see whether it says something.
#
# So every check in this suite is run against the same pinned third-party peers the official TCK
# legs judge -- `a2a-go` v2.4.0 on two bindings, and the A2A project's own Python SDK by way of the
# TCK scenario agent -- and the result is published NEXT TO the busbar result, per requirement.
# A check that passes both may be real or may be vacuous. A check that DISCRIMINATES -- passes one
# and fails the other, for a reason it states -- has proven it is measuring something.
#
# The control legs here are REPORTED, not gated. Unlike `testing/a2a-tck/run-tck.sh`, they are not
# baseline-compared, because the purpose is not to detect a change in the control; it is to
# establish that these checks have a failure mode at all.
#
# USAGE
#   run-supplement.sh control-jsonrpc     a2a-go v2.4.0, JSON-RPC binding
#   run-supplement.sh control-http-json   a2a-go v2.4.0, HTTP+JSON binding
#   run-supplement.sh control-scenario    the TCK scenario agent (a2a-python), direct
#   run-supplement.sh target <card-url>   any endpoint, with whatever credentials you pass after it
#
# The BUSBAR leg does NOT live here. It needs a booted subject, two minted principals and an
# out-of-band issuer key, so it lives with the rest of the subject rig:
#   scripts/a2a-subject/boot.sh --supplement
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CONTROL_GO_VERSION="v2.4.0"     # must match testing/a2a-tck/run-tck.sh and a2a-harness
WORK="${A2A_TCK_WORK:-${TMPDIR:-/tmp}/a2a-tck-work}"
BIN_DIR="${A2AHT_CONTROL_BIN:-$WORK/bin}"
OUT="${A2ASUP_OUT:-$WORK/supplement}"
mkdir -p "$OUT" "$BIN_DIR"

say () { printf '\n=== %s ===\n' "$*"; }

# The pinned TCK's checkout and virtualenv, borrowed rather than duplicated. See the note in
# `scripts/a2a-subject/boot.sh::leg_supplement`: the gRPC binding is driven through the
# specification's OWN generated stubs, and there must be exactly one place the pin is verified.
prepare () {
  local line
  line="$("$ROOT/testing/a2a-tck/run-tck.sh" prepare)"
  TCK_DIR="$(printf '%s\n' "$line" | sed -n 's/^A2A_TCK_DIR=//p')"
  TCK_PY="$(printf '%s\n' "$line" | sed -n 's/^A2A_TCK_PYTHON=//p')"
  [ -x "$TCK_PY" ] || { echo "the pinned TCK interpreter is missing at $TCK_PY" >&2; exit 2; }
}

install_control () {
  if [ ! -x "$BIN_DIR/a2a" ]; then
    say "installing control a2a-go ${CONTROL_GO_VERSION}"
    GOBIN="$BIN_DIR" go install "github.com/a2aproject/a2a-go/v2/cmd/a2a@${CONTROL_GO_VERSION}"
  fi
  "$BIN_DIR/a2a" --help >/dev/null
}

serve_control () {           # serve_control <port> <transport>
  "$BIN_DIR/a2a" serve --echo --port "$1" --quiet --transport "$2" \
    > "$OUT/control-$2.log" 2>&1 &
  CONTROL_PID=$!
  for _ in $(seq 1 50); do
    curl -fsS -m 2 -o /dev/null "http://127.0.0.1:$1/.well-known/agent-card.json" && return 0
    sleep 0.2
  done
  echo "control did not come up on port $1" >&2; cat "$OUT/control-$2.log" >&2
  kill "$CONTROL_PID" 2>/dev/null || true; exit 2
}

stop_control () { [ -n "${CONTROL_PID:-}" ] && kill "$CONTROL_PID" 2>/dev/null || true; }

run_against () {             # run_against <label> <card-url> [extra args...]
  local label="$1" card="$2"; shift 2
  # NOTE THE EXIT CODE IS SWALLOWED. A control leg's job is to REPORT what the checks say about a
  # peer nobody here wrote; a non-zero from it is the expected and useful outcome, not a gate.
  ( cd "$HERE" && PYTHONPATH="$TCK_DIR:${PYTHONPATH:-}" "$TCK_PY" -m a2asup \
      --label "$label" --card-url "$card" \
      --json "$OUT/$label.json" "$@" ) || true
}

case "${1:-}" in
  control-jsonrpc)
    prepare; install_control
    say "control: a2a-go ${CONTROL_GO_VERSION} / jsonrpc"
    serve_control 9711 jsonrpc; trap stop_control EXIT
    run_against control-a2a-go-jsonrpc "http://127.0.0.1:9711/.well-known/agent-card.json"
    stop_control; trap - EXIT ;;

  control-http-json)
    prepare; install_control
    say "control: a2a-go ${CONTROL_GO_VERSION} / http_json"
    serve_control 9712 http_json; trap stop_control EXIT
    run_against control-a2a-go-http-json "http://127.0.0.1:9712/.well-known/agent-card.json"
    stop_control; trap - EXIT ;;

  control-scenario)
    prepare
    say "control: TCK scenario agent (a2a-python), direct"
    "$ROOT/testing/a2a-tck/scenario-agent/serve.sh" 9713 > "$OUT/control-scenario.log" 2>&1 &
    CONTROL_PID=$!; trap stop_control EXIT
    for _ in $(seq 1 300); do
      curl -fsS -m 2 -o /dev/null "http://127.0.0.1:9713/.well-known/agent-card.json" && break
      sleep 0.5
    done
    run_against control-scenario-agent "http://127.0.0.1:9713/.well-known/agent-card.json"
    stop_control; trap - EXIT ;;

  target)
    prepare
    card="${2:?run-supplement.sh target needs a card URL}"; shift 2
    run_against "target" "$card" "$@" ;;

  *) sed -n '/^# USAGE/,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
