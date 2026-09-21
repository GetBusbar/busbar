#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# WebSocket conformance harness driver: Autobahn|Testsuite against a real busbar ws-over-tcp
# subject, following the same control-always + subject-armed-or-red shape as
# `scripts/mcp-conformance.sh`.
#
# DOCKER-LIVE IS CI-ONLY. This script's `--selftest` mode never touches Docker: it proves the
# parser (`bin/parse-autobahn-report.mjs`) bites on captured fixture reports and that the
# arm-state transition (`armed=false` -> never "pass") holds, which is what a local dev box
# without Docker can prove. `--control` / `--negative-control` / `--subject` run the real
# `crossbario/autobahn-testsuite` `fuzzingclient` image and require Docker; they are what CI runs.
#
# MODES
#   --selftest            prove the parser + arm-state logic bite (no Docker, runs anywhere)
#   --subject-arm          build the ws-conformance-subject bin and report whether it is ARMED
#   --control               run Autobahn against the pinned reference echo server (Docker)
#   --negative-control      run Autobahn against the deliberately broken echo server (Docker); MUST be RED
#   --subject                run Autobahn against the busbar ws-conformance-subject (Docker); ARMED OR RED
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/../.." && pwd)"
PARSER="$ROOT/bin/parse-autobahn-report.mjs"
FIXTURES="$ROOT/fixtures"
REPORTS_DIR="$ROOT/reports"

mode="${1:---selftest}"

selftest() {
  echo "== parser selftest =="
  node "$PARSER" --selftest

  echo "== parser against captured fixture reports =="
  local tmp
  tmp="$(mktemp -d)"

  # A GOOD report, armed, must render pass.
  if ! node "$PARSER" --report "$FIXTURES/autobahn-report-good.json" --armed true --out "$tmp/good.json"; then
    echo "FAIL: the good fixture report was refused" >&2
    return 1
  fi
  local good_status
  good_status="$(node -e "console.log(JSON.parse(require('fs').readFileSync('$tmp/good.json','utf8')).status)")"
  [ "$good_status" = "pass" ] || { echo "FAIL: good fixture rendered status=$good_status, want pass" >&2; return 1; }
  echo "  ok: good fixture -> status=pass"

  # A BAD report, armed, must render fail -- and the script must exit non-zero.
  if node "$PARSER" --report "$FIXTURES/autobahn-report-bad.json" --armed true --out "$tmp/bad.json"; then
    echo "FAIL: the bad fixture report was accepted (exit 0)" >&2
    return 1
  fi
  local bad_status
  bad_status="$(node -e "console.log(JSON.parse(require('fs').readFileSync('$tmp/bad.json','utf8')).status)")"
  [ "$bad_status" = "fail" ] || { echo "FAIL: bad fixture rendered status=$bad_status, want fail" >&2; return 1; }
  echo "  ok: bad fixture -> status=fail"

  # UNARMED must never render pass, even over the good report -- the arm-state transition.
  node "$PARSER" --report "$FIXTURES/autobahn-report-good.json" --armed false --out "$tmp/unarmed.json" || true
  local unarmed_status
  unarmed_status="$(node -e "console.log(JSON.parse(require('fs').readFileSync('$tmp/unarmed.json','utf8')).status)")"
  [ "$unarmed_status" = "not-run" ] || { echo "FAIL: unarmed run over a good report rendered status=$unarmed_status, want not-run" >&2; return 1; }
  echo "  ok: unarmed + good report -> status=not-run (NOT pass)"

  echo "== subject binary builds and reports ARMED =="
  local subject_rc=0
  subject_arm || subject_rc=$?
  rm -rf "$tmp"
  [ "$subject_rc" -eq 0 ] || return "$subject_rc"

  echo
  echo "ws-conformance selftest: all fixture and arm-state checks passed"
}

subject_arm() {
  if cargo build --manifest-path "$REPO_ROOT/Cargo.toml" -p ws-conformance-subject; then
    if [ -x "$REPO_ROOT/target/debug/ws-conformance-subject" ]; then
      echo "  ok: ws-conformance-subject built (ARMED)"
      return 0
    fi
  fi
  echo "  RED: ws-conformance-subject did not build (NOT ARMED)" >&2
  return 1
}

run_autobahn() {
  # $1: agent name; $2: the port the server-under-test listens on; $3: output tag
  local agent="$1" port="$2" tag="$3"
  local outdir="$REPORTS_DIR/$tag"
  mkdir -p "$outdir"
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is unavailable in this environment. Docker-live Autobahn runs are CI-only;" >&2
    echo "this local environment can only prove the parser and the subject's arm state (see --selftest)." >&2
    return 3
  fi
  local cfg
  cfg="$(mktemp)"
  sed -e "s/__TAG__/$tag/" -e "s/__AGENT__/$agent/" -e "s/__PORT__/$port/" \
    "$ROOT/config/fuzzingclient.json.tmpl" > "$cfg"
  docker run --rm --network host \
    -v "$cfg:/config/fuzzingclient.json:ro" \
    -v "$outdir:/reports" \
    crossbario/autobahn-testsuite \
    wstest -m fuzzingclient -s /config/fuzzingclient.json
  rm -f "$cfg"
}

case "$mode" in
  --selftest) selftest ;;
  --subject-arm) subject_arm ;;
  --control)
    echo "$mode: Docker-live mode; runs in CI (crossbario/autobahn-testsuite vs the reference echo peer)." >&2
    log="$(mktemp)"; node "$ROOT/reference/echo-server.mjs" >"$log" 2>&1 & pid=$!
    port=""
    for _ in $(seq 1 50); do port="$(sed -n 's/^REFERENCE_PORT=//p' "$log")"; [ -n "$port" ] && break; sleep 0.1; done
    [ -n "$port" ] || { echo "reference echo server never printed REFERENCE_PORT" >&2; kill "$pid" 2>/dev/null; exit 1; }
    rc=0; run_autobahn reference "$port" control || rc=$?
    kill "$pid" 2>/dev/null || true
    [ "$rc" -eq 3 ] && exit 3
    [ "$rc" -eq 0 ] || exit "$rc"
    node "$PARSER" --report "$REPORTS_DIR/control/index.json" --armed true --commit "${GITHUB_SHA:-local}" --out "$REPORTS_DIR/control/verdict.json"
    ;;
  --negative-control)
    echo "$mode: Docker-live mode; runs in CI (crossbario/autobahn-testsuite vs the deliberately broken peer)." >&2
    log="$(mktemp)"; node "$ROOT/broken/broken-echo-server.mjs" >"$log" 2>&1 & pid=$!
    port=""
    for _ in $(seq 1 50); do port="$(sed -n 's/^BROKEN_PORT=//p' "$log")"; [ -n "$port" ] && break; sleep 0.1; done
    [ -n "$port" ] || { echo "broken echo server never printed BROKEN_PORT" >&2; kill "$pid" 2>/dev/null; exit 1; }
    rc=0; run_autobahn broken "$port" negative-control || rc=$?
    kill "$pid" 2>/dev/null || true
    [ "$rc" -eq 3 ] && exit 3
    # This leg is proven correct when the SUITE catches the defect -- i.e. the parser must find
    # it RED. The docker run itself exiting non-zero is not required (Autobahn exits 0 having
    # produced a report; the defect shows up IN the report).
    if node "$PARSER" --report "$REPORTS_DIR/negative-control/index.json" --armed true --out "$REPORTS_DIR/negative-control/verdict.json"; then
      echo "RED: the negative control was graded green -- the suite failed to catch a deliberately broken peer" >&2
      exit 1
    fi
    echo "ok: the negative control was correctly graded red"
    ;;
  --subject)
    echo "$mode: Docker-live mode; runs in CI (crossbario/autobahn-testsuite vs busbar's ws-conformance-subject)." >&2
    cargo build --manifest-path "$REPO_ROOT/Cargo.toml" -p ws-conformance-subject
    bin="$REPO_ROOT/target/debug/ws-conformance-subject"
    armed=false
    port=""
    if [ -x "$bin" ]; then
      log="$(mktemp)"; "$bin" >"$log" 2>&1 & pid=$!
      for _ in $(seq 1 50); do port="$(sed -n 's/^WS_SUBJECT_PORT=//p' "$log")"; [ -n "$port" ] && break; sleep 0.1; done
      [ -n "$port" ] && armed=true
    fi
    rc=0
    if [ "$armed" = "true" ]; then
      run_autobahn busbar "$port" subject || rc=$?
      kill "$pid" 2>/dev/null || true
      [ "$rc" -eq 3 ] && exit 3
    fi
    mkdir -p "$REPORTS_DIR/subject"
    node "$PARSER" --report "$REPORTS_DIR/subject/index.json" --armed "$armed" --commit "${GITHUB_SHA:-local}" --out "$REPORTS_DIR/subject/verdict.json"
    exit $?
    ;;
  *)
    echo "usage: run.sh [--selftest|--subject-arm|--control|--negative-control|--subject]" >&2
    exit 2
    ;;
esac
