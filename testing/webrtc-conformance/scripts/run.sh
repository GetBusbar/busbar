#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# THE BROWSER CELL: headless Chromium and Firefox drive a real offer/answer, data-channel echo and
# media round trip against busbar's terminating datagram path (the webrtc-conformance-subject),
# in the same control-always + subject-armed-or-red shape as testing/ws-conformance/scripts/run.sh.
#
# MODES
#   --selftest           the judgement bites on captured fixtures and the subject builds (no browser)
#   --subject-arm        build the webrtc-conformance-subject and report whether it is ARMED
#   --install            fetch the pinned browsers (npx playwright install chromium firefox)
#   --control            the page's own control (the browser against itself) must PASS
#   --negative-control   the subject with its line echo broken MUST grade red on media alone
#   --subject            the cell against the subject; ARMED OR RED
#
# Browsers are the instrument: a browser that does not launch makes a leg exit 3 (not-run), never
# a pass. The subject binds the host's first non-loopback IPv4 address (WEBRTC_SUBJECT_HOST
# overrides it), the one candidate its answer advertises.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/../.." && pwd)"
DRIVE="$ROOT/bin/drive.mjs"
FIXTURES="$ROOT/fixtures"
REPORTS_DIR="$ROOT/reports"
SUBJECT_BIN="$REPO_ROOT/target/debug/webrtc-conformance-subject"

mode="${1:---selftest}"

subject_arm() {
  if cargo build --manifest-path "$REPO_ROOT/Cargo.toml" -p webrtc-conformance-subject; then
    if [ -x "$SUBJECT_BIN" ]; then
      echo "  ok: webrtc-conformance-subject built (ARMED)"
      return 0
    fi
  fi
  echo "  RED: webrtc-conformance-subject did not build (NOT ARMED)" >&2
  return 1
}

status_of() {
  node -e "console.log(JSON.parse(require('fs').readFileSync('$1','utf8')).status)"
}

selftest() {
  echo "== judgement selftest =="
  node "$DRIVE" --selftest
  local tmp
  tmp="$(mktemp -d)"
  node "$DRIVE" --judge "$FIXTURES/good.txt" --armed true --out "$tmp/good.json"
  [ "$(status_of "$tmp/good.json")" = "pass" ] || { echo "FAIL: good fixture is not pass" >&2; return 1; }
  echo "  ok: good fixture -> pass"
  if node "$DRIVE" --judge "$FIXTURES/bad.txt" --armed true --out "$tmp/bad.json"; then
    echo "FAIL: the bad fixture was accepted (exit 0)" >&2
    return 1
  fi
  [ "$(status_of "$tmp/bad.json")" = "fail" ] || { echo "FAIL: bad fixture is not fail" >&2; return 1; }
  echo "  ok: bad fixture -> fail"
  node "$DRIVE" --judge "$FIXTURES/good.txt" --armed false --out "$tmp/unarmed.json" || true
  [ "$(status_of "$tmp/unarmed.json")" = "not-run" ] || { echo "FAIL: unarmed + good is not not-run" >&2; return 1; }
  echo "  ok: unarmed + good fixture -> not-run (NOT pass)"
  echo "== subject binary builds and reports ARMED =="
  local rc=0
  subject_arm || rc=$?
  rm -rf "$tmp"
  [ "$rc" -eq 0 ] || return "$rc"
  echo
  echo "webrtc-conformance selftest: all judgement and arm-state checks passed"
}

host() {
  if [ -n "${WEBRTC_SUBJECT_HOST:-}" ]; then
    echo "$WEBRTC_SUBJECT_HOST"
    return
  fi
  local ip=""
  if command -v hostname >/dev/null 2>&1; then
    ip="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v '^127\.' | head -n1 || true)"
  fi
  echo "${ip:-127.0.0.1}"
}

# Start the subject with "$@"; sets SUBJECT_PID and SUBJECT_URL.
start_subject() {
  [ -x "$SUBJECT_BIN" ] || subject_arm
  local out
  out="$(mktemp)"
  WEBRTC_SUBJECT_HOST="$(host)" "$SUBJECT_BIN" "$@" >"$out" 2>"$out.err" &
  SUBJECT_PID=$!
  SUBJECT_URL=""
  for _ in $(seq 1 300); do
    SUBJECT_URL="$(sed -n 's/^WEBRTC_SUBJECT_URL=//p' "$out" | head -n1)"
    [ -n "$SUBJECT_URL" ] && break
    kill -0 "$SUBJECT_PID" 2>/dev/null || break
    sleep 0.1
  done
  if [ -z "$SUBJECT_URL" ]; then
    echo "  RED: the subject did not come up" >&2
    cat "$out.err" >&2 || true
    return 1
  fi
  echo "  subject at $SUBJECT_URL"
}

stop_subject() {
  [ -n "${SUBJECT_PID:-}" ] && kill "$SUBJECT_PID" 2>/dev/null || true
  wait "${SUBJECT_PID:-}" 2>/dev/null || true
}
trap stop_subject EXIT

drive() {
  # $1: page mode (cell|control); $2: report tag
  mkdir -p "$REPORTS_DIR/$2"
  node "$DRIVE" --url "$SUBJECT_URL" --mode "$1" --out "$REPORTS_DIR/$2"
}

case "$mode" in
  --selftest) selftest ;;
  --subject-arm) subject_arm ;;
  --install)
    (cd "$ROOT" && npx --no-install playwright install chromium firefox)
    ;;
  --control)
    start_subject
    drive control control
    ;;
  --negative-control)
    start_subject --break media
    rc=0
    drive cell negative-control || rc=$?
    [ "$rc" -eq 3 ] && exit 3
    # It must be red, and red on the media cells alone: the channel cells passing shows the
    # instrument reached the subject, the media cells failing shows it catches a broken line.
    node -e '
      const v = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
      const red = (b, c) => !(v.browsers[b] && v.browsers[b][c] && v.browsers[b][c].pass);
      const ok = v.status === "fail" &&
        ["chromium", "firefox"].every((b) => red(b, "media-round-trip") && !red(b, "channel-text"));
      console.log("webrtc-conformance: negative-control " + (ok ? "bites" : "DOES NOT BITE") + ": " + v.reason);
      process.exit(ok ? 0 : 1);
    ' "$REPORTS_DIR/negative-control/verdict.json"
    ;;
  --subject)
    if ! start_subject; then
      mkdir -p "$REPORTS_DIR/subject"
      echo '{"armed":false,"status":"not-run","reason":"the subject did not build or boot","browsers":{}}' \
        >"$REPORTS_DIR/subject/verdict.json"
      exit 1
    fi
    drive cell subject
    ;;
  *)
    echo "usage: $0 --selftest|--subject-arm|--install|--control|--negative-control|--subject" >&2
    exit 2
    ;;
esac
