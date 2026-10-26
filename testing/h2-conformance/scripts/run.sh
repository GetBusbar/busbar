#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# HTTP/2 CONFORMANCE (registry id `h2`): h2spec (RFC 9113 / RFC 7541) over TLS, ALPN h2, against the
# `tls:` listener of a busbar built from this checkout. The listener is the root's hyper server over
# the connector's rustls, so what h2spec grades is core's, not a plugin's. Three legs, as in every
# conformance suite (busbar-release template/conformance/run.sh):
#
#   CONTROL           a known-good third-party h2 server (nghttpd, a digest-pinned docker image). It is
#                     held to its committed per-case baseline (baselines/nghttpd-control.json): this
#                     proves the harness, the cert and h2spec itself work.
#   NEGATIVE CONTROL  broken/broken-h2-server.py, which acknowledges nothing and validates nothing. It
#                     MUST grade red; if it grades green the grader is blind.
#   SUBJECT           the busbar binary, booted with `tls:` on a run-time self-signed cert. Armed or
#                     red: one that will not build or boot is `fail`, never a skip. It passes only when
#                     EVERY h2spec case passed (bin/parse-h2spec-junit.py).
#
#   bash testing/h2-conformance/scripts/run.sh [all]    all three legs, writes $CONFORMANCE_OUT/verdict.json
#   bash testing/h2-conformance/scripts/run.sh --selftest   the judge bites on planted reports (no docker, no build)
#
# Env (set by testing/conformance/run.sh): CONFORMANCE_OUT, BUSBAR_CHECKOUT (default: this repo),
# CARGO_TARGET_DIR. Needs docker, curl, openssl and python3 on PATH.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
PARSER="$HERE/bin/parse-h2spec-junit.py"
OUT="${CONFORMANCE_OUT:-$REPO_ROOT/target/h2-conformance}"
CHECKOUT="${BUSBAR_CHECKOUT:-$REPO_ROOT}"
TARGET="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
SUITE="${CONFORMANCE_SUITE:-h2}"

# THE INSTRUMENTS, PINNED. ModernCI compute is aarch64 and h2spec publishes amd64 release binaries
# only, so h2spec v2.6.0 is built from its tagged commit (the commit sha is checked, its Go
# dependencies are pinned by its own go.sum) inside a golang image pinned by digest. The control is
# nghttpd from a Debian image pinned by digest.
H2SPEC_VERSION=2.6.0
H2SPEC_COMMIT=70ac2294010887f48b18e2d64f5cccd48421fad1
GO_IMAGE='golang@sha256:3b4a11519ad929d1e1d261a12cff056f0c85b735253d7d861346b9c6f8b36437'
CONTROL_IMAGE='debian@sha256:a717a33469731894e77e912ea7d714e27c2dc38ee6554fd1a3102e92999cfc66'
# A response larger than the initial flow-control window: h2spec's http2/6.9.2 case skips itself
# against a smaller one, and a skipped case is not a pass.
BIG_PATH=/big
BIG_BYTES=300000
PER_CASE_TIMEOUT=5

mkdir -p "$OUT"
say() { printf 'h2: %s\n' "$*" >&2; }
PIDS=()
CONTAINER=""
cleanup() {
  local p
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  [ -n "$CONTAINER" ] && docker rm -f "$CONTAINER" >/dev/null 2>&1
  return 0
}
trap cleanup EXIT

# fetch_h2spec: the pinned h2spec on H2SPEC, or return 1.
fetch_h2spec() {
  local root="${MODERNCI_CACHE_DIR:-$HOME/.cache}/conformance-tools/h2spec-$H2SPEC_VERSION-$H2SPEC_COMMIT-$(uname -m)"
  if [ ! -x "$root/h2spec" ]; then
    mkdir -p "$root" || return 1
    docker run --rm -e CGO_ENABLED=0 -v "$root:/out" "$GO_IMAGE" sh -c "
      set -e
      git clone -q https://github.com/summerwind/h2spec /src && cd /src
      git checkout -q v$H2SPEC_VERSION
      [ \"\$(git rev-parse HEAD)\" = $H2SPEC_COMMIT ] || { echo 'h2spec v$H2SPEC_VERSION is not commit $H2SPEC_COMMIT' >&2; exit 1; }
      go build -trimpath -o /out/h2spec ./cmd/h2spec" >"$OUT/h2spec-build.log" 2>&1 \
      || { tail -20 "$OUT/h2spec-build.log" >&2; say "could not build h2spec v$H2SPEC_VERSION"; return 1; }
  fi
  H2SPEC="$root/h2spec"
}

# make_cert <dir>: a throwaway self-signed EC cert (CN/SAN localhost + 127.0.0.1) and its SEC1 key.
make_cert() {
  openssl ecparam -name prime256v1 -genkey -noout -out "$1/key.pem" 2>/dev/null \
    && openssl req -x509 -new -key "$1/key.pem" -out "$1/cert.pem" -days 1 -subj /CN=localhost \
         -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' 2>/dev/null \
    && chmod a+r "$1/key.pem" "$1/cert.pem"
}

free_port() {
  python3 -I -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'
}

# h2spec_run <port> <path> <report>: the full generic+http2+hpack battery over TLS, JUnit to <report>.
h2spec_run() {
  "$H2SPEC" -t -k -h 127.0.0.1 -p "$1" -P "$2" -o "$PER_CASE_TIMEOUT" -j "$3" >"$3.log" 2>&1
  [ -s "$3" ]
}

wait_listening() { # <port> <pid or empty> [tries, 0.3 s apart]
  local i
  for i in $(seq 1 "${3:-100}"); do
    python3 -I -c "import socket,sys;socket.create_connection(('127.0.0.1',$1),0.5).close()" 2>/dev/null && return 0
    [ -n "${2:-}" ] && ! kill -0 "$2" 2>/dev/null && return 1
    sleep 0.3
  done
  return 1
}

# ── legs: each prints one line and leaves its result in $OUT/<leg>.json ──────────────────────────

leg_control() {
  local d="$OUT/control"; mkdir -p "$d/htdocs"
  make_cert "$d" || { LEG_REASON="could not make a cert (openssl)"; return 1; }
  head -c "$BIG_BYTES" /dev/zero | tr '\0' 'a' >"$d/htdocs/big"; echo ok >"$d/htdocs/index.html"
  chmod -R a+rX "$d"
  docker pull -q "$CONTROL_IMAGE" >/dev/null 2>&1 || { LEG_REASON="could not pull the control image $CONTROL_IMAGE"; return 1; }
  CONTAINER="h2-control-$$"
  docker run -d --name "$CONTAINER" -p 127.0.0.1::8443 -v "$d:/c:ro" "$CONTROL_IMAGE" sh -c \
    'apt-get update -qq && apt-get install -y -qq nghttp2-server >/dev/null && nghttpd --version && exec nghttpd -d /c/htdocs 8443 /c/key.pem /c/cert.pem' >/dev/null \
    || { LEG_REASON="the control container did not start"; return 1; }
  local port=""
  for _ in $(seq 1 30); do port="$(docker port "$CONTAINER" 8443/tcp 2>/dev/null | head -1 | sed 's/.*://')"; [ -n "$port" ] && break; sleep 1; done
  # apt installs the package before nghttpd listens.
  wait_listening "${port:-1}" "" 300 || { LEG_REASON="the control peer (nghttpd) did not listen"; docker logs "$CONTAINER" >&2; return 1; }
  docker logs "$CONTAINER" 2>&1 | grep -m1 '^nghttpd' >&2
  h2spec_run "$port" "$BIG_PATH" "$d/report.xml" || { LEG_REASON="h2spec wrote no report against the control"; return 1; }
  python3 -I "$PARSER" --report "$d/report.xml" --role control --baseline "$HERE/baselines/nghttpd-control.json" --out "$OUT/control.json" >&2
  local rc=$?
  docker rm -f "$CONTAINER" >/dev/null 2>&1; CONTAINER=""
  LEG_REASON="$(python3 -I -c "import json;print(json.load(open('$OUT/control.json'))['reason'])")"
  return $rc
}

leg_negative() {
  local d="$OUT/negative"; mkdir -p "$d"
  make_cert "$d" || { LEG_REASON="could not make a cert (openssl)"; return 1; }
  local port; port="$(free_port)"
  python3 -I "$HERE/broken/broken-h2-server.py" "$port" "$d/cert.pem" "$d/key.pem" >"$d/server.log" 2>&1 &
  local pid=$!; PIDS+=("$pid")
  wait_listening "$port" "$pid" || { LEG_REASON="the broken peer did not listen"; return 1; }
  # A short per-case timeout: the broken peer answers nothing the cases wait for.
  PER_CASE_TIMEOUT=1 h2spec_run "$port" /x "$d/report.xml" || { LEG_REASON="h2spec wrote no report against the broken peer"; return 1; }
  python3 -I "$PARSER" --report "$d/report.xml" --role negative --out "$OUT/negative.json" >&2
  local rc=$?
  kill "$pid" 2>/dev/null
  LEG_REASON="$(python3 -I -c "import json;print(json.load(open('$OUT/negative.json'))['reason'])")"
  return $rc
}

# SUBJECT_ARMED=0/1: whether the subject got as far as being judged.
leg_subject() {
  SUBJECT_ARMED=0
  local d="$OUT/subject"; mkdir -p "$d"
  say "subject: building busbar (release) from $CHECKOUT"
  if ! CARGO_TARGET_DIR="$TARGET" cargo build --locked --release --manifest-path "$CHECKOUT/Cargo.toml" -p busbar --bin busbar >"$d/build.log" 2>&1; then
    tail -30 "$d/build.log" >&2; LEG_REASON="busbar did not build from the checkout (see subject/build.log)"; SUBJECT_ARMED=1; return 1
  fi
  local bin="$TARGET/release/busbar"
  [ -x "$bin" ] || { LEG_REASON="the build left no $bin"; SUBJECT_ARMED=1; return 1; }
  SUBJECT_ARMED=1
  make_cert "$d" || { LEG_REASON="could not make a cert (openssl)"; return 1; }
  ( umask 077; "$bin" --generate-signing-key >"$d/signing.key" 2>"$d/genkey.log" ) || { LEG_REASON="busbar --generate-signing-key failed"; return 1; }
  local port; port="$(free_port)"
  bash "$HERE/scripts/subject-config.sh" "$d" "$port" || { LEG_REASON="could not write the subject config"; return 1; }
  ( exec env BUSBAR_CONFIG="$d/config.yaml" BUSBAR_PROVIDERS="$d/providers.yaml" BUSBAR_ADMIN_TOKEN="h2-conformance-$$" RUST_LOG=warn "$bin" ) \
    >"$d/busbar.log" 2>&1 &
  local pid=$!; PIDS+=("$pid")
  wait_listening "$port" "$pid" || { tail -30 "$d/busbar.log" >&2; LEG_REASON="busbar did not listen on the tls: port (see subject/busbar.log)"; return 1; }
  # Armed means: TLS answers and ALPN lands on h2. A listener that only speaks 1.1 is a finding.
  local ver; ver="$(curl -ksS --http2 -m 10 -o /dev/null -w '%{http_version}' "https://127.0.0.1:$port$SUBJECT_PATH" 2>"$d/curl.log" || true)"
  if [ "$ver" != 2 ]; then LEG_REASON="the tls: listener did not negotiate h2 (curl saw HTTP version '$ver')"; return 1; fi
  h2spec_run "$port" "$SUBJECT_PATH" "$d/report.xml" || { LEG_REASON="h2spec wrote no report against busbar"; return 1; }
  python3 -I "$PARSER" --report "$d/report.xml" --role subject --out "$OUT/subject.json" >&2
  local rc=$?
  kill "$pid" 2>/dev/null
  LEG_REASON="$(python3 -I -c "import json;print(json.load(open('$OUT/subject.json'))['reason'])")"
  return $rc
}

SUBJECT_PATH="${SUBJECT_PATH:-/healthz}"

selftest() {
  say "== judge selftest =="
  python3 -I "$PARSER" --selftest
}

write_verdict() { # <status> <armed true|false> <reason>
  python3 -I - "$OUT/verdict.json" "$SUITE" "$1" "$2" "$3" <<'PY'
import json, sys
out, suite, status, armed, reason = sys.argv[1:6]
json.dump({
    "suite": suite,
    "status": status,
    "armed": armed == "true",
    "standard": "HTTP/2 (RFC 9113)",
    "plan": "h2spec over TLS (ALPN h2) against the tls: listener",
    "spec_version": "h2spec 2.6.0",
    "reason": reason,
}, open(out, "w"), indent=2)
PY
}

main() {
  fetch_h2spec || { write_verdict fail true "h2spec v$H2SPEC_VERSION could not be fetched and verified on this host"; return 1; }
  local c_ok=0 n_ok=0 s_ok=0 c_why n_why s_why
  LEG_REASON=""; leg_control && c_ok=1; c_why="$LEG_REASON"
  LEG_REASON=""; leg_negative && n_ok=1; n_why="$LEG_REASON"
  LEG_REASON=""; leg_subject && s_ok=1; s_why="$LEG_REASON"
  say "control: $([ $c_ok = 1 ] && echo ok || echo FAILED): $c_why"
  say "negative control: $([ $n_ok = 1 ] && echo ok || echo FAILED): $n_why"
  say "subject: $([ $s_ok = 1 ] && echo PASS || echo FAIL): $s_why"
  local reason="control: $c_why | negative control: $n_why | subject: $s_why"
  if [ $c_ok = 1 ] && [ $n_ok = 1 ] && [ $s_ok = 1 ]; then
    write_verdict pass true "$reason"; return 0
  fi
  write_verdict fail true "$reason"; return 1
}

case "${1:-all}" in
  --selftest) selftest ;;
  all) main ;;
  *) echo "usage: run.sh [all|--selftest]" >&2; exit 2 ;;
esac
