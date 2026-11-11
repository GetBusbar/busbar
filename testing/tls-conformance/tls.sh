#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# The `tls` suite of testing/conformance/suites.tsv: testssl.sh against busbar core's connector TLS
# listener on loopback, judged by the SAME named assertions the released-image assessment uses
# (scripts/release/tls-assert.json, judged by scripts/release/tls_assess.py: protocol floor, cipher
# allow-list, chain, key size, expiry, no HIGH/CRITICAL; never a letter grade), in three legs and one
# verdict:
#   1. CONTROL           a known-good third-party server (digest-pinned nginx, modern TLS config)
#                        MUST meet every assertion.
#   2. NEGATIVE CONTROL  a deliberately weak server (SSLv3/TLS 1.0/1.1, 3DES/RC4/export ciphers, RSA 1024:
#                        the old OpenSSL s_server bundled in the pinned testssl.sh image) MUST be refused,
#                        and for the right reasons: min_protocol, ciphers_allowed and key_size must fail.
#   3. SUBJECT           dist/default's shipped busbar binary, booted through the evidence rig's
#                        normal product fixture with tls.cert/key file references. This supplies the
#                        production composition's real linked file-secret module and HTTP transport.
#                        It must meet every assertion. The chain is judged against its own certificate
#                        (testssl --add-ca), so "trusted" means the served chain is well formed and
#                        verifies to that anchor; the public-CA chain is the released-image assessment's.
# All three always run. `pass` only when all three hold; a subject that cannot be built or booted is
# `fail` (armed). Writes $CONFORMANCE_OUT/verdict.json and the assertion evidence beside it. Needs the native worker's read-only testssl instrument bundle, bash, python3 and OpenSSL 3.
# Every server runs as a process inside the candidate network namespace; no Docker access.
set -uo pipefail
: "${CONFORMANCE_OUT:?}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
H="$repo/testing/tls-conformance"
say() { printf 'tls: %s\n' "$*" >&2; }

# testssl.sh 3.2.4 (the rolling `3.2` tag, pinned by digest), the nginx stable-alpine index, both by digest.
TESTSSL_IMAGE='drwetter/testssl.sh@sha256:6f84a73a128117eddf45fb5196f6e6c6428e9a167b7dd6a022482b66ffc85c82'
TESTSSL_VER=3.2.4
NGINX_IMAGE='nginx@sha256:47928bf67eb62a1863cb08d9ecb52d3e704304ba614eaee17884204677702951'
INSTRUMENT=/opt/busbar-conformance/testssl
OLD_OPENSSL="$INSTRUMENT/bin/openssl.Linux.x86_64" # Exact static OpenSSL 1.0.2-bad from pinned image
NGINX="$INSTRUMENT/nginx/nginx"
NGINX_LOADER="$INSTRUMENT/nginx/lib/ld-musl-x86_64.so.1"

W="$(mktemp -d "${TMPDIR:-/tmp}/tls-conf.XXXXXX")"
fixture_pids=(); pids=()
cleanup() {
  local p i failed=0
  for p in "${fixture_pids[@]+"${fixture_pids[@]}"}"; do
    kill "$p" 2>/dev/null || true
    for ((i=0; i<50; i++)); do
      kill -0 "$p" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$p" 2>/dev/null; then
      kill -KILL "$p" 2>/dev/null || true
      failed=1
    fi
    wait "$p" 2>/dev/null || true
  done
  for p in "${pids[@]+"${pids[@]}"}"; do
    if kill -0 "$p" 2>/dev/null; then
      if ! kill "$p" 2>/dev/null && kill -0 "$p" 2>/dev/null; then
        say "could not terminate TLS subject supervisor $p"; failed=1
      fi
      # subject.py's finally stops and reaps Busbar, allowing up to 15 seconds for shutdown.
      # Reap that supervisor before this shell exits and its process-group owner cleans up.
      for ((i=0; i<100; i++)); do
        kill -0 "$p" 2>/dev/null || break
        sleep 0.2
      done
      if kill -0 "$p" 2>/dev/null; then
        say "TLS subject supervisor $p did not stop within 20 seconds"
        if ! kill -KILL "$p" 2>/dev/null && kill -0 "$p" 2>/dev/null; then
          say "could not kill TLS subject supervisor $p"; failed=1; continue
        fi
        failed=1
      fi
    fi
    wait "$p" || { say "TLS subject supervisor $p exited unsuccessfully"; failed=1; }
  done
  fixture_pids=(); pids=()
  rm -rf "$W"
  return "$failed"
}
trap 'cleanup || exit 1' EXIT
why=()
final() {
  mkdir -p "$CONFORMANCE_OUT/evidence"
  python3 -I - "$W" "$CONFORMANCE_OUT/evidence/diagnostics.json" <<'PYLOG'
import json, pathlib, sys
work = pathlib.Path(sys.argv[1])
logs = {}
for name in ("control.log", "weak.log", "subject.log", "nginx.log", "weak-server.log", "subject-server.log"):
    path = work / name
    if path.is_file():
        with path.open("rb") as stream:
            stream.seek(max(0, path.stat().st_size - 65536))
            logs[name] = stream.read(65536).decode("utf-8", errors="replace")
pathlib.Path(sys.argv[2]).write_text(json.dumps({"logs": logs}, indent=2) + "\n")
PYLOG
  cleanup || why+=("the TLS subject supervisor did not shut down and reap cleanly")
  python3 -I - "$CONFORMANCE_OUT/verdict.json" "$TESTSSL_VER" "${why[@]+"${why[@]}"}" <<'PY'
import json, sys
out, ver, why = sys.argv[1], sys.argv[2], sys.argv[3:]
v = {"suite": "tls", "status": "fail" if why else "pass", "armed": True,
     "standard": "TLS server posture: protocol floor, cipher allow-list, chain, key size, expiry, no HIGH/CRITICAL findings",
     "plan": "testssl.sh against the connector's rustls listener on loopback, named assertions of scripts/release/tls-assert.json",
     "spec_version": f"testssl.sh {ver}; rustls via dist/default busbar"}
if why: v["reason"] = "; ".join(why)
json.dump(v, open(out, "w"), indent=2); open(out, "a").write("\n")
print(json.dumps(v))
sys.exit(1 if why else 0)
PY
  exit $?
}

if [ "$(uname -s)/$(uname -m)" != Linux/x86_64 ]; then
  why+=("the pinned native TLS instruments require Linux x86_64"); final
fi
for tool in "$INSTRUMENT/testssl.sh" "$OLD_OPENSSL" "$NGINX" "$NGINX_LOADER" "$INSTRUMENT/nginx/busybox"; do
  [ -f "$tool" ] && [ ! -L "$tool" ] && [ -x "$tool" ] || { why+=("missing admitted native TLS instrument: $tool"); final; }
done
# The shared release judge must be in the admitted source; candidates never fetch code.
J="$repo/scripts/release"
if [ ! -f "$J/tls_assess.py" ] || [ ! -f "$J/tls-assert.json" ]; then
  why+=("the shared TLS judge is absent from admitted source"); final
fi
cat >"$W/testssl" <<'SH'
#!/usr/bin/env bash
exec bash /opt/busbar-conformance/testssl/testssl.sh --add-ca "$TLS_CA" "$@"
SH
# testssl requires a resolver executable even for localhost. Use the real
# applets from the already pinned BusyBox; no downloads or synthetic DNS answers.
for applet in hexdump nslookup; do
cat >"$W/$applet" <<'SH'
#!/usr/bin/env bash
exec /opt/busbar-conformance/testssl/nginx/lib/ld-musl-x86_64.so.1 \
  --library-path /opt/busbar-conformance/testssl/nginx/lib \
  /opt/busbar-conformance/testssl/nginx/busybox "${0##*/}" "$@"
SH
chmod +x "$W/$applet"
done
chmod +x "$W/testssl"
export TESTSSL="$W/testssl" PATH="$W:$PATH"

free_port() { python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
wait_port() { for _ in $(seq 1 60); do (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 1; done; return 1; }
# Certificate generation does not judge posture; the pinned testssl scanner does.
mkcert() {
  mkdir -p "$1"; local k='ec -pkeyopt ec_paramgen_curve:prime256v1'; [ "$2" != ec ] && k="rsa:$2"
  # shellcheck disable=SC2086
  openssl req -x509 -newkey $k -nodes -days 90 \
    -subj /CN=localhost -addext subjectAltName=DNS:localhost -addext crlDistributionPoints=URI:http://localhost/ref.crl \
    -keyout "$1/key.pem" -out "$1/cert.pem" >"$1/mkcert.log" 2>&1
}
# assess <name> <port> <ca> <digest of the artifact served>: run the judge; its stdout in $W/<name>.log;
# the exit is the judge's.
assess() {
  TLS_CA="$3" python3 -I "$J/tls_assess.py" run --host "localhost:$2" --version "$(git -C "$repo" rev-parse HEAD 2>/dev/null || echo unknown)" \
    --image-digest "$4" --variant "$1" --out "$W/out" >"$W/$1.log" 2>&1
  local rc=$?; sed "s/^/tls[$1]: /" "$W/$1.log" >&2; return $rc
}

# ── leg 1: CONTROL ──────────────────────────────────────────────────────────────────────────────────
say "=== leg 1: control (nginx, modern TLS config)"
mkcert "$W/nginx" ec
port="$(free_port)"
cat >"$W/nginx/nginx.conf" <<CONF
pid $W/nginx/nginx.pid;
error_log stderr warn;
events {}
http {
  access_log off; error_log stderr warn;
  client_body_temp_path $W/nginx/client;
  proxy_temp_path $W/nginx/proxy;
  fastcgi_temp_path $W/nginx/fastcgi;
  uwsgi_temp_path $W/nginx/uwsgi;
  scgi_temp_path $W/nginx/scgi;
  server {
    listen 127.0.0.1:$port ssl;
    server_name localhost;
    ssl_certificate $W/nginx/cert.pem;
    ssl_certificate_key $W/nginx/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_tickets off;
    location / { return 200 "ok\n"; }
  }
}
CONF
"$NGINX_LOADER" --library-path "$INSTRUMENT/nginx/lib" "$NGINX" -p "$W/nginx/" -c "$W/nginx/nginx.conf" -g 'daemon off; master_process off;' >"$W/nginx.log" 2>&1 &
fixture_pids+=($!)
if [ -s "$W/nginx/cert.pem" ] && wait_port "$port"; then
  assess control "$port" "$W/nginx/cert.pem" "sha256:${NGINX_IMAGE##*sha256:}" || why+=("the control leg failed: a known-good nginx did not meet the assertions: $(grep -E '^FAIL' "$W/control.log" | head -5 | tr '\n' '|')")
else why+=("the control server (nginx) could not be started"); fi

# ── leg 2: NEGATIVE CONTROL ─────────────────────────────────────────────────────────────────────────
say "=== leg 2: negative control (old OpenSSL s_server: SSLv3/TLS1.0, 3DES/RC4/export, RSA 1024)"
mkcert "$W/weak" 1024
port="$(free_port)"
# This OpenSSL's -accept takes a service/port, not modern host:port syntax.
# Its socket is confined to the candidate network namespace.
OPENSSL_CONF=/dev/null "$OLD_OPENSSL" s_server -accept "$port" -cert "$W/weak/cert.pem" -key "$W/weak/key.pem" -www \
  -cipher 'DES-CBC3-SHA:RC4-SHA:RC4-MD5:AES128-SHA:EXP-RC4-MD5:EXP-DES-CBC-SHA:ECDHE-RSA-AES128-SHA' >"$W/weak-server.log" 2>&1 &
fixture_pids+=($!)
if [ -s "$W/weak/cert.pem" ] && wait_port "$port"; then
  if assess weak "$port" "$W/weak/cert.pem" "sha256:${TESTSSL_IMAGE##*sha256:}"; then why+=("negative control: the deliberately weak server met every assertion")
  else
    for a in min_protocol ciphers_allowed key_size; do
      grep -q "^FAIL.* $a:" "$W/weak.log" || why+=("negative control: the weak server was refused, but not by $a")
    done
  fi
else why+=("the weak server could not be started, so the negative control did not run: $(tail -c 300 "$W/weak/mkcert.log" 2>/dev/null | tr '\n' ' ')$(tail -c 300 "$W/weak-server.log" 2>/dev/null | tr '\n' ' ')"); fi

# ── leg 3: SUBJECT ──────────────────────────────────────────────────────────────────────────────────
say "=== leg 3: subject (dist/default busbar's production TLS listener)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo/target}"
subject_target="$CARGO_TARGET_DIR/dist-default"
if (cd "$repo" && cargo build --locked --manifest-path dist/default/Cargo.toml --target-dir "$subject_target" --bin busbar) >&2; then
  bin="$subject_target/debug/busbar"
  if mkcert "$W/subject" ec; then
    python3 -I "$H/subject.py" "$bin" "$W/subject" >"$W/subject-server.log" 2>&1 & pids+=($!)
    for _ in $(seq 1 120); do [ -s "$W/subject/addr" ] && break; sleep 1; done
    if [ -s "$W/subject/addr" ]; then
      port="$(sed 's/.*://' "$W/subject/addr")"
      sum="$( (sha256sum "$bin" 2>/dev/null || shasum -a 256 "$bin") | cut -d' ' -f1)"
      assess subject "$port" "$W/subject/cert.pem" "sha256:$sum" || why+=("the subject failed the assertions: $(grep -E '^FAIL' "$W/subject.log" | head -8 | tr '\n' '|')")
    else why+=("the subject (dist/default busbar) did not start: $(tail -2 "$W/subject-server.log" | tr '\n' ' ')"); fi
  else why+=("the subject certificate could not be generated"); fi
else why+=("the subject (dist/default busbar) did not build"); fi

mkdir -p "$CONFORMANCE_OUT/evidence" && cp -R "$W/out/." "$CONFORMANCE_OUT/evidence/" 2>/dev/null; cp "$W"/*.log "$CONFORMANCE_OUT/evidence/" 2>/dev/null
cp "$W/subject/product/busbar.log" "$CONFORMANCE_OUT/evidence/subject-busbar.log" 2>/dev/null || true
cp "$W/subject/product/config.yaml" "$CONFORMANCE_OUT/evidence/subject-config.yaml" 2>/dev/null || true
final
