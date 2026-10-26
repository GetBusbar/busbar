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
#   3. SUBJECT           examples/tls_subject.rs of crates/busbar-core-connector: a run-time self-signed
#                        certificate read back through tls::build_server_config, bound with
#                        Listening::bind, the identity test framer (core-only, no plugin). It must meet
#                        every assertion. The chain is judged against the subject's own certificate
#                        (testssl --add-ca), so "trusted" means the served chain is well formed and
#                        verifies to that anchor; the public-CA chain is the released-image assessment's.
# All three always run. `pass` only when all three hold; a subject that cannot be built or booted is
# `fail` (armed). Writes $CONFORMANCE_OUT/verdict.json and the assertion evidence beside it. Needs docker
# (Linux: --network host), python3, no host openssl (certificates come from the pinned image).
set -uo pipefail
: "${CONFORMANCE_OUT:?}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
H="$repo/testing/tls-conformance"
say() { printf 'tls: %s\n' "$*" >&2; }

# testssl.sh 3.2.4 (the rolling `3.2` tag, pinned by digest), the nginx stable-alpine index, both by digest.
TESTSSL_IMAGE='drwetter/testssl.sh@sha256:6f84a73a128117eddf45fb5196f6e6c6428e9a167b7dd6a022482b66ffc85c82'
TESTSSL_VER=3.2.4
NGINX_IMAGE='nginx@sha256:47928bf67eb62a1863cb08d9ecb52d3e704304ba614eaee17884204677702951'
OLD_OPENSSL=/home/testssl/bin/openssl.Linux.x86_64   # OpenSSL 1.0.2-bad, shipped in the testssl.sh image
PR_1713=refs/pull/1713/head

W="$(mktemp -d "${TMPDIR:-/tmp}/tls-conf.XXXXXX")"
cids=(); pids=()
cleanup() {
  for c in "${cids[@]+"${cids[@]}"}"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  for p in "${pids[@]+"${pids[@]}"}"; do kill "$p" 2>/dev/null || true; done
  rm -rf "$W"
}
trap cleanup EXIT
why=()
final() {
  python3 -I - "$CONFORMANCE_OUT/verdict.json" "$TESTSSL_VER" "${why[@]+"${why[@]}"}" <<'PY'
import json, sys
out, ver, why = sys.argv[1], sys.argv[2], sys.argv[3:]
v = {"suite": "tls", "status": "fail" if why else "pass", "armed": True,
     "standard": "TLS server posture: protocol floor, cipher allow-list, chain, key size, expiry, no HIGH/CRITICAL findings",
     "plan": "testssl.sh against the connector's rustls listener on loopback, named assertions of scripts/release/tls-assert.json",
     "spec_version": f"testssl.sh {ver}; rustls via busbar-core-connector"}
if why: v["reason"] = "; ".join(why)
json.dump(v, open(out, "w"), indent=2); open(out, "a").write("\n")
print(json.dumps(v))
sys.exit(1 if why else 0)
PY
  exit $?
}

command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || { why+=("docker is unavailable, so testssl.sh could not run"); final; }

# ── the judge: ONE home per fact (scripts/release/tls_assess.py + tls-assert.json) ────────────────────
J="$repo/scripts/release"
if [ ! -f "$J/tls_assess.py" ] || [ ! -f "$J/tls-assert.json" ]; then
  # PR #1713 has not landed in this tree: take its two files from the PR ref at run time. Never copied
  # into this repo (a second copy would be a second home); once #1713 is in, this branch is not taken.
  J="$W/judge"; mkdir -p "$J"
  jerr=""
  for remote in origin "https://github.com/GetBusbar/busbar"; do
    jerr="$jerr [$remote: $(git -C "$repo" fetch -q "$remote" "$PR_1713" 2>&1 | tail -1)]"
    if git -C "$repo" show FETCH_HEAD:scripts/release/tls_assess.py >"$J/tls_assess.py" 2>/dev/null \
       && git -C "$repo" show FETCH_HEAD:scripts/release/tls-assert.json >"$J/tls-assert.json" 2>/dev/null; then
      say "judge: scripts/release/{tls_assess.py,tls-assert.json} are not in this tree; taken from $PR_1713 via $remote"; jerr=""; break
    fi
  done
  if [ -n "$jerr" ]; then  # the repo is public: the PR's branch over plain https
    RAW=https://raw.githubusercontent.com/GetBusbar/busbar/lane-release-publish-gate/scripts/release
    if curl -fsSL --retry 2 -o "$J/tls_assess.py" "$RAW/tls_assess.py" && curl -fsSL --retry 2 -o "$J/tls-assert.json" "$RAW/tls-assert.json"; then
      say "judge: taken from the lane-release-publish-gate branch (PR #1713) over https"; jerr=""
    fi
  fi
  if [ -n "$jerr" ]; then
    why+=("the shared TLS judge (scripts/release/tls_assess.py, tls-assert.json from PR #1713) is neither in this tree nor fetchable from $PR_1713:$jerr"); final
  fi
fi

docker pull -q "$TESTSSL_IMAGE" >/dev/null 2>&1 || docker image inspect "$TESTSSL_IMAGE" >/dev/null 2>&1 || { why+=("the pinned testssl.sh image could not be pulled"); final; }

# ── testssl as tls_assess.py wants it: one executable, the JSON path on the host ──────────────────────
# tls_assess.py calls $TESTSSL <its flags> --jsonfile <host path> https://<host>; this runs the pinned
# image on the host network, mounts the JSON's directory, and adds $TLS_CA as the trust anchor.
cat >"$W/testssl" <<'SH'
#!/usr/bin/env bash
args=(); mounts=()
while [ $# -gt 0 ]; do
  if [ "$1" = "--jsonfile" ]; then
    d="$(dirname "$2")"; mounts=(-v "$d:/out"); args+=(--jsonfile "/out/$(basename "$2")"); shift 2
  else args+=("$1"); shift; fi
done
exec docker run --rm --network host --user "$(id -u):$(id -g)" -e HOME=/tmp "${mounts[@]}" \
  -v "$TLS_CA:/ca.pem:ro" "$TLS_IMAGE" --add-ca /ca.pem "${args[@]}"
SH
chmod +x "$W/testssl"
export TESTSSL="$W/testssl" TLS_IMAGE="$TESTSSL_IMAGE"

free_port() { python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
wait_port() { for _ in $(seq 1 60); do (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 1; done; return 1; }
# mkcert <dir> <rsa-bits|ec>: a self-signed certificate for localhost, minted by the pinned image's openssl.
mkcert() {
  mkdir -p "$1"; local k='ec -pkeyopt ec_paramgen_curve:prime256v1'; [ "$2" != ec ] && k="rsa:$2"
  # shellcheck disable=SC2086
  docker run --rm --user "$(id -u):$(id -g)" -v "$1:/w" --entrypoint openssl "$TESTSSL_IMAGE" req -x509 -newkey $k -nodes -days 90 \
    -subj /CN=localhost -addext subjectAltName=DNS:localhost -addext crlDistributionPoints=URI:http://localhost/ref.crl \
    -keyout /w/key.pem -out /w/cert.pem >"$1/mkcert.log" 2>&1 && chmod 644 "$1/key.pem"
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
pid /tmp/nginx.pid;
events {}
http {
  access_log off; error_log /dev/stderr warn;
  server {
    listen 127.0.0.1:$port ssl;
    server_name localhost;
    ssl_certificate /etc/nginx/tls/cert.pem;
    ssl_certificate_key /etc/nginx/tls/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_tickets off;
    location / { return 200 "ok\n"; }
  }
}
CONF
if [ -s "$W/nginx/cert.pem" ] && cid="$(docker run -d --rm --network host -v "$W/nginx/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$W/nginx:/etc/nginx/tls:ro" "$NGINX_IMAGE")" && cids+=("$cid") && wait_port "$port"; then
  assess control "$port" "$W/nginx/cert.pem" "sha256:${NGINX_IMAGE##*sha256:}" || why+=("the control leg failed: a known-good nginx did not meet the assertions: $(grep -E '^FAIL' "$W/control.log" | head -5 | tr '\n' '|')")
else why+=("the control server (nginx) could not be started"); fi

# ── leg 2: NEGATIVE CONTROL ─────────────────────────────────────────────────────────────────────────
say "=== leg 2: negative control (old OpenSSL s_server: SSLv3/TLS1.0, 3DES/RC4/export, RSA 1024)"
mkcert "$W/weak" 1024
port="$(free_port)"
if [ -s "$W/weak/cert.pem" ] && cid="$(docker run -d --network host --user "$(id -u):$(id -g)" -v "$W/weak:/w:ro" --entrypoint "$OLD_OPENSSL" "$TESTSSL_IMAGE" \
     s_server -accept "$port" -cert /w/cert.pem -key /w/key.pem -www \
     -cipher 'DES-CBC3-SHA:RC4-SHA:RC4-MD5:AES128-SHA:EXP-RC4-MD5:EXP-DES-CBC-SHA:ECDHE-RSA-AES128-SHA')" && cids+=("$cid") && wait_port "$port"; then
  if assess weak "$port" "$W/weak/cert.pem" "sha256:${TESTSSL_IMAGE##*sha256:}"; then why+=("negative control: the deliberately weak server met every assertion")
  else
    for a in min_protocol ciphers_allowed key_size; do
      grep -q "^FAIL.* $a:" "$W/weak.log" || why+=("negative control: the weak server was refused, but not by $a")
    done
  fi
else why+=("the weak server could not be started, so the negative control did not run: $(tail -c 300 "$W/weak/mkcert.log" 2>/dev/null | tr '\n' ' ')$([ -n "${cid:-}" ] && docker logs "$cid" 2>&1 | tail -3 | tr '\n' ' ')"); fi

# ── leg 3: SUBJECT ──────────────────────────────────────────────────────────────────────────────────
say "=== leg 3: subject (busbar-core-connector's TLS listener)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo/target}"
if (cd "$repo" && cargo build -p busbar-core-connector --example tls_subject) >&2; then
  bin="$CARGO_TARGET_DIR/debug/examples/tls_subject"
  mkdir -p "$W/subject"; "$bin" "$W/subject" >"$W/subject-server.log" 2>&1 & pids+=($!)
  for _ in $(seq 1 60); do [ -s "$W/subject/addr" ] && break; sleep 1; done
  if [ -s "$W/subject/addr" ]; then
    port="$(sed 's/.*://' "$W/subject/addr")"
    sum="$( (sha256sum "$bin" 2>/dev/null || shasum -a 256 "$bin") | cut -d' ' -f1)"
    assess subject "$port" "$W/subject/cert.pem" "sha256:$sum" || why+=("the subject failed the assertions: $(grep -E '^FAIL' "$W/subject.log" | head -8 | tr '\n' '|')")
  else why+=("the subject (tls_subject) did not start: $(tail -2 "$W/subject-server.log" | tr '\n' ' ')"); fi
else why+=("the subject (crates/busbar-core-connector example tls_subject) did not build"); fi

mkdir -p "$CONFORMANCE_OUT/evidence" && cp -R "$W/out/." "$CONFORMANCE_OUT/evidence/" 2>/dev/null; cp "$W"/*.log "$CONFORMANCE_OUT/evidence/" 2>/dev/null
final
