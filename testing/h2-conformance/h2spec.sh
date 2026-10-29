#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# The `h2` suite of testing/conformance/suites.tsv: h2spec (summerwind/h2spec, the HTTP/2 conformance
# tester, RFC 9113 + RFC 7541) over TLS with ALPN h2 against busbar's `tls:` listener, in three legs
# and one verdict:
#   1. CONTROL           a known-good third-party HTTP/2 server: Caddy (Go's x/net/http2), digest-pinned.
#                        No production server passes all 146 h2spec tests (measured 2026-10-29: nginx
#                        1.28 fails 28, Apache mod_http2 8-9, nghttpd 1, Caddy 4-6), so the control is
#                        held to Caddy's KNOWN deviations at this pin (CONTROL_KNOWN, each one may pass
#                        or fail: two of them are timing races) and to nothing else: any other failing
#                        test, or fewer than CONTROL_MIN_PASSED passes, fails the control.
#   2. NEGATIVE CONTROL  the same Caddy with HTTP/2 off (`protocols h1`, ALPN http/1.1 only) MUST be
#                        graded red: h2spec must fail there, or it cannot tell h2 from not-h2.
#   3. SUBJECT           busbar, the shipped binary (dist/default, built `--locked` from this checkout),
#                        booted with a `tls:` block on a loopback listener (ALPN offers h2 then
#                        http/1.1). It MUST pass every h2spec test: no failure, no skip, no allow-list.
# All three always run. `pass` only when all three hold; anything else is `fail` (armed), with the
# failing test ids named. h2spec is the official release asset at a pinned version, checked against
# its pinned sha256 before it is unpacked (as testing/conformance/tools.sh provisions its tools). Its
# release ships amd64 binaries only: on Linux the static binary runs inside a pinned linux/amd64
# busybox image (its platform manifest, by digest) on the host network, on macOS natively. The PKI is generated at run time
# (testing/evidence-conformance/pki.py, no openssl). Needs docker (Linux: --network host), python3,
# cargo. Writes $CONFORMANCE_OUT/verdict.json and the JUnit reports beside it.
set -uo pipefail
: "${CONFORMANCE_OUT:?}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
say() { printf 'h2: %s\n' "$*" >&2; }

H2SPEC_VER=v2.6.0
H2SPEC_SHA_linux_amd64=157ee0de702e01ad40e752dbf074b366027e550c8e7504f9450da2809e279318
H2SPEC_SHA_darwin_amd64=981cb9f90a6f5e36300063022bd4eb7438d3dcf66d63a146a8541359697d1601
# caddy:2-alpine (v2.11.7), the multi-arch index, by digest.
CADDY_IMAGE='caddy@sha256:eb4d35b7452d1ab6171fbdbe8d9275b2301dad6dad92115d91e19fb9b24d510f'
MIN_TESTS=146   # h2spec v2.6.0 runs 146 (generic, http2, hpack)
CONTROL_MIN_PASSED=138
# Caddy v2.11.7's known h2spec deviations (package | test), measured over repeated runs.
CONTROL_KNOWN='http2/4.2 | Sends a large size HEADERS frame that exceeds the SETTINGS_MAX_FRAME_SIZE
http2/6.5.3 | Sends multiple values of SETTINGS_INITIAL_WINDOW_SIZE
http2/6.9.1 | Sends multiple WINDOW_UPDATE frames increasing the flow control window to above 2^31-1 on a stream
http2/8.1.2.2 | Sends a HEADERS frame that contains the connection-specific header field
http2/8.1.2.2 | Sends a HEADERS frame that contains the TE header field with any value other than "trailers"
http2/8.1.2.6 | Sends a HEADERS frame with the "content-length" header field which does not equal the DATA frame payload length'
export CONTROL_KNOWN
# busybox 1.37.0-musl, the linux/amd64 platform manifest by digest: h2spec's carrier on Linux.
CARRIER_IMAGE='busybox@sha256:5624bb6777cf469b1fb50ae3f981b15d2715ee2fffaf20b9998cfb7843726835'

W="$(mktemp -d "${TMPDIR:-/tmp}/h2-conf.XXXXXX")"
cids=(); pids=()
cleanup() {
  for c in "${cids[@]+"${cids[@]}"}"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  for p in "${pids[@]+"${pids[@]}"}"; do kill "$p" 2>/dev/null || true; done
  rm -rf "$W"
}
trap cleanup EXIT
why=()
final() {
  mkdir -p "$CONFORMANCE_OUT/evidence"; cp "$W"/*.xml "$W"/*.log "$CONFORMANCE_OUT/evidence/" 2>/dev/null
  python3 -I - "$CONFORMANCE_OUT/verdict.json" "$H2SPEC_VER" "${why[@]+"${why[@]}"}" <<'PY'
import json, sys
out, ver, why = sys.argv[1], sys.argv[2], sys.argv[3:]
v = {"suite": "h2", "status": "fail" if why else "pass", "armed": True,
     "standard": "HTTP/2 (RFC 9113) and HPACK (RFC 7541)",
     "plan": "h2spec over TLS (ALPN h2) against the tls: listener of the shipped busbar binary",
     "spec_version": f"h2spec {ver}"}
if why: v["reason"] = "; ".join(why)[:4000]
json.dump(v, open(out, "w"), indent=2); open(out, "a").write("\n")
print(json.dumps(v))
sys.exit(1 if why else 0)
PY
  exit $?
}

_sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
free_port() { python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
wait_port() { for _ in $(seq 1 120); do (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 1; done; return 1; }

# ── the instrument: h2spec at the pin ───────────────────────────────────────────────────────────────
case "$(uname -s)" in
  Linux)  plat=linux_amd64; sha=$H2SPEC_SHA_linux_amd64
          command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || { why+=("docker is unavailable, so h2spec (amd64) and the Caddy peers could not run"); final; } ;;
  Darwin) plat=darwin_amd64; sha=$H2SPEC_SHA_darwin_amd64 ;;
  *) why+=("no pinned h2spec for $(uname -s)"); final ;;
esac
cache="${MODERNCI_CACHE_DIR:-$HOME/.cache}/conformance-tools/h2spec-$H2SPEC_VER-$plat"
tgz="$cache.tar.gz"
if [ ! -f "$tgz" ] || [ "$(_sha256 "$tgz")" != "$sha" ]; then
  mkdir -p "$(dirname "$tgz")"
  curl -fsSL --retry 3 -o "$tgz.part.$$" "https://github.com/summerwind/h2spec/releases/download/$H2SPEC_VER/h2spec_$plat.tar.gz" \
    || { rm -f "$tgz.part.$$"; why+=("the h2spec $H2SPEC_VER release asset could not be downloaded"); final; }
  got="$(_sha256 "$tgz.part.$$")"
  [ "$got" = "$sha" ] || { rm -f "$tgz.part.$$"; why+=("h2spec $H2SPEC_VER: sha256 mismatch (expected $sha, got $got)"); final; }
  mv "$tgz.part.$$" "$tgz"
fi
mkdir -p "$W/h2spec" && tar -xzf "$tgz" -C "$W/h2spec" h2spec || { why+=("the h2spec archive could not be unpacked"); final; }
docker pull -q "$CADDY_IMAGE" >/dev/null 2>&1 || docker image inspect "$CADDY_IMAGE" >/dev/null 2>&1 \
  || { why+=("the pinned Caddy image could not be pulled"); final; }
if [ "$plat" = linux_amd64 ]; then
  docker pull -q --platform linux/amd64 "$CARRIER_IMAGE" >/dev/null 2>&1 || docker image inspect "$CARRIER_IMAGE" >/dev/null 2>&1 \
    || { why+=("h2spec's pinned carrier image (busybox, linux/amd64) could not be pulled: $(docker pull --platform linux/amd64 "$CARRIER_IMAGE" 2>&1 | tail -1)"); final; }
fi

# h2spec_run <name> <port>: the JUnit report at $W/<name>.xml, the console at $W/<name>.log.
h2spec_run() {
  if [ "$plat" = linux_amd64 ]; then
    docker run --rm --platform linux/amd64 --network host --user "$(id -u):$(id -g)" \
      -v "$W/h2spec:/h2:ro" -v "$W:/out" --entrypoint /h2/h2spec "$CARRIER_IMAGE" \
      -t -k -h 127.0.0.1 -p "$2" --timeout 5 -j "/out/$1.xml" >"$W/$1.log" 2>&1
  else
    "$W/h2spec/h2spec" -t -k -h 127.0.0.1 -p "$2" --timeout 5 -j "$W/$1.xml" >"$W/$1.log" 2>&1
  fi
  return 0
}
# grade <name> [known]: "<tests> <passed> <failed> <skipped> <unknown failures>" from the JUnit
# report; with `known`, a failure CONTROL_KNOWN lists is not counted in <failed>. A failure is named
# `<package> | <test>`, the report's own identity of a test.
grade() {
  python3 -I - "$W/$1.xml" "${2:-}" <<'PY'
import os, sys, xml.etree.ElementTree as ET
known = set(os.environ.get("CONTROL_KNOWN", "").splitlines()) if sys.argv[2] == "known" else set()
try:
    root = ET.parse(sys.argv[1]).getroot()
except (OSError, ET.ParseError) as e:
    print(0, 0, 0, 0, f"no-report:{type(e).__name__}"); sys.exit()
n = p = f = s = 0; bad = []
for c in root.iter("testcase"):
    n += 1
    tid = f"{c.get('package', '')} | {c.get('classname', '')}"
    if c.find("failure") is not None or c.find("error") is not None:
        if tid not in known:
            f += 1; bad.append(tid)
    elif c.find("skipped") is not None:
        s += 1; bad.append("skipped: " + tid)
    else:
        p += 1
print(n, p, f, s, (" ;; ".join(bad[:30]) or "-").replace("\n", " "))
PY
}

# certificates for localhost, from the rig's own PKI
python3 -I - "$repo/testing/evidence-conformance/pki.py" "$W/pki" <<'PY' || { why+=("the run's PKI could not be minted"); final; }
import importlib.util, os, sys
s = importlib.util.spec_from_file_location("pki", sys.argv[1]); p = importlib.util.module_from_spec(s); s.loader.exec_module(p)
os.makedirs(sys.argv[2], exist_ok=True)
ca = p.Cert("h2 conformance CA", ca=True); ca.write(sys.argv[2], "ca")
p.Cert("localhost", issuer=ca, server=True, dns=["localhost"], ips=["127.0.0.1"]).write(sys.argv[2], "leaf", chain=True)
PY
chmod 644 "$W/pki/"*

# caddy_leg <name> <h1 h2|h1>: run Caddy serving those protocols on a free port, run h2spec at it.
caddy_leg() {
  local port; port="$(free_port)"
  mkdir -p "$W/$1"
  cat >"$W/$1/Caddyfile" <<CONF
{
  auto_https off
  admin off
  servers {
    protocols $2
  }
}
https://:$port {
  bind 127.0.0.1
  tls /etc/tls/leaf.pem /etc/tls/leaf.key
  respond "ok"
}
CONF
  local cid
  if cid="$(docker run -d --rm --network host -v "$W/$1/Caddyfile:/etc/caddy/Caddyfile:ro" -v "$W/pki:/etc/tls:ro" "$CADDY_IMAGE")" \
     && cids+=("$cid") && wait_port "$port"; then
    h2spec_run "$1" "$port"; return 0
  fi
  [ -n "${cid:-}" ] && docker logs "$cid" >"$W/$1-caddy.log" 2>&1
  return 1
}

# ── leg 1: CONTROL ──────────────────────────────────────────────────────────────────────────────────
say "=== leg 1: control (Caddy, h1 + h2)"
if caddy_leg control "h1 h2"; then
  read -r n p f s bad <<<"$(grade control known)"
  say "control: $n tests, $p passed, $f failed beyond its known deviations, $s skipped"
  { [ "$n" -ge "$MIN_TESTS" ] && [ "$f" = 0 ] && [ "$p" -ge "$CONTROL_MIN_PASSED" ]; } \
    || why+=("the control leg failed: Caddy ($n tests, $p passed, $f failed beyond its known deviations: $bad; $(tail -2 "$W/control.log" | tr '\n' ' '))")
else why+=("the control server (Caddy, h2) could not be started: $(tail -3 "$W/control-caddy.log" 2>/dev/null | tr '\n' ' ')"); fi

# ── leg 2: NEGATIVE CONTROL ─────────────────────────────────────────────────────────────────────────
say "=== leg 2: negative control (Caddy, h1 only: ALPN http/1.1 only)"
if caddy_leg negative h1; then
  read -r n p f s bad <<<"$(grade negative)"
  say "negative: $n tests, $p passed, $f failed, $s skipped"
  if [ "$f" = 0 ] && [ "$n" -ge "$MIN_TESTS" ]; then why+=("negative control: a Caddy with HTTP/2 off passed h2spec");
  elif [ "$n" -ge "$MIN_TESTS" ] && [ "$p" -gt $(( n / 10 )) ]; then why+=("negative control: a Caddy with HTTP/2 off passed $p of $n h2spec tests");
  elif [ "$n" = 0 ] && ! grep -qiE 'alpn|h2|preface|protocol' "$W/negative.log"; then why+=("negative control: h2spec wrote no report and did not say why: $(tail -3 "$W/negative.log" | tr '\n' ' ')"); fi
else why+=("the negative control server (Caddy, h1) could not be started: $(tail -3 "$W/negative-caddy.log" 2>/dev/null | tr '\n' ' ')"); fi

# ── leg 3: SUBJECT ──────────────────────────────────────────────────────────────────────────────────
say "=== leg 3: subject (busbar's tls: listener, ALPN h2)"
tgt="${CARGO_TARGET_DIR:-$repo/target}/dist-default"
if (cd "$repo" && cargo build --locked --manifest-path dist/default/Cargo.toml --target-dir "$tgt" --bin busbar) >&2; then
  data="$(free_port)"; admin="$(free_port)"; mkdir -p "$W/subject"
  echo '{}' >"$W/subject/providers.yaml"
  cat >"$W/subject/config.yaml" <<CONF
{"listen": "127.0.0.1:$data", "admin_listen": "127.0.0.1:$admin", "store": {"module": "memory"},
 "providers": {}, "models": {}, "providers_file": "$W/subject/providers.yaml",
 "auth": {"chain": [], "admin_auth": []},
 "tls": {"cert": {"file": "$W/pki/leaf.pem"}, "key": {"file": "$W/pki/leaf.key"}}}
CONF
  (cd "$W/subject" && BUSBAR_CONFIG="$W/subject/config.yaml" exec "$tgt/debug/busbar") >"$W/subject-busbar.log" 2>&1 &
  bpid=$!; pids+=("$bpid")
  if wait_port "$data"; then
    h2spec_run subject "$data"
    read -r n p f s bad <<<"$(grade subject)"
    say "subject: $n tests, $p passed, $f failed, $s skipped"
    { [ "$n" -ge "$MIN_TESTS" ] && [ "$p" = "$n" ]; } || why+=("the subject did not pass h2spec: $n tests, $p passed, $f failed, $s skipped: $bad")
    kill -0 "$bpid" 2>/dev/null || why+=("busbar exited during the h2spec run: $(tail -3 "$W/subject-busbar.log" | tr '\n' ' ')")
  else why+=("busbar (the subject) did not start: $(tail -3 "$W/subject-busbar.log" | tr '\n' ' ')"); fi
else why+=("the subject (dist/default busbar) did not build"); fi

final
