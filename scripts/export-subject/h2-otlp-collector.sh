#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Gating scenario `export.rig|h2-otlp-collector` -- the OTLP export, end to end, across a real
# process boundary.
#
# WHAT IT PROVES, AND WHY NO CELL IN THE TREE COULD. `busbar-export-otlp`'s own cells start at a
# hand-built batch and prove the framing. The root's cells drive the real layer, the real gate and
# the real drain and stop at the sink's door; the newest of them decodes the protobuf back, but off
# a FAKE wire, inside the test process, with the publisher's generated types on both sides of the
# comparison. Between them sat one process boundary: does a span the SHIPPED BINARY emitted arrive
# at a program that speaks OTLP as that span? This boots the release binary with `export: otlp`
# pointed at scripts/export-subject/otlp-collector.mjs, drives real requests through the llm plane
# against a mock upstream, and compares what the collector decoded -- byte for byte -- against
# expected-spans.json. A producer that dropped a parent link, a sink that framed the wrong field
# number, or an egress client that mangled the body is red here and green everywhere else.
#
# THE COMPARISON IS `cmp`, NOT A JSON WALK. The collector emits sorted keys, a fixed indent and one
# trailing newline, and normalises exactly the five things that are facts about the RUN rather than
# about the export (its own header states each rule). Everything else crosses untouched, so a field
# that appeared, vanished or changed value is a byte difference and there is no predicate that could
# have been written loosely enough to tolerate it.
#
# Usage:
#   h2-otlp-collector.sh                 the live arm: the real binary, the real socket
#   h2-otlp-collector.sh --selftest      the offline arm (no build, no binary, no port): the reader
#                                        is held to a RECORDED real export, and the differ is shown
#                                        a difference it must refuse
#
# Env: EXPORT_SUBJECT_BUSBAR_BIN (default target/release/busbar)
#      EXPORT_SUBJECT_LISTEN_PORT / _MOCK_PORT / _COLLECTOR_PORT (default: three free ports
#                                     this run picks out of 47000-47999)
#      EXPORT_SUBJECT_CAPTURE=<file>  write the raw protobuf body of the first delivery there, which
#                                     is how captured-export.pb is re-recorded when the wire changes
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
EXPECTED="${HERE}/expected-spans.json"
# THE RECORDED EXPORT, IN BASE64 AND NOT IN BYTES. It is a real `ExportTraceServiceRequest` this
# binary once framed and a real socket once carried; it is checked in so the reader has something to
# be held to with no build, no binary and no port. Text rather than a blob because every gate in
# this tree walks the tracked files as source, and a fixture a reviewer cannot `git diff` is a
# fixture nobody reviews. Re-record it with EXPORT_SUBJECT_CAPTURE=<file> on the live arm.
CAPTURED_B64="${HERE}/captured-export.pb.b64"

# ── the offline arm ────────────────────────────────────────────────────────────────────────────
# It answers the two questions a live run cannot answer about ITSELF: can this reader read a real
# export, and can this comparison fail? A rig whose differ is broken is green on every commit.
if [ "${1:-}" = "--selftest" ]; then
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/otlp-selftest-XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  [ -s "$CAPTURED_B64" ] || { echo "SELFTEST FAIL: ${CAPTURED_B64} is missing or empty; there is no recorded export to hold the reader to" >&2; exit 1; }
  base64 -d <"$CAPTURED_B64" >"${tmp}/captured.pb" 2>/dev/null \
    || { echo "SELFTEST FAIL: ${CAPTURED_B64} is not decodable base64" >&2; exit 1; }

  # 1. THE READER, against a real export this binary once made. Same decode, same canonical write,
  #    same expectation as the live arm -- only the socket is absent.
  node "${HERE}/otlp-collector.mjs" --decode "${tmp}/captured.pb" "${tmp}/decoded.json" \
    || { echo "SELFTEST FAIL: the collector could not decode the recorded export" >&2; exit 1; }
  if ! cmp -s "${tmp}/decoded.json" "$EXPECTED"; then
    echo "SELFTEST FAIL: the recorded export does not decode to the checked-in expectation" >&2
    diff -u "$EXPECTED" "${tmp}/decoded.json" >&2
    exit 1
  fi

  # 2. NON-VACUITY. An expectation with no spans, or with one, would pass a rig that had lost the
  #    parent-link question entirely; the live arm drives two and both must be there.
  spans="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["spans"]))' "$EXPECTED")"
  [ "$spans" -ge 2 ] || { echo "SELFTEST FAIL: the expectation carries ${spans} span(s); fewer than two cannot pin an identity relation" >&2; exit 1; }

  # 3. THE DIFFER CAN SEE A DIFFERENCE. One span's parent link is rewritten in a COPY of the
  #    expectation and the comparison must refuse it -- which is the exact mutation the live arm
  #    exists to catch, run against the comparison itself.
  python3 - "$EXPECTED" "${tmp}/mutated.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
doc["spans"][0]["parent"] = "span-2"
open(sys.argv[2], "w").write(json.dumps(doc, indent=2) + "\n")
PY
  if cmp -s "${tmp}/decoded.json" "${tmp}/mutated.json"; then
    echo "SELFTEST FAIL: a rewritten parent link compared EQUAL; this rig could not fail" >&2
    exit 1
  fi
  echo "SELFTEST PASS: the reader decodes a recorded real export to the expectation (${spans} spans), and a broken parent link is refused"
  exit 0
fi

# ── the live arm ───────────────────────────────────────────────────────────────────────────────
# shellcheck source=../../testing/fleet-fixtures/lib.sh
source "${REPO}/testing/fleet-fixtures/lib.sh"

BIN="${EXPORT_SUBJECT_BUSBAR_BIN:-${REPO}/target/release/busbar}"
[ -x "$BIN" ] || { echo "export-subject: no busbar binary at $BIN (build with: cargo build -p busbar --release)" >&2; exit 2; }
# THREE FREE PORTS, PICKED AND NOT ASSUMED. Four agents share a self-hosted runner, so a fixed
# triple is a coin flip against whatever the agent beside this one is holding, and `assert_port_free`
# below would then refuse a verdict for a reason that has nothing to do with the export. The BAND is
# fixed (47000-47999) so an operator reading a firewall rule or an `ss` dump knows whose ports these
# are; which three inside it is this run's own answer.
read -r LP MP CP <<<"$(python3 - <<'PORTS'
import socket
held, ports = [], []
for port in range(47000, 48000):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
    except OSError:
        s.close()
        continue
    held.append(s)
    ports.append(port)
    if len(ports) == 3:
        break
if len(ports) != 3:
    raise SystemExit("export-subject: no three free ports in 47000-47999")
for s in held:
    s.close()
print(" ".join(str(p) for p in ports))
PORTS
)"
LP="${EXPORT_SUBJECT_LISTEN_PORT:-$LP}"
MP="${EXPORT_SUBJECT_MOCK_PORT:-$MP}"
CP="${EXPORT_SUBJECT_COLLECTOR_PORT:-$CP}"
W="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/otlp-rig-XXXXXX")"
RECEIVED="${W}/received.json"

fail() { echo "FAIL export.rig|h2-otlp-collector: $1" >&2; exit 1; }

for p in "$LP" "$MP" "$CP"; do
  assert_port_free "$p" || fail "port ${p} is busy before the rig starts; refusing a verdict against someone else's process"
done

capture=()
[ -n "${EXPORT_SUBJECT_CAPTURE:-}" ] && capture=(--capture "${EXPORT_SUBJECT_CAPTURE}")
node "${HERE}/otlp-collector.mjs" "$CP" "$RECEIVED" "${capture[@]}" >"${W}/collector.log" 2>&1 &
track_pid $!
wait_for_http "http://127.0.0.1:${CP}/received" 10 || fail "the collector fixture did not come up on ${CP}"

python3 "${REPO}/testing/fleet-fixtures/mock-upstream.py" "$MP" otlp-rig-marker >"${W}/mock.log" 2>&1 &
track_pid $!
wait_for_http "http://127.0.0.1:${MP}/" 10 || true

cat >"${W}/providers.yaml" <<YAML
mock:
  protocol: anthropic
  base_url: "http://127.0.0.1:${MP}"
YAML

# THE COLLECTOR IS NAMED ON /v1/traces, which is the OTLP/HTTP binding's own path and the one the
# fixture answers; a wrong path is a 404 there, so this line is load-bearing rather than decorative.
cat >"${W}/config.yaml" <<YAML
listen: "127.0.0.1:${LP}"
auth:
  chain: []
export:
  collector:
    module: otlp
    settings: { url: "http://127.0.0.1:${CP}/v1/traces" }
providers:
  mock:
    api_key: { env: OTLP_RIG_UPSTREAM_KEY }
models:
  test-model:
    provider: mock
pools:
  default:
    members:
      - model: test-model
YAML

BUSBAR_CONFIG="${W}/config.yaml" BUSBAR_PROVIDERS="${W}/providers.yaml" \
  OTLP_RIG_UPSTREAM_KEY=unused RUST_LOG=info "$BIN" >"${W}/busbar.log" 2>&1 &
busbar_pid=$!
track_pid "$busbar_pid"
wait_for_http "http://127.0.0.1:${LP}/healthz" 45 || { cat "${W}/busbar.log" >&2; fail "busbar did not come up"; }
grep -q 'OTLP tracing enabled' "${W}/busbar.log" \
  || { cat "${W}/busbar.log" >&2; fail "this boot did not compose the OTLP export at all; a comparison against it would judge nothing"; }

# TWO REQUESTS, NOT ONE. One span cannot carry an identity RELATION: a producer that linked every
# span to the one beside it, or that minted one trace id for the process, is invisible with a single
# root. Two independent requests are two independent traces and two roots, and that is the shape the
# expectation pins.
for i in 1 2; do
  code="$(curl -sS -m 20 -o "${W}/resp.${i}" -w '%{http_code}' -X POST "http://127.0.0.1:${LP}/v1/chat/completions" \
    -H 'Content-Type: application/json' \
    -d '{"model":"test-model","messages":[{"role":"user","content":"ping"}]}')"
  [ "$code" = "200" ] || { cat "${W}/resp.${i}" >&2; fail "request ${i} answered ${code}, not 200; there is no finished request to have exported"; }
done

# The drain is a five-second maintenance tick, so the wait is for the EXPORT and not for the request.
waited=0
until [ "$(curl -s -m 5 "http://127.0.0.1:${CP}/received" | python3 -c 'import json,sys; print(json.load(sys.stdin)["spans"])' 2>/dev/null || echo 0)" -ge 2 ]; do
  waited=$((waited + 1))
  [ "$waited" -lt 40 ] || { cat "${W}/busbar.log" >&2; fail "the collector received fewer than two spans in 40s; what left this process is not what this process observed"; }
  sleep 1
done

kill "$busbar_pid" 2>/dev/null
wait "$busbar_pid" 2>/dev/null

if ! cmp -s "$RECEIVED" "$EXPECTED"; then
  echo "FAIL export.rig|h2-otlp-collector: what a collector received is not what this tree says it exports" >&2
  diff -u "$EXPECTED" "$RECEIVED" >&2
  exit 1
fi
echo "PASS export.rig|h2-otlp-collector: the release binary's spans arrive at a process that speaks OTLP byte-for-byte as expected-spans.json"
