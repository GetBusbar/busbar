#!/usr/bin/env bash
# PGO build creator: produce a profile-guided-optimized busbar binary in three phases.
#
#   1. build instrumented      (-Cprofile-generate)
#   2. train on a traffic MIX  (concurrent + governed: openai chat passthrough at 10x weight,
#                               anthropic-ingress translation, SSE streaming, and an auth-refusal
#                               sliver - all as signed-key Bearer traffic through the keys chain,
#                               against an embedded zero-dependency mock upstream), repeated as
#                               THREE independent trainer runs (fresh gateway process each) whose
#                               raw profiles all feed ONE llvm-profdata merge - see TRAIN_RUNS
#   3. build optimized         (-Cprofile-use)
#
# This is the release build: the layout of the shipped binary is deliberate (profile-guided),
# not the linker's dice roll, and the profile regenerates fresh from THIS source tree on every
# run - nothing is checked in, nothing goes stale. Usage:
#
#   scripts/pgo-build.sh                # binary at target/pgo/release/busbar
#   PGO_REQS=5000 scripts/pgo-build.sh  # more training requests per traffic shape
#   PGO_TARGET=x86_64-unknown-linux-musl scripts/pgo-build.sh
#                                       # cargo --target build; binary at
#                                       # target/pgo/<target>/release/busbar. The instrumented
#                                       # binary must be host-executable (native-arch runners;
#                                       # musl-static runs fine on its build host) - if it
#                                       # isn't, PGO cannot train and the build FAILS (see below).
#
# FAIL-CLOSED RULE: PGO is MANDATORY for every release. If ANY pgo phase fails (instrumented
# build, training run producing no .profraw, profile merge, or the optimized build), the script
# logs LOUDLY why and exits NON-ZERO. It NEVER falls back to a plain `cargo build --release`:
# a release that cannot be PGO-built must fail, not silently ship a non-optimized binary.
#
# On success the binary lands at the SAME deterministic path, echoed on the last line:
#
#   target/pgo/release/busbar                 (no PGO_TARGET)
#   target/pgo/<PGO_TARGET>/release/busbar    (with PGO_TARGET)
#
# POSITIVE PGO PROOF: on success the script writes a marker file next to the binary,
#   target/pgo/<seg>release/busbar.pgo-verified
# recording the merged .profdata path, its byte size, and the .profraw count that fed it. The
# marker is written ONLY after the optimized (-Cprofile-use) build succeeds and only when the
# merged profile is non-empty, so its presence is proof the shipped binary was PGO-optimized.
# The workflow asserts this marker exists and is non-trivial before shipping, so it is impossible
# to ship a non-PGO binary and pass. Every fatal exit removes any stale marker first.
#
# Knobs: PGO_REQS (base request count, default 2000; the openai passthrough volume shape runs
# 10x this so its weight in the merged profile matches its weight in production; each of the
# TRAIN_RUNS trainer runs drives 1/RUN_DIV of every shape - see the constants below), PGO_STREAMS
# (streamed requests, default 200), PGO_CONC (loadgen keep-alive connections, default 32 - the
# middle of the benchmark's c=8..64 range), PGO_PORT / PGO_MOCK_PORT (defaults 18080/18000),
# PGO_TARGET (cargo --target). Requires: cargo, rustup (llvm-tools is installed on demand),
# python3, curl. The training mix mirrors the benchmark suites (perf / xlate / stream) PLUS the
# governed production shape (signed-key auth + group admission + per-principal reqlog); keep the
# shapes in sync when the product grows a new hot path.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

REQS="${PGO_REQS:-2000}"
STREAMS="${PGO_STREAMS:-200}"
CONC="${PGO_CONC:-32}"
# Multi-run profile accumulation - constants, NOT knobs: this is a fixed part of the release
# recipe, not something to tune per build. A single trainer run's edge counters carry sampling
# noise (racy non-atomic increments under concurrency, scheduler-dependent interleavings), and
# that noise is the main residual driver of the build-to-build layout lottery. Running the SAME
# governed mix in TRAIN_RUNS independent trainer runs - a fresh gateway process each time, so
# each run flushes its own .profraw set - and then feeding ALL raw profiles to ONE llvm-profdata
# merge averages the noise: llvm-profdata sums counters across inputs, and the sum of three
# independent samples has a tighter relative error than any single one.
# Wall-time math: each run drives 1/RUN_DIV of every shape's single-run count, so total counted
# requests = TRAIN_RUNS/RUN_DIV = 3/2 = 1.5x the historical single-run volume; with 3x the
# (seconds-scale) gateway boot/teardown, total training wall time lands in the 1.5-2x band.
# Shape weights are ratios, so halving every shape per run preserves the mix exactly.
TRAIN_RUNS=3
RUN_DIV=2
PORT="${PGO_PORT:-18080}"
MOCK_PORT="${PGO_MOCK_PORT:-18000}"
TARGET="${PGO_TARGET:-}"
# Unquoted on use (deliberate - a target triple has no spaces); empty = no --target flag,
# which keeps the historical no-target behavior byte-identical.
TARGET_FLAG="${TARGET:+--target $TARGET}"
# The target-triple path segment cargo inserts under --target-dir when --target is used.
TARGET_SEG="${TARGET:+$TARGET/}"
# BOLT PREREQUISITE: Linux release binaries are linked with --emit-relocs so the shipped ELF keeps
# its relocation sections. scripts/bolt-pass.sh (the post-link layout-optimization pass) REQUIRES
# them: llvm-bolt on aarch64 emits a binary that SEGFAULTS when its input was linked without
# relocations — proven on real hardware, where the same pass over an --emit-relocs build ran clean.
# Harmless on x86_64 (extra .rela.* sections; no code or layout change), so BOTH Linux
# architectures get it rather than one arch quietly differing from the other. Meaningless off
# Linux (ld64/link.exe have no such flag, and BOLT does not apply), hence the gate on the
# EFFECTIVE triple — the explicit --target when given, the host otherwise, so a host build on a
# Linux box gets the same link a --target build does. Applied to the OPTIMIZED build only: the
# instrumented binary trains and is never shipped. release-build.sh's non-PGO arm mirrors this
# (same case, same flag) so the two arms stay byte-identical minus the profile.
EFFECTIVE_TRIPLE="${TARGET:-$(rustc -vV | sed -n 's/^host: //p')}"
case "$EFFECTIVE_TRIPLE" in
  *-linux-*) EMIT_RELOCS="-Clink-arg=-Wl,--emit-relocs" ;;
  *)         EMIT_RELOCS="" ;;
esac
# ARM64 ATOMICS (LSE): rustc's aarch64-linux targets default to the armv8.0 baseline, where every
# atomic RMW compiles to an outline-atomics helper call — measured at 12.1% of self-time on a
# Graviton profile. The DEFAULT arm64 release therefore raises its floor to armv8.1 (+lse: native
# LDADD/CAS/SWP), which every 2016+ arm64 server and desktop core has (Graviton, Ampere, Apple,
# Neoverse, RPi5). Older armv8.0 boards (RPi4-class Cortex-A72) get their own explicitly-suffixed
# `armv8.0` artifact, built with BUSBAR_ARM64_BASELINE=1 — that build IS the historical baseline
# build, byte-for-byte the same recipe minus this flag.
# The flag joins BOTH the instrumented (phase 1) and optimized (phase 3) builds: a profile gathered
# on a different ISA variant than the one it optimizes is a training mismatch. Linux-only gate on
# purpose: aarch64-apple-darwin's default target-cpu already includes LSE, and non-arm64 triples
# have no such feature. Not applied to x86_64 anywhere, so those builds are byte-identical to before.
if [ "${BUSBAR_ARM64_BASELINE:-0}" = "1" ]; then
  LSE_FLAG=""
else
  case "$EFFECTIVE_TRIPLE" in
    aarch64-*-linux-*) LSE_FLAG="-Ctarget-feature=+lse" ;;
    *)                 LSE_FLAG="" ;;
  esac
fi
# THE deterministic output path (see fail-closed rule above).
OUT="target/pgo/${TARGET_SEG}release/busbar"
# Positive-proof marker: written only after a verified PGO build; the workflow gates on it.
MARKER="$OUT.pgo-verified"
PROF_DIR="$(pwd)/target/pgo-profiles"
WORK="$(mktemp -d)"
cleanup() {
  pkill -P $$ 2>/dev/null || true
  [ -n "${BUSBAR_PID:-}" ] && kill "$BUSBAR_PID" 2>/dev/null || true
  [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT
log() { echo "[pgo-build] $*"; }

# The fail-closed arm: log LOUDLY why PGO could not complete and exit NON-ZERO. NEVER fall back
# to a plain build - a release that cannot be PGO-built must fail rather than silently ship a
# non-optimized binary. Removes any stale proof marker so a prior run's marker can never be
# mistaken for this run's (the workflow gates on the marker).
pgo_fail() {
  echo "[pgo-build] ############################################################" >&2
  echo "[pgo-build] # PGO FAILED (FAIL-CLOSED): $*" >&2
  echo "[pgo-build] # PGO is MANDATORY for releases - refusing to ship a non-PGO binary." >&2
  echo "[pgo-build] # This build is BLOCKED. Fix the cause above and re-run; do NOT bypass" >&2
  echo "[pgo-build] # by disabling PGO. Common causes: instrumented binary not host-executable" >&2
  echo "[pgo-build] # (cross target), llvm-tools missing, or the trainer crashing/timing out." >&2
  echo "[pgo-build] ############################################################" >&2
  rm -f "$MARKER" 2>/dev/null || true
  # Stop any training processes a mid-phase failure left behind.
  [ -n "${BUSBAR_PID:-}" ] && kill "$BUSBAR_PID" 2>/dev/null || true
  [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null || true
  BUSBAR_PID=""; MOCK_PID=""
  exit 1
}

# Any stale marker from a previous run must never survive into a fresh run: drop it up front so
# its presence at the end is proof of THIS run's success (belt-and-suspenders with pgo_fail).
rm -f "$MARKER" 2>/dev/null || true

# ---- phase 1: instrumented build ------------------------------------------------------------
log "phase 1/3: instrumented build"
rm -rf "$PROF_DIR"; mkdir -p "$PROF_DIR"
# $LSE_FLAG joins the INSTRUMENTED build too (not just the optimized one): the training profile
# must be gathered on the same ISA variant the optimized build targets, or the profile is a
# statement about a different binary.
# shellcheck disable=SC2086  # TARGET_FLAG is deliberately unquoted (see its definition)
RUSTFLAGS="-Cprofile-generate=$PROF_DIR${LSE_FLAG:+ $LSE_FLAG}" \
  cargo build --release -p busbar $TARGET_FLAG --target-dir target/pgo-gen \
  || pgo_fail "instrumented build failed"
INSTRUMENTED="target/pgo-gen/${TARGET_SEG}release/busbar"
[ -x "$INSTRUMENTED" ] || pgo_fail "instrumented binary missing at $INSTRUMENTED"
# BUILD-TIME PROFRAW PURGE. RUSTFLAGS applies -Cprofile-generate to BUILD SCRIPTS and PROC MACROS
# too (host == target on every runner this trains on), and each one that EXECUTES during the
# build above dumps its own .profraw into $PROF_DIR (the flag's embedded default path). On a
# cold cache that is dozens of files - measured: 57 of a 61-file merge were compile-time dumps,
# and proc_macro2/syn/regex_automata token-loop counters outranked the gateway's real hot path
# in the merged profile. Two harms: shared std/core generics (slice iters, fmt glue) carry the
# SAME symbol+hash in a proc macro and in busbar, so llvm-profdata SUMS compile-time counts into
# serving-path functions and -Cprofile-use lays code out for the noise; and the drift detector's
# trainer ranking drowns in it. A warm cache runs few or no build scripts, so warm and cold
# builds shipped DIFFERENT profiles - the cold one (every CI release) the polluted one. Purge
# everything the build dumped BEFORE any training execution runs; every .profraw that feeds the
# merge after this line comes from the trainer's own invocations of the instrumented binary
# (keygen, --validate, and the per-run gateways). Fail-closed unchanged: the per-run run<N>_*
# flush proofs and the merge-time re-checks below still gate on the files that matter.
rm -f "$PROF_DIR"/*.profraw

# ---- embedded mock upstream (zero deps: python3 stdlib) --------------------------------------
# Speaks just enough OpenAI chat-completions for training: fixed JSON reply, and a paced SSE
# stream when the request body carries "stream": true. Not a test double for correctness - a
# traffic generator's counterparty. The benchmark repo's mock is the real one; this exists so
# the release build has no external checkout dependency.
cat > "$WORK/mock.py" <<'PY'
import http.server, json, time, sys
PORT = int(sys.argv[1])
# ~600 B of completion content (not a 22-byte quip): the response parse/serialize/usage-tap
# paths should train on the body sizes a real completion has.
BODY = json.dumps({
    "id": "chatcmpl-pgo", "object": "chat.completion", "created": 0, "model": "gpt-4o-mini",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": "profile training reply. " * 24},
                  "finish_reason": "stop"}],
    "usage": {"prompt_tokens": 12, "completion_tokens": 96, "total_tokens": 108},
}).encode()
CHUNK = ('data: ' + json.dumps({"id": "chatcmpl-pgo", "object": "chat.completion.chunk",
         "created": 0, "model": "gpt-4o-mini",
         "choices": [{"index": 0, "delta": {"content": "tok "}, "finish_reason": None}]}) + '\n\n').encode()
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        body = self.rfile.read(n)
        if b'"stream": true' in body or b'"stream":true' in body:
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("transfer-encoding", "chunked")
            self.end_headers()
            def w(b):
                self.wfile.write(f"{len(b):x}\r\n".encode() + b + b"\r\n")
            for _ in range(16):
                w(CHUNK); self.wfile.flush(); time.sleep(0.005)
            w(b"data: [DONE]\n\n"); w(b""); self.wfile.flush()
        else:
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(BODY)))
            self.end_headers()
            self.wfile.write(BODY)
class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    # socketserver's default listen backlog is 5: a concurrent trainer ramping its egress pool
    # overflows that, the connect errors trip busbar's breaker, and the run 503s spuriously.
    request_queue_size = 128
S(("127.0.0.1", PORT), H).serve_forever()
PY

# ---- embedded loadgen (zero deps: python3 stdlib) --------------------------------------------
# Replaces the per-request `xargs -P curl` trainer. That loop spawned a fresh process AND a fresh
# TCP connection for every request, which (a) capped training volume at under ~1k req/s of mostly
# fork/exec, and (b) trained the accept/handshake/connection-setup path as if it ran once PER
# REQUEST - when the benchmark that matters (c=8..64 openai passthrough on keep-alive
# connections) runs it approximately never. The counter distribution was the inverse of
# production. This loadgen holds PGO_CONC persistent connections busy, so the tokio scheduler,
# hyper keep-alive read path, and the reqwest egress pool all train under real concurrency
# (instrumented counters are per-edge counts; racy non-atomic drops under contention are
# proportional, so concurrency loses nothing and gains the contended paths). FAIL-CLOSED: any
# response with an unexpected status exits non-zero - the old curl loop never checked status, so
# a trainer that silently 4xx'd every request would have profiled the refusal path as "success".
#   argv: port conc total expected-status path [header=value ...]; body on stdin
cat > "$WORK/loadgen.py" <<'PY'
import http.client, sys, threading, time
PORT, CONC, TOTAL = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
EXPECT, PATH = int(sys.argv[4]), sys.argv[5]
HDRS = {"content-type": "application/json"}
for kv in sys.argv[6:]:
    k, _, v = kv.partition("="); HDRS[k] = v
BODY = sys.stdin.buffer.read()
lock, errs, first = threading.Lock(), [0], [None]
def worker(n):
    conn = http.client.HTTPConnection("127.0.0.1", PORT)
    for _ in range(n):
        status, data = -1, b""
        for _attempt in (0, 1):
            try:
                conn.request("POST", PATH, BODY, HDRS)
                r = conn.getresponse(); data = r.read(); status = r.status
                if r.will_close:  # server said Connection: close (e.g. after a 401): reopen
                    conn.close(); conn = http.client.HTTPConnection("127.0.0.1", PORT)
                break
            except Exception as e:
                # A keep-alive connection the server already closed surfaces as a broken
                # write on the NEXT request: reconnect and retry that request once.
                data = repr(e).encode()
                conn.close(); conn = http.client.HTTPConnection("127.0.0.1", PORT)
        if status != EXPECT:
            with lock:
                errs[0] += 1
                if first[0] is None:
                    first[0] = (status, data[:200])
    conn.close()
base, extra = divmod(TOTAL, CONC)
ts = [threading.Thread(target=worker, args=(base + (1 if i < extra else 0),)) for i in range(CONC)]
t0 = time.time()
for t in ts: t.start()
for t in ts: t.join()
dt = max(time.time() - t0, 1e-9)
print("    %d/%d ok in %.1fs (%d req/s)" % (TOTAL - errs[0], TOTAL, dt, TOTAL / dt), file=sys.stderr)
if errs[0]:
    print("    FIRST FAILURE: status=%s body=%r" % first[0], file=sys.stderr)
    sys.exit(1)
PY

# ---- busbar training config (mirrors the benchmark manifest's shape) -------------------------
# Written per trainer run because each run binds its own port stride (see the training loop);
# everything except the ports is byte-identical across runs.
write_run_configs() {
  local run_port="$1" run_mock_port="$2"
  cat > "$WORK/config.yaml" <<YAML
listen: "127.0.0.1:$run_port"
admin_listen: "127.0.0.1:$((run_port + 1))"
# 1.5.3 grammar. Two keys moved and the old spellings are now fail-closed boot refusals, which is
# how this script broke the 1.5.3 Docker build: PGO is mandatory, the instrumented binary refused
# its own training config, and the release could not produce an image. The trainer must be written
# in the grammar of the binary it trains.
#   observability.emit_server_timing -> advanced.response_headers.server_timing (block DELETED)
#   auth.upstream_credentials        -> pools.upstream_credentials (all-pools default)
advanced:
  response_headers:
    server_timing: true
# Signed-key front door. Production traffic is governed - Bearer bbk_* tokens through the keys
# arm, group admission, per-principal reqlog chains - and with the old empty chain NONE of that
# trained: ed25519 verify, the governance admit/charge, and the governed reqlog branch were laid
# out as cold code (the old "Bearer pgo-token" header was extracted and never verified). The
# trainer mints one throwaway key per run against its own admin listener (the store is
# in-memory, so the binding row only exists inside this process - exactly right for a trainer).
identity-providers:
  admin-tokens: { module: admin-tokens, token: { env: PGO_ADMIN_TOKEN } }
auth:
  chain: [keys]
  admin_auth: [admin-tokens]
  signing_key: { env: PGO_SIGNING_KEY }
# Effectively-unbounded caps: the point is to run the admission check-and-charge path hot, not
# to exercise 429s (the refusal sliver in phase 2 covers the reject arms, lightly).
groups:
  bench:
    limits:
      - { requests: 100000000, per: minute }
      - { concurrent: 4096 }
providers:
  mock:
    api_key: { env: PGO_MOCK_KEY }
models:
  gpt-4o-mini:
    provider: mock
    max_concurrent: 512
    max_requests: -1
pools:
  upstream_credentials: own
  bench-pool:
    members:
      - model: gpt-4o-mini
YAML
  cat > "$WORK/providers.yaml" <<YAML
mock:
  protocol: openai
  base_url: http://127.0.0.1:$run_mock_port
  error_map: {}
YAML
}

# ---- phase 2: train --------------------------------------------------------------------------
# Per-run shape counts: 1/RUN_DIV of the historical single-run mix (see TRAIN_RUNS/RUN_DIV at
# the top). The shapes' RELATIVE weights - openai volume at 10x, large-body and anthropic
# translation at 1x, the stream count, the ~1% refusal sliver - are unchanged; only the absolute
# per-run counts shrink, and the merge sums them back across runs.
#
# SIGNED-TOKEN COVERAGE, verified (do not add a dedicated "signed" shape): every shape below
# ALREADY sends a signed busbar token - the minted bbk_* Bearer/x-api-key credential IS the
# 1.5.0 Ed25519 signed token (there is no other bearer-credential shape), so ed25519 verify,
# the generation gate, AND the per-request hex digesting all train at full volume. The
# drift-check once flagged `hex::ToHex::encode_hex` (the reqlog chain digest, reached via
# ingress finish_inner -> busbar_api::auth::sha256_hex on every governed request) as a trainer
# gap; the calibration profile disproved it - sha256_hex carried one call per counted request
# (8052 across 3 runs at PGO_REQS=400) with 32-iteration hex-loop counters inside - the symbol
# merely INLINES AWAY in the instrumented binary while production's optimized binary outlines
# it. scripts/pgo-drift-check.sh now classifies that case (instrumentation-invisible) instead
# of misreporting it as a scenario gap.
RUN_VOLUME=$((REQS * 10 / RUN_DIV))
RUN_REQS=$((REQS / RUN_DIV))
RUN_STREAMS=$((STREAMS / RUN_DIV))
RUN_REFUSALS=$((REQS / 10 / RUN_DIV))
# The warmup was 500 in the single-run era; it is uncounted overhead paid once per run, so it
# halves per run too (total warmup 750 vs 500 - the extra 250 is part of the 1.5-2x budget).
RUN_WARMUP=$((500 / RUN_DIV))
log "phase 2/3: training ($TRAIN_RUNS runs, c=$CONC, per run: $RUN_VOLUME openai + $RUN_REQS large-body + $RUN_REQS xlate + $RUN_STREAMS streams + $RUN_REFUSALS refusals)"
# The signing key is minted by the instrumented binary itself (offline, needs no config): the
# trainer stays in the grammar of the binary it trains, and the CLI arm gets a profile too.
# One key serves all runs - it is env-provided config, so reusing it keeps the runs identical
# in everything except the counter noise the multi-run merge exists to average out.
PGO_SIGNING_KEY="$("./$INSTRUMENTED" --generate-signing-key 2>/dev/null)"
[ -n "$PGO_SIGNING_KEY" ] || pgo_fail "--generate-signing-key produced no key"
PGO_ADMIN_TOKEN="pgo-admin-$$"
export PGO_SIGNING_KEY PGO_ADMIN_TOKEN

OPENAI_BODY='{"model":"gpt-4o-mini","messages":[{"role":"user","content":"profile training request with a moderately sized body to exercise the parser"}]}'
# ~1.4 KB request-body variant: real prompts are not one-liners, so the ingress parse/copy
# paths get a size distribution instead of a single 130-byte point.
FILLER="$(printf 'profile training filler segment %.0s' $(seq 1 42))"
OPENAI_BODY_LARGE='{"model":"gpt-4o-mini","messages":[{"role":"user","content":"'"$FILLER"'"}]}'
ANTH_BODY='{"model":"gpt-4o-mini","max_tokens":64,"messages":[{"role":"user","content":"profile training request for the translation path"}]}'
STREAM_BODY='{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"streaming profile training"}]}'

# Each iteration is a complete, independent trainer run: fresh mock, fresh gateway process,
# fresh in-memory client key. Each run's gateway gets an explicit per-run LLVM_PROFILE_FILE
# (run<N>_%m_%p.profraw) instead of the toolchain default: rustc's default pattern is %m-only,
# under which same-binary processes ONLINE-merge into a single locked file - counters would
# still accumulate, but no per-run artifact would exist to verify. The explicit per-run name
# makes each run's flush a checkable fact, and the final llvm-profdata merge sums all runs'
# sets. Any failure in any run goes through pgo_fail: multi-run does not soften fail-closed -
# three chances to fail, still zero chances to ship untrained.
for RUN in $(seq 1 "$TRAIN_RUNS"); do
  # Deterministic per-run port stride (+10 per run, both listeners and the mock): back-to-back
  # runs never contend with the previous run's connections lingering in TIME_WAIT, and nothing
  # here depends on wall clock or randomness.
  RUN_PORT=$((PORT + (RUN - 1) * 10))
  RUN_MOCK_PORT=$((MOCK_PORT + (RUN - 1) * 10))
  write_run_configs "$RUN_PORT" "$RUN_MOCK_PORT"
  # Validate the training config with the binary BEFORE serving: this names the failure that the
  # 1.5.3 grammar break (documented at the config above) produced as a silent dead trainer.
  BUSBAR_CONFIG="$WORK/config.yaml" BUSBAR_PROVIDERS="$WORK/providers.yaml" PGO_MOCK_KEY=x \
    "./$INSTRUMENTED" --validate \
    || pgo_fail "run $RUN/$TRAIN_RUNS: training config rejected by the binary it trains (--validate)"
  python3 "$WORK/mock.py" "$RUN_MOCK_PORT" & MOCK_PID=$!
  LLVM_PROFILE_FILE="$PROF_DIR/run${RUN}_%m_%p.profraw" \
    BUSBAR_CONFIG="$WORK/config.yaml" BUSBAR_PROVIDERS="$WORK/providers.yaml" PGO_MOCK_KEY=x \
    "./$INSTRUMENTED" & BUSBAR_PID=$!
  for _ in $(seq 1 50); do
    curl -sf -o /dev/null "http://127.0.0.1:$RUN_PORT/healthz" && break; sleep 0.2
  done
  # The instrumented binary must actually be serving (it may not even be host-executable under a
  # cross PGO_TARGET) - a dead trainer means no profile, so fail loud now rather than merge-fail.
  curl -sf -o /dev/null "http://127.0.0.1:$RUN_PORT/healthz" \
    || pgo_fail "run $RUN/$TRAIN_RUNS: instrumented busbar never became healthy (not host-executable, or crashed)"

  # Mint the run's client key on the admin listener (per run - the key store is in-memory, so it
  # dies with the run's gateway). This also trains the admin plane (admin chain, scope check,
  # mutation limiter, audit) - one warm request on an otherwise-cold surface, now once per run.
  CLIENT_TOKEN="$(curl -sS -X POST "http://127.0.0.1:$((RUN_PORT + 1))/api/v1/admin/keys" \
    -H "authorization: Bearer $PGO_ADMIN_TOKEN" -H "content-type: application/json" \
    -d '{"name":"pgo","group":"bench","expires_in":"1h"}' \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')" \
    || pgo_fail "run $RUN/$TRAIN_RUNS: key mint on the admin listener failed"
  case "$CLIENT_TOKEN" in bbk_*) ;; *) pgo_fail "run $RUN/$TRAIN_RUNS: minted client token malformed: '$CLIENT_TOKEN'" ;; esac

  # warmup (uncounted): ramp the reqwest egress pool and let reliability state learn the lane
  # healthy BEFORE the volume shape, so training measures steady state, not cold-start ramp.
  printf '%s' "$OPENAI_BODY" | python3 "$WORK/loadgen.py" "$RUN_PORT" "$CONC" "$RUN_WARMUP" 200 \
    /v1/chat/completions "authorization=Bearer $CLIENT_TOKEN" \
    || pgo_fail "run $RUN/$TRAIN_RUNS: training warmup failed"
  # shape 1: openai chat passthrough at 10x weight - THE volume path; its share of the merged
  # profile's counts should match its share of production load, so branch statistics and the
  # hot/cold split are decided by this shape.
  printf '%s' "$OPENAI_BODY" | python3 "$WORK/loadgen.py" "$RUN_PORT" "$CONC" "$RUN_VOLUME" 200 \
    /v1/chat/completions "authorization=Bearer $CLIENT_TOKEN" \
    || pgo_fail "run $RUN/$TRAIN_RUNS: training shape 1 (openai chat) failed"
  log "  run $RUN/$TRAIN_RUNS: shape 1 (openai chat x$RUN_VOLUME) done"
  printf '%s' "$OPENAI_BODY_LARGE" | python3 "$WORK/loadgen.py" "$RUN_PORT" "$CONC" "$RUN_REQS" 200 \
    /v1/chat/completions "authorization=Bearer $CLIENT_TOKEN" \
    || pgo_fail "run $RUN/$TRAIN_RUNS: training shape 1b (openai chat, large body) failed"
  log "  run $RUN/$TRAIN_RUNS: shape 1b (openai chat, large body) done"
  # shape 2: anthropic ingress -> openai upstream (the translation path). x-api-key, not Bearer:
  # that is what real anthropic-dialect clients send, and it trains the second extractor branch.
  printf '%s' "$ANTH_BODY" | python3 "$WORK/loadgen.py" "$RUN_PORT" "$CONC" "$RUN_REQS" 200 \
    /v1/messages "x-api-key=$CLIENT_TOKEN" "anthropic-version=2023-06-01" \
    || pgo_fail "run $RUN/$TRAIN_RUNS: training shape 2 (anthropic translation) failed"
  log "  run $RUN/$TRAIN_RUNS: shape 2 (anthropic translation) done"
  # shape 3: SSE streaming relay (the loadgen's read() drains the chunked event stream to
  # completion, so the relay's full write-flush-finish path trains, not just the headers).
  printf '%s' "$STREAM_BODY" | python3 "$WORK/loadgen.py" "$RUN_PORT" "$CONC" "$RUN_STREAMS" 200 \
    /v1/chat/completions "authorization=Bearer $CLIENT_TOKEN" \
    || pgo_fail "run $RUN/$TRAIN_RUNS: training shape 3 (SSE streaming) failed"
  log "  run $RUN/$TRAIN_RUNS: shape 3 (SSE streaming) done"
  # shape 4: refusal sliver (~1% of the mix, expects 401): biases the verify branch correctly
  # (valid overwhelmingly likely) while still giving the reject/finish_rejected arms real counts
  # instead of zero - small enough that refusal code is not promoted into the hot layout.
  printf '%s' "$OPENAI_BODY" | python3 "$WORK/loadgen.py" "$RUN_PORT" "$CONC" "$RUN_REFUSALS" 401 \
    /v1/chat/completions "authorization=Bearer bbk_bogus.bogus" \
    || pgo_fail "run $RUN/$TRAIN_RUNS: training shape 4 (auth refusal) failed"
  log "  run $RUN/$TRAIN_RUNS: shape 4 (auth refusal) done"

  # graceful stop so the runtime flushes this run's .profraw files before the next run boots
  kill "$BUSBAR_PID"; wait "$BUSBAR_PID" 2>/dev/null || true; BUSBAR_PID=""
  kill "$MOCK_PID" 2>/dev/null || true; wait "$MOCK_PID" 2>/dev/null || true; MOCK_PID=""
  # Per-run flush proof: the run's gateway must have written its named .profraw set. A run that
  # served traffic but flushed nothing would silently thin the merge below the designed three
  # samples - fail closed here, attributed to the run that lost its profile.
  ls "$PROF_DIR"/run"${RUN}"_*.profraw >/dev/null 2>&1 \
    || pgo_fail "run $RUN/$TRAIN_RUNS flushed no .profraw (gateway exited without writing its profile)"
  log "  run $RUN/$TRAIN_RUNS complete (.profraw flushed)"
done

# ---- phase 3: merge + optimized build --------------------------------------------------------
log "phase 3/3: merge profiles + optimized build"
rustup component add llvm-tools >/dev/null 2>&1 || true
PROFDATA="$(find "$(rustc --print sysroot)" -name llvm-profdata -type f | head -1)"
[ -n "$PROFDATA" ] || pgo_fail "llvm-profdata not found (rustup component add llvm-tools)"
ls "$PROF_DIR"/*.profraw >/dev/null 2>&1 \
  || pgo_fail "no .profraw files produced (instrumented run flushed nothing)"
# Re-verify every trainer run's named .profraw set still exists at merge time (each run already
# asserted its own flush; this catches anything deleting profiles between training and merge).
# Note the raw-file COUNT is not a per-run invariant: the keygen/--validate invocations use the
# toolchain's default %m-only pattern, under which same-binary processes online-merge into one
# locked file - only the run<N>_ sets are guaranteed one-per-run.
for RUN in $(seq 1 "$TRAIN_RUNS"); do
  ls "$PROF_DIR"/run"${RUN}"_*.profraw >/dev/null 2>&1 \
    || pgo_fail "run $RUN/$TRAIN_RUNS .profraw set missing at merge time"
done
RAW_COUNT="$(find "$PROF_DIR" -maxdepth 1 -name '*.profraw' -type f | wc -l | tr -d ' ')"
MERGED="$PROF_DIR/merged.profdata"
# ONE merge over ALL runs' raw profiles: llvm-profdata sums the edge counters across the
# accumulated per-run sets, which is exactly the noise-averaging the multi-run design buys.
"$PROFDATA" merge -o "$MERGED" "$PROF_DIR"/*.profraw \
  || pgo_fail "llvm-profdata merge failed"
# The merged profile is what -Cprofile-use consumes; an empty/absent one means the optimized
# build below would silently be a no-op PGO. Assert it is real BEFORE the build feeds it in.
[ -s "$MERGED" ] || pgo_fail "merged profile is empty/missing at $MERGED (training produced no usable coverage)"
MERGED_SIZE="$(wc -c < "$MERGED" | tr -d ' ')"

# BUSBAR_PGO=1 stamps the BUILD-PROVENANCE record (crates/busbar/build.rs) so the shipped binary
# self-reports `pgo=true` via `busbar --build-info` / `--version`. This is belt-and-suspenders: the
# build script ALSO detects `-Cprofile-use` in CARGO_ENCODED_RUSTFLAGS, so PGO is recorded even if
# this env is ever dropped — but the explicit signal is the contract. A plain `cargo build --release`
# sets neither and correctly reports `pgo=false`, which is the whole point of the stamp.
# $EMIT_RELOCS rides along on Linux targets only — the BOLT prerequisite documented at its
# definition near the top of this file. $LSE_FLAG (arm64 default only; see its definition) joins
# here exactly as it joined the instrumented build, and BOLT's emit-relocs path is unchanged by it.
# shellcheck disable=SC2086  # TARGET_FLAG is deliberately unquoted (see its definition)
BUSBAR_PGO=1 RUSTFLAGS="-Cprofile-use=$MERGED${EMIT_RELOCS:+ $EMIT_RELOCS}${LSE_FLAG:+ $LSE_FLAG}" \
  cargo build --release -p busbar $TARGET_FLAG --target-dir target/pgo \
  || pgo_fail "optimized (-Cprofile-use) build failed"
[ -x "$OUT" ] || pgo_fail "optimized binary missing at $OUT"

# POSITIVE VERIFICATION: write the proof marker only now - after a non-empty merged profile was
# fed to a successful -Cprofile-use build. Its existence (checked by the workflow) is proof the
# shipped binary is PGO-optimized. Guard the merged profile is STILL non-empty at write time.
[ -s "$MERGED" ] || pgo_fail "merged profile vanished before marker write at $MERGED"
{
  echo "pgo-verified=1"
  echo "profile=$MERGED"
  echo "profile_bytes=$MERGED_SIZE"
  echo "profraw_count=$RAW_COUNT"
  echo "target=${TARGET:-<host>}"
  # Which ISA variant this arm64 binary is: `+lse` (armv8.1 floor, the default arm64 artifact) or
  # `baseline` (armv8.0-compatible, the explicitly-suffixed compat artifact / any non-arm64 target).
  # Extra marker keys are ignored by older readers; verify-artifact.py's pgo_applied row parses
  # key=value lines generically.
  echo "target_features=${LSE_FLAG:+lse}"
  echo "arm64_baseline=${BUSBAR_ARM64_BASELINE:-0}"
  echo "train_runs=$TRAIN_RUNS"
  echo "reqs_per_shape=$REQS"
  echo "streams=$STREAMS"
  echo "built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$MARKER" || pgo_fail "could not write proof marker at $MARKER"
[ -s "$MARKER" ] || pgo_fail "proof marker empty after write at $MARKER"

log "done: $OUT"
log "PGO VERIFIED: marker=$MARKER profile=$MERGED (${MERGED_SIZE} bytes from ${RAW_COUNT} .profraw)"
echo "$OUT"
