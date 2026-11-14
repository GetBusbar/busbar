#!/usr/bin/env bash
# pgo-workload.sh - ONE training run of the release profile workload against a given busbar binary.
#
#   scripts/pgo-workload.sh --binary <path> --run <n> [--runs <total>]
#
# The single definition of "representative traffic" for both profile-guided passes:
#   * PGO  - scripts/pgo-build.sh runs it TRAIN_RUNS times against the -Cprofile-generate binary,
#            with LLVM_PROFILE_FILE set by the caller (inherited by every process started here);
#   * BOLT - the CI training job runs it against the `llvm-bolt -instrument` rewrite of the
#            PGO-optimized binary, whose counters are written when the gateway exits gracefully.
# One workload for both is the point: a BOLT layout trained on different traffic than the PGO
# layout it refines would undo the first pass's decisions.
#
# The gateway is stopped GRACEFULLY (SIGTERM, then wait) at the end, so both instrumentation
# runtimes flush. Run <n> binds ports PGO_PORT+10(n-1) / PGO_MOCK_PORT+10(n-1), so back-to-back
# runs never contend with lingering TIME_WAIT connections.
#
# FAIL-CLOSED: any refused config, unhealthy gateway, failed key mint or any window that does not
# serve (or, for the refusal sliver, refuse) every request exits non-zero, naming the pair.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

INSTRUMENTED="" RUN="" TRAIN_RUNS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --binary) INSTRUMENTED="${2:?--binary needs a path}"; shift 2 ;;
    --run)    RUN="${2:?--run needs a number}"; shift 2 ;;
    --runs)   TRAIN_RUNS="${2:?--runs needs a number}"; shift 2 ;;
    *) echo "pgo-workload.sh: unknown argument '$1'" >&2; exit 2 ;;
  esac
done
[ -n "$INSTRUMENTED" ] && [ -x "$INSTRUMENTED" ] || { echo "pgo-workload.sh: --binary must name an executable (got '$INSTRUMENTED')" >&2; exit 2; }
case "$RUN" in ''|*[!0-9]*) echo "pgo-workload.sh: --run must be a positive integer" >&2; exit 2 ;; esac
TRAIN_RUNS="${TRAIN_RUNS:-$RUN}"
case "$INSTRUMENTED" in /*) ;; *) INSTRUMENTED="$(pwd)/$INSTRUMENTED" ;; esac

CONC="${PGO_CONC:-32}"
PORT="${PGO_PORT:-18080}"
MOCK_PORT="${PGO_MOCK_PORT:-18000}"
WORK="$(mktemp -d)"
BUSBAR_PID="" MOCK_PID=""
cleanup() {
  [ -n "${BUSBAR_PID:-}" ] && kill "$BUSBAR_PID" 2>/dev/null || true
  [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT
log() { echo "[pgo-workload] $*"; }
pgo_fail() {
  echo "[pgo-workload] # TRAINING FAILED (FAIL-CLOSED): $*" >&2
  exit 1
}

# ---- the training rig: the benchmark's own mock and load generator -----------------------------
# The trainer drives the GetBusbar/benchmarking rig, not a stand-in: `mock` (one hyper server that
# answers all six wire protocols by request path, static bytes, the request body drained) and
# `otb loadgen` (holds <conc> keep-alive connections busy for <secs>, prints one stats line). Training
# against the instrument the board is measured with means the profile is laid out for the traffic the
# benchmark publishes - every egress codec, not just the OpenAI one the old embedded python mock
# could answer. Both are BUILT BY THE CALLER, READ-ONLY, at the benchmarking repository's ENGINE_PIN
# commit (the frozen instrument every board row is measured with; training never edits it), and are
# passed in by path:
#   PGO_BENCH_MOCK=<path to the benchmarking `mock` binary>
#   PGO_BENCH_OTB=<path to the benchmarking `otb` binary>
# The CI training job builds them (cargo --locked at ENGINE_PIN) and records the pin beside the profile.
# A local run builds them the same way:
#   git clone https://github.com/GetBusbar/benchmarking && git -C benchmarking checkout \
#     "$(head -1 benchmarking/ENGINE_PIN)" && cargo build --release --locked \
#     --manifest-path benchmarking/mock/Cargo.toml && cargo build --release --locked \
#     --manifest-path benchmarking/engine/Cargo.toml --bin otb
# FAIL-CLOSED: training without them is refused, never silently swapped for a different rig.
BENCH_MOCK="${PGO_BENCH_MOCK:-}"
BENCH_OTB="${PGO_BENCH_OTB:-}"
[ -n "$BENCH_MOCK" ] && [ -x "$BENCH_MOCK" ] \
  || pgo_fail "PGO_BENCH_MOCK must name the benchmarking mock binary (got '${BENCH_MOCK}'); training needs the benchmark's own upstream"
[ -n "$BENCH_OTB" ] && [ -x "$BENCH_OTB" ] \
  || pgo_fail "PGO_BENCH_OTB must name the benchmarking otb binary (got '${BENCH_OTB}'); training needs the benchmark's own load generator"

# ---- busbar training config (mirrors the benchmark manifest's shape) -------------------------
# Written per trainer run because each run binds its own port stride (see the training loop);
# everything except the ports is byte-identical across runs.
. scripts/pgo-config.sh

# ---- the ingress side of the grid: one row per client dialect ---------------------------------
# The same table the benchmark engine holds (engine/src/ingress.rs: path, body, auth_headers), so
# every one of the 36 ingress x egress pairs the board publishes is driven. Gemini and bedrock carry
# the model in the PATH; the rest in the body. Credentials travel in OTB_LOADGEN_HEADERS (JSON), in
# the environment, never on argv, where `ps` would show the run's live key to every user on the box.
PGO_INGRESS_DIALECTS="openai responses anthropic gemini cohere bedrock"
ingress_path() { # ingress_path <dialect> <model>
  case "$1" in
    openai)    printf '/v1/chat/completions' ;;
    responses) printf '/v1/responses' ;;
    anthropic) printf '/v1/messages' ;;
    gemini)    printf '/v1beta/models/%s:generateContent' "$2" ;;
    cohere)    printf '/v2/chat' ;;
    bedrock)   printf '/model/%s/converse' "$2" ;;
  esac
}
# ingress_body <dialect> <model> <text> [stream]: the benchmark's probe body, with the content
# replaced by <text> so the large-body shape is the same request at a realistic prompt size.
ingress_body() {
  local s="" m="$2" t="$3"
  [ "${4:-}" = stream ] && s='"stream":true,'
  case "$1" in
    openai)    printf '{%s"model":"%s","messages":[{"role":"user","content":"%s"}],"max_tokens":16}' "$s" "$m" "$t" ;;
    responses) printf '{%s"model":"%s","input":"%s"}' "$s" "$m" "$t" ;;
    anthropic) printf '{%s"model":"%s","max_tokens":64,"messages":[{"role":"user","content":"%s"}]}' "$s" "$m" "$t" ;;
    gemini)    printf '{%s"contents":[{"parts":[{"text":"%s"}]}]}' "$s" "$t" ;;
    cohere)    printf '{%s"model":"%s","messages":[{"role":"user","content":"%s"}]}' "$s" "$m" "$t" ;;
    bedrock)   printf '{%s"messages":[{"role":"user","content":[{"text":"%s"}]}]}' "$s" "$t" ;;
  esac
}
ingress_headers() { # ingress_headers <dialect> <credential> -> OTB_LOADGEN_HEADERS JSON
  case "$1" in
    anthropic) printf '[["x-api-key","%s"],["anthropic-version","2023-06-01"]]' "$2" ;;
    gemini)    printf '[["x-goog-api-key","%s"]]' "$2" ;;
    *)         printf '[["authorization","Bearer %s"]]' "$2" ;;
  esac
}

# drive <label> <expect: ok|refused> <secs> <ingress> <model> <body>: one otb loadgen window at
# c=$CONC on keep-alive connections. FAIL-CLOSED on the stats line: an `ok` window must have served
# requests and failed none (a trainer that silently 4xx'd would profile the refusal path as success);
# a `refused` window must have refused every request it sent.
drive() {
  local label="$1" expect="$2" secs="$3" ing="$4" model="$5" body="$6" line ok fail
  line="$(OTB_LOADGEN_HEADERS="$HDRS" "$BENCH_OTB" loadgen "127.0.0.1:$RUN_PORT" \
    "$(ingress_path "$ing" "$model")" "$CONC" "$secs" "$body" 2>"$WORK/loadgen.err")" \
    || pgo_fail "run $RUN/$TRAIN_RUNS: $label: otb loadgen exited non-zero ($(head -c 300 "$WORK/loadgen.err"))"
  ok="$(printf '%s' "$line" | sed -n 's/.* ok=\([0-9]*\).*/\1/p')"
  fail="$(printf '%s' "$line" | sed -n 's/.*fail=\([0-9]*\).*/\1/p')"
  [ -n "$ok" ] && [ -n "$fail" ] || pgo_fail "run $RUN/$TRAIN_RUNS: $label: unreadable loadgen stats line: $line"
  case "$expect" in
    ok)      [ "$ok" -gt 0 ] && [ "$fail" -eq 0 ] \
               || pgo_fail "run $RUN/$TRAIN_RUNS: $label: expected every request served, got ok=$ok fail=$fail ($line)" ;;
    refused) [ "$ok" -eq 0 ] && [ "$fail" -gt 0 ] \
               || pgo_fail "run $RUN/$TRAIN_RUNS: $label: expected every request refused, got ok=$ok fail=$fail ($line)" ;;
  esac
  log "  run $RUN/$TRAIN_RUNS: $label ok=$ok fail=$fail"
}

# ---- the mix --------------------------------------------------------------------------
# THE MIX, in seconds of keep-alive load per trainer run (UNIT = PGO_UNIT_SECS, default 2):
#   openai -> openai          10 units  THE volume path; its share of the merged counters should
#                                       match its share of production, so it decides hot/cold
#   openai -> openai, ~1.4 KB  1 unit   real prompts are not one-liners: a size distribution for
#                                       the ingress parse/copy paths instead of one 130-byte point
#   every other pair (35)      1 unit   each ingress codec x each egress codec, translation included
#   SSE streams (4 pairs)      2 units  {openai, anthropic} ingress x {openai, anthropic} egress, the
#                                       pairs the mock streams natively (engine streams_natively)
#   refusal sliver             1 unit   a bogus bbk_ token: biases the verify branch (valid is
#                                       overwhelmingly likely) while the reject arms get real counts
# Duration windows rather than request counts: the benchmark's loadgen is duration-driven, and the
# shape RATIOS are what the profile encodes. The merge sums counters across TRAIN_RUNS runs.
UNIT="${PGO_UNIT_SECS:-2}"
log "run $RUN/$TRAIN_RUNS: training (c=$CONC, unit=${UNIT}s, 36-pair grid + streams + refusals, benchmarking rig $BENCH_MOCK)"
# The signing key is minted by the instrumented binary itself (offline, needs no config): the
# trainer stays in the grammar of the binary it trains, and the CLI arm gets a profile too.
PGO_SIGNING_KEY="$("$INSTRUMENTED" --generate-signing-key 2>/dev/null)"
[ -n "$PGO_SIGNING_KEY" ] || pgo_fail "--generate-signing-key produced no key"
PGO_ADMIN_TOKEN="pgo-admin-$$"
# The benchmark manifest's own upstream credentials (gateways/busbar/env): the mock ignores them,
# bedrock's is an access-key:secret pair so its signer runs exactly as against AWS.
PGO_MOCK_KEY=dummy
PGO_BEDROCK_KEY="AKIAMOCKACCESSKEY:mock-secret-access-key"
export PGO_SIGNING_KEY PGO_ADMIN_TOKEN PGO_MOCK_KEY PGO_BEDROCK_KEY

FILLER="$(printf 'profile training filler segment %.0s' $(seq 1 42))"

# Deterministic per-run port stride (+10 per run, both listeners and the mock): back-to-back
# runs never contend with the previous run's connections lingering in TIME_WAIT.
RUN_PORT=$((PORT + (RUN - 1) * 10))
RUN_MOCK_PORT=$((MOCK_PORT + (RUN - 1) * 10))
write_run_configs "$RUN_PORT" "$RUN_MOCK_PORT"
# Validate the training config with the binary BEFORE serving: this names the failure that the
# 1.5.3 grammar break (documented in pgo-config.sh) produced as a silent dead trainer.
BUSBAR_CONFIG="$WORK/config.yaml" BUSBAR_PROVIDERS="$WORK/providers.yaml" \
  "$INSTRUMENTED" --validate \
  || pgo_fail "run $RUN/$TRAIN_RUNS: training config rejected by the binary it trains (--validate)"
# A short, fixed stream pace: the relay's write/flush/finish path trains per frame, and a
# 64 x 20 ms default stream would spend the window asleep.
MOCK_STREAM_CHUNKS=16 MOCK_STREAM_INTERVAL_MS=5 "$BENCH_MOCK" -port "$RUN_MOCK_PORT" \
  >"$WORK/mock.log" 2>&1 & MOCK_PID=$!
BUSBAR_CONFIG="$WORK/config.yaml" BUSBAR_PROVIDERS="$WORK/providers.yaml" \
  "$INSTRUMENTED" & BUSBAR_PID=$!
for _ in $(seq 1 50); do
  curl -sf -o /dev/null "http://127.0.0.1:$RUN_PORT/healthz" && break; sleep 0.2
done
curl -sf -o /dev/null "http://127.0.0.1:$RUN_PORT/healthz" \
  || pgo_fail "run $RUN/$TRAIN_RUNS: instrumented busbar never became healthy (not host-executable, or crashed)"

# Mint the run's client key on the admin listener (the key store is in-memory, so it dies with
# the run's gateway). The admin bearer goes in a header file inside $WORK, not on curl's argv.
printf 'authorization: Bearer %s\n' "$PGO_ADMIN_TOKEN" > "$WORK/admin-hdr"
CLIENT_TOKEN="$(curl -sS -X POST "http://127.0.0.1:$((RUN_PORT + 1))/api/v1/admin/keys" \
  -H @"$WORK/admin-hdr" -H "content-type: application/json" \
  -d '{"name":"pgo","group":"bench","expires_in":"1h"}' \
  | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')" \
  || pgo_fail "run $RUN/$TRAIN_RUNS: key mint on the admin listener failed"
# The malformed-token message reports the SHAPE, never the value.
case "$CLIENT_TOKEN" in
  bbk_*) ;;
  *) pgo_fail "run $RUN/$TRAIN_RUNS: minted client token malformed (${#CLIENT_TOKEN} chars, starts '$(printf '%.4s' "$CLIENT_TOKEN")', expected a bbk_ prefix)" ;;
esac

# warmup (uncounted in intent, short): ramp the egress pool and let reliability state learn the
# lane healthy BEFORE the volume shape, so training measures steady state, not cold-start ramp.
HDRS="$(ingress_headers openai "$CLIENT_TOKEN")"
drive "warmup" ok 1 openai gpt-4o-mini "$(ingress_body openai gpt-4o-mini hello)"
drive "openai->openai (volume)" ok $((UNIT * 10)) openai gpt-4o-mini "$(ingress_body openai gpt-4o-mini hello)"
drive "openai->openai (large body)" ok "$UNIT" openai gpt-4o-mini "$(ingress_body openai gpt-4o-mini "$FILLER")"
for ING in $PGO_INGRESS_DIALECTS; do
  HDRS="$(ingress_headers "$ING" "$CLIENT_TOKEN")"
  for EG in $PGO_EGRESS_DIALECTS; do
    [ "$ING" = openai ] && [ "$EG" = openai ] && continue
    M="$(pgo_model_for "$EG")"
    drive "$ING->$EG" ok "$UNIT" "$ING" "$M" "$(ingress_body "$ING" "$M" hello)"
  done
done
for ING in openai anthropic; do
  HDRS="$(ingress_headers "$ING" "$CLIENT_TOKEN")"
  for EG in openai anthropic; do
    M="$(pgo_model_for "$EG")"
    drive "$ING->$EG (SSE)" ok $((UNIT * 2)) "$ING" "$M" "$(ingress_body "$ING" "$M" hello stream)"
  done
done
HDRS="$(ingress_headers openai bbk_bogus.bogus)"
drive "auth refusal" refused "$UNIT" openai gpt-4o-mini "$(ingress_body openai gpt-4o-mini hello)"

# graceful stop so the runtime flushes this run's .profraw files before the next run boots
kill "$BUSBAR_PID"; wait "$BUSBAR_PID" 2>/dev/null || true; BUSBAR_PID=""
kill "$MOCK_PID" 2>/dev/null || true; wait "$MOCK_PID" 2>/dev/null || true; MOCK_PID=""
log "run $RUN/$TRAIN_RUNS complete"
