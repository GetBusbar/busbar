#!/usr/bin/env bash
# proto-deletion-gate.sh — THE DELETION TEST, run for real: build busbar WITHOUT the extracted
# anthropic protocol crate and prove the deletion at three levels. "Delete a protocol and the app
# never knew it existed" is the acceptance test the whole plugin seam is measured by
# (design/one-core-mcp-a2a-as-protocols.md; GOAL orchestration R-D upgrades it from build-proof to
# BOOT-proof: no/fewer protocols is a valid busbar, and it must SERVE, not merely compile).
#
# LEVELS
#   1. STATIC   — core's sources never name a protocol crate: the underscore crate-name grep over
#                 crates/busbar-core/src is exactly zero (core-split exit criterion 7).
#   2. BUILD    — `cargo build -p busbar` with the `proto-anthropic` feature OFF produces a binary.
#                 The dependency edge and the registration line are gated by the same feature, so
#                 this is a complete deletion, not a stubbed one.
#   3. BOOT     — the deleted binary:
#                 a. REFUSES a config naming `protocol: anthropic` under `--validate`, with the
#                    unknown-protocol refusal naming the remaining five dialects and NOT anthropic
#                    (config_validate's registry-derived arm — the refusal the empty-set red test
#                    pinned, firing on the unknown-name branch);
#                 b. ACCEPTS the same config re-pointed at `protocol: openai` (the other dialects
#                    still serve);
#                 c. BOOTS with the openai config and ANSWERS: /healthz 200 and /stats 200 (the
#                    operator surface is alive), while the anthropic-format ingress path
#                    (POST /v1/messages) resolves to NO handler (non-2xx), because the dialect that
#                    served it is not in the build.
#   CONTROL     — the DEFAULT build (feature on) accepts the anthropic config, proving the gate
#                 measures the feature edge and not a broken fixture.
#
# WATCHED RED: run against the pre-extraction tree (anthropic still a core built-in), level 3a
# fails — the featureless build still accepts `protocol: anthropic` — which is the red that makes
# this gate's green evidence. See the gate's landing commit for the recorded red run.
#
# A separate CARGO_TARGET_DIR keeps the deleted-feature build from thrashing the default target
# dir's artifacts (feature flips would otherwise rebuild the workspace twice per developer loop).
set -uo pipefail
cd "$(dirname "$0")/.."

note() { printf '  %s\n' "$1"; }
die()  { printf 'proto-deletion-gate: FAIL — %s\n' "$1"; exit 1; }

# ── level 1: static ──────────────────────────────────────────────────────────────────────────────
if git grep -q "busbar_proto" -- crates/busbar-core/src; then
  git grep -n "busbar_proto" -- crates/busbar-core/src
  die "crates/busbar-core/src names a protocol crate; the seam only means something if core cannot"
fi
note "level 1 static: core names no protocol crate (grep count 0)"

# ── level 2: the deleted build ───────────────────────────────────────────────────────────────────
DEL_TARGET="target/deletion-gate"
note "level 2 build: cargo build -p busbar --no-default-features --features auth-admin-tokens,hooks-ranking"
CARGO_TARGET_DIR="$DEL_TARGET" cargo build -q -p busbar \
  --no-default-features --features "auth-admin-tokens,hooks-ranking" \
  || die "the busbar binary must build with the anthropic protocol crate deleted"
DELETED_BIN="$DEL_TARGET/debug/busbar"
[ -x "$DELETED_BIN" ] || die "deleted-build binary not found at $DELETED_BIN"
note "level 2 build: ok ($DELETED_BIN)"

# ── fixtures ─────────────────────────────────────────────────────────────────────────────────────
FIX=$(mktemp -d "${TMPDIR:-/tmp}/proto-deletion-gate.XXXXXX")
trap 'rm -rf "$FIX"; [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null' EXIT
mk_configs() { # $1 = protocol, $2 = listen
  cat > "$FIX/providers.yaml" <<EOF
mock:
  protocol: $1
  base_url: "http://127.0.0.1:9"
  api_key_env: MOCK_KEY
EOF
  cat > "$FIX/config.yaml" <<EOF
listen: "$2"
providers:
  mock:
    api_key: { env: MOCK_KEY }
models:
  test-model:
    provider: mock
EOF
}
run_busbar() { # binary, args... ; env comes from the fixture
  MOCK_KEY=test-key BUSBAR_SIGNING_KEY=0000000000000000000000000000000000000000000000000000000000000001 \
  BUSBAR_CONFIG="$FIX/config.yaml" BUSBAR_PROVIDERS="$FIX/providers.yaml" "$@"
}

# ── level 3a: the deleted binary refuses protocol: anthropic, naming the cause ───────────────────
mk_configs anthropic "127.0.0.1:0"
OUT=$(run_busbar "$DELETED_BIN" --validate 2>&1); RC=$?
if [ $RC -eq 0 ]; then
  die "the deleted binary ACCEPTED a config naming protocol: anthropic (the deletion changed nothing)"
fi
echo "$OUT" | grep -q "unknown protocol 'anthropic'" \
  || die "the refusal must NAME the unknown protocol; got: $OUT"
echo "$OUT" | grep -q "must be one of: openai, gemini, bedrock, responses, cohere" \
  || die "the refusal must name the five remaining dialects (and not anthropic); got: $OUT"
note "level 3a refusal: 'unknown protocol anthropic — must be one of: openai, gemini, bedrock, responses, cohere' (exit $RC)"

# ── level 3b: the remaining dialects still validate ──────────────────────────────────────────────
mk_configs openai "127.0.0.1:0"
OUT=$(run_busbar "$DELETED_BIN" --validate 2>&1) || die "the deleted binary must accept an openai config; got: $OUT"
note "level 3b remaining dialects: openai config validates clean"

# ── level 3c: the deleted binary BOOTS and answers (R-D: fewer protocols is a valid busbar) ──────
PORT=$(( (RANDOM % 20000) + 30000 ))
mk_configs openai "127.0.0.1:$PORT"
run_busbar "$DELETED_BIN" >"$FIX/boot.log" 2>&1 &
SRV_PID=$!
up=""
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then up=1; break; fi
  kill -0 "$SRV_PID" 2>/dev/null || break
  sleep 0.5
done
[ -n "$up" ] || { cat "$FIX/boot.log"; die "the deleted binary did not come up on /healthz"; }
curl -fsS "http://127.0.0.1:$PORT/stats" >/dev/null || die "/stats must answer on the deleted binary"
MSG_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$PORT/v1/messages" \
  -H 'content-type: application/json' -d '{"model":"test-model","max_tokens":8,"messages":[]}')
case "$MSG_CODE" in
  2*) die "POST /v1/messages answered $MSG_CODE on a build with no anthropic dialect" ;;
esac
kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; SRV_PID=""
note "level 3c boot: /healthz 200, /stats 200, anthropic-format ingress answers $MSG_CODE (no handler)"

# ── control: the default build (feature ON) accepts the anthropic config ─────────────────────────
note "control: cargo build -p busbar (default features)"
cargo build -q -p busbar || die "default build failed"
mk_configs anthropic "127.0.0.1:0"
OUT=$(run_busbar target/debug/busbar --validate 2>&1) \
  || die "the DEFAULT build must accept protocol: anthropic (gate would be measuring a broken fixture); got: $OUT"
note "control: default build accepts protocol: anthropic"

echo "proto-deletion-gate: PASS (static 0, deleted build boots+serves, anthropic refused by name, five dialects remain, control green)"
