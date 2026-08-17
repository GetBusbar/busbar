#!/usr/bin/env bash
# proto-deletion-gate.sh — THE DELETION TEST, run for real: build busbar WITHOUT an extracted
# protocol crate and prove the deletion at three levels, for EACH extracted dialect in turn.
# "Delete a protocol and the app never knew it existed" is the acceptance test the whole plugin
# seam is measured by (design/one-core-mcp-a2a-as-protocols.md; GOAL orchestration R-D upgrades it
# from build-proof to BOOT-proof: no/fewer protocols is a valid busbar, and it must SERVE, not
# merely compile).
#
# LEVELS (per dialect)
#   1. STATIC   — core's sources never name a protocol crate: the underscore crate-name grep over
#                 crates/busbar-core/src is exactly zero (core-split exit criterion 7). Checked
#                 ONCE, up front — it is a property of the whole tree, not any one dialect.
#   2. BUILD    — `cargo build -p busbar` with the dialect's OWN feature OFF (every other extracted
#                 dialect's feature stays ON) produces a binary. The dependency edge and the
#                 registration line are gated by the same feature, so this is a complete deletion of
#                 ONE dialect, not a stubbed one and not an accidental multi-dialect deletion.
#   3. BOOT     — the deleted binary:
#                 a. REFUSES a config naming the deleted dialect under `--validate`, with the
#                    unknown-protocol refusal naming the REMAINING dialects and NOT the deleted one
#                    (config_validate's registry-derived arm — the refusal the empty-set red test
#                    pinned, firing on the unknown-name branch);
#                 b. ACCEPTS the same config re-pointed at a REMAINING dialect (the other dialects
#                    still serve);
#                 c. BOOTS with the remaining-dialect config and ANSWERS: /healthz 200 and /stats
#                    200 (the operator surface is alive), while the deleted dialect's ingress path
#                    resolves to NO handler (non-2xx), because the dialect that served it is not in
#                    the build.
#   CONTROL     — the DEFAULT build (every feature on) accepts the deleted dialect's config, proving
#                 the gate measures the feature edge and not a broken fixture.
#   MCP LEG     — the MCP protocol crate (busbar-proto-mcp), on its own feature axis:
#                 `default minus proto-mcp` must build and BOOT and SERVE. This is a distinct axis
#                 from level 2's --no-default-features (which drops every optional feature at once),
#                 and it is what proves the protocol crates are independently droppable rather than
#                 droppable only as a set.
#
# WHAT THE MCP LEG DELIBERATELY DOES NOT CLAIM, so nobody later reads it as proving more:
#   MCP's HTTP surface (`POST /mcp`) is served by the mcp/ PLANE in busbar-core — its own router
#   mount, gated by the `tools:` config section — and NOT by this protocol crate's cells. The crate
#   carries MCP the PROTOCOL (its ProtocolDecl and the tools/call + subscribe codecs); the plane did
#   not travel with it, because a `&'static ProtocolDecl` carries no AppState/config/boot handle and
#   there is no plane-kind seam in core yet. So dropping `proto-mcp` removes MCP from the protocol
#   registry, and it does NOT change what `/mcp` answers. There is therefore no honest HTTP probe
#   for this leg, and one is not invented here: the registry-level property is pinned by a unit test
#   instead (proto/tests/registry_tests.rs::a_codec_less_declaration_does_not_move_the_operator_
#   visible_list_when_it_is_folded_ahead, plus the crate's own suite, which runs in BOTH the crate
#   build and core's dual-compiled build). When the plane-kind seam lands and the plane leaves core,
#   THIS is the leg that grows the `/mcp` probe.
#
# WATCHED RED, each dialect's first landing: run against the pre-extraction tree (the dialect still
# a core built-in), level 3a fails — the featureless build still accepts the deleted dialect's
# config — which is the red that makes this gate's green evidence. See each dialect's landing commit
# for the recorded red run.
#
# A separate CARGO_TARGET_DIR keeps the deleted-feature build from thrashing the default target
# dir's artifacts (feature flips would otherwise rebuild the workspace twice per developer loop).
set -uo pipefail
cd "$(dirname "$0")/.."

note() { printf '  %s\n' "$1"; }
die()  { printf 'proto-deletion-gate: FAIL — %s\n' "$1"; exit 1; }

# ── level 1: static (once, for the whole tree) ──────────────────────────────────────────────────
if git grep -q "busbar_proto" -- crates/busbar-core/src; then
  git grep -n "busbar_proto" -- crates/busbar-core/src
  die "crates/busbar-core/src names a protocol crate; the seam only means something if core cannot"
fi
note "level 1 static: core names no protocol crate (grep count 0)"

# ── fixtures ─────────────────────────────────────────────────────────────────────────────────────
FIX=$(mktemp -d "${TMPDIR:-/tmp}/proto-deletion-gate.XXXXXX")
trap 'rm -rf "$FIX"; [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null' EXIT
mk_providers() { # $1 = protocol name
  # printf, not a heredoc: `executable-config-lint.py` extracts every `<<DELIM` heredoc verbatim and
  # requires a LITERAL `protocol:` value (it validates the extracted text against the real engine,
  # so a shell-parameter-substituted value would either dodge the check or manufacture a false
  # failure). `mk_config` below has used printf for the same reason since this gate's first version.
  printf 'mock:\n  protocol: %s\n  base_url: "http://127.0.0.1:9"\n  api_key_env: MOCK_KEY\n' \
    "$1" > "$FIX/providers.yaml"
}
# ── PICKING A PORT THAT IS ACTUALLY FREE ────────────────────────────────────────────────────────
# This gate boots a real binary on a real socket twice, and it used to pick the port with
# `(RANDOM % 20000) + 30000` and hope. Under a fleet that hope fails: on 2026-08-17 a sibling
# agent's run of this same gate held the number this one drew, the boot died on
# `Address already in use (os error 48)`, and the gate reported FAIL. A gate that reports a
# protocol-deletion defect when the real fault is a port clash is worse than a slow gate, because
# the reader goes looking for the defect.
#
# `free_port` proves a port pair is bindable instead of guessing. The first attempt at this asked
# for :0 and read the number back, which does not work here for two reasons, both found by running
# it: macOS answers :0 from the EPHEMERAL range (49152+), the same pool an outgoing connection can
# take back between the check and busbar's own bind; and :0 says nothing about port+1, which the
# admin plane needs. So it binds BOTH ports explicitly, low in the range, and holds them until the
# moment it prints.
free_port() {
  # Ask Python to find a CONSECUTIVE PAIR it can actually bind, low in the range. Binding :0 is not
  # enough on macOS: the OS answers from the ephemeral range (49152+), which is the same pool an
  # outgoing connection can take between our check and busbar's bind, and it tells us nothing about
  # port+1, which the admin plane needs. So we bind both explicitly and keep them held until the
  # moment we print, which is the shortest TOCTOU window a shell script can get.
  python3 - <<'PYEOF' 2>/dev/null
import socket, random
for _ in range(200):
    base = random.randrange(30000, 45000, 2)
    socks = []
    try:
        for port in (base, base + 1):
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            s.bind(("127.0.0.1", port))
            socks.append(s)
        print(base)
        break
    except OSError:
        continue
    finally:
        for s in socks:
            s.close()
PYEOF
}

mk_config() { # $1 = listen, $2 = admin listen (the admin plane defaults to :8081, which a laptop
  # or a concurrently running gate may already hold — the boot leg must not fail on a port squat)
  printf 'listen: "%s"\nadmin_listen: "%s"\nproviders:\n  mock:\n    api_key: { env: MOCK_KEY }\nmodels:\n  test-model:\n    provider: mock\n' \
    "$1" "$2" > "$FIX/config.yaml"
}
run_busbar() { # binary, args... ; env comes from the fixture
  MOCK_KEY=test-key BUSBAR_SIGNING_KEY=0000000000000000000000000000000000000000000000000000000000000001 \
  BUSBAR_CONFIG="$FIX/config.yaml" BUSBAR_PROVIDERS="$FIX/providers.yaml" "$@"
}

# ── run_gate: levels 2/3 + control, for ONE extracted dialect ───────────────────────────────────
# $1 = dialect name (config `protocol:` value, e.g. "anthropic")
# $2 = its Cargo feature name (e.g. "proto-anthropic")
# $3 = comma-separated features to keep ON for every OTHER extracted dialect (so this run deletes
#      exactly one dialect, not every extracted dialect at once)
# $4 = remaining dialects string, in `known_protocols()` order, as the refusal names them
# $5 = a REMAINING dialect's name to prove still serves (level 3b/3c)
# $6 = an ingress path native to THE DELETED dialect, to prove it 404s post-deletion (level 3c)
run_gate() {
  local proto="$1" feature="$2" keep_features="$3" remaining="$4" control_proto="$5" deleted_ingress_path="$6"
  local del_target="target/deletion-gate-${proto}"
  local keep_arg=""
  [ -n "$keep_features" ] && keep_arg=",${keep_features}"

  note "── dialect: ${proto} (feature ${feature}) ──"
  note "level 2 build: cargo build -p busbar --no-default-features --features auth-admin-tokens,hooks-ranking${keep_arg}"
  CARGO_TARGET_DIR="$del_target" cargo build -q -p busbar \
    --no-default-features --features "auth-admin-tokens,hooks-ranking${keep_arg}" \
    || die "the busbar binary must build with the ${proto} protocol crate deleted"
  local deleted_bin="$del_target/debug/busbar"
  [ -x "$deleted_bin" ] || die "deleted-build binary not found at $deleted_bin"
  note "level 2 build: ok ($deleted_bin)"

  # ── level 3a: the deleted binary refuses protocol: $proto, naming the cause ───────────────────
  mk_providers "$proto"; mk_config "127.0.0.1:0" "127.0.0.1:0"
  local out rc
  out=$(run_busbar "$deleted_bin" --validate 2>&1); rc=$?
  if [ $rc -eq 0 ]; then
    die "the deleted binary ACCEPTED a config naming protocol: $proto (the deletion changed nothing)"
  fi
  echo "$out" | grep -q "unknown protocol '$proto'" \
    || die "the refusal must NAME the unknown protocol; got: $out"
  echo "$out" | grep -q "must be one of: $remaining" \
    || die "the refusal must name the remaining dialects (and not $proto); got: $out"
  note "level 3a refusal: 'unknown protocol $proto — must be one of: $remaining' (exit $rc)"

  # ── level 3b: the remaining dialects still validate ─────────────────────────────────────────────
  mk_providers "$control_proto"; mk_config "127.0.0.1:0" "127.0.0.1:0"
  out=$(run_busbar "$deleted_bin" --validate 2>&1) || die "the deleted binary must accept a $control_proto config; got: $out"
  note "level 3b remaining dialects: $control_proto config validates clean"

  # ── level 3c: the deleted binary BOOTS and answers (R-D: fewer protocols is a valid busbar) ────
  local port; port=$(free_port) || die "could not find a free port pair for the deletion boot"
  local admin_port=$(( port + 1 ))
  mk_providers "$control_proto"; mk_config "127.0.0.1:$port" "127.0.0.1:$admin_port"
  run_busbar "$deleted_bin" >"$FIX/boot-${proto}.log" 2>&1 &
  SRV_PID=$!
  local up=""
  for _ in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; then up=1; break; fi
    kill -0 "$SRV_PID" 2>/dev/null || break
    sleep 0.5
  done
  [ -n "$up" ] || { cat "$FIX/boot-${proto}.log"; die "the deleted binary did not come up on /healthz"; }
  curl -fsS "http://127.0.0.1:$port/stats" >/dev/null || die "/stats must answer on the deleted binary"
  local msg_code
  msg_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$port$deleted_ingress_path" \
    -H 'content-type: application/json' -d '{"model":"test-model","max_tokens":8,"messages":[]}')
  case "$msg_code" in
    2*) die "POST $deleted_ingress_path answered $msg_code on a build with no $proto dialect" ;;
  esac
  kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; SRV_PID=""
  note "level 3c boot: /healthz 200, /stats 200, ${proto}-format ingress answers $msg_code (no handler)"

  # ── control: the default build (feature ON) accepts the deleted dialect's config ────────────────
  note "control: cargo build -p busbar (default features)"
  cargo build -q -p busbar || die "default build failed"
  mk_providers "$proto"; mk_config "127.0.0.1:0" "127.0.0.1:0"
  out=$(run_busbar target/debug/busbar --validate 2>&1) \
    || die "the DEFAULT build must accept protocol: $proto (gate would be measuring a broken fixture); got: $out"
  note "control: default build accepts protocol: $proto"
}

# ── ANTHROPIC: every OTHER protocol crate stays ON so this run deletes ONLY anthropic ───────────
run_gate "anthropic" "proto-anthropic" "proto-gemini,proto-mcp,proto-openai-chat" \
  "gemini, openai, bedrock, responses, cohere" "openai" "/v1/messages"

# ── OPENAI CHAT: every OTHER protocol crate stays ON so this run deletes ONLY openai chat ────────
run_gate "openai" "proto-openai-chat" "proto-anthropic,proto-gemini,proto-mcp" \
  "anthropic, gemini, bedrock, responses, cohere" "anthropic" "/v1/chat/completions"

# ── GEMINI: every OTHER protocol crate stays ON so this run deletes ONLY gemini ──────────────────
# The deleted-ingress probe is gemini's own URL space (`/v1beta/models/{model}:{action}`), where the
# MODEL rides in the path — the reason this dialect declares `path_ingress` at all.
run_gate "gemini" "proto-gemini" "proto-anthropic,proto-mcp,proto-openai-chat" \
  "anthropic, openai, bedrock, responses, cohere" "anthropic" \
  "/v1beta/models/test-model:generateContent"

# ── MCP: its own leg, NOT a run_gate call — see the header's "what the mcp leg does not claim". ──
# MCP has no ingress path this gate can probe (the `/mcp` PLANE stays in core), so levels 3a/3c do
# not apply to it and the discriminating half is static instead.

# ── mcp-a: MCP THE PROTOCOL LIVES IN THE CRATE, NOT IN CORE (the leg that goes RED) ──────────────
# On the pre-extraction tree these three assertions fail: the dialect was a core built-in at
# crates/busbar-core/src/handlers/mcp.rs, there was no crate to declare it, and the composition root
# had no feature-gated registration line for it.
[ ! -e crates/busbar-core/src/handlers/mcp.rs ] \
  || die "crates/busbar-core/src/handlers/mcp.rs still exists: MCP the protocol has not left core"
grep -q 'name: "mcp"' crates/busbar-proto-mcp/src/lib.rs \
  || die "crates/busbar-proto-mcp must declare the mcp protocol (name: \"mcp\")"
grep -q 'feature = "proto-mcp"' crates/busbar/src/main.rs \
  || die "the composition root must register busbar_proto_mcp::DECL behind the proto-mcp feature"
note "mcp-a static: mcp declared by the crate, absent from core, registered by the composition root"

# ── mcp-b: the MCP protocol crate is independently droppable, and the binary still SERVES ────────
# `default minus proto-mcp` — a real, separate feature axis, and the per-crate BUILD+BOOT proof
# (R-D). It is NOT a behaviour discriminator and is not presented as one: mcp-a above is what goes
# red without the move.
MCP_TARGET="target/deletion-gate-mcp"
MCP_KEEP="auth-admin-tokens,hooks-ranking,proto-anthropic,proto-gemini,proto-openai-chat"
note "mcp-b build: cargo build -p busbar --no-default-features --features $MCP_KEEP (proto-mcp OFF)"
CARGO_TARGET_DIR="$MCP_TARGET" cargo build -q -p busbar \
  --no-default-features --features "$MCP_KEEP" \
  || die "the busbar binary must build with the mcp protocol crate deleted and the dialects kept"
MCP_DELETED_BIN="$MCP_TARGET/debug/busbar"
[ -x "$MCP_DELETED_BIN" ] || die "mcp-deleted build binary not found at $MCP_DELETED_BIN"
note "mcp-b build: ok ($MCP_DELETED_BIN)"

# The kept dialects still validate on this axis — so the leg is measuring the mcp edge specifically
# and not a binary that lost every protocol.
mk_providers "anthropic"; mk_config "127.0.0.1:0" "127.0.0.1:0"
OUT=$(run_busbar "$MCP_DELETED_BIN" --validate 2>&1) \
  || die "the mcp-deleted binary must still accept protocol: anthropic; got: $OUT"
note "mcp-b kept dialect: anthropic config validates clean with proto-mcp off"

# and it BOOTS and SERVES (R-D: fewer protocols is a valid busbar).
PORT=$(free_port) || die "could not find a free port pair for the mcp-deleted boot"
ADMIN_PORT=$(( PORT + 1 ))
mk_providers "anthropic"; mk_config "127.0.0.1:$PORT" "127.0.0.1:$ADMIN_PORT"
run_busbar "$MCP_DELETED_BIN" >"$FIX/boot-mcp.log" 2>&1 &
SRV_PID=$!
up=""
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then up=1; break; fi
  kill -0 "$SRV_PID" 2>/dev/null || break
  sleep 0.5
done
[ -n "$up" ] || { cat "$FIX/boot-mcp.log"; die "the mcp-deleted binary did not come up on /healthz"; }
curl -fsS "http://127.0.0.1:$PORT/stats" >/dev/null || die "/stats must answer on the mcp-deleted binary"
kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; SRV_PID=""
note "mcp-b boot: /healthz 200, /stats 200 with the mcp protocol crate deleted"

echo "proto-deletion-gate: PASS (static 0; anthropic, openai-chat and gemini each delete independently, boot+serve, remaining dialects unaffected, control green; mcp independently droppable and still serving)"
