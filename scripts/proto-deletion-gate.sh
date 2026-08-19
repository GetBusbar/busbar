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
#   MCP LEG     — the MCP protocol crate (busbar-mcp, its codec half), on its own feature axis:
#                 `default minus plane-mcp` must build and BOOT and SERVE. This is a distinct axis
#                 from level 2's --no-default-features (which drops every optional feature at once),
#                 and it is what proves the protocol crates are independently droppable rather than
#                 droppable only as a set.
#
# WHAT THE MCP LEG DELIBERATELY DOES NOT CLAIM, so nobody later reads it as proving more:
#   MCP's HTTP surface (`POST /mcp`) is served by the mcp/ PLANE in busbar-core — its own router
#   mount, gated by the `tools:` config section — and NOT by this protocol crate's cells. The crate
#   carries MCP the PROTOCOL (its ProtocolDecl and the tools/call + subscribe codecs); the plane did
#   not travel with it, because a `&'static ProtocolDecl` carries no AppState/config/boot handle and
#   there is no plane-kind seam in core yet. So dropping `plane-mcp` removes MCP from the protocol
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
SRV_PID=""
# Reap the subject on EVERY exit path, including a signal. Two things this gate got wrong before:
#   * the EXIT trap alone does not run when the shell is killed by SIGINT/SIGTERM (bash dies from the
#     signal without running it), so a Ctrl-C mid-boot orphaned the subject;
#   * `$!` was the pid of the SUBSHELL bash forks for a backgrounded FUNCTION, not of busbar — see
#     `run_busbar_bg`. Killing that pid left busbar alive, reparented to init, still holding its
#     port. Four such orphans were found on a dev box.
# `kill 0` is deliberately NOT used (it would signal this script's whole process group, i.e. the
# parent gate runner too); the subject is exec'd so its own pid is enough.
cleanup() {
  if [ -n "${SRV_PID:-}" ]; then
    kill "$SRV_PID" 2>/dev/null
    wait "$SRV_PID" 2>/dev/null
    SRV_PID=""
  fi
  rm -rf "$FIX"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM HUP
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

# An EMPTY providers file and a config with no `providers:`/`models:` — the fixture for a build that
# carries no wire protocol at all, so there is nothing a lane could legally name.
mk_no_providers() { printf '{}\n' > "$FIX/providers.yaml"; }
mk_config_no_providers() { # $1 = listen, $2 = admin listen
  # `providers:`/`models:` are present but EMPTY — the schema requires the fields, and empty maps are
  # the honest statement of a busbar that serves no lane. Nothing here names a wire protocol.
  printf 'listen: "%s"\nadmin_listen: "%s"\nproviders: {}\nmodels: {}\n' "$1" "$2" > "$FIX/config.yaml"
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

# The same, for BACKGROUNDED boots — `exec`, so the subshell bash forks for `run_busbar_bg ... &` is
# REPLACED by the binary and `$!` is the binary's own pid. Without the exec, `$!` names a wrapper
# shell whose death leaves busbar running with PPID 1, listening on its port forever.
run_busbar_bg() { # binary, args... ; caller supplies the redirections and the trailing `&`
  MOCK_KEY=test-key BUSBAR_SIGNING_KEY=0000000000000000000000000000000000000000000000000000000000000001 \
  BUSBAR_CONFIG="$FIX/config.yaml" BUSBAR_PROVIDERS="$FIX/providers.yaml" exec "$@"
}

# ── llm_dialect_refused: level 3a, for ONE dialect of the deleted LLM protocol ──────────────────
# $1 = the deleted binary, $2 = the dialect's config `protocol:` value, $3 = the remaining-dialect
# string the refusal must name. Called once per dialect the plugin carried: deleting the plugin
# deletes ALL of them, and a leg that checked only one would pass on a plugin that had quietly kept
# five.
llm_dialect_refused() {
  local bin="$1" proto="$2" remaining="$3" out rc
  mk_providers "$proto"; mk_config "127.0.0.1:0" "127.0.0.1:0"
  out=$(run_busbar "$bin" --validate 2>&1); rc=$?
  if [ $rc -eq 0 ]; then
    die "the deleted binary ACCEPTED a config naming protocol: $proto (the deletion changed nothing)"
  fi
  if [ -n "$remaining" ]; then
    # Some codec protocol still remains, so config_validate takes its unknown-name arm and names the
    # survivors in the `must be one of:` tail.
    echo "$out" | grep -q "unknown protocol '$proto'" \
      || die "the refusal must NAME the unknown protocol; got: $out"
    echo "$out" | grep -q "must be one of: $remaining" \
      || die "the refusal must name the remaining protocols (and not $proto); got: $out"
    note "level 3a refusal: 'unknown protocol $proto — must be one of: $remaining' (exit $rc)"
  else
    # NO codec protocol remains at all (deleting the LLM plugin left only codec-less MCP). The
    # empty-codec-set arm of config_validate fires instead of the unknown-name arm — a DISTINCT,
    # stronger refusal that still names the rejected protocol. Accept either the empty-set message
    # or, defensively, the unknown-name form.
    echo "$out" | grep -Eq "wire codec compiled in|unknown protocol '$proto'" \
      || die "the refusal must reject protocol $proto (empty-codec-set or unknown-name arm); got: $out"
    echo "$out" | grep -q "$proto" \
      || die "the refusal must NAME the rejected protocol $proto; got: $out"
    note "level 3a refusal: empty-codec-set rejects protocol $proto (exit $rc)"
  fi
}

# ── run_gate: levels 2/3 + control, for ONE extracted PROTOCOL ──────────────────────────────────
# $1 = protocol label, and the config `protocol:` value whose refusal levels 3a/control assert
# $2 = its Cargo feature name (e.g. "proto-llm")
# $3 = comma-separated features to keep ON for every OTHER protocol plugin (so this run deletes
#      exactly one PLUGIN, not every plugin at once)
# $4 = remaining dialects string, in `known_protocols()` order, as the refusal names them; EMPTY
#      when the deletion leaves no codec protocol at all
# $5 = a REMAINING dialect's name to prove still serves (level 3b/3c), or empty when none remains
# $6 = an ingress path native to THE DELETED protocol, to prove it 404s post-deletion (level 3c)
# $7 = optional: extra dialect names the deleted plugin also carried, space separated; each gets its
#      own level-3a refusal, because ONE plugin now carries SIX dialects and all six must go
run_gate() {
  local proto="$1" feature="$2" keep_features="$3" remaining="$4" control_proto="$5" deleted_ingress_path="$6"
  local also_deleted="${7:-}"
  local del_target="target/deletion-gate-${proto}"
  local keep_arg=""
  [ -n "$keep_features" ] && keep_arg=",${keep_features}"

  note "── protocol: ${proto} (feature ${feature}) ──"
  note "level 2 build: cargo build -p busbar --no-default-features --features auth-admin-tokens,hooks-ranking${keep_arg}"
  CARGO_TARGET_DIR="$del_target" cargo build -q -p busbar \
    --no-default-features --features "auth-admin-tokens,hooks-ranking${keep_arg}" \
    || die "the busbar binary must build with the ${proto} protocol crate deleted"
  local deleted_bin="$del_target/debug/busbar"
  [ -x "$deleted_bin" ] || die "deleted-build binary not found at $deleted_bin"
  note "level 2 build: ok ($deleted_bin)"

  # ── level 3a: the deleted binary refuses EVERY dialect the plugin carried, naming the cause ───
  llm_dialect_refused "$deleted_bin" "$proto" "$remaining"
  local extra
  for extra in $also_deleted; do
    llm_dialect_refused "$deleted_bin" "$extra" "$remaining"
  done

  # ── level 3b: the remaining dialects still validate ─────────────────────────────────────────────
  # SKIPPED, honestly and loudly, when the deletion leaves NO dialect behind: there is then nothing
  # for a provider lane to name, and inventing a control here would be asserting against a fixture
  # rather than against the build. Level 3c still proves the binary boots and serves.
  local out
  if [ -n "$control_proto" ]; then
    mk_providers "$control_proto"; mk_config "127.0.0.1:0" "127.0.0.1:0"
    out=$(run_busbar "$deleted_bin" --validate 2>&1) || die "the deleted binary must accept a $control_proto config; got: $out"
    note "level 3b remaining dialects: $control_proto config validates clean"
  else
    note "level 3b remaining dialects: none left to validate (this deletion removed the last one)"
  fi

  # ── level 3c: the deleted binary BOOTS and answers (R-D: fewer protocols is a valid busbar) ────
  local port; port=$(free_port) || die "could not find a free port pair for the deletion boot"
  local admin_port=$(( port + 1 ))
  if [ -n "$control_proto" ]; then
    mk_providers "$control_proto"; mk_config "127.0.0.1:$port" "127.0.0.1:$admin_port"
  else
    # NO DIALECT LEFT TO CONFIGURE — so boot with no providers and no models at all. This is the
    # R-D claim at its limit and the reason it is worth making: a busbar that speaks NO wire
    # protocol is still a valid busbar, and it must SERVE its operator surface rather than refuse
    # to start. A gate that could only boot a binary with a provider in it could never assert that.
    mk_no_providers; mk_config_no_providers "127.0.0.1:$port" "127.0.0.1:$admin_port"
  fi
  run_busbar_bg "$deleted_bin" >"$FIX/boot-${proto}.log" 2>&1 &
  SRV_PID=$!
  # READINESS SIGNAL depends on whether any lane exists. `/healthz` is a lane-readiness probe: with
  # zero lanes it CORRECTLY answers 503 "no usable lanes" (endpoints::healthz), so in the empty case
  # it is not the up-signal — `/stats` is (the operator surface answers regardless of lanes). When a
  # control dialect provides a lane, `/healthz` is the up-signal as before.
  local up_probe="/healthz"
  [ -z "$control_proto" ] && up_probe="/stats"
  local up=""
  for _ in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:$port$up_probe" >/dev/null 2>&1; then up=1; break; fi
    kill -0 "$SRV_PID" 2>/dev/null || break
    sleep 0.5
  done
  [ -n "$up" ] || { cat "$FIX/boot-${proto}.log"; die "the deleted binary did not come up on $up_probe"; }
  curl -fsS "http://127.0.0.1:$port/stats" >/dev/null || die "/stats must answer on the deleted binary"
  if [ -z "$control_proto" ]; then
    # POSITIVE ASSERTION on the limit case: a busbar with no lanes reports NOT-ready on /healthz —
    # an honest readiness answer, not a crash — while /stats (checked above) still serves. 503 is
    # the expected code; any 2xx would mean it falsely claims readiness with nothing to serve.
    local hz
    hz=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/healthz")
    [ "$hz" = "503" ] || die "with zero lanes /healthz must report 503 (no usable lanes); got $hz"
    note "level 3c boot (no lanes): /stats 200 serves, /healthz 503 honestly not-ready"
  fi
  local msg_code
  msg_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$port$deleted_ingress_path" \
    -H 'content-type: application/json' -d '{"model":"test-model","max_tokens":8,"messages":[]}')
  case "$msg_code" in
    2*) die "POST $deleted_ingress_path answered $msg_code on a build with no $proto dialect" ;;
  esac
  kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; SRV_PID=""
  note "level 3c boot: up on $up_probe, /stats 200, ${proto}-format ingress answers $msg_code (no handler)"

  # ── control: the default build (feature ON) accepts the deleted dialect's config ────────────────
  note "control: cargo build -p busbar (default features)"
  cargo build -q -p busbar || die "default build failed"
  mk_providers "$proto"; mk_config "127.0.0.1:0" "127.0.0.1:0"
  out=$(run_busbar target/debug/busbar --validate 2>&1) \
    || die "the DEFAULT build must accept protocol: $proto (gate would be measuring a broken fixture); got: $out"
  note "control: default build accepts protocol: $proto"
}

# ── THE LLM PROTOCOL: ONE leg, because there is ONE plugin ──────────────────────────────────────
# This replaced three per-dialect legs (anthropic, openai-chat, gemini), and the replacement is not
# a loss of coverage — it is the coverage the seam now actually has. There is no `proto-gemini`
# feature to drop any more: the operator's choice is LLM coverage or none, so the only deletion the
# build can make is the whole protocol, and asserting a per-dialect deletion would be asserting
# against a knob that does not exist.
#
# It is STRICTER than the six per-dialect legs it replaces in the way that matters: deleting the ONE
# plugin deletes ALL SIX dialects, and each gets its own level-3a refusal (see `llm_dialect_refused`),
# so a plugin that dropped its dependency edge while quietly leaving even one dialect resident in
# core fails here. The MCP protocol crate stays ON, so this run deletes exactly one PLUGIN — and MCP
# has no wire codec, so the codec-protocol list is EMPTY afterward: there is NO remaining LLM dialect
# and NO control dialect to re-point a lane at (both the remaining-string and control args are empty,
# which routes level 3b to its honest skip and level 3c to a NO-PROVIDERS boot — a busbar that speaks
# no wire protocol at all is still a valid busbar and must serve its operator surface).
#
# The deleted-ingress probe is anthropic's `/v1/messages`; every other dialect's URL space
# (gemini's `/v1beta/...`, bedrock's `/model/{id}/converse`, `/v1/responses`, `/v2/chat`) is covered
# by the same binary having no LLM handler at all.
run_gate "anthropic" "proto-llm" "plane-mcp" \
  "" "" "/v1/messages" \
  "gemini openai bedrock responses cohere"

# ── MCP: its own leg, NOT a run_gate call — see the header's "what the mcp leg does not claim". ──
# MCP has no ingress path this gate can probe (the `/mcp` PLANE stays in core), so levels 3a/3c do
# not apply to it and the discriminating half is static instead.

# ── mcp-a: MCP THE PROTOCOL LIVES IN THE CRATE, NOT IN CORE (the leg that goes RED) ──────────────
# On the pre-extraction tree these three assertions fail: the dialect was a core built-in at
# crates/busbar-core/src/handlers/mcp.rs, there was no crate to declare it, and the composition root
# had no feature-gated registration line for it.
[ ! -e crates/busbar-core/src/handlers/mcp.rs ] \
  || die "crates/busbar-core/src/handlers/mcp.rs still exists: MCP the protocol has not left core"
grep -q 'name: "mcp"' crates/busbar-mcp/src/codec/mod.rs \
  || die "crates/busbar-mcp/src/codec must declare the mcp protocol (name: \"mcp\")"
grep -q 'feature = "plane-mcp"' crates/busbar/src/main.rs \
  || die "the composition root must register busbar_mcp::PROTO_DECL behind the plane-mcp feature"
note "mcp-a static: mcp declared by the crate, absent from core, registered by the composition root"

# ── mcp-b: the MCP protocol crate is independently droppable, and the binary still SERVES ────────
# `default minus plane-mcp` — a real, separate feature axis, and the per-crate BUILD+BOOT proof
# (R-D). It is NOT a behaviour discriminator and is not presented as one: mcp-a above is what goes
# red without the move.
MCP_TARGET="target/deletion-gate-mcp"
MCP_KEEP="auth-admin-tokens,hooks-ranking,proto-llm"
note "mcp-b build: cargo build -p busbar --no-default-features --features $MCP_KEEP (plane-mcp OFF)"
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
note "mcp-b kept dialect: anthropic config validates clean with plane-mcp off"

# and it BOOTS and SERVES (R-D: fewer protocols is a valid busbar).
PORT=$(free_port) || die "could not find a free port pair for the mcp-deleted boot"
ADMIN_PORT=$(( PORT + 1 ))
mk_providers "anthropic"; mk_config "127.0.0.1:$PORT" "127.0.0.1:$ADMIN_PORT"
run_busbar_bg "$MCP_DELETED_BIN" >"$FIX/boot-mcp.log" 2>&1 &
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

echo "proto-deletion-gate: PASS (static 0; the LLM protocol deletes as one plugin and all six dialects it carries are refused, boot+serve, remaining dialects unaffected, control green; mcp independently droppable and still serving)"
