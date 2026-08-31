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
# WHAT THE MCP LEG NOW CLAIMS: dropping `plane-mcp` compiles out BOTH halves of MCP — the
#   protocol codec crate (busbar-mcp) AND the MCP PLANE in `busbar-mcp/src/mcp` (gated by the
#   `busbar-core/plane-mcp` feature the binary's `plane-mcp` forwards). Core names no `crate::mcp`
#   type in that build, so:
#     * mcp-b: the binary BUILDS, BOOTS and SERVES its operator surface (/healthz, /stats), and the
#       MCP plane's routes are ABSENT from its table. The receiving door mounts only when an `mcp:`
#       block is configured, so a bare `POST /mcp` 404 does not by itself separate "compiled out"
#       from "present but unconfigured"; mcp-b-mounted supplies the missing half — the DEFAULT build,
#       given an `mcp:` block, MOUNTS the door (its RFC 9728 metadata route answers 200), so the 404
#       here means the plane genuinely left, not merely that the door was never asked to mount.
#     * mcp-c: a `tools:`/`mcp:` config names the compiled-out plane, so `--validate` REFUSES it,
#       naming the plane (the config analogue of a deleted-dialect refusal) — which is also why the
#       OFF build cannot itself be booted with the mounting `mcp:` block: the present/absent contrast
#       is drawn across the OFF build (no `mcp:`, door absent) and the DEFAULT build (`mcp:`, mounted).
#     * mcp-d: the SAME drop with `plane-a2a` kept ON — MCP gone while A2A still mounts and routes —
#       proving the planes are independently droppable in both directions, not only as a set.
#   Historic note (pre-D3): the plane was an unconditional core built-in that did not travel with the
#   codec crate, so `/mcp` answered regardless of `plane-mcp` and this leg was static-only — the
#   registry-level property pinned by a unit test instead
#   (proto/tests/registry_tests.rs::a_codec_less_declaration_does_not_move_the_operator_visible_list_
#   when_it_is_folded_ahead). D3 gave the plane its own compile-out switch, and this is the leg that
#   grew the `/mcp` and config probes it promised.
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

# ── level 1b: structural — the IrReq/IrResp hub enums (G6 step A4a scaffolding) ──────────────────
# The `g6-freeze-witness.sh` count DELIBERATELY excludes `IrReq`/`IrResp`: they do not relocate as a
# family, they DISSOLVE (at A4b) onto a neutral core-owned `Box<dyn ir::handle::IrHandle>` plus the
# core-owned invoke/subscribe leaves — counting them would conflate "dissolved" with "named" and
# inflate the number ~160x, masking per-leaf progress. So their removal needs its OWN structural gate.
#
# A4a only ENCAPSULATED the concrete IR codec surface; A4b DISSOLVES the hub enums. This gate is now
# FLIPPED (as promised at A4a) to "must be ABSENT": `crates/busbar-core/src/ir/variant.rs` — the file
# that DEFINED `enum IrReq`/`enum IrResp` and their operation-blind surface — is deleted at A4b, the
# surface having inverted onto `ir::handle::IrHandle` (the neutral `Box<dyn IrHandle>` the engine
# drives) plus the core-owned invoke/subscribe leaf handles. This is the structural proof the enum is
# gone; the freeze witness → 0 pins the concrete-family relocation, this pins the dissolve.
if [ -e crates/busbar-core/src/ir/variant.rs ]; then
  die "ir/variant.rs still exists — A4b dissolves IrReq/IrResp onto Box<dyn IrHandle> and DELETES this file"
fi
if grep -rREq "\benum IrReq\b|\benum IrResp\b" crates/busbar-core/src; then
  die "enum IrReq/IrResp still defined in core — the A4b dissolve must remove them entirely"
fi
note "level 1b structural: IrReq/IrResp hub enums ABSENT (A4b dissolve complete — variant.rs deleted)"

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
  # BUSBAR_ADMIN_TOKEN is only read by fixtures that carry an `admin-tokens` credential (the MCP
  # door-mount control below, whose `mcp:` block requires a closed data-plane chain); every other
  # fixture ignores it.
  MOCK_KEY=test-key BUSBAR_SIGNING_KEY=0000000000000000000000000000000000000000000000000000000000000001 \
  BUSBAR_ADMIN_TOKEN=admin-token-for-the-deletion-gate-control-only \
  BUSBAR_CONFIG="$FIX/config.yaml" BUSBAR_PROVIDERS="$FIX/providers.yaml" "$@"
}

# The same, for BACKGROUNDED boots — `exec`, so the subshell bash forks for `run_busbar_bg ... &` is
# REPLACED by the binary and `$!` is the binary's own pid. Without the exec, `$!` names a wrapper
# shell whose death leaves busbar running with PPID 1, listening on its port forever.
run_busbar_bg() { # binary, args... ; caller supplies the redirections and the trailing `&`
  MOCK_KEY=test-key BUSBAR_SIGNING_KEY=0000000000000000000000000000000000000000000000000000000000000001 \
  BUSBAR_ADMIN_TOKEN=admin-token-for-the-deletion-gate-control-only \
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

# ── MCP: its own leg, NOT a run_gate call — see the header's "WHAT THE MCP LEG NOW CLAIMS". ──────
# MCP is not a codec dialect, so the LLM levels 3a/3c (a `protocol:` refusal, an LLM-format ingress)
# do not apply to it. Its ingress IS probed, but the door is CONFIG-gated (an `mcp:` block mounts it),
# so absence is proven by a mounted-vs-absent PAIR (mcp-b + mcp-b-mounted) rather than by a bare 404,
# and the compile-out itself is pinned by the config refusal (mcp-c) and the static declaration (mcp-a).

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

# ── mcp-c: THE MCP PLANE'S CONFIG SURFACE LEFT WITH IT ──────────────────────────────────────────
# `plane-mcp` off compiles `busbar-mcp/src/mcp` out, so a `tools:` section names a plane this
# build does not carry. `resolve` REFUSES such a config, naming the SECTION and pointing at the
# compiled-out plane's feature (rebuild with it, or remove the block) — the config analogue of the
# protocol registry refusing a deleted dialect. The neutral core cannot name the plane itself: a
# plane token in a neutral crate is exactly what the plane-purity gate forbids, so the refusal is
# actionable by section, not by plane name. This is the leg that went RED before D3: the plane was an
# unconditional core built-in, so a `tools:` config validated clean with `plane-mcp` off.
printf 'listen: "127.0.0.1:0"\nadmin_listen: "127.0.0.1:0"\nproviders: {}\nmodels: {}\ntools:\n  s:\n    url: "https://example.com/mcp"\n' > "$FIX/config.yaml"
mk_no_providers
if run_busbar "$MCP_DELETED_BIN" --validate >"$FIX/tools-validate.out" 2>&1; then
  cat "$FIX/tools-validate.out"; die "the mcp-deleted binary ACCEPTED a tools: config — the MCP plane's config surface did not leave with it"
fi
grep -qiE "tools:" "$FIX/tools-validate.out" \
  && grep -qiE "compiled without the plane that owns it|rebuild with that plane.s feature" "$FIX/tools-validate.out" \
  || { cat "$FIX/tools-validate.out"; die "the tools: refusal must name the section AND point at the compiled-out plane's feature (neutral core cannot name the plane — plane-purity)"; }
note "mcp-c config: a tools: section is REFUSED, naming the section and the compiled-out plane's feature"

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
# THE /mcp HTTP LEG: the MCP PLANE — its `/mcp` data-plane mount and its RFC 9728 metadata route
# — is compiled out with `plane-mcp`, so on this build the mount is ABSENT from the route table.
# The operator surface (/healthz, /stats) and the surviving LLM/A2A planes still serve. Before the
# plane grew its own compile-out switch this could not be probed: it was an unconditional core
# built-in and `/mcp` answered regardless of the feature, which is why this leg was static-only.
#
# WHY TWO PROBES, NOT JUST POST /mcp: the RECEIVING door mounts only when an `mcp:` block is
# configured (its mere presence mounts the plane), and this OFF-build boot carries no `mcp:` block —
# so `POST /mcp` here would 404 even on a plane-ON build with the same config. A bare 404 therefore
# does NOT by itself tell "plane compiled out" from "plane present but door not configured". The
# discriminating signal is the paired mounted-vs-absent control below: this OFF build 404s the
# plane's routes; the DEFAULT build, given an `mcp:` block that MOUNTS the door, answers its RFC 9728
# metadata route 200 (mcp-b-mounted). Absence here is meaningful only because presence is proven
# there — and mcp-c already showed this OFF build REFUSES the very `mcp:` block that would mount it.
MCP_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$PORT/mcp" \
  -H 'content-type: application/json' -d '{"jsonrpc":"2.0","method":"initialize","id":1}')
case "$MCP_CODE" in
  2*) die "POST /mcp answered $MCP_CODE with the MCP plane compiled out — the plane's data path did not leave core" ;;
esac
# The mount's one unauthenticated route — GET /.well-known/oauth-protected-resource<path> — is 404
# here: with the plane compiled out it is not in the table at all. (On a mounted plane it is 200,
# asserted at mcp-b-mounted below.) This is the ABSENT half of the mounted-vs-absent discriminator.
MCP_META_OFF=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/.well-known/oauth-protected-resource/mcp")
[ "$MCP_META_OFF" = "404" ] \
  || die "the MCP metadata route must be ABSENT (404) with plane-mcp off; got $MCP_META_OFF"
kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; SRV_PID=""
note "mcp-b boot: /healthz 200, /stats 200, POST /mcp $MCP_CODE + metadata 404 (plane ABSENT) with plane-mcp off"

# ── mcp-b-mounted: the DEFAULT build (plane-mcp ON), given an `mcp:` block, MOUNTS the door ───────
# This is the PRESENT half of the discriminator. The default binary (built by the control leg above)
# is booted with an `mcp:` block whose `canonical_uri` path is `/mcp`, so the plane's ingress and its
# RFC 9728 metadata route are mounted. The metadata route (the mount's one RouteAuth::None route)
# answers 200 — proof the door is genuinely mounted and ROUTES, not merely present-but-silent. A
# non-configured resource path answers 401 (the data-plane chain, not a blanket 200), so the 200 is
# specific to the mounted resource. Paired with the 404 above, POST /mcp / the metadata route now
# DISCRIMINATE "plane present & mounted" (200) from "plane compiled out" (404).
#
# The `mcp:` block requires a CLOSED data-plane chain (an MCP endpoint with an empty `auth.chain` is
# an open front door and is refused at boot), so the fixture carries the minimal `keys` chain plus an
# `admin-tokens` credential and a signing key — the smallest config that both boots and mounts /mcp.
[ -x target/debug/busbar ] || die "default build binary missing for the mcp mounted control"
MCP_ON_PORT=$(free_port) || die "could not find a free port pair for the mcp-mounted control boot"
MCP_ON_ADMIN=$(( MCP_ON_PORT + 1 ))
printf 'listen: "127.0.0.1:%s"\nadmin_listen: "127.0.0.1:%s"\npublic_url: https://busbar.example.com\nproviders: {}\nmodels: {}\nidentity-providers:\n  admin-tokens:\n    module: admin-tokens\n    token: { env: BUSBAR_ADMIN_TOKEN }\nauth:\n  signing_key: { env: BUSBAR_SIGNING_KEY }\n  chain: [keys]\n  admin_auth: [admin-tokens]\nmcp:\n  canonical_uri: https://busbar.example.com/mcp\n  authorization_servers:\n    - https://login.example.com\n' \
  "$MCP_ON_PORT" "$MCP_ON_ADMIN" > "$FIX/config.yaml"
mk_no_providers
run_busbar_bg target/debug/busbar >"$FIX/boot-mcp-mounted.log" 2>&1 &
SRV_PID=$!
up=""
for _ in $(seq 1 60); do
  # /stats is behind the data-plane chain here (it 401s), so the mounted metadata route IS the
  # readiness signal — it is unauthenticated and 200 exactly when the plane finished mounting.
  if curl -fsS "http://127.0.0.1:$MCP_ON_PORT/.well-known/oauth-protected-resource/mcp" >/dev/null 2>&1; then up=1; break; fi
  kill -0 "$SRV_PID" 2>/dev/null || break
  sleep 0.5
done
[ -n "$up" ] || { cat "$FIX/boot-mcp-mounted.log"; die "the mcp-mounted control did not mount /mcp on the default build"; }
MCP_META_ON=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$MCP_ON_PORT/.well-known/oauth-protected-resource/mcp")
[ "$MCP_META_ON" = "200" ] \
  || die "with plane-mcp ON and an mcp: block, the MCP metadata route must MOUNT (200); got $MCP_META_ON"
MCP_META_UNCONF=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$MCP_ON_PORT/.well-known/oauth-protected-resource/not-the-resource")
[ "$MCP_META_ON" != "$MCP_META_UNCONF" ] \
  || die "the mounted 200 must be SPECIFIC to the configured resource, not a blanket answer; unconfigured path also gave $MCP_META_UNCONF"
kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; SRV_PID=""
note "mcp-b-mounted: plane-mcp ON mounts the door — metadata route 200 (present), unconfigured path $MCP_META_UNCONF; vs 404 with plane-mcp off (DISCRIMINATES present-mounted from compiled-out)"

# ── a2a-b: THE A2A PLANE IS INDEPENDENTLY DROPPABLE, and the binary still SERVES LLM + MCP ────────
# The exact analogue of the mcp-b/mcp-c legs: `plane-a2a` off compiles `busbar-a2a/src/a2a`
# (and its plane-side helper `plane::taskstore`) out, so core names no `crate::a2a` type. This is a
# SEPARATE feature axis from `plane-mcp` — dropping it keeps MCP, proving the two planes are
# independently droppable rather than droppable only as a set.
A2A_TARGET="target/deletion-gate-a2a"
A2A_KEEP="auth-admin-tokens,hooks-ranking,proto-llm,plane-mcp"
note "a2a-b build: cargo build -p busbar --no-default-features --features $A2A_KEEP (plane-a2a OFF)"
CARGO_TARGET_DIR="$A2A_TARGET" cargo build -q -p busbar \
  --no-default-features --features "$A2A_KEEP" \
  || die "the busbar binary must build with the A2A plane compiled out and LLM + MCP kept"
A2A_DELETED_BIN="$A2A_TARGET/debug/busbar"
[ -x "$A2A_DELETED_BIN" ] || die "a2a-deleted build binary not found at $A2A_DELETED_BIN"
note "a2a-b build: ok ($A2A_DELETED_BIN)"

# The kept LLM dialect still validates on this axis — so the leg measures the a2a edge specifically
# and not a binary that lost everything.
mk_providers "anthropic"; mk_config "127.0.0.1:0" "127.0.0.1:0"
OUT=$(run_busbar "$A2A_DELETED_BIN" --validate 2>&1) \
  || die "the a2a-deleted binary must still accept protocol: anthropic; got: $OUT"
note "a2a-b kept dialect: anthropic config validates clean with plane-a2a off"

# MCP still routes with the A2A plane gone: a `tools:` config validates clean (plane-mcp is kept in
# this build), so this is not a binary that dropped every plane — only A2A left.
printf 'listen: "127.0.0.1:0"\nadmin_listen: "127.0.0.1:0"\nproviders: {}\nmodels: {}\ntools:\n  s:\n    url: "https://example.com/mcp"\n    pin:\n      mechanism: unpinned\n' > "$FIX/config.yaml"
mk_no_providers
run_busbar "$A2A_DELETED_BIN" --validate >"$FIX/a2a-tools-validate.out" 2>&1 \
  || { cat "$FIX/a2a-tools-validate.out"; die "the a2a-deleted binary must still ACCEPT a tools: config — MCP did not survive the A2A drop"; }
note "a2a-b MCP-survives: a tools: config validates clean with plane-a2a off"

# ── a2a-c: THE A2A PLANE'S CONFIG SURFACE LEFT WITH IT ───────────────────────────────────────────
# `plane-a2a` off compiles `busbar-a2a/src/a2a` out, so an `agents:` section names a plane this
# build does not carry. `resolve` REFUSES such a config, naming the SECTION and pointing at the
# compiled-out plane's feature (rebuild with it, or remove the block) — the config analogue of the
# protocol registry refusing a deleted dialect, and the symmetric twin of mcp-c. The neutral core
# cannot name the plane itself: a plane token in a neutral crate is what the plane-purity gate
# forbids, so the refusal is actionable by section, not by plane name.
printf 'listen: "127.0.0.1:0"\nadmin_listen: "127.0.0.1:0"\nproviders: {}\nmodels: {}\nagents:\n  a:\n    url: "https://example.com/a2a"\n' > "$FIX/config.yaml"
mk_no_providers
if run_busbar "$A2A_DELETED_BIN" --validate >"$FIX/agents-validate.out" 2>&1; then
  cat "$FIX/agents-validate.out"; die "the a2a-deleted binary ACCEPTED an agents: config — the A2A plane's config surface did not leave with it"
fi
grep -qiE "agents:" "$FIX/agents-validate.out" \
  && grep -qiE "compiled without the plane that owns it|rebuild with that plane.s feature" "$FIX/agents-validate.out" \
  || { cat "$FIX/agents-validate.out"; die "the agents: refusal must name the section AND point at the compiled-out plane's feature (neutral core cannot name the plane — plane-purity)"; }
note "a2a-c config: an agents: section is REFUSED, naming the section and the compiled-out plane's feature"

# and it BOOTS and SERVES (R-D: fewer planes is a valid busbar).
PORT=$(free_port) || die "could not find a free port pair for the a2a-deleted boot"
ADMIN_PORT=$(( PORT + 1 ))
mk_providers "anthropic"; mk_config "127.0.0.1:$PORT" "127.0.0.1:$ADMIN_PORT"
run_busbar_bg "$A2A_DELETED_BIN" >"$FIX/boot-a2a.log" 2>&1 &
SRV_PID=$!
up=""
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then up=1; break; fi
  kill -0 "$SRV_PID" 2>/dev/null || break
  sleep 0.5
done
[ -n "$up" ] || { cat "$FIX/boot-a2a.log"; die "the a2a-deleted binary did not come up on /healthz"; }
curl -fsS "http://127.0.0.1:$PORT/stats" >/dev/null || die "/stats must answer on the a2a-deleted binary"
# THE /a2a HTTP LEG: the A2A PLANE — its `POST /a2a/agents/{id}` receiving mount — is compiled
# out with `plane-a2a`, so a POST under `/a2a` resolves to NO plane handler (non-2xx), while the
# operator surface (/healthz, /stats) and the surviving LLM/MCP planes still serve.
#
# As with mcp-b, this OFF-build boot carries NO `agents:`/`public_url`, and the A2A receiving door
# mounts only when BOTH are set — so `POST /a2a` here would 404 even on a plane-ON build with the
# same config. The bare 404 is turned into a real discriminator by the mounted-vs-absent control
# below (a2a-b-mounted): the DEFAULT build, given `agents:` + `public_url`, mounts the door and
# ROUTES a POST /a2a to a live plane response (non-404), while an unmounted sibling path still 404s.
A2A_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$PORT/a2a/agents/probe" \
  -H 'content-type: application/json' -d '{"jsonrpc":"2.0","method":"message/send","id":1}')
case "$A2A_CODE" in
  2*) die "POST /a2a answered $A2A_CODE with the A2A plane compiled out — the plane's data path did not leave core" ;;
esac
kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; SRV_PID=""
note "a2a-b boot: /healthz 200, /stats 200, POST /a2a $A2A_CODE (plane ABSENT) with plane-a2a off"

# ── a2a-b-mounted: the DEFAULT build (plane-a2a ON), given `agents:`+`public_url`, MOUNTS the door ─
# The PRESENT half of the discriminator. The default binary is booted with a receiving A2A config
# (`public_url` + one `agents:` entry), so `POST /a2a` routes to the mounted plane and answers a
# plane status (503 here — the door is mounted but the fixture registers no live upstream), which is
# NON-404. A sibling path the plane does NOT own (`/a2a-not-a-route`) still 404s on the SAME running
# build, proving the non-404 is the SPECIFIC mounted door and not a blanket answer. Paired with the
# 404 above, POST /a2a now DISCRIMINATES "plane present & mounted" (non-404) from "compiled out" (404).
[ -x target/debug/busbar ] || die "default build binary missing for the a2a mounted control"
A2A_ON_PORT=$(free_port) || die "could not find a free port pair for the a2a-mounted control boot"
A2A_ON_ADMIN=$(( A2A_ON_PORT + 1 ))
printf 'listen: "127.0.0.1:%s"\nadmin_listen: "127.0.0.1:%s"\npublic_url: https://busbar.example.com\nproviders: {}\nmodels: {}\nagents:\n  probe:\n    url: https://remote-agent.example.com/a2a\n    pin:\n      mechanism: unpinned\n' \
  "$A2A_ON_PORT" "$A2A_ON_ADMIN" > "$FIX/config.yaml"
mk_no_providers
run_busbar_bg target/debug/busbar >"$FIX/boot-a2a-mounted.log" 2>&1 &
SRV_PID=$!
up=""
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$A2A_ON_PORT/stats" >/dev/null 2>&1; then up=1; break; fi
  kill -0 "$SRV_PID" 2>/dev/null || break
  sleep 0.5
done
[ -n "$up" ] || { cat "$FIX/boot-a2a-mounted.log"; die "the a2a-mounted control did not come up on the default build"; }
A2A_ON_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$A2A_ON_PORT/a2a" \
  -H 'content-type: application/json' -d '{"jsonrpc":"2.0","method":"message/send","id":1}')
case "$A2A_ON_CODE" in
  404) die "with plane-a2a ON and agents:+public_url, POST /a2a must MOUNT (non-404); got 404" ;;
esac
A2A_ON_UNROUTED=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$A2A_ON_PORT/a2a-not-a-route" \
  -H 'content-type: application/json' -d '{}')
[ "$A2A_ON_UNROUTED" = "404" ] \
  || die "the mounted non-404 must be SPECIFIC to the A2A door; an unowned path gave $A2A_ON_UNROUTED, not 404"
kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; SRV_PID=""
note "a2a-b-mounted: plane-a2a ON mounts the door — POST /a2a $A2A_ON_CODE (present), unowned path 404; vs 404 with plane-a2a off (DISCRIMINATES present-mounted from compiled-out)"

# ── mcp-d: DROP MCP, KEEP A2A ON — the symmetric twin of a2a-b (which drops A2A and keeps MCP) ────
# a2a-b/mcp-b drop the two planes as a SET or one-with-LLM-only; neither boots "MCP gone, A2A still
# serving". This leg does: build with `plane-a2a` (plus proto-llm + admin/hooks) but NOT `plane-mcp`,
# under `-D warnings`, and prove the two planes are independently droppable in BOTH directions — the
# A2A door mounts and routes on a build the MCP plane has left entirely.
MCP_A2AON_TARGET="target/deletion-gate-mcp-a2aon"
MCP_A2AON_KEEP="auth-admin-tokens,hooks-ranking,proto-llm,plane-a2a"
note "mcp-d build: RUSTFLAGS=-D warnings cargo build -p busbar --no-default-features --features $MCP_A2AON_KEEP (plane-mcp OFF, plane-a2a ON)"
RUSTFLAGS="-D warnings" CARGO_TARGET_DIR="$MCP_A2AON_TARGET" cargo build -q -p busbar \
  --no-default-features --features "$MCP_A2AON_KEEP" \
  || die "the busbar binary must build clean under -D warnings with plane-mcp OFF and plane-a2a ON"
MCP_A2AON_BIN="$MCP_A2AON_TARGET/debug/busbar"
[ -x "$MCP_A2AON_BIN" ] || die "mcp-d build binary not found at $MCP_A2AON_BIN"
note "mcp-d build: ok, clean under -D warnings ($MCP_A2AON_BIN)"

# MCP's config surface left with the plane: a `tools:` section names a plane this build does not
# carry, so `resolve` REFUSES it, naming the section and pointing at the compiled-out plane's feature
# (the mcp-c refusal, on the leg where A2A is the survivor rather than the casualty).
printf 'listen: "127.0.0.1:0"\nadmin_listen: "127.0.0.1:0"\nproviders: {}\nmodels: {}\ntools:\n  s:\n    url: "https://example.com/mcp"\n    pin:\n      mechanism: unpinned\n' > "$FIX/config.yaml"
mk_no_providers
if run_busbar "$MCP_A2AON_BIN" --validate >"$FIX/mcp-d-tools.out" 2>&1; then
  cat "$FIX/mcp-d-tools.out"; die "the mcp-d binary ACCEPTED a tools: config — the MCP plane's config surface did not leave with it"
fi
grep -qiE "tools:" "$FIX/mcp-d-tools.out" \
  && grep -qiE "compiled without the plane that owns it|rebuild with that plane.s feature" "$FIX/mcp-d-tools.out" \
  || { cat "$FIX/mcp-d-tools.out"; die "the mcp-d tools: refusal must name the section AND point at the compiled-out plane's feature (neutral core cannot name the plane — plane-purity)"; }
note "mcp-d config: a tools: section is REFUSED, naming the section and the compiled-out plane's feature (A2A survives)"

# A2A's config surface SURVIVES: an `agents:` section validates clean, because plane-a2a is ON.
printf 'listen: "127.0.0.1:0"\nadmin_listen: "127.0.0.1:0"\npublic_url: https://busbar.example.com\nproviders: {}\nmodels: {}\nagents:\n  probe:\n    url: https://remote-agent.example.com/a2a\n    pin:\n      mechanism: unpinned\n' > "$FIX/config.yaml"
mk_no_providers
run_busbar "$MCP_A2AON_BIN" --validate >"$FIX/mcp-d-agents.out" 2>&1 \
  || { cat "$FIX/mcp-d-agents.out"; die "the mcp-d binary must ACCEPT an agents: config — A2A did not survive the MCP drop"; }
note "mcp-d A2A-survives: an agents: config validates clean with plane-mcp off, plane-a2a on"

# It BOOTS, the A2A door MOUNTS and ROUTES (non-404), and POST /mcp is 404 (the MCP mount left).
PORT=$(free_port) || die "could not find a free port pair for the mcp-d boot"
ADMIN_PORT=$(( PORT + 1 ))
printf 'listen: "127.0.0.1:%s"\nadmin_listen: "127.0.0.1:%s"\npublic_url: https://busbar.example.com\nproviders: {}\nmodels: {}\nagents:\n  probe:\n    url: https://remote-agent.example.com/a2a\n    pin:\n      mechanism: unpinned\n' \
  "$PORT" "$ADMIN_PORT" > "$FIX/config.yaml"
mk_no_providers
run_busbar_bg "$MCP_A2AON_BIN" >"$FIX/boot-mcp-d.log" 2>&1 &
SRV_PID=$!
up=""
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$PORT/stats" >/dev/null 2>&1; then up=1; break; fi
  kill -0 "$SRV_PID" 2>/dev/null || break
  sleep 0.5
done
[ -n "$up" ] || { cat "$FIX/boot-mcp-d.log"; die "the mcp-d binary did not come up on /stats"; }
MCP_D_A2A=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$PORT/a2a" \
  -H 'content-type: application/json' -d '{"jsonrpc":"2.0","method":"message/send","id":1}')
[ "$MCP_D_A2A" != "404" ] \
  || die "with plane-a2a ON the A2A door must MOUNT (non-404) on the mcp-d build; got 404"
MCP_D_MCP=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$PORT/mcp" \
  -H 'content-type: application/json' -d '{"jsonrpc":"2.0","method":"initialize","id":1}')
[ "$MCP_D_MCP" = "404" ] \
  || die "with plane-mcp OFF, POST /mcp must be ABSENT (404) on the mcp-d build; got $MCP_D_MCP"
kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; SRV_PID=""
note "mcp-d boot: /stats 200, POST /a2a $MCP_D_A2A (A2A mounted), POST /mcp 404 (MCP compiled out)"

echo "proto-deletion-gate: PASS (static 0; the LLM protocol deletes as one plugin and all six dialects it carries are refused, boot+serve, remaining dialects unaffected, control green; mcp and a2a each independently droppable in BOTH directions — the receiving door mounts and routes when its plane is present and 404s when it is compiled out — and the binary still serving)"
