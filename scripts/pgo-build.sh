#!/usr/bin/env bash
# PGO build creator: produce a profile-guided-optimized busbar binary in three phases.
#
#   1. build instrumented      (-Cprofile-generate)
#   2. train on a traffic MIX  (concurrent + governed: the benchmark's full 6 x 6 ingress x egress
#                               grid with openai passthrough at 10x weight, SSE streaming, a large
#                               body and an auth-refusal sliver - all as signed-key traffic through
#                               the keys chain, against the GetBusbar/benchmarking `mock` upstream and
#                               driven by its `otb loadgen`), repeated as THREE independent trainer
#                               runs (fresh gateway process each) whose raw profiles all feed ONE
#                               llvm-profdata merge - see TRAIN_RUNS
#   3. build optimized         (-Cprofile-use)
#
# This is the release build: the layout of the shipped binary is deliberate (profile-guided),
# not the linker's dice roll. Releases build from the profile COMMITTED for their target
# (release/pgo/<target>.profdata, passed as PGO_PROFILE - phases 1-2 are skipped), so the optimized
# build is a function of the tree alone. Training (PGO_TRAIN_ONLY=<out>) is the CI training job's
# step; it needs the benchmarking rig (PGO_BENCH_MOCK, PGO_BENCH_OTB - see phase 2). Usage:
#
#   PGO_PROFILE=release/pgo/<target>.profdata scripts/pgo-build.sh
#                                       # optimized build; binary at target/pgo/release/busbar
#   PGO_TRAIN_ONLY=out.profdata PGO_BENCH_MOCK=… PGO_BENCH_OTB=… scripts/pgo-build.sh
#                                       # train and merge only; writes out.profdata
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
# Knobs: PGO_UNIT_SECS (seconds of keep-alive load per mix unit, default 2; see phase 2's mix
# table), PGO_CONC (loadgen keep-alive connections, default 32 - the middle of the benchmark's
# c=8..64 range), PGO_PORT / PGO_MOCK_PORT (defaults 18080/18000), PGO_TARGET (cargo --target).
# Requires: cargo, rustup (llvm-tools is installed on demand), python3, curl, and for training the
# benchmarking rig binaries. The training mix is the benchmark's grid PLUS the governed production
# shape (signed-key auth + group admission + per-principal reqlog); keep it in sync when the
# product grows a new hot path.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

# ── THE RELEASE KEY, BEFORE ANY PHASE COMPILES ANYTHING ─────────────────────────────────────────
# This script is a producer of SHIPPED BYTES on two paths: scripts/release-build.sh drives it for
# every PGO target, and the removed docker.yml drives it DIRECTLY for both image legs, with
# BUSBAR_RELEASE_PUBKEY on the step's own env: block. Both optimized builds bake the key in through
# plugin-sign's `option_env!`, a compile-time read that is silently `None` when the variable is
# absent - which is how images shipped that could not verify any first-party plugin (2026-08-02).
# The direct the removed docker.yml path had no input-side assertion at all, so it gets the same one the
# release path uses, from the same file. No second copy: scripts/release-key-guard.sh is the
# implementation for both. A local profiling run is not special-cased (an opt-out is how the
# assertion stops being asserted); export a dummy 64-hex BUSBAR_RELEASE_PUBKEY for one:
#   BUSBAR_RELEASE_PUBKEY=$(printf '0%.0s' {1..64}) scripts/pgo-build.sh
scripts/release-key-guard.sh require || exit 1

# Production owns its flag/profile channel; preserve any existing owner instrumentation by
# refusing to silently replace a rustc wrapper. The final compiler receipt checks resolved args.
scripts/build-provenance-gate.sh --check-build-env || exit 1
RECEIPT_WRAPPER="$(scripts/build-provenance-gate.sh --prepare-wrapper)" || exit 1
RECEIPT_SOURCE="$(env -u GIT_INDEX_FILE -u GIT_DIR -u GIT_WORK_TREE git -C "$(pwd)" rev-parse --verify HEAD)" || exit 1

# Multi-run profile accumulation - constants, NOT knobs: this is a fixed part of the release
# recipe, not something to tune per build. A single trainer run's edge counters carry sampling
# noise (racy non-atomic increments under concurrency, scheduler-dependent interleavings), and
# that noise is the main residual driver of the build-to-build layout lottery. Running the SAME
# governed mix in TRAIN_RUNS independent trainer runs - a fresh gateway process each time, so
# each run flushes its own .profraw set - and then feeding ALL raw profiles to ONE llvm-profdata
# merge averages the noise: llvm-profdata sums counters across inputs, and the sum of three
# independent samples has a tighter relative error than any single one.
# Wall time: roughly 50 mix units of load per run, so ~2 minutes per run at the default unit,
# plus the seconds-scale gateway boot/teardown.
TRAIN_RUNS=3
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
# THREE binutils interactions make --emit-relocs more than one flag (the first CI arm64 build
# failed on all of them at once, "final link failed: invalid operation"):
#   1. The release profile's `strip = true` becomes `-Wl,--strip-all`, which DELETES the very
#      .rela.* sections --emit-relocs emits. `-Cstrip=debuginfo` (RUSTFLAGS overrides the
#      profile) keeps relocations and the symbol table BOLT wants while still dropping debug
#      sections; the BOLTed artifact is stripped after the pass, and the un-BOLTed shipped
#      binary carries symbols+relocs as the price of post-link optimizability (~ single-digit
#      MiB, inside the artifact-contract floors, which bound only minimums).
#   2. (Disproven candidate, recorded so nobody re-adds it: the aarch64 erratum rewrite
#      --fix-cortex-a53-843419 COEXISTS with --emit-relocs — the profiler-box builds carry
#      both and link clean; binutils has no --no- negation for it either. strip=true was the
#      whole failure.)
#   3. The armv8.0-compat arm64 build (BUSBAR_ARM64_BASELINE=1) is not BOLTed (BOLT applies to
#      the default artifacts), so it keeps the historical fully-stripped link with no emitted
#      relocs — byte-for-byte the pre-BOLT recipe.
if [ "${BUSBAR_ARM64_BASELINE:-0}" = "1" ]; then
  EMIT_RELOCS=""
else
  case "$EFFECTIVE_TRIPLE" in
    # Preserve function symbols/unwind and a stable ELF identity for native profile custody.
    # DWARF is stripped: these bytes support function attribution, not source-line claims.
    *-linux-*) EMIT_RELOCS="-Clink-arg=-Wl,--emit-relocs -Clink-arg=-Wl,--build-id=sha1 -Cstrip=debuginfo" ;;
    *)         EMIT_RELOCS="" ;;
  esac
fi
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
# C-RUNTIME LINKAGE (W17): the MSVC build links the CRT statically (+crt-static), so a Windows
# binary needs no Visual C++ Redistributable. Carried here because this script sets RUSTFLAGS, and an
# explicit RUSTFLAGS makes cargo ignore .cargo/config.toml's target.<triple>.rustflags, which holds
# the same flag for every other build. Joins both phases, like LSE_FLAG. Windows declares pgo:false
# today, so this is parity with release-build.sh's non-PGO arm rather than a live branch.
case "$EFFECTIVE_TRIPLE" in
  *-windows-msvc) CRT_FLAG="-Ctarget-feature=+crt-static" ;;
  *)              CRT_FLAG="" ;;
esac
# PATH REMAPPING (reproducibility + privacy). Without it the shipped bytes embed the builder's
# absolute paths - every panic location in a registry or git dependency names
# $CARGO_HOME/registry/src/... or $CARGO_HOME/git/checkouts/..., and path dependencies outside the
# dist/default workspace name the checkout - so the same tree built under another home or checkout
# directory gives different bytes, and the release leaks the build host's layout. Measured on a
# first-party plugin cdylib built the way release builds are: 52 such absolute paths. Both prefixes
# map to fixed names. It joins BOTH PGO phases identically: LLVM names a local-linkage function in a
# profile by its source path, so a profile trained under one mapping misses those functions under
# another. release-build.sh's non-PGO arm carries the same two flags. Paths with whitespace cannot
# ride RUSTFLAGS (cargo splits it on whitespace), so they are refused rather than half-applied.
REMAP_HOME="${CARGO_HOME:-$HOME/.cargo}"
case "$(pwd)$REMAP_HOME" in *[[:space:]]*) echo "the checkout or CARGO_HOME path contains whitespace; --remap-path-prefix cannot be passed through RUSTFLAGS" >&2; exit 1 ;; esac
REMAP_FLAGS="--remap-path-prefix=$(pwd)=/busbar --remap-path-prefix=$REMAP_HOME=/cargo"
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

# ── A COMMITTED PROFILE, OR TRAIN ONE (owner decision D4, 2026-10-26) ──────────────────────────
# A release builds from the profile COMMITTED for its target (release/pgo/<target>.profdata,
# passed by scripts/release-build.sh as PGO_PROFILE). The optimized build is then a function of
# the tree alone, and a second builder can reproduce it byte for byte. Training stays nondeterministic
# (concurrency, timing), so it is done once, on purpose: PGO_TRAIN_ONLY=<path> runs phases 1-2 and
# the merge, writes the merged profile to <path> and stops. The release tooling's `pgo-train`
# step drives that, and a person reviews and commits the result. Both modes are fail-closed.
if [ -n "${PGO_PROFILE:-}" ] && [ -n "${PGO_TRAIN_ONLY:-}" ]; then
  pgo_fail "PGO_PROFILE (build from a committed profile) and PGO_TRAIN_ONLY (train one) are exclusive"
fi
if [ -n "${PGO_PROFILE:-}" ]; then
  [ -s "$PGO_PROFILE" ] || pgo_fail "the committed profile is missing or empty at $PGO_PROFILE"
  MERGED="$(cd "$(dirname "$PGO_PROFILE")" && pwd)/$(basename "$PGO_PROFILE")"
  MERGED_SIZE="$(wc -c < "$MERGED" | tr -d ' ')"
  # THE PROFILE'S RECEIPT. A committed profile travels with the manifest its training run wrote
  # (<profile minus .profdata>.manifest, key=value): the raw-profile count that fed it, its digest,
  # and what trained it. The proof marker below must carry a NUMBER for profraw_count -
  # verify-artifact.py's pgo_applied row refuses anything else - and the honest number for a
  # committed profile is the one recorded when it was trained, not a placeholder. (The placeholder
  # this replaces, `committed`, failed that row on every committed-profile release.) The digest
  # check binds the receipt to these exact profile bytes.
  PGO_MANIFEST="${MERGED%.profdata}.manifest"
  [ -s "$PGO_MANIFEST" ] || pgo_fail "the committed profile has no training manifest at $PGO_MANIFEST (commit the .manifest the training job wrote beside it)"
  RAW_COUNT="$(sed -n 's/^profraw_count=//p' "$PGO_MANIFEST")"
  case "$RAW_COUNT" in ''|*[!0-9]*|0) pgo_fail "the training manifest $PGO_MANIFEST records no positive profraw_count ('$RAW_COUNT')" ;; esac
  WANT_SHA="$(sed -n 's/^profile_sha256=//p' "$PGO_MANIFEST")"
  HAVE_SHA="$( (sha256sum "$MERGED" 2>/dev/null || shasum -a 256 "$MERGED") | cut -d' ' -f1)"
  [ -n "$WANT_SHA" ] && [ "$WANT_SHA" = "$HAVE_SHA" ] \
    || pgo_fail "the committed profile's digest $HAVE_SHA does not match its training manifest ($WANT_SHA): the profile and its receipt are from different training runs"
  log "phases 1-2 skipped: building from the committed profile $MERGED (${MERGED_SIZE} bytes)"
else
# ---- phase 1: instrumented build ------------------------------------------------------------
log "phase 1/3: instrumented build"
rm -rf "$PROF_DIR"; mkdir -p "$PROF_DIR"
# $LSE_FLAG joins the INSTRUMENTED build too (not just the optimized one): the training profile
# must be gathered on the same ISA variant the optimized build targets, or the profile is a
# statement about a different binary.
# shellcheck disable=SC2086  # TARGET_FLAG is deliberately unquoted (see its definition)
BUSBAR_PROVENANCE_SOURCE="$RECEIPT_SOURCE" BUSBAR_PROVENANCE_WRAPPER=1 RUSTC_WRAPPER="$RECEIPT_WRAPPER" \
RUSTFLAGS="-Cprofile-generate=$PROF_DIR $REMAP_FLAGS${LSE_FLAG:+ $LSE_FLAG}${CRT_FLAG:+ $CRT_FLAG}" \
  cargo build --release --locked --manifest-path dist/default/Cargo.toml --bin busbar $TARGET_FLAG --target-dir target/pgo-gen \
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

# ---- phase 2: train --------------------------------------------------------------------------
# The workload lives in scripts/pgo-workload.sh (one trainer run against a given binary), because the
# BOLT pass replays the SAME traffic against its instrumented rewrite: one definition of
# representative traffic for both profile-guided passes. It drives the GetBusbar/benchmarking rig -
# its `mock` upstream and `otb loadgen` - built READ-ONLY at that repository's ENGINE_PIN commit and
# passed in as PGO_BENCH_MOCK / PGO_BENCH_OTB (the rig is the benchmark's frozen instrument; it is
# never edited for training). Each run is a complete, independent trainer run: fresh mock, fresh
# gateway process, fresh in-memory client key, with an explicit per-run LLVM_PROFILE_FILE
# (run<N>_%m_%p.profraw) so each run's flush is a checkable fact. Any failure in any run is fatal:
# multi-run does not soften fail-closed.
log "phase 2/3: training ($TRAIN_RUNS runs via scripts/pgo-workload.sh)"
for RUN in $(seq 1 "$TRAIN_RUNS"); do
  LLVM_PROFILE_FILE="$PROF_DIR/run${RUN}_%m_%p.profraw" PGO_PORT="$PORT" PGO_MOCK_PORT="$MOCK_PORT" \
    scripts/pgo-workload.sh --binary "$INSTRUMENTED" --run "$RUN" --runs "$TRAIN_RUNS" \
    || pgo_fail "run $RUN/$TRAIN_RUNS: the training workload failed (see [pgo-workload] above)"
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
if [ -n "${PGO_TRAIN_ONLY:-}" ]; then
  mkdir -p "$(dirname "$PGO_TRAIN_ONLY")"
  cp "$MERGED" "$PGO_TRAIN_ONLY" || pgo_fail "could not write the trained profile to $PGO_TRAIN_ONLY"
  # The receipt a committed-profile build reads back (see PGO_MANIFEST above). Deliberately no
  # wall-clock field: the manifest is committed, and two reviews of the same training run must
  # see the same bytes.
  {
    echo "profraw_count=$RAW_COUNT"
    echo "profile_bytes=$MERGED_SIZE"
    echo "profile_sha256=$( (sha256sum "$MERGED" 2>/dev/null || shasum -a 256 "$MERGED") | cut -d' ' -f1)"
    echo "source_commit=$RECEIPT_SOURCE"
    echo "toolchain=$(rustc -V)"
    echo "target=${TARGET:-$EFFECTIVE_TRIPLE}"
    echo "target_features=${LSE_FLAG:+lse}"
    echo "arm64_baseline=${BUSBAR_ARM64_BASELINE:-0}"
    echo "train_runs=$TRAIN_RUNS"
    echo "unit_secs=${PGO_UNIT_SECS:-2}"
    echo "conc=${PGO_CONC:-32}"
    echo "bench_engine_pin=${PGO_BENCH_ENGINE_PIN:-unrecorded}"
  } > "${PGO_TRAIN_ONLY%.profdata}.manifest" || pgo_fail "could not write the training manifest"
  log "trained profile: $PGO_TRAIN_ONLY (${MERGED_SIZE} bytes from ${RAW_COUNT} .profraw); review and commit it"
  exit 0
fi
fi

# BUSBAR_PGO=1 IS DELIBERATELY NOT SET HERE ANY MORE. crates/busbar/build.rs stamps the
# build-provenance record `pgo=` from EITHER that env var OR the presence of `-Cprofile-use` in
# CARGO_ENCODED_RUSTFLAGS — the flags cargo ACTUALLY applied — and it is an OR, so the explicit env
# var always won and the stamp could only ever repeat this script's intention back to it. Dropping
# the env var turns the stamp into an INDEPENDENT WITNESS: it now says pgo=true only when the flag
# genuinely reached the compiler. Verified: a build with `-Cprofile-use` in RUSTFLAGS and BUSBAR_PGO
# unset reports `pgo=true`; a plain build reports `pgo=false`, which the removed ci.yml's build-provenance gate
# already asserts. build.rs declares rerun-if-env-changed for both signals, so the stamp cannot go
# stale across this switch.
# $EMIT_RELOCS rides along on Linux targets only — the BOLT prerequisite documented at its
# definition near the top of this file. $LSE_FLAG (arm64 default only; see its definition) joins
# here exactly as it joined the instrumented build, and BOLT's emit-relocs path is unchanged by it.
# shellcheck disable=SC2086  # TARGET_FLAG is deliberately unquoted (see its definition)
BUSBAR_PROVENANCE_SOURCE="$RECEIPT_SOURCE" BUSBAR_PROVENANCE_WRAPPER=1 RUSTC_WRAPPER="$RECEIPT_WRAPPER" \
RUSTFLAGS="-Cprofile-use=$MERGED $REMAP_FLAGS${EMIT_RELOCS:+ $EMIT_RELOCS}${LSE_FLAG:+ $LSE_FLAG}${CRT_FLAG:+ $CRT_FLAG}" \
  python3 scripts/release/cargo_capture.py --directory "${BUSBAR_CARGO_CAPTURE_DIR:-$WORK/cargo-final}" -- \
  build --release --locked --manifest-path dist/default/Cargo.toml --bin busbar $TARGET_FLAG --target-dir target/pgo \
  || pgo_fail "optimized (-Cprofile-use) build failed"
[ -x "$OUT" ] || pgo_fail "optimized binary missing at $OUT"

# ── OUTPUT-SIDE PGO PROOF: ASK THE ARTIFACT, NOT THE BUILD ────────────────────────────────────
# Everything above this line asserts that -Cprofile-use was PASSED. Nothing asserted it was
# APPLIED, and `[ -x "$OUT" ]` cannot tell the difference: cargo exiting 0 with a binary at the
# expected path is equally consistent with a full PGO build, with rustc declining an unusable
# profile (a warning, not an error), and with cargo judging a PREVIOUS run's non-PGO artifact
# up-to-date and rebuilding nothing — `target/pgo` is never cleaned and this RUSTFLAGS string is
# byte-identical between runs. Proven by construction: a toolchain that ignored RUSTFLAGS produced
# a non-PGO binary and this script printed "PGO VERIFIED", exited 0, and wrote the marker.
#
# Two assertions close it, both about the bytes that will ship:
#   FRESHNESS - the artifact must post-date the profile it claims to be built from. A no-op build
#               leaves $OUT older than the merge that just ran.
#   THE STAMP - the binary must self-report pgo=true (plus profile=release, opt-level=3,
#               debug-assertions=false). With BUSBAR_PGO no longer set, that bit is derived from
#               cargo's own CARGO_ENCODED_RUSTFLAGS, so it is the compiler's account of what it
#               was given rather than this script's account of what it sent.
[ "$OUT" -nt "$MERGED" ] \
  || pgo_fail "$OUT is not newer than the merged profile at $MERGED - the optimized build was a no-op and this run would have stamped a previous build's bytes as PGO-verified"
scripts/build-provenance-gate.sh "$OUT" release true \
  || pgo_fail "the optimized binary does not self-report an optimized PGO release build (-Cprofile-use did not reach the compiler, or the release profile was weakened). The build-provenance stamp is read from the flags cargo actually applied, so this is the artifact disagreeing with the build - never write a proof marker over that."

# POSITIVE VERIFICATION: write the proof marker only now - after a non-empty merged profile was
# fed to a successful -Cprofile-use build. Its existence (checked by the workflow) is proof the
# shipped binary is PGO-optimized. Guard the merged profile is STILL non-empty at write time.
[ -s "$MERGED" ] || pgo_fail "merged profile vanished before marker write at $MERGED"
{
  echo "pgo-verified=1"
  echo "profile=$MERGED"
  echo "profile_bytes=$MERGED_SIZE"
  echo "profraw_count=$RAW_COUNT"
  echo "profile_sha256=$( (sha256sum "$MERGED" 2>/dev/null || shasum -a 256 "$MERGED") | cut -d' ' -f1)"
  echo "target=${TARGET:-<host>}"
  # `lse` identifies the armv8.1 floor of the default arm64 artifact. An empty value identifies
  # the armv8.0-compatible compat artifact or a non-arm64 target.
  # Extra marker keys are ignored by older readers; verify-artifact.py's pgo_applied row parses
  # key=value lines generically.
  echo "target_features=${LSE_FLAG:+lse}"
  echo "arm64_baseline=${BUSBAR_ARM64_BASELINE:-0}"
  echo "train_runs=$TRAIN_RUNS"
  echo "unit_secs=${PGO_UNIT_SECS:-2}"
  echo "built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$MARKER" || pgo_fail "could not write proof marker at $MARKER"
[ -s "$MARKER" ] || pgo_fail "proof marker empty after write at $MARKER"

log "done: $OUT"
log "PGO VERIFIED: marker=$MARKER profile=$MERGED (${MERGED_SIZE} bytes from ${RAW_COUNT} .profraw)"
echo "$OUT"
