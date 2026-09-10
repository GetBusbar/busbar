# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # VC_* are consumed by the legs/*.sh that source this file
#
# SHARED HELPER for the voice-conformance legs — NOT a leg (it lives outside legs/, so the runner's
# `legs/*.sh` glob never discovers it). Sourced by each `legs/<name>.sh` to locate the REAL Rust
# conformance harness (`busbar-voice`'s `voice-conform` bin) the legs shell out to. The legs reuse the
# crate's production codecs + runtime through this bin; they never reimplement a codec in shell.

# Resolved from THIS file's location (testing/voice-conformance/lib/): the battery dir, repo root,
# fixtures, and the cross-dialect map. Computed once at source time.
VC_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VC_DIR="$(cd "$VC_LIB_DIR/.." && pwd)"          # testing/voice-conformance
VC_ROOT="$(cd "$VC_DIR/../.." && pwd)"          # repo root
VC_FIXTURES="$VC_DIR/fixtures"
VC_MAP="$VC_ROOT/docs/design/voice-cross-dialect-map.json"

# The trees the harness IS. A `voice-conform` older than any file under these is a binary that would
# judge source it was not built from — which is not an error at run time, it is a PASS about code
# nobody is running. The legs are in the list for the reason the note below already gives: the bin
# answers a `composition <slice>` subcommand per leg, so a leg added after the binary was built is a
# slice the binary has never heard of.
_vc_harness_trees() {
  printf '%s\n' \
    "$VC_ROOT/crates/busbar-voice/src" \
    "$VC_ROOT/crates/busbar-streams-codec/src" \
    "$VC_ROOT/crates/busbar-plane-streams/src" \
    "$VC_DIR/legs" \
    "$VC_DIR/lib"
}

# Echo the first file that is NEWER than the given binary, and return 0 when there is one.
# `-print -quit` stops at the first hit: this runs once per leg and the question is "is there any",
# not "how many".
_vc_newer_than() {
  local bin="$1" dir hit
  while IFS= read -r dir; do
    [ -d "$dir" ] || continue
    hit="$(find "$dir" -type f -newer "$bin" -print -quit 2>/dev/null || true)"
    if [ -n "$hit" ]; then
      printf '%s' "$hit"
      return 0
    fi
  done < <(_vc_harness_trees)
  return 1
}

# Echo the path to the built `voice-conform` binary, building it once if necessary.
#   * $VOICE_CONFORM_BIN, if set, names the binary the workflow built once and exported — and it is
#     CHECKED before it is used. It was taken verbatim, which meant a path to nothing, or to a
#     binary built before the source beside it changed, was believed: a stale harness runs, passes,
#     and reports conformance about code that is not in the tree. That is the same false green the
#     runner's own anti-vacuity rule exists to refuse, one level further in, and unlike a missing
#     binary it leaves no trace at all — every leg reports PASS.
#   * else the harness is built (cargo is incremental, so an up-to-date binary costs a lock and a
#     stat; a binary older than the legs it serves once reported "unknown composition slice" for
#     four legs that existed only in source, and this is what stops that recurring) — features
#     `runtime,test-support` — the D2 governance probe needs the
#     async session engine, and the admit/route/audit/exit composition legs drive the substrate's
#     `FixtureHost` test double over the real `EngineHost` seam) — cargo noise goes to stderr so it
#     never pollutes the RESULT lines the runner parses on stdout.
voice_conform_bin() {
  if [ -n "${VOICE_CONFORM_BIN:-}" ]; then
    if [ ! -x "$VOICE_CONFORM_BIN" ]; then
      printf 'voice-conform: VOICE_CONFORM_BIN=%s is not an executable file\n' \
        "$VOICE_CONFORM_BIN" >&2
      return 1
    fi
    local newer
    if newer="$(_vc_newer_than "$VOICE_CONFORM_BIN")"; then
      printf 'voice-conform: VOICE_CONFORM_BIN=%s is older than %s — it would report conformance about source it was not built from\n' \
        "$VOICE_CONFORM_BIN" "$newer" >&2
      return 1
    fi
    printf '%s' "$VOICE_CONFORM_BIN"
    return 0
  fi
  local bin="${CARGO_TARGET_DIR:-$VC_ROOT/target}/debug/voice-conform"
  cargo build -q --manifest-path "$VC_ROOT/Cargo.toml" \
    -p busbar-voice --features runtime,test-support --bin voice-conform >&2 || return 1
  [ -x "$bin" ] || return 1
  printf '%s' "$bin"
}
