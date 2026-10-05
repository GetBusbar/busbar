# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # VC_* are consumed by the legs/*.sh that source this file
#
# SHARED HELPER for the voice-conformance legs — NOT a leg (it lives outside legs/, so the runner's
# `legs/*.sh` glob never discovers it). Sourced by each `legs/<name>.sh` to locate the REAL Rust
# conformance harness the legs shell out to: `busbar-plane-streaming`'s dev-only `voice_conform`
# example, which drives the streaming plane's DOOR both ways through the loader — the linked door and
# the `streaming_door` example cdylib, dlopened (ARCHITECT Q6). The legs reuse the plane's own door
# and codecs through this harness; they never reimplement a codec — or a door — in shell.

# Resolved from THIS file's location (testing/voice-conformance/lib/): the battery dir, repo root,
# fixtures, and the cross-dialect map. Computed once at source time.
VC_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VC_DIR="$(cd "$VC_LIB_DIR/.." && pwd)"          # testing/voice-conformance
VC_ROOT="$(cd "$VC_DIR/../.." && pwd)"          # repo root
VC_FIXTURES="$VC_DIR/fixtures"
VC_MAP="$VC_ROOT/qa/evidence/voice-cross-dialect-map.json"

# The trees the harness IS. A `voice_conform` older than any file under these is a binary that would
# judge source it was not built from — which is not an error at run time, it is a PASS about code
# nobody is running. The legs are in the list for the reason the note below already gives: the bin
# answers a `composition <slice>` subcommand per leg, so a leg added after the binary was built is a
# slice the binary has never heard of.
_vc_harness_trees() {
  printf '%s\n' \
    "$VC_ROOT/crates/busbar-plane-streaming/src" \
    "$VC_ROOT/crates/busbar-plane-streaming/examples" \
    "$VC_ROOT/crates/plugin-loader/src" \
    "$VC_ROOT/crates/busbar-contract/src" \
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

# Echo the path to the built `voice_conform` harness, building it (and the dropped-in door beside it)
# once if necessary.
#   * $VOICE_CONFORM_BIN, if set, names the harness the workflow built once and exported — and it is
#     CHECKED before it is used: a path to nothing, or to a binary built before the source beside it
#     changed, would run, pass, and report conformance about code that is not in the tree (the same
#     false green the runner's anti-vacuity rule refuses, one level further in). The dropped-in door
#     it loads is found beside it (or at $VOICE_CONFORM_DOOR); a door that is not there is a FAIL in
#     every assertion, never a skip.
#   * else both examples are built (cargo is incremental, so an up-to-date pair costs a lock and a
#     stat; a harness older than the legs it serves would answer "unknown composition slice" for a leg
#     that exists only in source) — cargo noise goes to stderr so it never pollutes the RESULT lines
#     the runner parses on stdout.
voice_conform_bin() {
  if [ -n "${VOICE_CONFORM_BIN:-}" ]; then
    if [ ! -x "$VOICE_CONFORM_BIN" ]; then
      printf 'voice_conform: VOICE_CONFORM_BIN=%s is not an executable file\n' \
        "$VOICE_CONFORM_BIN" >&2
      return 1
    fi
    local newer
    if newer="$(_vc_newer_than "$VOICE_CONFORM_BIN")"; then
      printf 'voice_conform: VOICE_CONFORM_BIN=%s is older than %s — it would report conformance about source it was not built from\n' \
        "$VOICE_CONFORM_BIN" "$newer" >&2
      return 1
    fi
    printf '%s' "$VOICE_CONFORM_BIN"
    return 0
  fi
  local bin="${CARGO_TARGET_DIR:-$VC_ROOT/target}/debug/examples/voice_conform"
  cargo build -q --manifest-path "$VC_ROOT/Cargo.toml" -p busbar-plane-streaming \
    --example voice_conform --example streaming_door >&2 || return 1
  [ -x "$bin" ] || return 1
  printf '%s' "$bin"
}
