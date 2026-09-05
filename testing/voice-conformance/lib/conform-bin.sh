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

# Echo the path to the built `voice-conform` binary, building it once if necessary.
#   * $VOICE_CONFORM_BIN, if set, is used verbatim (the workflow builds once and exports it).
#   * else a prebuilt target/debug binary is reused if present.
#   * else the harness is built (features `runtime,test-support` — the D2 governance probe needs the
#     async session engine, and the admit/route/audit/exit composition legs drive the substrate's
#     `FixtureHost` test double over the real `EngineHost` seam) — cargo noise goes to stderr so it
#     never pollutes the RESULT lines the runner parses on stdout.
voice_conform_bin() {
  if [ -n "${VOICE_CONFORM_BIN:-}" ]; then
    printf '%s' "$VOICE_CONFORM_BIN"
    return 0
  fi
  local bin="${CARGO_TARGET_DIR:-$VC_ROOT/target}/debug/voice-conform"
  if [ ! -x "$bin" ]; then
    cargo build -q --manifest-path "$VC_ROOT/Cargo.toml" \
      -p busbar-voice --features runtime,test-support --bin voice-conform >&2 || return 1
  fi
  printf '%s' "$bin"
}
