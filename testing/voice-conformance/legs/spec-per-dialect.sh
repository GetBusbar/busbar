# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: spec-per-dialect — the voice conformance spec, run once PER DIALECT.
#
# The matrix is the two dialects busbar's voice plane will speak: openai and gemini. Each slice runs
# the full spec battery against that dialect's peer and holds it to the dialect's own required
# scenario set (set equality, never a floor — see the sibling MCP `assert_covered`).
#
# STATUS: ready. Wired against the `busbar-voice` plane. Each slice drives EVERY captured fixture in
# `testing/voice-conformance/fixtures/$dialect/` through the dialect's real codec
# (`OpenAiRealtimeCodec` / `GeminiLiveCodec`) as wire JSON → IR → wire JSON, and asserts round-trip
# stability at the level the codec guarantees (IR-fixpoint; some families are also byte-stable, and
# an atomic Gemini `toolCall` that decodes to a streamed triple is held to the correlation
# fingerprint, since the stateless writer re-frames per event). A fixture that decodes to NOTHING is
# only accepted when it is a documented drop+warn; anything else fails RED. One fixture — the Gemini
# `realtimeInput.audio{}` uplink shape the shipped codec does not read — stays an HONEST PENDING
# sub-item (printed, never dressed as a pass), not a reason to weaken the whole leg.

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=conformance
LEG_STATUS=ready
LEG_SLICES=(openai gemini)

leg_execute() {
  local dialect="$1"
  local bin
  bin="$(voice_conform_bin)" || { echo "RESULT $dialect FAIL harness build failed"; return 0; }
  "$bin" spec "$dialect" "$VC_FIXTURES/$dialect"
}
