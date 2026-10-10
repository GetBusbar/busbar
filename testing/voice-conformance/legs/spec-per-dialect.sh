# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: spec-per-dialect — the voice conformance spec, run once PER DIALECT (openai, gemini).
#
# Every captured fixture in `testing/voice-conformance/fixtures/$dialect/`:
#   * CODEC: wire JSON → IR → wire JSON → IR through the dialect's codec in the plane crate
#     (`OpenAiRealtimeCodec` / `GeminiLiveCodec`), stable at the level the codec guarantees
#     (IR-fixpoint, or the correlation fingerprint for an atomic Gemini toolCall); a fixture that
#     decodes to nothing passes only as a documented drop;
#   * DOOR: pushed through a live session on the dialect's door (the caller's frames as caller pieces,
#     the far end's as far-end pieces), linked AND dropped; the door must relay it by the session rules
#     (a documented drop on no wire at all), every far frame on the dialect's socket need, the far end's
#     tokens reported as units. RED arm per fixture: a door reporting a token never sent fails.

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
