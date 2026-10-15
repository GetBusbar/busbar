# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: cross-parity — the 4 ORDERED OpenAI<->Gemini pairs (oo, og, go, gg).
#
# For every shared concept of the machine-readable `qa/evidence/voice-cross-dialect-map.json`:
#   * CODEC: the plane's own codecs (`busbar_plane_streaming::codec`, the module the door's sessions
#     run) bridge the concept A → IR → B → IR keeping its load-bearing fields (correlation-collapsed
#     fingerprint; documented non-survivors excluded per the map);
#   * DOOR: the bridged B wire is pushed through a live session on the door that speaks B, on the
#     linked AND the dropped door, and what the door relays must equal the session rules (a caller
#     frame reaches the far end as sent, the caller's session config replaced by the locked one; a
#     far-end frame reaches the caller as sent, usage consumed into reported units, a barge-in also
#     cancelling and truncating upstream). RED arm per concept: a door reporting a token the far end
#     never sent fails.
# Every asymmetry row is exercised as a documented drop+warn in its origin→other direction (codec);
# concepts with no decoding source fixture print a SUBITEM PENDING line, never a pass. The diagonal
# pairs (oo, gg) are slices in their own right: a mapping that is not identity within a dialect is
# already broken.

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=conformance
LEG_STATUS=ready
LEG_SLICES=(oo og go gg)

leg_execute() {
  local pair="$1"
  local bin
  bin="$(voice_conform_bin)" || { echo "RESULT $pair FAIL harness build failed"; return 0; }
  "$bin" cross "$pair" "$VC_FIXTURES/openai" "$VC_FIXTURES/gemini" "$VC_MAP"
}
