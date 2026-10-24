# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: replay — captured-transcript replay.
#
# Each dialect's captured `transcript.jsonl` (testing/voice-conformance/fixtures/{openai,gemini}/):
#   * READ: the harness's own reader (ARCHITECT ruling R-18) reads every frame in order and finds the
#     expected concept skeleton (config → connect → audio → tool call → tool result → audio →
#     barge-in → close/complete) in order;
#   * DOOR: the whole transcript driven through ONE live session on the door (client lines as caller
#     pieces, server lines as far-end pieces), linked AND dropped; what the door relays must equal the
#     session rules (byte for byte, a governed frame under the lock), and the same skeleton must appear in the order the door emitted it
#     (the far end's usage reports included: they are relayed, and also reported as units). RED arms:
#     a door reporting a token the transcript never sent, re-encoding a frame, or dropping one fails.

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=conformance
LEG_STATUS=ready
LEG_SLICES=(default)

leg_execute() {
  local slice="$1"
  local bin
  bin="$(voice_conform_bin)" || { echo "RESULT $slice FAIL harness build failed"; return 0; }
  "$bin" replay "$VC_FIXTURES"
}
