# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: replay — captured-transcript replay.
#
# Each dialect's captured `transcript.jsonl` (testing/voice-conformance/fixtures/{openai,gemini}/):
#   * CODEC: decoded through ONE session state in order, every event re-framed to valid wire JSON, and
#     the expected concept skeleton (config → connect → audio → tool call → tool result → audio →
#     barge-in → close/complete) re-derived in order;
#   * DOOR: the whole transcript driven through ONE live session on the door (client lines as caller
#     pieces, server lines as far-end pieces), linked AND dropped; what the door relays must equal the
#     session rules, and the same skeleton must appear in the order the door emitted it (less the far
#     end's usage, which the session consumes into reported units). RED arm: a door reporting a token
#     the transcript never sent fails.

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
