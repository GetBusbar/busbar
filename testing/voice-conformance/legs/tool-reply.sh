# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: tool-reply — a tool call is RELAYED, never answered (Law 11; QUESTIONS Q98; ARCHITECT Q128).
#
# THE DOOR'S HALF (judged on both duplex dialects, OpenAI Realtime and Gemini Live, linked AND dropped
# door): the model's tool call reaches the caller as it was made (dialect translation only); the door
# sends the far end NOTHING for it (busbar authors no tool result); the call is counted once; and the
# caller's own result reaches the far end unchanged and alone (no door-authored response). RED arm: a
# door that answers the call upstream fails.
#
# NOT PORTED, BY RULING: the old leg certified in-process tool execution and busbar waking, refusing
# and sweeping client tool replies through an open-call table; those assertions violate Law 11 and are
# not carried in any form.

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=conformance
LEG_STATUS=ready
LEG_SLICES=(tool-reply)

leg_execute() {
  local slice="$1"
  local bin
  bin="$(voice_conform_bin)" || { echo "RESULT $slice FAIL harness build failed"; return 0; }
  "$bin" composition "$slice"
}
