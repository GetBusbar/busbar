# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: gemini-live-route — the Gemini Live dialect has a door, not just a codec.
#
# THE DOOR'S HALF (judged, linked AND dropped door): the snapshot claims `GET
# /v1/realtime/gemini/{call_id}` (an upgrade line whose refusals render in Gemini's dialect) beside the
# OpenAI doors under the ONE audience; `arrive` on it answers the gemini_live dialect for a principal
# on the session model's DIRECT route; and the handshake crosses the door — the caller's `setup`
# reaches the far end as a Gemini setup on the Live socket need, the far end's `setupComplete` reaches
# the caller verbatim. RED arm: a Gemini claim refused in the OpenAI dialect fails.

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=conformance
LEG_STATUS=ready
LEG_SLICES=(gemini-live-route)

leg_execute() {
  local slice="$1"
  local bin
  bin="$(voice_conform_bin)" || { echo "RESULT $slice FAIL harness build failed"; return 0; }
  "$bin" composition "$slice"
}
