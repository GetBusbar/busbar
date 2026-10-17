# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: twilio-media — the Twilio call's audio in and out, and its one end (Twilio's Media Streams
# messages: https://www.twilio.com/docs/voice/media-streams/websocket-messages).
#
# THE DOOR'S HALF (judged, linked AND dropped door): inbound `media` frames (base64 µ-law) reach the far
# end as the caller's audio, byte for byte, while `connected`, `start`, `dtmf` and the `mark` echo reach
# it as nothing; the far end's audio is written back to Twilio as `media` frames carrying the call's
# own `streamSid` (a second call carries its own, not the first's), the end of the far end's audio is
# written as Twilio's `mark` (a name, the call's streamSid), a barge-in is written as `clear`; `stop`
# ends the call exactly once and the ended call is refused on every side. RED arm: an outbound frame
# on the wrong streamSid fails.
#
# THE KERNEL'S HALF: the WebSocket transport that carries the frames and the far end's dial.

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=conformance
LEG_STATUS=ready
LEG_SLICES=(twilio-media)

leg_execute() {
  local slice="$1"
  local bin
  bin="$(voice_conform_bin)" || { echo "RESULT $slice FAIL harness build failed"; return 0; }
  "$bin" twilio "$slice" "$VC_FIXTURES/twilio"
}
