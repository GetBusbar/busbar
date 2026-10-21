# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: twilio-media — the Twilio call's audio in and out, and its one end (Twilio's Media Streams
# messages: https://www.twilio.com/docs/voice/media-streams/websocket-messages).
#
# THE DOOR'S HALF (judged, linked AND dropped door; EVERY far-bound frame is described): inbound
# `media` frames (base64 µ-law) reach the far end as the caller's audio, byte for byte; `start` locks
# the far end to the operator's session in µ-law and sends it nothing else; `connected`, `dtmf` and the
# `mark` echo reach it as nothing; the far end's audio is written back to Twilio as `media` frames
# carrying the call's own `streamSid` (a second call carries its own, not the first's), a barge-in is
# written as `clear` and sends the far end nothing, and the end of the far end's audio sends the far
# end nothing (no spec line asks busbar to write Twilio a `mark` for it: THE DESIGN §2 l.418-419,
# Part 2 #45); `stop` ends the call exactly once and the ended call is refused on every side. RED arm:
# an outbound frame on the wrong streamSid fails.
#
# THE TOOL CALL (Law 11, BUSBAR-1.6.0.md l.2133-2135: "a tool call on any session, Twilio included,
# is relayed down that session as-is"): a far end's function call reaches the Twilio caller frame for
# frame, byte for byte, and the far end is sent nothing for it. RED arms: a door that swallows the call
# on the telephony leg, and one that answers it upstream, fail.
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
