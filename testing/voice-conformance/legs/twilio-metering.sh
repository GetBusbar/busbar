# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: twilio-metering — a Twilio session's units, reported per declared class once per turn
# (mirrors metering-lease; BUSBAR-1.6.0.md THE DESIGN §1 step "meter", "only far-end-reported units
# bill"; the TODO's STREAMING: THREE WAYS AUDIO IS SERVED AND NOT BILLED, first bullet).
#
# THE DOOR'S HALF (judged, linked AND dropped door): caller audio arrives as Twilio `media` frames
# (8000 µ-law bytes a second); the far end's tokens are reported as cumulative REPORTED units once
# per turn, and the open turn's audio seconds in every answer as they stream (a short answer's
# re-call does not count its audio twice); a call that ends mid-turn (`stop` arrives while a turn is open) settles that open turn's
# audio once instead of discarding it; a call whose far end never answered reports its audio and no
# fee; a turn already closed is not counted again at `stop`, and a second `stop` reports nothing.
# RED arm: a door that reports the mid-turn call without the open turn's second fails.
#
# THE KERNEL'S HALF: the session account (reserving against the caller's budget chain, capping,
# ledgering), which a plane cannot see.

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=conformance
LEG_STATUS=ready
LEG_SLICES=(twilio-metering)

leg_execute() {
  local slice="$1"
  local bin
  bin="$(voice_conform_bin)" || { echo "RESULT $slice FAIL harness build failed"; return 0; }
  "$bin" twilio "$slice" "$VC_FIXTURES/twilio"
}
