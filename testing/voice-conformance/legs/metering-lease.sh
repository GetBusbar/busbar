# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: metering-lease — a session's units, reported per declared class (BUSBAR-1.6.0.md THE DESIGN
# §1 step "meter"; Part 3 §12: "only far-end-reported units bill").
#
# THE DOOR'S HALF (judged, linked AND dropped door): the tail declares the six counted classes plus the
# per-session fee unit; `arrive` admits on no estimate; every session answer reports cumulative
# REPORTED units — a turn's far-end tokens once per turn, the open turn's audio seconds in every
# answer as they stream (a short answer's re-call does not count its audio twice), the open turn
# settled once at the end, and the fee only once the
# far end answered (a session whose far end never answered reports none). RED arm: a door reporting one
# token more than the far end sent fails.
#
# THE KERNEL'S HALF: the session account — reserving against the caller's budget chain, capping at its
# tightest remaining bucket, ledgering the counts (the streaming door's served leg, one request on the
# presenting key's governance ledger:
# crates/busbar/src/root/tests/serve_tests.rs::a_session_door_mint_is_served_under_the_providers_credential).

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=conformance
LEG_STATUS=ready
LEG_SLICES=(metering-lease)

leg_execute() {
  local slice="$1"
  local bin
  bin="$(voice_conform_bin)" || { echo "RESULT $slice FAIL harness build failed"; return 0; }
  "$bin" composition "$slice"
}
