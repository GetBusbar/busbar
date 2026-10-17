# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: exit-terminal — one session ends ONCE (BUSBAR-1.6.0.md THE DESIGN §1, the exit step).
#
# THE DOOR'S HALF (judged, linked AND dropped door): the caller's end settles the open turn's audio
# seconds once and carries the session's end exactly once (cumulative units final); afterwards the
# stream is refused on every side (a collection and a far-end piece) and `drive` names nothing; a
# session torn down before its first frame ends with no units and no fee. RED arm: a second end fails.
#
# THE KERNEL'S HALF: sealing the session's one line and evicting its durable row (served leg:
# crates/busbar/src/root/tests/gauntlet_kernel.rs::served_rider_ends_each_call_once).

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=conformance
LEG_STATUS=ready
LEG_SLICES=(exit-terminal)

leg_execute() {
  local slice="$1"
  local bin
  bin="$(voice_conform_bin)" || { echo "RESULT $slice FAIL harness build failed"; return 0; }
  "$bin" composition "$slice"
}
