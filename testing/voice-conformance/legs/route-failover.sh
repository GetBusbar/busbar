# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: route-failover — the door's half of the route walk (BUSBAR-1.6.0.md THE DESIGN §1 step 5 ROUTE;
# Part 3 §12 "The route pump": the walk — pool, member pick, breaker, failover, exhaustion — is the
# kernel's, and the driver builds no second one).
#
# THE DOOR'S HALF (judged, linked AND dropped door): the mint names the LOCAL route — busbar mints the
# ticket and dials nothing (row 132, BUSBAR-1.6.0.md l.766) — and every door that reaches the far end
# (the SDP door's call, the Gemini Live and telephony sockets) names the session model's DIRECT route
# (and none with no model configured); a turn's ATTEMPT carries nothing of its own, so each attempt the
# walk makes dials the same session afresh. The plane opens no socket and holds no breaker or guard.
# RED arm: an ATTEMPT that carries a frame of its own fails.

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=conformance
LEG_STATUS=ready
LEG_SLICES=(route-failover)

leg_execute() {
  local slice="$1"
  local bin
  bin="$(voice_conform_bin)" || { echo "RESULT $slice FAIL harness build failed"; return 0; }
  "$bin" composition "$slice"
}
