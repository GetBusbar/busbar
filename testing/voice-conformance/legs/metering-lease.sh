# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: metering-lease — a served session's money hop is the HOST's, and its ceiling is the CALLER's.
#
# The governance leg proves the D2 lease hard-closes at whatever cap it is handed. This leg judges the
# question one step earlier, which fails independently: WHERE the lease lives and WHOSE budget sets
# its cap. A served session must reserve on the host's own reserve-then-settle lease — the one the
# rest of the deployment's spend flows through — with the ceiling read off the presenting principal's
# real budget chain: the tightest remaining bucket, widened from the budget projection's micro-units
# into the lease's nanodollars.
#
# The two boundaries are judged too: a caller with nothing capped anywhere in its chain has no ceiling
# to impose and stays uncapped (exactly as an unbudgeted model call does), and a caller whose budget
# is already spent is denied at the reserve, so it never opens a session at all.
#
# WAS RED: every session reserved an uncapped in-process cell, so no caller's budget could reach a
# live session and the host never saw the lease.

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
