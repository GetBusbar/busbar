# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: session-scope — the plane's `session` grant kind, at the door.
#
# THE DOOR'S HALF (judged, linked AND dropped door): the tail declares the `session` grant kind; every
# one of the five doors asks for a principal (none admits anonymously) under the one session-open
# operation; an unpublished claim is refused 404 with the plane's own code; a grant refusal renders as
# the dialect's permission_error. RED arm: a door that admits anonymously fails.
#
# THE KERNEL'S HALF: matching the presenting key's grants (wildcard, an explicit session grant, one aimed
# at another pool, an empty list) — the approve step (served leg:
# crates/busbar/src/root/tests/gauntlet_kernel.rs::served_rider_refuses_a_grant_short_of_the_operation).

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=conformance
LEG_STATUS=ready
LEG_SLICES=(session-scope)

leg_execute() {
  local slice="$1"
  local bin
  bin="$(voice_conform_bin)" || { echo "RESULT $slice FAIL harness build failed"; return 0; }
  "$bin" composition "$slice"
}
