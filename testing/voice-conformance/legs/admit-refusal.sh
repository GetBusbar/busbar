# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: admit-refusal — a refused unit opens nothing and dials nothing, and its refusal is rendered in
# the dialect's error shape (BUSBAR-1.6.0.md THE DESIGN §1, step 4 ADMIT; Part 3 §12 "refused → refusal").
#
# THE DOOR'S HALF (judged, linked AND dropped door, `voice_conform composition admit-refusal`): the
# kernel's refusal — budget 429, grant 403, credential 401 — is rendered by the door's `refusal` op in
# the realtime dialects' error envelope (the kernel's status kept, `content-type: application/json`,
# no record row); a refused unit's stream has no session (its far-end piece and its collection are
# refused, `drive` names nothing), while an admitted control on the same door dials (its frame rides
# the realtime socket need). RED arm: a door that renders the budget refusal as a server error fails.
#
# THE KERNEL'S HALF (not the door's, so not judged here): reading the caller's budget chain dry and
# refusing before any hold or ledger posting — the admit step, proven on the served leg by
# crates/busbar/src/root/tests/gauntlet_kernel.rs::served_rider_refuses_an_over_budget_caller_before_it_dials.

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=conformance
LEG_STATUS=ready
LEG_SLICES=(admit-refusal)

leg_execute() {
  local slice="$1"
  local bin
  bin="$(voice_conform_bin)" || { echo "RESULT $slice FAIL harness build failed"; return 0; }
  "$bin" composition "$slice"
}
