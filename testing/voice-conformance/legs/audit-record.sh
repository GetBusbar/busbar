# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: audit-record — the audit kind and operation the kernel's ONE row per unit is written under, and
# no row of the door's own beside it (BUSBAR-1.6.0.md THE DESIGN §1, the fixed record; Part 3 §12 "audit").
#
# THE DOOR'S HALF (judged, linked AND dropped door): the tail states the `streaming_session` audit kind
# and the one `streaming.session.open` operation class; every one of the five doors' units arrives
# as that operation; and the door writes NO record row of its own — it declares no record kind, and
# across two whole sessions, a mint and a refusal its answers carry zero record writes — so the
# kernel's one fixed record is the only row (never doubled). RED arm: a door that writes a row fails.
#
# NOT THE DOOR'S: the door does not write the session's audit row — the plane is a pure kind and the
# kernel writes the one fixed record at the unit's audit step (served leg:
# crates/busbar/src/root/tests/gauntlet_kernel.rs::served_rider_audits_each_call_once). The plane's
# `session_unit` keeps a session row internally, but the door surfaces none (no record kind declared).

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=conformance
LEG_STATUS=ready
LEG_SLICES=(audit-record)

leg_execute() {
  local slice="$1"
  local bin
  bin="$(voice_conform_bin)" || { echo "RESULT $slice FAIL harness build failed"; return 0; }
  "$bin" composition "$slice"
}
