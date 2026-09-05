# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: exit-terminal — one voice session ends ONCE: exactly one metering-lease settlement and exactly
# one admin-audit row, even when the session is INTERRUPTED (torn down before it runs a single frame,
# and independently closed twice — the shape a parked per-frame handler's stale guard plus the node's
# own sweep produce, ARCHITECTURE.md's loop, the "exit" step — ONE exit path).
#
# TWO INDEPENDENT PROOFS, both over the substrate's `FixtureHost` (the same faithful in-memory
# `CostHold`/audit-ring stand-in the admit/route/audit legs use):
#
#   1. METERING SETTLES EXACTLY ONCE UNDER A DOUBLE CLOSE. `MeteringHost::cost_close` is the primitive
#      `LeaseCloseGuard::drop` calls, and its OWN contract is that a redundant close is a harmless
#      `None` -- "no double refund" (see `runtime/metering.rs`'s doc comment on `LeaseCloseGuard`).
#      This leg reserves, settles a real increment, then closes the SAME lease id TWICE directly
#      against the host: the FIRST close must return the exact settled amount: the SECOND -- the
#      "interrupted, closed again" case -- must return nothing, proving there is nothing left to
#      double-settle.
#   2. THE SESSION'S ONE AUDIT ROW SURVIVES AN INTERRUPTION. A session opened through the real
#      `topology::begin_session` (lands its one `audit-record` row, see the `audit-record` leg), then
#      torn down immediately -- the core dropped and the D2 close guard dropped -- without ever
#      running a frame. Exactly one audit row must remain: not zero (the interruption did not erase
#      the row the open already wrote) and not two (nothing re-fires on teardown).
#
# WAS RED: before `open_admitted_session` wrote its one audit row (see `audit-record`), there was no
# row to prove survives anything at all; and before this leg existed, nothing exercised the SAME
# double-close shape production's own `LeaseCloseGuard`/parked-handler race notes as the reason a
# by-value guard (not a refcount-gated `Drop`) is required.

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
