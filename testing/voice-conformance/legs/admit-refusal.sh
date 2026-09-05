# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: admit-refusal — a key whose budget is already spent is refused AT THE DOOR, before any provider
# dial (ARCHITECTURE.md's loop, step 4 ADMIT: a refused reserve costs zero bytes and zero charge).
#
# `topology::begin_session` reserves the D2 lease strictly AFTER the destination gate and strictly
# BEFORE any socket is touched (`topology::open_admitted_session`'s doc comment: "the session's own
# charge... fires only AFTER the gate clears"). This leg drives that real function with a REFUSE-ALL
# cap (`Some(0)`, the reserve-then-settle lease's own "already spent" shape) over the substrate's
# `FixtureHost` and asserts: (a) `begin_session` returns `Err(StartError::BudgetRefused)` — the
# plane's own refusal, not a generic one; (b) no cost lease was ever opened host-side
# (`FixtureHost::leases_opened()` does not advance across the refusal); (c) no ledger posting landed
# for the presenting principal (`FixtureHost::ledger_usage`) — voice posts no separate "kernel-floor"
# line at Admit the way ARCHITECTURE.md describes for an ALREADY-DIALED provider push (nothing is ever
# dialed here, so nothing is owed and voice's design posts none); (d) a sanity/negative control — the SAME
# destination with an uncapped budget opens cleanly — so a leg that always failed (or always passed)
# could not hide behind this result.
#
# WAS RED (this leg's own history): before this leg existed, `governance.sh`'s D2 checkpoint probed
# exhaustion AFTER a session had already opened and spent partway through its cap; nothing proved the
# DOOR itself refuses a caller who arrives already spent, or that the refusal costs zero dial/zero
# ledger. A caller with `Some(0)` remaining could only be judged by mid-session exhaustion, never by an
# admission that never opens at all.

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
