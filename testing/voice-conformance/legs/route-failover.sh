# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: route-failover — a down provider trips the breaker on its first hard-down strike, and a tripped
# breaker refuses EVERY further dial before any socket/URL work — the documented terminal outcome
# (ARCHITECTURE.md's loop, step 5 ROUTE) with no repeated egress once the cell is open.
#
# `topology::dial_provider` probes the `(pool, lane)` breaker cell through the host seam FIRST — before
# any DNS/guard/socket work — and folds a real dial's outcome back into the SAME cell
# (`host.breaker_record_signal`). This leg drives that real function twice over the substrate's
# `FixtureHost` (a real in-memory breaker, not a stand-in that always admits):
#
#   1. breaker CLOSED, a real dial to a target the default fail-closed `GuardPolicy` refuses (a
#      plaintext `ws://` loopback address) — a genuine `DialProviderError::Dial(_)`, and the guard
#      refusal's canonical signal (Auth-class) trips the cell HARD DOWN on this first strike.
#   2. breaker now OPEN — a SECOND dial, to a syntactically GARBAGE target a real dial would fail
#      differently on (`DialProviderError::Dial(Url(_))`), must instead come back
#      `DialProviderError::BreakerOpen` with a positive `Retry-After` — proving the breaker check runs
#      STRICTLY BEFORE any dial attempt, not just that a dial eventually fails again.
#
# WAS RED (this leg's own history): `dial_provider`'s breaker-admit-first order and its fold-back onto
# the cell existed and were unit-tested in isolation, but no conformance leg judged the OBSERVABLE
# outcome from the plane's own public seam — that a real hard-down dial actually opens the SAME cell a
# second dial is judged against, and that the terminal refusal it then returns names ZERO further dial
# attempt (as opposed to, say, a retried dial that merely fails again for a different reason).

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
