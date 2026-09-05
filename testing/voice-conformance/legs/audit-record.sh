# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: audit-record — one governed voice session lands EXACTLY ONE new admin-audit entry, carrying the
# plane's own action literal and outcome (ARCHITECTURE.md's audit-chain discipline, applied to the
# voice-plane mutation a session open represents).
#
# Before this leg, NOTHING in `busbar-voice` ever called `JournalHost::audit_record` — a session could
# open, meter and close without leaving a single row on the admin audit trail. `topology::
# open_admitted_session` now journals ONE row (`action = "voice.session.open"`, `outcome = "applied"`,
# `principal` = the session's owner) at its single `Ok` success point, through the live host
# (`VoiceRuntime::audit_session`, a no-op on the pre-host/dev-default runtime with nothing to journal
# through). This leg drives that real code path twice over the substrate's `FixtureHost` — a full
# `EngineHost` double whose `audit_record` now RECORDS (not a no-op) — and asserts:
#
#   * a clean session open lands EXACTLY ONE row, shaped `("voice.session.open", "voice:<call-id>",
#     "applied", <owner>)` — the literal action/outcome vocabulary, not a placeholder;
#   * a SECOND, independent session adds exactly one MORE row (two sessions -> two rows, never
#     doubled, never dropped) — so a leg that always saw "at least one" could not pass by luck.
#
# WAS RED: with no call site at all, `FixtureHost::audit_log()` stayed empty across every session this
# leg opens; the very first assertion (`len() == 1`) is what a truly wired call site must clear.

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
