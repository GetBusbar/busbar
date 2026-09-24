// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The session tick's closing arms owe what its accruing arm owes (item 284).

use busbar_contract::caps::ReasonCode;

use crate::tick::{session_tick, SessionTick, SESSION_IDLE_MAX_MS};

/// A CLOSE IS AN END, NOT A PARDON. A priced session that closes — revoked, budget run dry, gone
/// quiet — still owes the priced seconds since its last settled tick, and still owes the checkpoint
/// of what it accrued since the last one, because the checkpoint is what a crash before the
/// session's own settle pays out on. Deciding the close first and returning a bare reason dropped
/// both: 60 s of priced time never priced, and 4,200 accrued nano-units a crash would not pay.
#[test]
fn every_closing_arm_carries_the_owed_interval_and_the_checkpoint() {
    for (revoked, budget_dry, idle_for, reason) in [
        (true, false, 0, ReasonCode::Revoked),
        (false, true, 0, ReasonCode::OverBudget),
        (
            false,
            false,
            SESSION_IDLE_MAX_MS,
            ReasonCode::DeadlineExceeded,
        ),
    ] {
        assert_eq!(
            session_tick(
                1_000,
                60_000,
                idle_for,
                Some(4_200),
                true,
                budget_dry,
                revoked
            ),
            SessionTick::Close {
                reason,
                elapsed: 60_000,
                checkpoint: Some(4_200),
            },
            "the {reason:?} close dropped what the session owed"
        );
    }
    // The owed interval is clipped at the idle bound exactly as the accruing arm clips it.
    assert_eq!(
        session_tick(1_000, SESSION_IDLE_MAX_MS + 1, 0, None, true, false, true),
        SessionTick::Close {
            reason: ReasonCode::Revoked,
            elapsed: SESSION_IDLE_MAX_MS,
            checkpoint: None,
        }
    );
    // Unpriced session time owes nothing on the way out, but the checkpoint is still written.
    assert_eq!(
        session_tick(1_000, 60_000, 0, Some(77), false, false, true),
        SessionTick::Close {
            reason: ReasonCode::Revoked,
            elapsed: 0,
            checkpoint: Some(77),
        }
    );
}
