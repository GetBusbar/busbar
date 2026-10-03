// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The identity, under random postings and under a hand-corrupted amount.

use crate::identity::{closed_window_is_settled, residual};
use crate::settle::Ledger;
use crate::totals::Totals;

use super::fixtures::key;

#[test]
fn every_column_the_identity_names_is_actually_load_bearing() {
    // A column that could be edited without the identity noticing is a column the identity is not
    // really checking. Each one is nudged in turn.
    let base = Totals {
        drawn: 1_000,
        settled: 400,
        open_holds: 200,
        open_slice_remainders: 400,
        ..Totals::zero()
    };
    assert!(residual(&Totals::zero(), &base).holds());

    let nudge: [fn(&mut Totals); 7] = [
        |t| t.settled += 1,
        |t| t.open_holds += 1,
        |t| t.open_slice_remainders += 1,
        |t| t.unreconciled += 1,
        |t| t.adjustments += 1,
        |t| t.overdraft_carried_out += 1,
        |t| t.cross_window_transfers += 1,
    ];
    for (i, change) in nudge.iter().enumerate() {
        let mut edited = base;
        change(&mut edited);
        assert!(
            !residual(&Totals::zero(), &edited).holds(),
            "column {i} can be edited without the identity noticing"
        );
    }
    // And the right-hand side.
    let mut edited = base;
    edited.drawn += 1;
    assert!(!residual(&Totals::zero(), &edited).holds());
}

#[test]
fn the_identity_is_measured_as_a_delta_from_the_last_checkpoint() {
    // The whole point of a checkpoint is that verification does not have to walk history. The case
    // that makes it visible is a checkpoint whose own figures do NOT balance from zero — a migration
    // that sealed an opening balance carried over from a previous release, which was settled without
    // this deployment ever having drawn it. Everything after that point still has to close.
    let since = Totals {
        settled: 3_000,
        ..Totals::zero()
    };
    assert!(
        !residual(&Totals::zero(), &since).holds(),
        "the fixture is only interesting if the opening figures do not balance from zero"
    );

    let mut now = since;
    now.drawn += 1_000;
    now.open_holds += 400;
    now.open_slice_remainders += 600;
    assert!(
        residual(&since, &now).holds(),
        "activity since the checkpoint balances, whatever the checkpoint opened at"
    );
    assert!(
        !residual(&Totals::zero(), &now).holds(),
        "and walking history from zero would report the migration as a hole"
    );
}

#[test]
fn a_closed_window_that_is_still_moving_is_a_different_finding_from_one_that_does_not_balance() {
    let since = Totals {
        drawn: 1_000,
        settled: 1_000,
        ..Totals::zero()
    };
    // Nothing moved: settled.
    assert!(closed_window_is_settled(&since, &since).is_ok());

    // A transfer out, matched by the value leaving the remainder column: still settled, because the
    // window's own figures balance.
    let mut transferred = since;
    transferred.open_slice_remainders -= 100;
    transferred.cross_window_transfers += 100;
    assert!(closed_window_is_settled(&since, &transferred).is_ok());

    // A settlement into a closed window: not settled, by 50.
    let mut posted_late = since;
    posted_late.settled += 50;
    assert_eq!(closed_window_is_settled(&since, &posted_late), Err(50));
}

/// "STOPPED MOVING" IS BOTH SIDES OF THE IDENTITY READING ZERO, not the residual between them.
///
/// The columns the check looks at are the identity's own — a second sum over a hand-picked subset is
/// a second definition of "the books balance", and it answers wrong in both directions: a
/// reconciliation that moves value between two columns it disagrees about reads as a window still
/// moving, while a posting that lands in the one column it skips moves the window invisibly.
///
/// But the RESIDUAL is not the answer either, and this is the case that says why. A late posting
/// into a reported window that draws 200 and settles 200 is perfectly balanced — the residual is
/// zero and stays zero — and it is exactly the thing a closed window must not do. Both sides moved;
/// they moved together. So the check compares the two column totals, each against where the
/// checkpoint left it, and a window is settled only when neither has moved.
#[test]
fn a_closed_window_moves_when_either_side_of_the_identity_moves_even_if_they_balance() {
    let since = Totals {
        drawn: 1_000,
        settled: 1_000,
        ..Totals::zero()
    };

    // A reconciliation INSIDE a closed window: value moves from the settled column to the
    // unreconciled one and the books are exactly where they were. Nothing entered or left the
    // window, so nothing moved.
    let mut reconciled = since;
    reconciled.unreconciled += 40;
    reconciled.settled -= 40;
    assert_eq!(
        closed_window_is_settled(&since, &reconciled),
        Ok(()),
        "a reconciliation that only re-columns value did not move the window"
    );
    assert!(
        residual(&since, &reconciled).holds(),
        "and the identity agrees, which is the whole point of asking it"
    );

    // A posting that lands in `unreconciled` ALONE: value appeared in a window that is already
    // reported, which is precisely what this check exists to catch.
    let mut posted_late = since;
    posted_late.unreconciled += 40;
    assert_eq!(
        closed_window_is_settled(&since, &posted_late),
        Err(40),
        "value posted into a closed window is a closed window that moved"
    );

    // The same for the overdraft column, which the old sum also skipped. Overdraft carried out is
    // subtracted by the identity, so 40 more of it is a window down by 40.
    let mut overdrawn = since;
    overdrawn.overdraft_carried_out += 40;
    assert_eq!(closed_window_is_settled(&since, &overdrawn), Err(-40));

    // A BALANCED late posting: 200 more drawn from the store and 200 more settled against it. The
    // residual is zero — the books balance, and would balance in an open window — but a window that
    // has been closed and reported has just had money moved through it, and that is the alarm.
    let mut balanced_late_posting = since;
    balanced_late_posting.drawn += 200;
    balanced_late_posting.settled += 200;
    assert!(
        residual(&since, &balanced_late_posting).holds(),
        "the fixture is only interesting if the residual stays at zero"
    );
    assert_eq!(
        closed_window_is_settled(&since, &balanced_late_posting),
        Err(200),
        "a balanced posting into a reported window is still a window that moved"
    );

    // And a draw with nothing to show for it moves the window by what was drawn.
    let mut drawn_only = since;
    drawn_only.drawn += 15;
    assert_eq!(closed_window_is_settled(&since, &drawn_only), Err(15));
}

#[test]
fn cross_window_transfers_close_on_both_sides() {
    let mut ledger = Ledger::new();
    let k = key("windows");
    ledger.record_draw(&k, 100, 900);
    ledger.record_cross_window_transfer(&k, 100, 200, 300);

    assert!(residual(&Totals::zero(), &ledger.book().get(&k, 100)).holds());
    assert!(residual(&Totals::zero(), &ledger.book().get(&k, 200)).holds());
    assert_eq!(ledger.book().get(&k, 100).open_slice_remainders, 600);
    assert_eq!(ledger.book().get(&k, 200).open_slice_remainders, 300);
    // The two transfer columns are equal and opposite, so a transfer recorded on one side only
    // could not pass both checks.
    assert_eq!(
        ledger.book().get(&k, 100).cross_window_transfers,
        -ledger.book().get(&k, 200).cross_window_transfers
    );
}

#[test]
fn an_attribution_bucket_balances_when_everything_accrued_was_posted() {
    assert!(crate::identity::attribution_holds(1_234, 1_234));
    assert!(!crate::identity::attribution_holds(1_234, 1_233));
}

/// ITEMS 105/131: a maximally broken book FAILS verification rather than wrapping into a clean one.
///
/// `settled = i128::MAX`, `open_holds = i128::MAX`, `open_slice_remainders = 2` sums to exactly
/// 2^128. A bare `+` panicked on these figures in a debug build and, in a release one, wrapped the
/// accounted side to ZERO — against zero drawn, a residual of zero and a book that verified clean.
/// Measured in both directions of the delta and through the verifier as well as the bare residual,
/// so the answer cannot depend on which door a caller reads it through.
#[test]
fn a_maximally_broken_book_fails_verification_instead_of_wrapping() {
    let broken = Totals {
        settled: i128::MAX,
        open_holds: i128::MAX,
        open_slice_remainders: 2,
        ..Totals::zero()
    };
    let r = residual(&Totals::zero(), &broken);
    assert!(
        !r.holds(),
        "a book summing to 2^128 wrapped to balanced: {r}"
    );
    assert_ne!(r.amount(), 0);

    // The other direction: a checkpoint at the ceiling and a book at the floor.
    let floor = Totals {
        settled: i128::MIN,
        drawn: i128::MAX,
        ..Totals::zero()
    };
    assert!(!residual(&broken, &floor).holds());
    assert!(!residual(&floor, &broken).holds());

    // And a closed window over the same figures reports that it moved.
    assert!(closed_window_is_settled(&Totals::zero(), &broken).is_err());

    // The ordinary case is untouched: a balanced book still balances.
    let fine = Totals {
        drawn: 1_000,
        settled: 400,
        open_holds: 200,
        open_slice_remainders: 400,
        ..Totals::zero()
    };
    assert!(residual(&Totals::zero(), &fine).holds());
}
