// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The identity, under random postings and under a hand-corrupted amount.

use crate::identity::residual;
use crate::totals::Totals;

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
