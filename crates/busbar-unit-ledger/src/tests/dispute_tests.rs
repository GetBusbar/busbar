// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Disputes: what opening one marks, and what resolving one moves.
//!
//! ## The property every test here is really about
//!
//! `disputed` is NOT a term of the identity. The identity's terms are settlements, open holds,
//! open-slice remainders, unreconciled, adjustments, overdraft carried, cross-window transfers and
//! drawn — and `disputed` is none of them. That is deliberate and it decides the whole design: a
//! disputed amount is value that is STILL COUNTED where it already was, with a flag on it saying
//! somebody has objected. Opening a dispute is not a move.
//!
//! If opening a dispute took the value out of settled, every open dispute would break the identity
//! until it closed, and an operator's reconciliation would be full of alarms that are really just
//! open customer queries. So the column is a marker, and the money only moves when a verdict says
//! it should — as an ADJUSTMENT, through the same primitive every other correction goes through.

use crate::settle::Ledger;

use super::fixtures::key;

/// Opening a dispute marks value without moving any.
///
/// The identity is asserted directly, over the same balance, before and after — because "does not
/// move value" is exactly the claim, and the only honest way to make it is to check the thing that
/// would notice.
#[test]
fn opening_a_dispute_marks_the_amount_and_moves_nothing() {
    let mut ledger = Ledger::new();
    let k = key("b");
    ledger.record_draw(&k, 1, 1_000);
    ledger.record_hold_opened(&k, 1, 1_000);
    ledger.record_slice_spent(&k, 1, 1_000);
    ledger.record_adjustment(&k, 1, 0); // no-op, to make `settled` explicit below
    let before = ledger.book().get(&k, 1);

    ledger.record_dispute_opened(&k, 1, 400, 90);

    let after = ledger.book().get(&k, 1);
    assert_eq!(after.disputed, 400, "the amount is marked as disputed");
    assert_eq!(after.open_dispute_count, 1);
    assert_eq!(after.oldest_dispute_age_secs, 90);

    assert_eq!(
        after.settled, before.settled,
        "opening a dispute moved value out of settled"
    );
    assert_eq!(after.drawn, before.drawn);
    assert_eq!(after.adjustments, before.adjustments);
    assert_eq!(
        crate::identity::residual(&before, &after).amount(),
        0,
        "an open dispute must not break the identity"
    );
}

/// A second dispute on the same balance adds to the mark and keeps the OLDEST age.
///
/// The age is what the overdue alarm reads, so taking the newer one would silently reset the clock
/// on a dispute that has been open for a month.
#[test]
fn a_second_dispute_adds_to_the_mark_and_keeps_the_oldest_age() {
    let mut ledger = Ledger::new();
    let k = key("b");
    ledger.record_dispute_opened(&k, 1, 400, 90);
    ledger.record_dispute_opened(&k, 1, 100, 10);

    let figures = ledger.book().get(&k, 1);
    assert_eq!(figures.disputed, 500);
    assert_eq!(figures.open_dispute_count, 2);
    assert_eq!(
        figures.oldest_dispute_age_secs, 90,
        "the younger dispute reset the overdue clock"
    );
}

/// Resolving a dispute clears the mark and, on its own, still moves no value.
///
/// The correction is a separate call, and keeping it separate is the point: `overturn` resolves a
/// dispute and moves nothing at all, so a resolver that always adjusted would post a zero-value
/// correction for every rejected objection.
#[test]
fn resolving_a_dispute_clears_the_mark_without_moving_value() {
    let mut ledger = Ledger::new();
    let k = key("b");
    ledger.record_draw(&k, 1, 1_000);
    ledger.record_hold_opened(&k, 1, 1_000);
    ledger.record_slice_spent(&k, 1, 1_000);
    ledger.record_dispute_opened(&k, 1, 400, 90);
    let before = ledger.book().get(&k, 1);

    ledger.record_dispute_resolved(&k, 1, 400);

    let after = ledger.book().get(&k, 1);
    assert_eq!(after.disputed, 0);
    assert_eq!(after.open_dispute_count, 0);
    assert_eq!(
        after.oldest_dispute_age_secs, 0,
        "the last dispute closed, so there is no oldest one"
    );
    assert_eq!(after.settled, before.settled, "a verdict is not a posting");
    assert_eq!(after.adjustments, before.adjustments);
}

/// Resolving more than is marked clears the mark and does not go negative.
///
/// A negative `disputed` would report a bucket as having less than nothing under objection, and the
/// overdue alarm reads this column.
#[test]
fn resolving_more_than_is_marked_clamps_at_nothing() {
    let mut ledger = Ledger::new();
    let k = key("b");
    ledger.record_dispute_opened(&k, 1, 100, 5);
    ledger.record_dispute_resolved(&k, 1, 999);

    let figures = ledger.book().get(&k, 1);
    assert_eq!(figures.disputed, 0);
    assert_eq!(
        figures.open_dispute_count, 0,
        "the count floors at zero too"
    );
}

/// One of two open disputes closing leaves the other marked.
#[test]
fn closing_one_of_two_leaves_the_other_open() {
    let mut ledger = Ledger::new();
    let k = key("b");
    ledger.record_dispute_opened(&k, 1, 400, 90);
    ledger.record_dispute_opened(&k, 1, 100, 10);
    ledger.record_dispute_resolved(&k, 1, 400);

    let figures = ledger.book().get(&k, 1);
    assert_eq!(figures.disputed, 100);
    assert_eq!(figures.open_dispute_count, 1);
    assert_ne!(
        figures.oldest_dispute_age_secs, 0,
        "a dispute is still open, so the overdue clock must still be running"
    );
}

/// The correcting money is an ADJUSTMENT, and the identity closes over it.
///
/// This is the whole shape of an upheld dispute: clear the mark, then correct the charge through
/// the one primitive every correction uses. Asserted together because either half alone is a
/// half-resolved dispute.
#[test]
fn an_upheld_dispute_corrects_through_adjustments_and_the_identity_still_closes() {
    let mut ledger = Ledger::new();
    let k = key("b");
    ledger.record_draw(&k, 1, 1_000);
    ledger.record_hold_opened(&k, 1, 1_000);
    ledger.record_slice_spent(&k, 1, 1_000);
    let opened = ledger.book().get(&k, 1);
    ledger.record_dispute_opened(&k, 1, 400, 90);

    ledger.record_dispute_resolved(&k, 1, 400);
    ledger.record_adjustment(&k, 1, 400);

    let after = ledger.book().get(&k, 1);
    assert_eq!(after.disputed, 0);
    assert_eq!(after.adjustments, 400, "the correction is in the books");
    assert_eq!(after.settled, opened.settled - 400, "and out of settled");
    assert_eq!(
        crate::identity::residual(&opened, &after).amount(),
        0,
        "a resolved dispute must leave the identity closing"
    );
}
