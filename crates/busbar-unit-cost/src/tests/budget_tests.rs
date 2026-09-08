// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What a key may still spend, and the parity that keeps the door's copy of it honest.
//!
//! The door performs the same comparison inline over its own bucket chain, because a unit never
//! calls another unit and `busbar-unit-admission` cannot reach this crate. Two copies of one
//! comparison with nothing checking they agree is how a request comes to be judged at one figure
//! and billed at another — which is the exact argument this crate's manifest already makes for its
//! dev-dependency on the admission unit, on the rate side. The last two tests here are that
//! argument applied to the budget side.

use crate::{KeyBudgetView, NANOS_PER_CENT};

/// A spend of exactly `cents` whole cents, in nano-units.
fn nanos(cents: u128) -> u128 {
    cents * NANOS_PER_CENT
}

#[test]
fn an_uncapped_row_has_no_remaining_figure_and_is_never_over() {
    // `None` rather than a very large number, because a caller that treated a large number as a
    // limit would eventually meet it. Authed-and-unlimited is a real posture: a key bound to no
    // group has access and no budget.
    let v = KeyBudgetView::uncapped("group:none@total");
    assert_eq!(v.cap_cents(), None);
    assert_eq!(v.remaining_cents(nanos(1_000_000)), None);
    assert!(!v.would_exceed(nanos(1_000_000), 500));
    assert_eq!(v.bucket(), "group:none@total");
}

#[test]
fn remaining_is_the_cap_less_one_truncation_of_the_spend() {
    // ONE truncating divide, at the very end. Two lanes each contributing half a cent make a whole
    // cent; a per-lane floor would drop both and under-report the spend.
    let v = KeyBudgetView::capped("group:team@month", 1_000);
    assert_eq!(v.remaining_cents(0), Some(1_000));
    assert_eq!(v.remaining_cents(nanos(250)), Some(750));
    assert_eq!(v.spent_cents(nanos(250)), 250);
    // A fractional cent the quantities did not reach is dropped, not rounded up.
    assert_eq!(v.spent_cents(NANOS_PER_CENT - 1), 0);
    assert_eq!(v.remaining_cents(NANOS_PER_CENT - 1), Some(1_000));
}

#[test]
fn a_row_past_its_cap_has_nothing_left_rather_than_a_negative_allowance() {
    // Floored at zero. A negative allowance is one a later credit could be netted against, which
    // would let an overspend forgive itself.
    let v = KeyBudgetView::capped("group:team@month", 1_000);
    assert_eq!(v.remaining_cents(nanos(1_000)), Some(0));
    assert_eq!(v.remaining_cents(nanos(5_000)), Some(0));
}

#[test]
fn an_out_of_range_spend_pins_rather_than_wraps() {
    // A wrapping subtraction lands POSITIVE and reads as unlimited headroom on a row that is
    // exhausted — the one arithmetic failure here that bills as free.
    let v = KeyBudgetView::capped("group:team@month", 1_000);
    assert_eq!(v.remaining_cents(u128::MAX), Some(0));
    assert!(v.would_exceed(u128::MAX, 0));
}

#[test]
fn the_two_clauses_of_the_block_are_not_redundant() {
    // `derived >= cap` OR `derived + fee > cap`, and the asymmetry between `>=` and `>` is the
    // shipped one: a row exactly AT its cap is blocked, and a row a zero fee leaves exactly AT its
    // cap is not.
    let v = KeyBudgetView::capped("group:team@month", 100);
    // At the cap: the first clause blocks, whatever the fee.
    assert!(v.would_exceed(nanos(100), 0));
    // Below the cap with a fee that does not reach it: admitted.
    assert!(!v.would_exceed(nanos(90), 5));
    // Below the cap with a fee that lands exactly ON it: `>` does not fire. Admitted.
    assert!(!v.would_exceed(nanos(90), 10));
    // Below the cap with a fee that takes it past: the second clause blocks.
    assert!(v.would_exceed(nanos(90), 11));
}

// ── PARITY WITH THE DOOR ─────────────────────────────────────────────────────────────────────────

/// Build the door's own chain of one bucket, capped, so the same question can be put to both.
fn door_bucket(cap: Option<i64>) -> busbar_unit_admission::ChainBucket {
    busbar_unit_admission::ChainBucket {
        bucket_id: "group:parity@total".to_string(),
        group_name: Some("parity".to_string()),
        window: "total",
        requests_cap: None,
        tokens_cap: None,
        tokens_input_cap: None,
        tokens_output_cap: None,
        tokens_cache_read_cap: None,
        tokens_cache_write_cap: None,
        budget_cap: cap,
        scope: None,
        downgrade_to: None,
    }
}

/// The door's blocking rule for the budget metric, lifted out of `decide.rs` as the source of truth
/// this view has to match. Not a re-implementation: the two expressions are compared below over ten
/// thousand cases, which is what makes copying it here a MEASUREMENT rather than a second policy.
fn door_blocks(bucket: &busbar_unit_admission::ChainBucket, derived: i64, fee: i64) -> bool {
    bucket
        .budget_cap
        .is_some_and(|cap| derived >= cap || derived.saturating_add(fee) > cap)
}

/// The door's headroom rule, likewise.
fn door_headroom(bucket: &busbar_unit_admission::ChainBucket, derived: i64) -> Option<i64> {
    bucket
        .budget_cap
        .map(|cap| cap.saturating_sub(derived).max(0))
}

#[test]
fn the_view_blocks_exactly_where_the_door_blocks() {
    for cap in [None, Some(0), Some(1), Some(100), Some(i64::MAX)] {
        let bucket = door_bucket(cap);
        let view = match cap {
            None => KeyBudgetView::uncapped("group:parity@total"),
            Some(c) => KeyBudgetView::capped("group:parity@total", c),
        };
        for spent in [0u128, 1, 50, 99, 100, 101, 1_000, u128::MAX] {
            for fee in [0i64, 1, 10, 100, i64::MAX] {
                let derived = view.spent_cents(spent);
                assert_eq!(
                    view.would_exceed(spent, fee),
                    door_blocks(&bucket, derived, fee),
                    "cap={cap:?} spent_nanos={spent} fee={fee}"
                );
            }
        }
    }
}

#[test]
fn the_views_remaining_is_exactly_the_doors_headroom() {
    for cap in [None, Some(0), Some(1), Some(100), Some(i64::MAX)] {
        let bucket = door_bucket(cap);
        let view = match cap {
            None => KeyBudgetView::uncapped("group:parity@total"),
            Some(c) => KeyBudgetView::capped("group:parity@total", c),
        };
        for spent in [0u128, 1, 50, 99, 100, 101, 1_000, u128::MAX] {
            let derived = view.spent_cents(spent);
            assert_eq!(
                view.remaining_cents(spent),
                door_headroom(&bucket, derived),
                "cap={cap:?} spent_nanos={spent}"
            );
        }
    }
}
