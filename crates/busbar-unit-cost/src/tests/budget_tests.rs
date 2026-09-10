// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What a key may still spend, and the parity that keeps the door's copy of it honest.
//!
//! The door performs the same comparison inline over its own bucket chain, because a unit never
//! calls another unit and the admission unit cannot reach this crate. Two copies of one
//! comparison with nothing checking they agree is how a request comes to be judged at one figure
//! and billed at another — which is the exact argument this crate's manifest already makes for its
//! dev-dependency on the admission unit, on the rate side. `tests/rate_conversion_agreement.rs`,
//! the file that holds the door and the ledger to one answer, carries that argument applied to the
//! budget side beside the rate one.

use super::{lines, INPUT};
use crate::{KeyBudgetView, LaneClass, RateCard, NANOS_PER_CENT};

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

// ── THE READ-TIME DERIVATION ─────────────────────────────────────────────────────────────────────
//
// The owner's final money model: price is NEVER stored. The ledger holds facts — quantities by
// class — and the amount is computed at read time from those lines times the rate table in force.
// These pin that the view DERIVES rather than reads, and that a rate correction moves the answer.

#[test]
fn spend_is_derived_from_the_ledgers_lines_and_the_card() {
    let card = RateCard::from_micro_rates([(LaneClass::new("blue", INPUT), 10.0)], 0);
    let l = lines(&[(INPUT, 1_000_000)]);
    let v = KeyBudgetView::capped("group:team@month", 10_000);
    // 1_000_000 quantities x 10 micro-units = 10 units = 1_000 cents.
    assert_eq!(
        v.spent_cents_from_usage(&card, [("blue", l.as_slice())].into_iter(), 0, false),
        1_000
    );
    assert_eq!(
        v.remaining_cents_from_usage(&card, [("blue", l.as_slice())].into_iter(), 0, false),
        Some(9_000)
    );
}

#[test]
fn correcting_the_rate_moves_the_answer_without_touching_the_ledger() {
    // The property a stored price would destroy. THE SAME LINES, two cards, two answers — and the
    // facts underneath never changed, which is exactly why they are the thing worth storing.
    let l = lines(&[(INPUT, 1_000_000)]);
    let v = KeyBudgetView::capped("group:team@month", 10_000);
    let cheap = RateCard::from_micro_rates([(LaneClass::new("blue", INPUT), 10.0)], 0);
    let dear = RateCard::from_micro_rates([(LaneClass::new("blue", INPUT), 20.0)], 0);
    assert_eq!(
        v.remaining_cents_from_usage(&cheap, [("blue", l.as_slice())].into_iter(), 0, false),
        Some(9_000)
    );
    assert_eq!(
        v.remaining_cents_from_usage(&dear, [("blue", l.as_slice())].into_iter(), 0, false),
        Some(8_000)
    );
}

#[test]
fn a_lane_the_card_does_not_name_derives_at_nothing() {
    // Designed behaviour, not a gap: an operator's card is what says a lane costs anything at all.
    let card = RateCard::from_micro_rates([(LaneClass::new("blue", INPUT), 10.0)], 0);
    let l = lines(&[(INPUT, 1_000_000)]);
    let v = KeyBudgetView::capped("group:team@month", 10_000);
    assert_eq!(
        v.spent_cents_from_usage(&card, [("unpriced", l.as_slice())].into_iter(), 0, false),
        0
    );
    assert_eq!(
        v.remaining_cents_from_usage(&card, [("unpriced", l.as_slice())].into_iter(), 0, false),
        Some(10_000)
    );
}

#[test]
fn the_view_stores_no_price() {
    // The final money model as a source assertion. The only figure this type holds is the CAP,
    // which is policy read from the pinned epoch; every amount is derived per call.
    let code: String = include_str!("../budget.rs")
        .lines()
        .map(str::trim_start)
        .filter(|l| !l.starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for stored in [
        "amount_cents:",
        "price_cents:",
        "spent_cents:",
        "stored_",
        "posted_amount",
    ] {
        assert!(
            !code.contains(stored),
            "KeyBudgetView holds `{stored}`; price is NEVER stored — the ledger holds facts and \
             every amount is derived at read time from the lines and the card"
        );
    }
}
