// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Clause two, three and five: what a posting stores, how it projects, and the tier multiplier.

use crate::cost::{
    checked_apply_tier, nanos_of_exact, price_at_card, HistorySeq, Posting, Quantity, Tally,
    STANDARD_TIER_BP,
};

use super::{card, INPUT};

/// **THE NEUTRAL TIER IS THE IDENTITY, AT EVERY MAGNITUDE INCLUDING THE CEILING.**

#[test]
fn the_neutral_tier_is_the_identity_at_every_magnitude() {
    assert_eq!(
        checked_apply_tier(u128::MAX, STANDARD_TIER_BP),
        Some(u128::MAX),
        "x1 at the ceiling must return the ceiling, not one ten-thousandth of it"
    );
    assert_eq!(checked_apply_tier(12_345, STANDARD_TIER_BP), Some(12_345));
    assert_eq!(checked_apply_tier(0, STANDARD_TIER_BP), Some(0));
    assert_eq!(checked_apply_tier(1, STANDARD_TIER_BP), Some(1));
}

/// A tiered amount that genuinely does not fit is refused; one that does is exact.

#[test]
fn only_a_genuinely_unrepresentable_tiered_amount_is_refused() {
    assert_eq!(checked_apply_tier(u128::MAX, 20_000), None);
    assert_eq!(
        checked_apply_tier(u128::MAX, STANDARD_TIER_BP),
        Some(u128::MAX)
    );
    assert_eq!(checked_apply_tier(0, 20_000), Some(0));

    assert_eq!(checked_apply_tier((u128::MAX / 2) + 1, 20_000), None);
    assert_eq!(
        checked_apply_tier(u128::MAX / 2, 20_000),
        Some(u128::MAX - 1)
    );
}

/// **#44 AT THE EXACT HALF.**

#[test]
fn a_tier_that_lands_on_an_exact_half_rounds_to_even() {
    assert_eq!(checked_apply_tier(5, 5_000), Some(2));

    assert_eq!(checked_apply_tier(15, 5_000), Some(8));

    assert_eq!(checked_apply_tier(25, 5_000), Some(12));

    assert_eq!(checked_apply_tier(3, 5_000), Some(2));

    assert_eq!(
        checked_apply_tier(14, 5_000),
        Some(7),
        "7.0 exactly: nothing to round"
    );
    assert_eq!(
        checked_apply_tier(16, 5_000),
        Some(8),
        "8.0 exactly: nothing to round"
    );
    assert_eq!(
        checked_apply_tier(1, 9_999),
        Some(1),
        "0.9999 rounds to the nearer 1"
    );
    assert_eq!(
        checked_apply_tier(1, 4_999),
        Some(0),
        "0.4999 rounds to the nearer 0"
    );
    assert_eq!(
        checked_apply_tier(1, 5_000),
        Some(0),
        "0.5 exactly: 0 is even"
    );
    assert_eq!(
        checked_apply_tier(3, 5_001),
        Some(2),
        "1.5003 rounds to the nearer 2"
    );
    assert_eq!(checked_apply_tier(45, 5_000), Some(22), "22.5: not 23");
    assert_eq!(checked_apply_tier(10_000, 9_999), Some(9_999));
    assert_eq!(checked_apply_tier(10_000, 9_000), Some(9_000));
}

/// **BYTE-NEUTRALITY AT THE ONLY TIER THIS TREE EVER ASKS FOR.**

#[test]
fn the_neutral_tier_moves_no_ordinary_amount() {
    let mut cases: Vec<u128> = Vec::new();
    let mut decade: u128 = 1;
    for _ in 0..34 {
        for near in [0u128, 1, 2, 4_999, 5_000, 5_001, 9_999] {
            cases.push(decade.saturating_add(near));
            cases.push(decade.saturating_sub(near));
        }
        decade = decade.saturating_mul(10);
    }
    cases.push(0);
    cases.push(u128::from(u64::MAX));
    cases.push(u128::from(u64::MAX) * 4);

    let mut checked = 0u32;
    for &pre in &cases {
        assert_eq!(
            checked_apply_tier(pre, STANDARD_TIER_BP),
            Some(pre),
            "x1 moved an ordinary amount: {pre}"
        );

        if pre < u128::MAX / 10_000 {
            assert_eq!(
                Some(pre.saturating_mul(10_000) / 10_000),
                checked_apply_tier(pre, STANDARD_TIER_BP),
                "the correction moved a byte at {pre}"
            );
        }
        checked += 1;
    }
    assert_eq!(checked, 479, "the sweep must actually have run");
}

/// The tier is #44's per-N-units division term and rounds half-to-even, but it rounds at the scale

#[test]
fn fifteen_nano_units_at_half_price_bill_seven() {
    let card = card("m", 0.015, 0.0, 0);
    let posting = Posting {
        lane: "m".to_string(),
        quantities: vec![Quantity::new(INPUT, 1)],
        fee_count: 0,
        tier_bp: 5_000,
        arrived_ms: 0,
        arrived_mono: 0,
        estimated: false,
    };
    let priced = price_at_card(HistorySeq::OPENING, &card, &posting).expect("the card prices it");
    assert_eq!(
        priced.pre_tier_nanos, 15,
        "fifteen nano-units before the tier"
    );
    assert_eq!(
        priced.priced_nanos, 7,
        "7.5 is exact at scale 15 and the one truncation bills 7"
    );

    let mut tally = Tally::at_card(&card);
    tally
        .row(
            "m",
            0,
            5_000,
            [(INPUT, crate::cost::whole(1))],
            crate::cost::whole(0),
        )
        .expect("the card prices it");
    let exact = tally.exact().expect("inside the range");
    assert_eq!(exact, 7_500_000, "the tier's answer at scale 15 is exact");
    assert_eq!(nanos_of_exact(exact), Ok(7));

    assert_eq!(checked_apply_tier(15, 5_000), Some(8));
}
