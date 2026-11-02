// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::fixtures::*;
use busbar_kernel_ledger::cost::{
    checked_apply_tier, LaneClass, MoneyError, Posting, RateCard, FEE_CLASS, STANDARD_TIER_BP,
};

#[test]
fn pre_tier_amount_is_the_sum_of_the_lines_including_the_fee() {
    let c = card("m", 2.0, 5.0, 3);
    let posted = priced(
        &c,
        "m",
        &usage(&[(INPUT, 3), (OUTPUT, 4)]),
        1,
        STANDARD_TIER_BP,
    );
    let amounts: Vec<(&str, u128)> = posted
        .lines
        .iter()
        .map(|l| (l.class.as_str(), l.amount_nanos))
        .collect();
    assert_eq!(
        amounts,
        vec![(INPUT, 6_000), (OUTPUT, 20_000), (FEE_CLASS, 30_000_000)]
    );
    assert_eq!(posted.pre_tier_nanos, 30_026_000);
    assert_eq!(posted.fee_count, 1);
    assert_eq!(
        posted.priced_nanos, posted.pre_tier_nanos,
        "the neutral tier changes nothing"
    );
}

#[test]
fn the_fee_line_is_always_present_even_at_zero() {
    let c = card("m", 1.0, 0.0, 7);
    let posted = priced(&c, "m", &usage(&[(INPUT, 10)]), 0, STANDARD_TIER_BP);
    let fee = posted.lines.last().expect("a fee line");
    assert_eq!(
        (fee.class.as_str(), fee.quantity, fee.amount_nanos),
        (FEE_CLASS, 0, 0)
    );
    assert_eq!(posted.pre_tier_nanos, 10_000);
}

#[test]
fn with_no_card_every_class_prices_at_zero_and_the_fee_still_posts() {
    let c = RateCard::absent(3);
    let posted = priced(
        &c,
        "anything",
        &usage(&[(INPUT, 1_000_000), (OUTPUT, 1_000_000)]),
        5,
        STANDARD_TIER_BP,
    );
    assert_eq!(posted.pre_tier_nanos, 150_000_000, "five fees of 3 cents");
    assert_eq!(minor(&posted), 15);
    assert!(!posted.lane_unpriced, "no card means no missing lane");
    assert!(
        posted.unpriced_classes().is_empty(),
        "with no card nothing is flagged unpriced; it is a deployment posture, not a per-line one"
    );
}

#[test]
fn a_class_a_present_card_does_not_name_prices_at_zero_and_is_flagged() {
    let c = card("m", 2.0, 0.0, 0);
    let posted = priced(
        &c,
        "m",
        &usage(&[(INPUT, 3), ("web_search", 3)]),
        0,
        STANDARD_TIER_BP,
    );
    assert_eq!(
        posted.pre_tier_nanos, 6_000,
        "the unnamed class adds nothing"
    );
    assert_eq!(posted.unpriced_classes(), vec!["web_search"]);
    let line = posted
        .lines
        .iter()
        .find(|l| l.class == "web_search")
        .expect("the line stays visible");
    assert_eq!((line.quantity, line.amount_nanos), (3, 0));
}

#[test]
fn a_lane_absent_from_a_present_card_prices_at_zero_and_reports_it() {
    let c = card("known", 5.0, 5.0, 2);
    let posted = priced(
        &c,
        "mystery",
        &usage(&[(INPUT, 1_000_000)]),
        1,
        STANDARD_TIER_BP,
    );
    assert!(posted.lane_unpriced);
    assert_eq!(
        posted.pre_tier_nanos, 20_000_000,
        "only the flat fee remains"
    );
}

#[test]
fn an_adversarial_class_name_cannot_collide_with_the_fee_line() {
    let c = RateCard::from_micro_rates(
        [
            (LaneClass::new("m", INPUT), 2.0),
            (LaneClass::new("m", FEE_CLASS), 0.01),
        ],
        3,
    );
    let posted = priced(
        &c,
        "m",
        &usage(&[(INPUT, 3), (FEE_CLASS, 5)]),
        1,
        STANDARD_TIER_BP,
    );

    assert_eq!(posted.pre_tier_nanos, 6_000 + 50 + 30_000_000);
    assert_eq!(
        posted.lines.len(),
        3,
        "the reported line and the fee line both stand"
    );
}

#[test]
fn each_class_bills_against_its_own_rate() {
    let c = card4("quad", [1.0, 2.0, 0.5, 4.0], 0);
    let posted = priced(
        &c,
        "quad",
        &usage(&[
            (INPUT, 10_000_000),
            (OUTPUT, 1_000_000),
            (CACHE_READ, 2_000_000),
            (CACHE_WRITE, 500_000),
        ]),
        0,
        STANDARD_TIER_BP,
    );
    assert_eq!(posted.pre_tier_nanos, 15_000_000_000);
    assert_eq!(minor(&posted), 1500);
}

#[test]
fn the_oracle_rate_card_reproduces_its_pinned_figure() {
    let c = card("oracle", 100_000.0, 200_000.0, 0);
    let posted = priced(
        &c,
        "oracle",
        &usage(&[(INPUT, 11), (OUTPUT, 7)]),
        0,
        STANDARD_TIER_BP,
    );
    assert_eq!(posted.pre_tier_nanos, 2_500_000_000, "two and a half units");
    assert_eq!(minor(&posted), 250);
    assert_eq!(micros(&posted), 2_500_000);
}

#[test]
fn the_cent_projection_truncates_toward_zero() {
    let c = card("m", 1.0, 0.0, 0);
    let at = |tokens: u64| {
        minor(&priced(
            &c,
            "m",
            &usage(&[(INPUT, tokens)]),
            0,
            STANDARD_TIER_BP,
        ))
    };
    assert_eq!(at(19_999), 1, "just under two cents floors to one");
    assert_eq!(at(20_000), 2, "exactly two cents is two");
    assert_eq!(at(20_001), 2, "just over two cents still floors to two");
}

#[test]
fn both_projections_refuse_rather_than_pin_or_wrap() {
    assert_eq!(minor_nanos(u128::MAX), Err(MoneyError::Overflow));
    assert_eq!(micros_nanos(u128::MAX), Err(MoneyError::Overflow));
    let c = card("m", 1e15, 0.0, 0);
    let history = busbar_kernel_ledger::cost::History::opening(c, 0);
    let posting = Posting::from_usage("m", &usage(&[(INPUT, u64::MAX)]), 0, STANDARD_TIER_BP, 0, 0);
    assert_eq!(
        busbar_kernel_ledger::cost::price(&history.current(), &posting),
        Err(busbar_kernel_ledger::cost::Unpriceable::Overflow),
        "an overflowing posting is refused, never billed at the ceiling"
    );
}

#[test]
fn the_nano_scale_keeps_sub_micro_precision() {
    let c = card("m", 3.125, 0.0, 0);
    let posted = priced(&c, "m", &usage(&[(INPUT, 8)]), 0, STANDARD_TIER_BP);
    assert_eq!(micros(&posted), 25);
    assert_eq!(minor(&posted), 0, "twenty-five micro-units is under a cent");
}

#[test]
fn an_explicit_zero_rate_is_known_and_bills_nothing() {
    let c = card4("freebie", [0.0, 0.0, 0.0, 0.0], 0);
    assert!(c.pricing_enabled());
    assert!(!c.lane_unpriced("freebie"));
    let posted = priced(
        &c,
        "freebie",
        &usage(&[
            (INPUT, u64::MAX),
            (OUTPUT, u64::MAX),
            (CACHE_READ, u64::MAX),
            (CACHE_WRITE, u64::MAX),
        ]),
        0,
        STANDARD_TIER_BP,
    );
    assert_eq!(posted.pre_tier_nanos, 0);
    assert!(posted.unpriced_classes().is_empty());
}

#[test]
fn the_tier_multiplier_applies_once_over_the_summed_pre_tier_amount() {
    let c = card("m", 2.0, 5.0, 3);
    let posted = priced(&c, "m", &usage(&[(INPUT, 3), (OUTPUT, 4)]), 1, 15_000);
    assert_eq!(posted.tier_bp, 15_000);
    assert_eq!(posted.pre_tier_nanos, 30_026_000);
    assert_eq!(posted.priced_nanos, 45_039_000);
    assert_eq!(minor(&posted), 4);

    assert_eq!(posted.lines[0].amount_nanos, 6_000);
}

#[test]
fn a_discount_tier_is_the_same_single_operation() {
    let c = card("m", 2.0, 5.0, 3);
    let posted = priced(&c, "m", &usage(&[(INPUT, 3), (OUTPUT, 4)]), 1, 8_000);
    assert_eq!(posted.pre_tier_nanos, 30_026_000);
    assert_eq!(posted.priced_nanos, 24_020_800);
    assert_eq!(minor(&posted), 2);
}

#[test]
fn the_tier_is_a_single_divide_not_a_sum_of_per_line_floors() {
    let c = RateCard::from_micro_rates(
        [
            (LaneClass::new("m", "a"), 0.005),
            (LaneClass::new("m", "b"), 0.005),
        ],
        0,
    );
    let posted = priced(&c, "m", &usage(&[("a", 1), ("b", 1)]), 0, 5_000);
    assert_eq!(posted.pre_tier_nanos, 10);
    assert_eq!(
        posted.priced_nanos, 5,
        "one divide of the summed ten, never two floors of two and a half"
    );
    assert_eq!(checked_apply_tier(10, 5_000), Some(5));
}

#[test]
fn the_estimated_mark_travels_onto_the_posting() {
    let c = card("m", 1.0, 0.0, 0);
    let reported = priced(&c, "m", &usage(&[(INPUT, 10)]), 0, STANDARD_TIER_BP);
    let floored = priced(
        &c,
        "m",
        &estimated_usage(&[(INPUT, 10)]),
        0,
        STANDARD_TIER_BP,
    );
    assert!(!reported.estimated);
    assert!(floored.estimated);
    assert_eq!(floored.pre_tier_nanos, reported.pre_tier_nanos);
}
