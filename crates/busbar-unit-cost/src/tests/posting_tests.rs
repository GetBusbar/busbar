// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Clause two, three and five: what a posting stores, how it projects, and the tier multiplier.

use super::*;
use crate::{
    apply_tier, cents_of, micros_of, price, LaneClass, RateCard, RateCardVersion, FEE_CLASS,
    STANDARD_TIER_BP,
};

/// The stored pre-tier amount is the sum over the posting's lines INCLUDING the fee line, and each
/// line records the rate it was priced at. Three input tokens at two thousand nano-units and four
/// output tokens at five thousand is twenty-six thousand; a three-cent fee is thirty million more.
#[test]
fn pre_tier_amount_is_the_sum_of_the_lines_including_the_fee() {
    let c = card("m", 2.0, 5.0, 3);
    let posted = price(
        &c.pin(),
        "m",
        &usage(&[(INPUT, 3), (OUTPUT, 4)]),
        1,
        STANDARD_TIER_BP,
    );
    let amounts: Vec<(&str, u128)> = posted
        .lines()
        .iter()
        .map(|l| (l.class.as_str(), l.amount_nanos))
        .collect();
    assert_eq!(
        amounts,
        vec![(INPUT, 6_000), (OUTPUT, 20_000), (FEE_CLASS, 30_000_000)]
    );
    assert_eq!(posted.pre_tier_amount(), 30_026_000);
    assert_eq!(posted.fee_count(), 1);
    assert_eq!(
        posted.priced_amount(),
        posted.pre_tier_amount(),
        "the neutral tier changes nothing"
    );
}

/// A posting with no fee carries a fee line of zero quantity all the same. The line is always
/// there, so the sum is always one shape and no reader has to know whether to add a fee.
#[test]
fn the_fee_line_is_always_present_even_at_zero() {
    let c = card("m", 1.0, 0.0, 7);
    let posted = price(&c.pin(), "m", &usage(&[(INPUT, 10)]), 0, STANDARD_TIER_BP);
    let fee = posted.lines().last().expect("a fee line");
    assert_eq!(
        (fee.class.as_str(), fee.quantity, fee.amount_nanos),
        (FEE_CLASS, 0, 0)
    );
    assert_eq!(posted.pre_tier_amount(), 10_000);
}

/// NO CARD AT ALL: every class prices at nothing and the fee still posts. This is the deployment
/// with pricing switched off — attribution only, plus whatever flat fee is configured.
#[test]
fn with_no_card_every_class_prices_at_zero_and_the_fee_still_posts() {
    let c = RateCard::absent(RateCardVersion::new("no-card"), 3);
    let posted = price(
        &c.pin(),
        "anything",
        &usage(&[(INPUT, 1_000_000), (OUTPUT, 1_000_000)]),
        5,
        STANDARD_TIER_BP,
    );
    assert_eq!(
        posted.pre_tier_amount(),
        150_000_000,
        "five fees of 3 cents"
    );
    assert_eq!(posted.cents(), 15);
    assert!(!posted.lane_unpriced(), "no card means no missing lane");
    assert!(
        posted.unpriced_classes().is_empty(),
        "with no card nothing is flagged unpriced; it is a deployment posture, not a per-line one"
    );
}

/// A card that is present but silent about a class prices that line at nothing AND says so. It is
/// never a silent nothing: the line stays visible with its quantity, flagged, so the condition
/// reaches a report instead of vanishing into a free response.
#[test]
fn a_class_a_present_card_does_not_name_prices_at_zero_and_is_flagged() {
    let c = card("m", 2.0, 0.0, 0);
    let posted = price(
        &c.pin(),
        "m",
        &usage(&[(INPUT, 3), ("web_search", 3)]),
        0,
        STANDARD_TIER_BP,
    );
    assert_eq!(
        posted.pre_tier_amount(),
        6_000,
        "the unnamed class adds nothing"
    );
    assert_eq!(posted.unpriced_classes(), vec!["web_search"]);
    let line = posted
        .lines()
        .iter()
        .find(|l| l.class == "web_search")
        .expect("the line stays visible");
    assert_eq!((line.quantity, line.amount_nanos), (3, 0));
}

/// A lane a present card does not name prices every line at nothing and reports the whole posting
/// unpriced, so the caller can fail closed rather than serve an unknown lane for free.
#[test]
fn a_lane_absent_from_a_present_card_prices_at_zero_and_reports_it() {
    let c = card("known", 5.0, 5.0, 2);
    let posted = price(
        &c.pin(),
        "mystery",
        &usage(&[(INPUT, 1_000_000)]),
        1,
        STANDARD_TIER_BP,
    );
    assert!(posted.lane_unpriced());
    assert_eq!(
        posted.pre_tier_amount(),
        20_000_000,
        "only the flat fee remains"
    );
}

/// An open class named exactly like the fee class cannot collide with the fee line or break the
/// posting: both are lines, both are summed, and the total is the plain sum of the two. The older
/// layout keyed components by display label and could fail the whole breakdown on a name clash.
#[test]
fn an_adversarial_class_name_cannot_collide_with_the_fee_line() {
    let c = RateCard::from_micro_rates(
        RateCardVersion::new("v1"),
        [
            (LaneClass::new("m", INPUT), 2.0),
            (LaneClass::new("m", FEE_CLASS), 0.01),
        ],
        3,
    );
    let posted = price(
        &c.pin(),
        "m",
        &usage(&[(INPUT, 3), (FEE_CLASS, 5)]),
        1,
        STANDARD_TIER_BP,
    );
    // 3 x 2000 + 5 x 10 + one 3-cent fee.
    assert_eq!(posted.pre_tier_amount(), 6_000 + 50 + 30_000_000);
    assert_eq!(
        posted.lines().len(),
        3,
        "the reported line and the fee line both stand"
    );
}

/// Each class bills against ITS OWN rate, never a neighbour's. The quantities are chosen so that
/// swapping any two rates changes the total, which is what a transposed cache-read and cache-write
/// mapping would do to every cached request.
#[test]
fn each_class_bills_against_its_own_rate() {
    let c = card4("quad", [1.0, 2.0, 0.5, 4.0], 0);
    let posted = price(
        &c.pin(),
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
    assert_eq!(posted.pre_tier_amount(), 15_000_000_000);
    assert_eq!(posted.cents(), 1500);
}

/// THE ORACLE'S CARD, reproduced. A tenth of a cost unit per input token and a fifth per output
/// token; eleven input tokens and seven output tokens is eighteen tokens, two and a half cost
/// units, two hundred and fifty cents. The figure the shadow comparison is pinned to.
#[test]
fn the_oracle_rate_card_reproduces_its_pinned_figure() {
    // A tenth of a cost unit is a hundred thousand micro-units per token.
    let c = card("oracle", 100_000.0, 200_000.0, 0);
    let posted = price(
        &c.pin(),
        "oracle",
        &usage(&[(INPUT, 11), (OUTPUT, 7)]),
        0,
        STANDARD_TIER_BP,
    );
    assert_eq!(
        posted.pre_tier_amount(),
        2_500_000_000,
        "two and a half units"
    );
    assert_eq!(posted.cents(), 250);
    assert_eq!(posted.micros(), 2_500_000);
}

/// The cent projection TRUNCATES toward zero; it never rounds up. Just under two cents is one, and
/// the exact boundary is two. A round-to-nearest defect would bill a cent the quantities never
/// reached.
#[test]
fn the_cent_projection_truncates_toward_zero() {
    let c = card("m", 1.0, 0.0, 0);
    let at = |tokens: u64| {
        price(
            &c.pin(),
            "m",
            &usage(&[(INPUT, tokens)]),
            0,
            STANDARD_TIER_BP,
        )
        .cents()
    };
    assert_eq!(at(19_999), 1, "just under two cents floors to one");
    assert_eq!(at(20_000), 2, "exactly two cents is two");
    assert_eq!(at(20_001), 2, "just over two cents still floors to two");
}

/// Both projections pin at the top of the signed range rather than wrapping. A wrapping conversion
/// would land negative, the cent floor would turn that into nothing, and an over-the-top ledger
/// would bill as free — escaping every cap it should have blocked.
#[test]
fn both_projections_saturate_rather_than_wrap() {
    assert_eq!(cents_of(u128::MAX), i64::MAX);
    assert_eq!(micros_of(u128::MAX), i64::MAX);
    let c = card("m", 1e15, 0.0, 0);
    let posted = price(
        &c.pin(),
        "m",
        &usage(&[(INPUT, u64::MAX)]),
        0,
        STANDARD_TIER_BP,
    );
    assert_eq!(posted.cents(), i64::MAX);
    assert_eq!(posted.micros(), i64::MAX);
}

/// Sub-micro precision survives, because the working scale is nano-units. Three and an eighth
/// micro-units per token times eight tokens is twenty-five micro-units exactly, with no truncation
/// at the micro boundary along the way.
#[test]
fn the_nano_scale_keeps_sub_micro_precision() {
    let c = card("m", 3.125, 0.0, 0);
    let posted = price(&c.pin(), "m", &usage(&[(INPUT, 8)]), 0, STANDARD_TIER_BP);
    assert_eq!(posted.micros(), 25);
    assert_eq!(posted.cents(), 0, "twenty-five micro-units is under a cent");
}

/// A class priced explicitly at zero is a KNOWN class that bills nothing at any volume — quite
/// different from a class the card never names. Pricing is on, the class is not flagged, and the
/// largest quantity there is still bills nothing.
#[test]
fn an_explicit_zero_rate_is_known_and_bills_nothing() {
    let c = card4("freebie", [0.0, 0.0, 0.0, 0.0], 0);
    assert!(c.pricing_enabled());
    assert!(!c.lane_unpriced("freebie"));
    let posted = price(
        &c.pin(),
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
    assert_eq!(posted.pre_tier_amount(), 0);
    assert!(posted.unpriced_classes().is_empty());
}

/// THE TIER, HAND COMPUTED. The card prices three input tokens at two thousand nano-units and four
/// output tokens at five thousand — twenty-six thousand — and the flat fee adds thirty million, so
/// the pre-tier amount is thirty million and twenty-six thousand. At one and a half times, that is
/// forty-five million thirty-nine thousand, which projects to four cents (four and a half, floored).
/// The multiplier applies ONCE, to the sum, and the posting stores all three figures.
#[test]
fn the_tier_multiplier_applies_once_over_the_summed_pre_tier_amount() {
    let c = card("m", 2.0, 5.0, 3);
    let posted = price(&c.pin(), "m", &usage(&[(INPUT, 3), (OUTPUT, 4)]), 1, 15_000);
    assert_eq!(posted.tier_bp(), 15_000);
    assert_eq!(posted.pre_tier_amount(), 30_026_000);
    assert_eq!(posted.priced_amount(), 45_039_000);
    assert_eq!(posted.cents(), 4);
    // The lines stay at their pre-tier amounts: the multiplier is on the sum, not on each line.
    assert_eq!(posted.lines()[0].amount_nanos, 6_000);
}

/// A tier below one is a discount and is the same single operation over the same sum. Four fifths
/// of thirty million and twenty-six thousand is twenty-four million twenty thousand eight hundred.
#[test]
fn a_discount_tier_is_the_same_single_operation() {
    let c = card("m", 2.0, 5.0, 3);
    let posted = price(&c.pin(), "m", &usage(&[(INPUT, 3), (OUTPUT, 4)]), 1, 8_000);
    assert_eq!(posted.pre_tier_amount(), 30_026_000);
    assert_eq!(posted.priced_amount(), 24_020_800);
    assert_eq!(posted.cents(), 2);
}

/// THE ONE DIVIDE, in the case that tells the two implementations apart. Two lines of five
/// nano-units each at half price: a sum of per-line floors is two plus two, which is four; the
/// single divide over the summed ten is five. The posting must charge five.
#[test]
fn the_tier_is_a_single_divide_not_a_sum_of_per_line_floors() {
    let c = RateCard::from_micro_rates(
        RateCardVersion::new("v1"),
        [
            (LaneClass::new("m", "a"), 0.005),
            (LaneClass::new("m", "b"), 0.005),
        ],
        0,
    );
    let posted = price(&c.pin(), "m", &usage(&[("a", 1), ("b", 1)]), 0, 5_000);
    assert_eq!(posted.pre_tier_amount(), 10);
    assert_eq!(
        posted.priced_amount(),
        5,
        "one divide of the summed ten, never two floors of two and a half"
    );
    assert_eq!(apply_tier(10, 5_000), 5);
}

/// The tier arithmetic saturates on the multiply rather than wrapping, so an enormous pre-tier
/// amount under a large multiplier pins high instead of landing back near nothing.
#[test]
fn the_tier_saturates_rather_than_wrapping() {
    assert_eq!(apply_tier(u128::MAX, 20_000), u128::MAX / 10_000);
    assert_eq!(apply_tier(0, 20_000), 0);
    assert_eq!(apply_tier(12_345, STANDARD_TIER_BP), 12_345);
}

/// The estimated mark travels from the usage report onto the posting: a figure the destination
/// never confirmed is visibly the kernel's own floor, all the way through.
#[test]
fn the_estimated_mark_travels_onto_the_posting() {
    let c = card("m", 1.0, 0.0, 0);
    let reported = price(&c.pin(), "m", &usage(&[(INPUT, 10)]), 0, STANDARD_TIER_BP);
    let floored = price(
        &c.pin(),
        "m",
        &estimated_usage(&[(INPUT, 10)]),
        0,
        STANDARD_TIER_BP,
    );
    assert!(!reported.estimated());
    assert!(floored.estimated());
    assert_eq!(floored.pre_tier_amount(), reported.pre_tier_amount());
}
