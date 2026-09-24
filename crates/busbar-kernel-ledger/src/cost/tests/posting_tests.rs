// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Clause two, three and five: what a posting stores, how it projects, and the tier multiplier.

use super::*;
use crate::cost::{
    apply_tier, apply_tier_signed, cents_of, checked_apply_tier, micros_of, LaneClass, RateCard,
    FEE_CLASS, STANDARD_TIER_BP,
};

/// The stored pre-tier amount is the sum over the posting's lines INCLUDING the fee line, and each
/// line records the rate it was priced at. Three input tokens at two thousand nano-units and four
/// output tokens at five thousand is twenty-six thousand; a three-cent fee is thirty million more.
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

/// A posting with no fee carries a fee line of zero quantity all the same. The line is always
/// there, so the sum is always one shape and no reader has to know whether to add a fee.
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

/// NO CARD AT ALL: every class prices at nothing and the fee still posts. This is the deployment
/// with pricing switched off — attribution only, plus whatever flat fee is configured.
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
    assert_eq!(posted.minor(), 15);
    assert!(!posted.lane_unpriced, "no card means no missing lane");
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

/// A lane a present card does not name prices every line at nothing and reports the whole posting
/// unpriced, so the caller can fail closed rather than serve an unknown lane for free.
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

/// An open class named exactly like the fee class cannot collide with the fee line or break the
/// posting: both are lines, both are summed, and the total is the plain sum of the two. The older
/// layout keyed components by display label and could fail the whole breakdown on a name clash.
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
    // 3 x 2000 + 5 x 10 + one 3-cent fee.
    assert_eq!(posted.pre_tier_nanos, 6_000 + 50 + 30_000_000);
    assert_eq!(
        posted.lines.len(),
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
    assert_eq!(posted.minor(), 1500);
}

/// THE ORACLE'S CARD, reproduced. A tenth of a cost unit per input token and a fifth per output
/// token; eleven input tokens and seven output tokens is eighteen tokens, two and a half cost
/// units, two hundred and fifty cents. The figure the shadow comparison is pinned to.
#[test]
fn the_oracle_rate_card_reproduces_its_pinned_figure() {
    // A tenth of a cost unit is a hundred thousand micro-units per token.
    let c = card("oracle", 100_000.0, 200_000.0, 0);
    let posted = priced(
        &c,
        "oracle",
        &usage(&[(INPUT, 11), (OUTPUT, 7)]),
        0,
        STANDARD_TIER_BP,
    );
    assert_eq!(posted.pre_tier_nanos, 2_500_000_000, "two and a half units");
    assert_eq!(posted.minor(), 250);
    assert_eq!(posted.micros(), 2_500_000);
}

/// The cent projection TRUNCATES toward zero; it never rounds up. Just under two cents is one, and
/// the exact boundary is two. A round-to-nearest defect would bill a cent the quantities never
/// reached.
#[test]
fn the_cent_projection_truncates_toward_zero() {
    let c = card("m", 1.0, 0.0, 0);
    let at = |tokens: u64| priced(&c, "m", &usage(&[(INPUT, tokens)]), 0, STANDARD_TIER_BP).minor();
    assert_eq!(at(19_999), 1, "just under two cents floors to one");
    assert_eq!(at(20_000), 2, "exactly two cents is two");
    assert_eq!(at(20_001), 2, "just over two cents still floors to two");
}

/// Both projections pin at the top of the signed range rather than wrapping. A wrapping conversion
/// would land negative, the cent floor would turn that into nothing, and an over-the-top ledger
/// would bill as free — escaping every cap it should have blocked.
///
/// And a POSTING that large is never priced at all (item 28): the lookup's figure is the one
/// function's, which REFUSES an overflow rather than billing the ceiling — so there is no pinned
/// posting for these projections to be asked about.
#[test]
fn both_projections_saturate_rather_than_wrap() {
    assert_eq!(cents_of(u128::MAX), i64::MAX);
    assert_eq!(micros_of(u128::MAX), i64::MAX);
    let c = card("m", 1e15, 0.0, 0);
    let history = crate::cost::History::opening(c, 0);
    let posting = Posting::from_usage("m", &usage(&[(INPUT, u64::MAX)]), 0, STANDARD_TIER_BP, 0, 0);
    assert_eq!(
        crate::cost::price(&history.current(), &posting),
        Err(crate::cost::Unpriceable::Overflow),
        "an overflowing posting is refused, never billed at the ceiling"
    );
}

/// Sub-micro precision survives, because the working scale is nano-units. Three and an eighth
/// micro-units per token times eight tokens is twenty-five micro-units exactly, with no truncation
/// at the micro boundary along the way.
#[test]
fn the_nano_scale_keeps_sub_micro_precision() {
    let c = card("m", 3.125, 0.0, 0);
    let posted = priced(&c, "m", &usage(&[(INPUT, 8)]), 0, STANDARD_TIER_BP);
    assert_eq!(posted.micros(), 25);
    assert_eq!(posted.minor(), 0, "twenty-five micro-units is under a cent");
}

/// A class priced explicitly at zero is a KNOWN class that bills nothing at any volume — quite
/// different from a class the card never names. Pricing is on, the class is not flagged, and the
/// largest quantity there is still bills nothing.
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

/// THE TIER, HAND COMPUTED. The card prices three input tokens at two thousand nano-units and four
/// output tokens at five thousand — twenty-six thousand — and the flat fee adds thirty million, so
/// the pre-tier amount is thirty million and twenty-six thousand. At one and a half times, that is
/// forty-five million thirty-nine thousand, which projects to four cents (four and a half, floored).
/// The multiplier applies ONCE, to the sum, and the posting stores all three figures.
#[test]
fn the_tier_multiplier_applies_once_over_the_summed_pre_tier_amount() {
    let c = card("m", 2.0, 5.0, 3);
    let posted = priced(&c, "m", &usage(&[(INPUT, 3), (OUTPUT, 4)]), 1, 15_000);
    assert_eq!(posted.tier_bp, 15_000);
    assert_eq!(posted.pre_tier_nanos, 30_026_000);
    assert_eq!(posted.priced_nanos, 45_039_000);
    assert_eq!(posted.minor(), 4);
    // The lines stay at their pre-tier amounts: the multiplier is on the sum, not on each line.
    assert_eq!(posted.lines[0].amount_nanos, 6_000);
}

/// A tier below one is a discount and is the same single operation over the same sum. Four fifths
/// of thirty million and twenty-six thousand is twenty-four million twenty thousand eight hundred.
#[test]
fn a_discount_tier_is_the_same_single_operation() {
    let c = card("m", 2.0, 5.0, 3);
    let posted = priced(&c, "m", &usage(&[(INPUT, 3), (OUTPUT, 4)]), 1, 8_000);
    assert_eq!(posted.pre_tier_nanos, 30_026_000);
    assert_eq!(posted.priced_nanos, 24_020_800);
    assert_eq!(posted.minor(), 2);
}

/// THE ONE DIVIDE, in the case that tells the two implementations apart. Two lines of five
/// nano-units each at half price: a sum of per-line floors is two plus two, which is four; the
/// single divide over the summed ten is five. The posting must charge five.
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
    assert_eq!(apply_tier(10, 5_000), 5);
}

/// **THE NEUTRAL TIER IS THE IDENTITY, AT EVERY MAGNITUDE INCLUDING THE CEILING.**
///
/// This cell used to read `assert_eq!(apply_tier(u128::MAX, 20_000), u128::MAX / 10_000)` and
/// called that saturation. It was not saturation, it was the defect written down as an
/// expectation: `saturating_mul` pinned the PRODUCT at `u128::MAX` and the divide by ten thousand
/// then shrank it, so the function returned one ten-thousandth of the true amount and a test
/// asserted that it should.
///
/// The row below it is why that mattered rather than being a curiosity at an unreachable input.
/// `tier_bp` is `STANDARD_TIER_BP` on EVERY production path in this tree (`units_llm.rs` pins it
/// on the posting, `policy.rs` pins it on the group, and both defaults resolve to it), so ×1 is
/// the only tier the arithmetic is ever actually asked for — and ×1 at the ceiling was returning
/// `34028236692093846346337460743176821` in place of
/// `340282366920938463463374607431768211455`. A bill of `u128::MAX` was derived as ten thousand
/// times less than itself.
#[test]
fn the_neutral_tier_is_the_identity_at_every_magnitude() {
    assert_eq!(
        apply_tier(u128::MAX, STANDARD_TIER_BP),
        u128::MAX,
        "x1 at the ceiling must return the ceiling, not one ten-thousandth of it"
    );
    assert_eq!(apply_tier(12_345, STANDARD_TIER_BP), 12_345);
    assert_eq!(apply_tier(0, STANDARD_TIER_BP), 0);
    assert_eq!(apply_tier(1, STANDARD_TIER_BP), 1);
}

/// A tiered amount that genuinely does not fit pins at the ceiling; one that does is exact.
///
/// The distinction the old spelling could not make: `u128::MAX` at double price really is past the
/// type, so `u128::MAX` is the honest narrowing of it — but `u128::MAX` at ×1 is not past anything
/// and must come back whole.
#[test]
fn only_a_genuinely_unrepresentable_tiered_amount_pins_at_the_ceiling() {
    assert_eq!(apply_tier(u128::MAX, 20_000), u128::MAX);
    assert_eq!(checked_apply_tier(u128::MAX, 20_000), None);
    assert_eq!(
        checked_apply_tier(u128::MAX, STANDARD_TIER_BP),
        Some(u128::MAX)
    );
    assert_eq!(apply_tier(0, 20_000), 0);
    // Half the ceiling at double price is exactly the ceiling plus one, which is the first value
    // that does not fit — the boundary stated as arithmetic rather than as a literal.
    assert_eq!(checked_apply_tier((u128::MAX / 2) + 1, 20_000), None);
    assert_eq!(
        checked_apply_tier(u128::MAX / 2, 20_000),
        Some(u128::MAX - 1)
    );
}

/// **#44 (`BUSBAR-1.6.0.md:372`) AT THE EXACT HALF, IN BOTH SIGNS.**
///
/// *"only a 'per-N-units' division term uses banker's (half-to-even) rounding"*, restated by #81
/// (`:428`): *"a per-N-units division term still uses banker's rounding (#44), because a DIVISION
/// can genuinely be inexact where a MEASUREMENT cannot."* `× tier_bp / 10_000` is that term.
///
/// The five tier implementations this tree carried truncated toward zero (four of them) or rounded
/// up (one), and not one of them was banker's. Truncation is not rounding: it is a discount the
/// operator never configured, taken in one direction, on every posting, forever.
///
/// Both signs, because a reversal is a negative amount and a rule that is not symmetric about zero
/// would let a correction be worth more or less depending on which side of the book it is written
/// on. Half-to-even is symmetric: `2.5 -> 2` and `-2.5 -> -2`.
#[test]
fn a_tier_that_lands_on_an_exact_half_rounds_to_even_in_both_signs() {
    // 5 x 5,000bp = 2.5 exactly. 2 is even, so DOWN. (Truncation agreed here by luck.)
    assert_eq!(apply_tier(5, 5_000), 2);
    assert_eq!(apply_tier_signed(-5, 5_000), -2);
    // 15 x 5,000bp = 7.5 exactly. 7 is odd, so UP to 8. (Truncation billed 7.)
    assert_eq!(apply_tier(15, 5_000), 8);
    assert_eq!(apply_tier_signed(-15, 5_000), -8);
    // 25 x 5,000bp = 12.5 exactly. 12 is even, so DOWN.
    assert_eq!(apply_tier(25, 5_000), 12);
    assert_eq!(apply_tier_signed(-25, 5_000), -12);
    // 3 x 5,000bp = 1.5 exactly. 1 is odd, so UP to 2. (Truncation billed 1.)
    assert_eq!(apply_tier(3, 5_000), 2);
    assert_eq!(apply_tier_signed(-3, 5_000), -2);

    // AND THE TIE IS THE ONLY PLACE THE EVEN RULE APPLIES. Either side of it goes to the nearer
    // neighbour regardless of parity, which is what distinguishes banker's from "always down to
    // even".
    assert_eq!(apply_tier(14, 5_000), 7, "7.0 exactly: nothing to round");
    assert_eq!(apply_tier(16, 5_000), 8, "8.0 exactly: nothing to round");
    assert_eq!(apply_tier(1, 9_999), 1, "0.9999 rounds to the nearer 1");
    assert_eq!(apply_tier(1, 4_999), 0, "0.4999 rounds to the nearer 0");
    assert_eq!(apply_tier(1, 5_000), 0, "0.5 exactly: 0 is even");
    assert_eq!(apply_tier(3, 5_001), 2, "1.5003 rounds to the nearer 2");
}

/// **HALF-AWAY-FROM-ZERO IS THE OTHER RULE IN #44, AND IT IS NOT THIS ONE.**
///
/// #44 (`:372`) carries two rounding rules in one sentence and they apply to different terms:
/// *"only a 'per-N-units' division term uses banker's (half-to-even) rounding; card-build-time
/// quantization stays half-away-from-zero (byte-identity)"*. Card-build quantisation is
/// [`crate::cost::nano_rate`], once, at the boundary where an operator's configured decimal becomes
/// an integer rate. The tier is not that term, and at a tie the two rules give different money —
/// which is exactly why the row names them separately.
///
/// Written as a test rather than a comment so that a future reader who reaches for the wrong half
/// of the row gets a NO instead of a plausible-looking diff.
#[test]
fn the_tier_does_not_use_the_card_builds_rounding_rule() {
    // At 7.5, half-away-from-zero gives 8 and half-to-even gives 8 too: agreement, not evidence.
    assert_eq!(apply_tier(15, 5_000), 8);
    // At 2.5 they part: half-away-from-zero gives 3, half-to-even gives 2. The tier gives 2.
    assert_eq!(
        apply_tier(5, 5_000),
        2,
        "not 3 — the tier is not card-build quantisation"
    );
    assert_eq!(apply_tier(25, 5_000), 12, "not 13");
    assert_eq!(apply_tier(45, 5_000), 22, "not 23");
}

/// The estimated mark travels from the usage report onto the posting: a figure the destination
/// never confirmed is visibly the kernel's own floor, all the way through.
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

/// **BYTE-NEUTRALITY AT THE ONLY TIER THIS TREE EVER ASKS FOR.**
///
/// `tier_bp` is [`STANDARD_TIER_BP`] on every production path: the live LLM posting pins it
/// (`crates/busbar/src/root/units_llm.rs`, `Posting::from_usage(.., STANDARD_TIER_BP, ..)`), the
/// group runtime pins it (`crates/busbar/src/root/policy.rs`), a `LedgerEntry` defaults to it, and
/// the recompute archive's `tier_bp` defaults to it. No operator configuration key sets a
/// basis-point multiplier at all — `config/pools.rs`'s `tier` is a routing LABEL (`"large"`), not a
/// price.
///
/// So this is the sweep that says the rounding correction moved no byte anybody can observe: over
/// the whole ordinary range, at the tier every posting actually carries, the answer is the input,
/// which is what the previous implementation also gave. Zero differences.
///
/// The rounding rule only becomes visible at a tier that is not ×1, and a tier that is not ×1 is
/// unreachable from any configuration this tree parses.
#[test]
fn the_neutral_tier_moves_no_ordinary_amount() {
    // A deterministic spread across every magnitude a book reaches, plus the exact powers of ten
    // either side of each one, so the sweep lands on and beside every rounding step.
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
            apply_tier(pre, STANDARD_TIER_BP),
            pre,
            "x1 moved an ordinary amount: {pre}"
        );
        // And the previous implementation's answer, computed here, is the same one — for every
        // amount whose ×10,000 stayed inside the type, which is every amount below about 3.4e34.
        if pre < u128::MAX / 10_000 {
            assert_eq!(
                pre.saturating_mul(10_000) / 10_000,
                apply_tier(pre, STANDARD_TIER_BP),
                "the correction moved a byte at {pre}"
            );
        }
        checked += 1;
    }
    assert_eq!(checked, 479, "the sweep must actually have run");
}
