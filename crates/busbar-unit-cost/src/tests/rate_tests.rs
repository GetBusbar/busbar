// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Clause one and clause four: the single conversion from a configured decimal to an integer rate,
//! and the pin that makes a posting immune to a later card edit.

use super::*;
use crate::{nano_rate, price, RateCard, RateCardVersion, STANDARD_TIER_BP};

/// The conversion rounds to NEAREST, half away from zero — it does not truncate. Fifteen
/// ten-thousandths of a micro-unit is one and a half nano-units and must become two; fourteen is
/// one and four tenths and must become one. A truncating conversion would silently under-price the
/// finest rate an operator can configure.
#[test]
fn nano_rate_rounds_to_nearest_at_the_nano_boundary() {
    assert_eq!(nano_rate(0.0015), 2, "one and a half rounds away from zero");
    assert_eq!(nano_rate(0.0014), 1, "one and four tenths floors to one");
}

/// The clamp is "finite AND positive", not "finite OR positive". An infinite rate — reachable from
/// a huge configured value times a thousand — is not finite but IS positive, and casting it to an
/// integer would saturate at the largest integer there is: a garbage billing rate, not the
/// defence. Not-a-number cannot tell the two spellings apart, so infinity is the case that does.
#[test]
fn nano_rate_clamps_a_non_finite_positive_rate_to_zero_not_the_maximum() {
    assert_eq!(nano_rate(f64::INFINITY), 0);
    assert_eq!(nano_rate(f64::NAN), 0);
    assert_eq!(nano_rate(-1.0), 0, "a negative rate is not a discount");
}

/// The card carries the integer rates straight through, per class, with no swapping between them.
#[test]
fn card_carries_integer_rates_per_class() {
    let c = card4("quad", [1.0, 2.0, 0.5, 4.0], 0);
    let r = c.lane_rates("quad").expect("the lane is priced");
    assert_eq!(
        (
            r.nanos_per_unit(INPUT),
            r.nanos_per_unit(OUTPUT),
            r.nanos_per_unit(CACHE_READ),
            r.nanos_per_unit(CACHE_WRITE),
        ),
        (1_000, 2_000, 500, 4_000)
    );
}

/// The three outcomes of a rate lookup, which are the whole pricing posture: no card is a
/// zero-rate view over every lane; a card that names the lane prices it; a card that does not name
/// the lane yields nothing at all, so the caller fails closed rather than serving for free.
#[test]
fn lane_lookup_has_exactly_three_outcomes() {
    let none = RateCard::absent(RateCardVersion::new("none"), 3);
    assert!(!none.pricing_enabled());
    assert!(
        !none.lane_unpriced("anything"),
        "with no card there is nothing to be missing from"
    );
    let view = none.lane_rates("anything").expect("a zero-rate view");
    assert_eq!(view.nanos_per_unit(INPUT), 0);

    let present = card("known", 1.0, 1.0, 0);
    assert!(present.pricing_enabled());
    assert!(!present.lane_unpriced("known"));
    assert!(present.lane_unpriced("mystery"));
    assert!(present.lane_rates("mystery").is_none());
}

/// A negative configured fee clamps to nothing at resolve. No request may bill a negative amount,
/// which would credit a budget bucket back toward headroom.
#[test]
fn negative_per_request_fee_clamps_to_zero() {
    let c = RateCard::absent(RateCardVersion::new("v"), -5);
    assert_eq!(c.per_request_fee_cents(), 0);
    assert_eq!(c.fee_unit_price_nanos(), 0);
}

/// The fee's unit price is its cents lifted to nano-units — an exact multiple of ten million,
/// which is what makes summing it in before the single truncation give the same cents as adding it
/// afterwards.
#[test]
fn fee_line_unit_price_is_cents_lifted_to_nano_units() {
    let c = RateCard::absent(RateCardVersion::new("v"), 3);
    assert_eq!(c.fee_unit_price_nanos(), 30_000_000);
    assert_eq!(c.fee_unit_price_nanos() % crate::NANOS_PER_CENT, 0);
}

/// A posting is priced against the card PINNED when its hold opened, and records that version. A
/// card edit that lands afterwards produces different figures under a different version, and moves
/// nothing already posted.
#[test]
fn a_pinned_card_prices_the_posting_and_a_later_edit_moves_nothing() {
    let at_hold = RateCard::from_micro_rates(
        RateCardVersion::new("card-1"),
        [(LaneClass::new("m", INPUT), 10.0)],
        0,
    );
    let pin = at_hold.pin();
    let report = usage(&[(INPUT, 1_000_000)]);
    let posted = price(&pin, "m", &report, 0, STANDARD_TIER_BP);
    assert_eq!(posted.cents(), 1000);
    assert_eq!(posted.rate_card_version().as_str(), "card-1");

    // The operator halves the rate. The new card is a new version; the posting already made is
    // untouched, and re-pricing through the OLD pin still gives the old figure.
    let corrected = RateCard::from_micro_rates(
        RateCardVersion::new("card-2"),
        [(LaneClass::new("m", INPUT), 5.0)],
        0,
    );
    let repriced = price(&corrected.pin(), "m", &report, 0, STANDARD_TIER_BP);
    assert_eq!(repriced.cents(), 500);
    assert_eq!(repriced.rate_card_version().as_str(), "card-2");
    assert_eq!(posted.cents(), 1000, "the earlier posting did not move");
    let again = price(&pin, "m", &report, 0, STANDARD_TIER_BP);
    assert_eq!(again, posted, "the pin still prices the card it froze");
}
