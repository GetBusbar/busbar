// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The read-time derivation, kept verbatim from the older release because the legacy usage
//! projection still reprices at read time. Quantities are the truth; the amount is derived.

use super::*;
use crate::{derive_spend_cents, derive_spend_micros, LaneClass, RateCard, RateCardVersion};

/// With NO card, quantities derive to nothing and only the flat fee counts. This is the
/// all-or-nothing switch in its off position.
#[test]
fn an_absent_card_prices_quantities_at_zero() {
    let c = RateCard::absent(RateCardVersion::new("none"), 3);
    let l = lines(&[(INPUT, 1_000_000), (OUTPUT, 1_000_000)]);
    assert_eq!(
        derive_spend_cents(&c, [("anything", l.as_slice())].into_iter(), 5, true),
        15,
        "quantities derive to nothing; five requests at three cents remain"
    );
}

/// With a card, derivation is integer arithmetic over the class split. Two and a half micro-units
/// per input token and ten per output token, a million of each, is twelve and a half cost units:
/// one thousand two hundred and fifty cents, twelve and a half million micro-units.
#[test]
fn a_present_card_derives_integer_spend() {
    let c = card("gpt-5", 2.5, 10.0, 0);
    let l = lines(&[(INPUT, 1_000_000), (OUTPUT, 1_000_000)]);
    assert_eq!(
        derive_spend_cents(&c, [("gpt-5", l.as_slice())].into_iter(), 0, false),
        1250
    );
    assert_eq!(
        derive_spend_micros(&c, [("gpt-5", l.as_slice())].into_iter(), 0, false),
        12_500_000
    );
}

/// Sub-micro precision survives the nano scale: three and an eighth micro-units per token times
/// eight tokens is twenty-five micro-units exactly, with no truncation at the micro boundary.
#[test]
fn the_nano_scale_keeps_sub_micro_precision() {
    let c = card("m", 3.125, 0.0, 0);
    let l = lines(&[(INPUT, 8)]);
    assert_eq!(
        derive_spend_micros(&c, [("m", l.as_slice())].into_iter(), 0, false),
        25
    );
}

/// A lane a present card does not name is reported unpriced — the admission path refuses it — and
/// derives at nothing on this path, because the only way a ledger row can name one is a card edit
/// that landed after the row was written. The retroactive effect is the designed behaviour.
#[test]
fn an_unknown_lane_with_a_card_is_unpriced_and_derives_zero() {
    let c = card("gpt-5", 1.0, 1.0, 0);
    assert!(c.lane_unpriced("mystery-lane"));
    assert!(!c.lane_unpriced("gpt-5"));
    let l = lines(&[(INPUT, 1_000_000)]);
    assert_eq!(
        derive_spend_cents(&c, [("mystery-lane", l.as_slice())].into_iter(), 0, false),
        0
    );
}

/// REPRICE ON READ: the quantities are fixed, so deriving under a corrected card yields the
/// corrected amount. There is no stored figure to migrate.
#[test]
fn repricing_on_read_recomputes_the_derived_spend() {
    let l = lines(&[(INPUT, 1_000_000)]);
    let wrong = card("m", 10.0, 0.0, 0);
    let fixed = card("m", 5.0, 0.0, 0);
    assert_eq!(
        derive_spend_cents(&wrong, [("m", l.as_slice())].into_iter(), 0, false),
        1000
    );
    assert_eq!(
        derive_spend_cents(&fixed, [("m", l.as_slice())].into_iter(), 0, false),
        500,
        "the same quantities under a corrected rate halve on the next read"
    );
}

/// A cent total past the top of the signed range pins there. The wrapping cast this replaced would
/// land negative, be floored to nothing, and derive an astronomical ledger as FREE — bypassing
/// every budget cap it should have blocked.
#[test]
fn the_derivation_saturates_and_never_wraps_toward_free() {
    let c = card("m", 1e15, 0.0, 0);
    let l = lines(&[(INPUT, u64::MAX)]);
    assert_eq!(
        derive_spend_cents(&c, [("m", l.as_slice())].into_iter(), 0, false),
        i64::MAX
    );
    assert_eq!(
        derive_spend_micros(&c, [("m", l.as_slice())].into_iter(), 0, false),
        i64::MAX
    );
}

/// Every class bills against its own rate. The quantities are chosen so any swap between two rates
/// changes the total.
#[test]
fn a_four_class_card_prices_each_class_against_its_own_rate() {
    let c = card4("quad", [1.0, 2.0, 0.5, 4.0], 0);
    let l = lines(&[
        (INPUT, 10_000_000),
        (OUTPUT, 1_000_000),
        (CACHE_READ, 2_000_000),
        (CACHE_WRITE, 500_000),
    ]);
    assert_eq!(
        derive_spend_cents(&c, [("quad", l.as_slice())].into_iter(), 0, false),
        1500
    );
}

/// The cent derivation truncates toward zero and never rounds up: a fractional cent is dropped
/// deterministically, never billed.
#[test]
fn the_cent_derivation_truncates_toward_zero() {
    let c = card("m", 1.0, 0.0, 0);
    let at = |tokens: u64| {
        let l = lines(&[(INPUT, tokens)]);
        derive_spend_cents(&c, [("m", l.as_slice())].into_iter(), 0, false)
    };
    assert_eq!(at(19_999), 1);
    assert_eq!(at(20_000), 2);
    assert_eq!(at(20_001), 2);
}

/// Two lanes billed into ONE bucket accumulate nano-units first and divide to cents ONCE. Two
/// lanes each contributing half a cent make a whole cent; a per-lane floor would drop both to
/// nothing and quietly undercharge every bucket that used more than one lane.
#[test]
fn sub_cent_contributions_across_lanes_sum_before_flooring() {
    let c = RateCard::from_micro_rates(
        RateCardVersion::new("v1"),
        [
            (LaneClass::new("a", INPUT), 5.0),
            (LaneClass::new("b", INPUT), 5.0),
        ],
        0,
    );
    let la = lines(&[(INPUT, 1_000)]);
    let lb = lines(&[(INPUT, 1_000)]);
    assert_eq!(
        derive_spend_cents(&c, [("a", la.as_slice())].into_iter(), 0, false),
        0,
        "one half-cent lane alone floors to nothing"
    );
    assert_eq!(
        derive_spend_cents(
            &c,
            [("a", la.as_slice()), ("b", lb.as_slice())].into_iter(),
            0,
            false
        ),
        1,
        "two half-cent lanes sum to a whole cent before the single divide"
    );
}

/// A class priced explicitly at zero is a known class that derives nothing at any volume.
#[test]
fn an_explicit_zero_rate_lane_derives_zero() {
    let c = card4("freebie", [0.0, 0.0, 0.0, 0.0], 0);
    assert!(!c.lane_unpriced("freebie"));
    let l = lines(&[
        (INPUT, u64::MAX),
        (OUTPUT, u64::MAX),
        (CACHE_READ, u64::MAX),
        (CACHE_WRITE, u64::MAX),
    ]);
    assert_eq!(
        derive_spend_cents(&c, [("freebie", l.as_slice())].into_iter(), 0, false),
        0
    );
}

/// A PARTIAL card: only the named lane contributes, the unnamed one derives nothing, and neither
/// panics nor borrows the other's rate.
#[test]
fn a_partial_card_prices_the_known_lane_and_zeroes_the_missing_one() {
    let c = card("priced", 2.0, 0.0, 0);
    assert!(!c.lane_unpriced("priced"));
    assert!(c.lane_unpriced("absent"));
    let known = lines(&[(INPUT, 1_000_000)]);
    let absent = lines(&[(INPUT, 9_999_999)]);
    assert_eq!(
        derive_spend_cents(
            &c,
            [("priced", known.as_slice()), ("absent", absent.as_slice())].into_iter(),
            0,
            false
        ),
        200
    );
}

/// The flat fee is the fee times the billable request count, added only when asked for. Both the
/// multiply and the add pin at the top of the range: an enormous request count can never wrap the
/// fee negative, which the floor would then turn into a free bucket.
#[test]
fn the_flat_fee_saturates_and_is_gated_by_the_flag() {
    let c = RateCard::absent(RateCardVersion::new("v"), i64::MAX);
    let l = lines(&[]);
    assert_eq!(
        derive_spend_cents(&c, [("m", l.as_slice())].into_iter(), u64::MAX, true),
        i64::MAX
    );
    assert_eq!(
        derive_spend_cents(&c, [("m", l.as_slice())].into_iter(), u64::MAX, false),
        0,
        "with the fee excluded it contributes nothing"
    );
}

/// A negative configured fee is clamped at resolve, so a hundred requests bill nothing rather than
/// crediting the bucket back toward headroom.
#[test]
fn a_negative_fee_can_never_credit_a_bucket() {
    let c = RateCard::absent(RateCardVersion::new("v"), -5);
    let l = lines(&[]);
    assert_eq!(c.per_request_fee_cents(), 0);
    assert_eq!(
        derive_spend_cents(&c, [("m", l.as_slice())].into_iter(), 100, true),
        0
    );
}

/// The micro projection's fee component is the cent fee times ten thousand, so the two projections
/// can never drift apart on the fee.
#[test]
fn the_micro_projection_fee_is_ten_thousand_times_the_cent_fee() {
    let c = RateCard::absent(RateCardVersion::new("v"), 3);
    let l = lines(&[]);
    assert_eq!(
        derive_spend_micros(&c, [("m", l.as_slice())].into_iter(), 5, true),
        150_000
    );
    assert_eq!(
        derive_spend_cents(&c, [("m", l.as_slice())].into_iter(), 5, true),
        15
    );
    assert_eq!(
        derive_spend_micros(&c, [("m", l.as_slice())].into_iter(), 5, false),
        0
    );
}

/// The budget boundary, in the exact cents the admission comparison uses: a quantity chosen to land
/// on an integer cap derives to precisely that integer, and one cent more of quantity derives
/// strictly above it.
#[test]
fn the_derived_spend_lands_exactly_on_an_integer_cap() {
    let c = card("m", 1.0, 0.0, 0);
    let at = |tokens: u64| {
        let l = lines(&[(INPUT, tokens)]);
        derive_spend_cents(&c, [("m", l.as_slice())].into_iter(), 0, false)
    };
    assert_eq!(at(1_000_000), 100);
    assert_eq!(at(1_010_000), 101);
}
