// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Canonical accumulation and checked projections. Quantities are the truth; the amount is derived.

use super::*;
use crate::cost::{whole, LaneClass, Money, MoneyError, RateCard, Tally, STANDARD_TIER_BP};

fn bucket_money<'a>(
    card: &RateCard,
    lanes: impl IntoIterator<Item = (&'a str, &'a [busbar_contract::caps::UsageLine])>,
    billable_requests: u64,
) -> Result<Money, MoneyError> {
    let mut tally = Tally::at_card(card);
    for (lane, lines) in lanes {
        tally.row(
            lane,
            0,
            STANDARD_TIER_BP,
            lines
                .iter()
                .map(|line| (line.class.as_str(), whole(line.quantity))),
            whole(0),
        )?;
    }
    tally.fee(0, STANDARD_TIER_BP, whole(billable_requests))?;
    tally.money()
}

/// With NO card, quantities derive to nothing and only the flat fee counts. This is the
#[test]
fn an_absent_card_prices_quantities_at_zero() {
    let c = RateCard::absent(3);
    let l = lines(&[(INPUT, 1_000_000), (OUTPUT, 1_000_000)]);
    assert_eq!(
        bucket_money(&c, [("anything", l.as_slice())], 5).and_then(Money::minor_i64),
        Ok(15),
        "quantities derive to nothing; five requests at three cents remain"
    );
}

/// With a card, derivation is integer arithmetic over the class split. Two and a half micro-units
#[test]
fn a_present_card_derives_integer_spend() {
    let c = card("lane-5", 2.5, 10.0, 0);
    let l = lines(&[(INPUT, 1_000_000), (OUTPUT, 1_000_000)]);
    assert_eq!(
        bucket_money(&c, [("lane-5", l.as_slice())], 0).and_then(Money::minor_i64),
        Ok(1250)
    );
    assert_eq!(
        bucket_money(&c, [("lane-5", l.as_slice())], 0).and_then(Money::micros_i64),
        Ok(12_500_000)
    );
}

/// Sub-micro precision survives the nano scale: three and an eighth micro-units per token times
#[test]
fn the_nano_scale_keeps_sub_micro_precision() {
    let c = card("m", 3.125, 0.0, 0);
    let l = lines(&[(INPUT, 8)]);
    assert_eq!(
        bucket_money(&c, [("m", l.as_slice())], 0).and_then(Money::micros_i64),
        Ok(25)
    );
}

#[test]
fn an_unknown_lane_with_a_card_is_unpriced_and_refuses() {
    let c = card("lane-5", 1.0, 1.0, 0);
    assert!(c.lane_unpriced("mystery-lane"));
    assert!(!c.lane_unpriced("lane-5"));
    let l = lines(&[(INPUT, 1_000_000)]);
    assert_eq!(
        bucket_money(&c, [("mystery-lane", l.as_slice())], 0).and_then(Money::minor_i64),
        Err(MoneyError::LaneUnpriced {
            card_seq: crate::cost::HistorySeq::OPENING,
            lane: "mystery-lane".to_string(),
        })
    );
}

/// REPRICE ON READ: the quantities are fixed, so deriving under a corrected card yields the
#[test]
fn repricing_on_read_recomputes_the_derived_spend() {
    let l = lines(&[(INPUT, 1_000_000)]);
    let wrong = card("m", 10.0, 0.0, 0);
    let fixed = card("m", 5.0, 0.0, 0);
    assert_eq!(
        bucket_money(&wrong, [("m", l.as_slice())], 0).and_then(Money::minor_i64),
        Ok(1000)
    );
    assert_eq!(
        bucket_money(&fixed, [("m", l.as_slice())], 0).and_then(Money::minor_i64),
        Ok(500),
        "the same quantities under a corrected rate halve on the next read"
    );
}

#[test]
fn the_derivation_refuses_an_overflow_and_never_pins_or_wraps() {
    let c = card("m", 1e15, 0.0, 0);
    let l = lines(&[(INPUT, u64::MAX)]);
    assert_eq!(
        bucket_money(&c, [("m", l.as_slice())], 0).and_then(Money::minor_i64),
        Err(MoneyError::Overflow)
    );
    assert_eq!(
        bucket_money(&c, [("m", l.as_slice())], 0).and_then(Money::micros_i64),
        Err(MoneyError::Overflow)
    );
}

/// Every class bills against its own rate. The quantities are chosen so any swap between two rates
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
        bucket_money(&c, [("quad", l.as_slice())], 0).and_then(Money::minor_i64),
        Ok(1500)
    );
}

/// The cent derivation truncates toward zero and never rounds up: a fractional cent is dropped
#[test]
fn the_cent_derivation_truncates_toward_zero() {
    let c = card("m", 1.0, 0.0, 0);
    let at = |tokens: u64| {
        let l = lines(&[(INPUT, tokens)]);
        bucket_money(&c, [("m", l.as_slice())], 0).and_then(Money::minor_i64)
    };
    assert_eq!(at(19_999), Ok(1));
    assert_eq!(at(20_000), Ok(2));
    assert_eq!(at(20_001), Ok(2));
}

/// Two lanes billed into ONE bucket accumulate nano-units first and divide to cents ONCE. Two
#[test]
fn sub_cent_contributions_across_lanes_sum_before_flooring() {
    let c = RateCard::from_micro_rates(
        [
            (LaneClass::new("a", INPUT), 5.0),
            (LaneClass::new("b", INPUT), 5.0),
        ],
        0,
    );
    let la = lines(&[(INPUT, 1_000)]);
    let lb = lines(&[(INPUT, 1_000)]);
    assert_eq!(
        bucket_money(&c, [("a", la.as_slice())], 0).and_then(Money::minor_i64),
        Ok(0),
        "one half-cent lane alone floors to nothing"
    );
    assert_eq!(
        bucket_money(&c, [("a", la.as_slice()), ("b", lb.as_slice())], 0)
            .and_then(Money::minor_i64),
        Ok(1),
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
        bucket_money(&c, [("freebie", l.as_slice())], 0).and_then(Money::minor_i64),
        Ok(0)
    );
}

/// A PARTIAL card: the named lane prices, and the unnamed one REFUSES the whole derivation (#42) —
#[test]
fn a_partial_card_prices_the_known_lane_and_refuses_the_missing_one() {
    let c = card("priced", 2.0, 0.0, 0);
    assert!(!c.lane_unpriced("priced"));
    assert!(c.lane_unpriced("absent"));
    let known = lines(&[(INPUT, 1_000_000)]);
    let absent = lines(&[(INPUT, 9_999_999)]);
    assert_eq!(
        bucket_money(
            &c,
            [("priced", known.as_slice()), ("absent", absent.as_slice())],
            0,
        )
        .and_then(Money::minor_i64),
        Err(MoneyError::LaneUnpriced {
            card_seq: crate::cost::HistorySeq::OPENING,
            lane: "absent".to_string(),
        })
    );
    assert_eq!(
        bucket_money(&c, [("priced", known.as_slice())], 0).and_then(Money::minor_i64),
        Ok(200),
        "the named lane alone prices as it always did"
    );
}

/// The flat fee is the fee times the billable request count. A product
#[test]
fn the_flat_fee_refuses_an_overflow_and_zero_billable_requests_add_nothing() {
    let c = RateCard::absent(i64::MAX);
    let l = lines(&[]);
    assert_eq!(
        bucket_money(&c, [("m", l.as_slice())], u64::MAX).and_then(Money::minor_i64),
        Err(MoneyError::Overflow)
    );
    assert_eq!(
        bucket_money(&c, [("m", l.as_slice())], 0).and_then(Money::minor_i64),
        Ok(0),
        "with no billable requests the fee contributes nothing"
    );
}

/// A negative configured fee is clamped at resolve, so a hundred requests bill nothing rather than
#[test]
fn a_negative_fee_can_never_credit_a_bucket() {
    let c = RateCard::absent(-5);
    let l = lines(&[]);
    assert_eq!(c.fee(), 0);
    assert_eq!(c.fee_unit_price_nanos(), 0);
    assert_eq!(
        bucket_money(&c, [("m", l.as_slice())], 100).and_then(Money::minor_i64),
        Ok(0)
    );
}

/// The micro projection's fee component is the cent fee times ten thousand, so the two projections
#[test]
fn the_micro_projection_fee_is_ten_thousand_times_the_cent_fee() {
    let c = RateCard::absent(3);
    let l = lines(&[]);
    assert_eq!(
        bucket_money(&c, [("m", l.as_slice())], 5).and_then(Money::micros_i64),
        Ok(150_000)
    );
    assert_eq!(
        bucket_money(&c, [("m", l.as_slice())], 5).and_then(Money::minor_i64),
        Ok(15)
    );
    assert_eq!(
        bucket_money(&c, [("m", l.as_slice())], 0).and_then(Money::micros_i64),
        Ok(0)
    );
}

/// The budget boundary, in the exact cents the admission comparison uses: a quantity chosen to land
#[test]
fn the_derived_spend_lands_exactly_on_an_integer_cap() {
    let c = card("m", 1.0, 0.0, 0);
    let at = |tokens: u64| {
        let l = lines(&[(INPUT, tokens)]);
        bucket_money(&c, [("m", l.as_slice())], 0).and_then(Money::minor_i64)
    };
    assert_eq!(at(1_000_000), Ok(100));
    assert_eq!(at(1_010_000), Ok(101));
}
