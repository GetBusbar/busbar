// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE ONE SCALE**, and the fact that nothing can name a second one.

use super::*;
use crate::cost::{History, LaneClass, RateCard, MICROS_PER_CENT, NANOS_PER_CENT, NANOS_PER_MICRO};

/// **THE SCALE IS A CONSTANT, NOT A CHOICE.** Ten million nano-units to one minor unit, which is
#[test]
fn the_one_scale_is_ten_million_nanos_and_nothing_can_name_another() {
    assert_eq!(NANOS_PER_CENT, 10_000_000);

    assert_eq!(NANOS_PER_MICRO, 1_000);
    assert_eq!(
        i64::try_from(NANOS_PER_CENT / NANOS_PER_MICRO).expect("the ratio fits"),
        MICROS_PER_CENT
    );
}

/// **ONE TRUNCATION, AT THE ONE DIVISOR, AT THE BOUNDARY.** Carried over verbatim from the deleted
#[test]
fn the_minor_projection_truncates_once_at_the_one_boundary() {
    assert_eq!(minor_nanos(19_999_999), Ok(1));
    assert_eq!(minor_nanos(20_000_000), Ok(2));
    assert_eq!(minor_nanos(20_000_001), Ok(2));
    assert_eq!(minor_nanos(2_000_000_000), Ok(200));

    assert_eq!(micros_nanos(2_000_000_000), Ok(2_000_000));
    assert_eq!(
        minor_nanos(u128::MAX),
        Err(crate::cost::MoneyError::Overflow),
        "refuses, never pins and never wraps"
    );
}

/// The checked projection IS the one divisor: every in-range total reads exactly `nanos /
#[test]
fn the_minor_projection_is_the_one_divisor_or_a_refusal() {
    for nanos in [0u128, 1, 9_999_999, 10_000_000, 123_456_789, u128::MAX] {
        let expected =
            i64::try_from(nanos / NANOS_PER_CENT).map_err(|_| crate::cost::MoneyError::Overflow);
        assert_eq!(minor_nanos(nanos), expected, "{nanos} nano-units");
    }
}

/// **A FEE IS ALWAYS A FIGURE, NEVER A SILENCE** — #77(5) (`BUSBAR-1.6.0.md:420`): *"free is an
#[test]
fn a_fee_of_nothing_is_an_explicit_zero_row_and_a_named_fee_bills() {
    use crate::cost::{price_ledger, LedgerEntry};

    let slice = vec![LedgerEntry::new("m", 0)
        .with_whole(INPUT, 1_000)
        .with_fee_count(4)];

    let free = RateCard::from_micro_rates([(LaneClass::new("m", INPUT), 5.0)], 0);
    assert_eq!(free.fee(), 0);
    let priced_free = price_ledger(&slice, &History::opening(free, 0))
        .expect("an explicit zero fee row is free, not unpriced");
    assert_eq!(priced_free.to_decimal_string(), "0.005000");

    let charged = RateCard::from_micro_rates([(LaneClass::new("m", INPUT), 5.0)], 3);
    assert_eq!(charged.fee(), 3);
    let priced_fee =
        price_ledger(&slice, &History::opening(charged, 0)).expect("the card names a fee");
    assert_eq!(priced_fee.to_decimal_string(), "0.125000");

    let negative = RateCard::from_micro_rates([(LaneClass::new("m", INPUT), 5.0)], -7);
    assert_eq!(negative.fee(), 0);
    assert_eq!(RateCard::absent(-7).fee(), 0);
}

/// **BILLING OFF IS THE ONE EXEMPTION** (#42 `BUSBAR-1.6.0.md:367`: *"rate_card ABSENT ⇒ NOT billed
#[test]
fn an_absent_card_prices_tokens_at_nothing_and_still_posts_its_fee() {
    use crate::cost::{price_ledger, LedgerEntry};

    let slice = vec![LedgerEntry::new("m", 0)
        .with_whole(INPUT, 1_000)
        .with_fee_count(4)];

    let carded = RateCard::absent(0);
    assert!(!carded.pricing_enabled());
    let nothing = price_ledger(&slice, &History::opening(carded, 0))
        .expect("billing off answers zero rather than refusing");
    assert!(nothing.is_zero(), "an uncarded node bills no tokens");

    let with_fee = RateCard::absent(3);
    let fee_only = price_ledger(&slice, &History::opening(with_fee, 0))
        .expect("billing off still posts the flat fee");
    assert_eq!(fee_only.to_decimal_string(), "0.120000");
}
