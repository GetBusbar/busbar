// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The currency axis: the scale each one rounds at, that a card prices natively, and that a
//! currency a card does not name is a refusal rather than a conversion.

use super::*;
use crate::{
    micros_of, minor_of, CurrencyCode, LaneClass, RateCard, Unpriceable, NANOS_PER_CENT,
    STANDARD_TIER_BP,
};

/// A code is three ASCII letters or it is not a code. Length, digits and punctuation are all
/// refused, and case is folded, so a card cannot name `usd` and `USD` as two currencies.
#[test]
fn a_currency_code_is_three_letters_folded_to_upper_case() {
    assert_eq!(CurrencyCode::new("usd"), Some(CurrencyCode::USD));
    assert_eq!(CurrencyCode::new("USD"), Some(CurrencyCode::USD));
    assert_eq!(CurrencyCode::USD.as_str(), "USD");
    assert_eq!(CurrencyCode::new("US"), None);
    assert_eq!(CurrencyCode::new("USDD"), None);
    assert_eq!(CurrencyCode::new("US1"), None);
    assert_eq!(CurrencyCode::new(""), None);
}

/// **THE SCALES.** A dollar's minor unit is a hundredth, a yen's is the yen itself, a dinar's is a
/// thousandth, and the divisor each one projects through is ten to the ninth less its exponent.
///
/// The USD row is the load-bearing one: its divisor must be exactly the constant every 1.5.5 cent
/// projection divided by, or every figure in that release moves.
#[test]
fn the_minor_unit_scale_is_the_currency_s_and_usd_is_the_legacy_cent() {
    let ccy = |c: &str| CurrencyCode::new(c).expect("a three-letter code");
    assert_eq!(CurrencyCode::USD.minor_exponent(), 2);
    assert_eq!(CurrencyCode::USD.nanos_per_minor(), NANOS_PER_CENT);
    assert_eq!(ccy("JPY").minor_exponent(), 0);
    assert_eq!(ccy("JPY").nanos_per_minor(), 1_000_000_000);
    assert_eq!(ccy("BHD").minor_exponent(), 3);
    assert_eq!(ccy("BHD").nanos_per_minor(), 1_000_000);
    assert_eq!(ccy("CLF").minor_exponent(), 4);
    assert_eq!(ccy("CLF").nanos_per_minor(), 100_000);
    // A currency the table does not name rounds like a dollar. Truncating less can never bill more
    // than the operator configured, which is the safe direction for an unknown.
    assert_eq!(ccy("ZZZ").minor_exponent(), 2);
    assert_eq!(ccy("ZZZ").nanos_per_minor(), NANOS_PER_CENT);
}

/// **ONE TRUNCATION, AT THE CURRENCY'S OWN DIVISOR, AT THE BOUNDARY.** The same nano-unit total
/// projects to a different integer in each currency, and each one truncates toward zero exactly
/// once. A yen boundary is a billion nano-units; a fils boundary is a million.
#[test]
fn the_minor_projection_truncates_once_at_each_currency_s_boundary() {
    let ccy = |c: &str| CurrencyCode::new(c).expect("a three-letter code");
    let (jpy, bhd) = (ccy("JPY"), ccy("BHD"));

    // Just under, exactly at, and just over two of each currency's minor units.
    assert_eq!(minor_of(19_999_999, CurrencyCode::USD), 1);
    assert_eq!(minor_of(20_000_000, CurrencyCode::USD), 2);
    assert_eq!(minor_of(20_000_001, CurrencyCode::USD), 2);

    assert_eq!(minor_of(1_999_999_999, jpy), 1);
    assert_eq!(minor_of(2_000_000_000, jpy), 2);
    assert_eq!(minor_of(2_000_000_001, jpy), 2);

    assert_eq!(minor_of(1_999_999, bhd), 1);
    assert_eq!(minor_of(2_000_000, bhd), 2);
    assert_eq!(minor_of(2_000_001, bhd), 2);

    // The same total, three currencies, three answers — and no answer is derived from another.
    assert_eq!(minor_of(2_000_000_000, CurrencyCode::USD), 200);
    assert_eq!(minor_of(2_000_000_000, jpy), 2);
    assert_eq!(minor_of(2_000_000_000, bhd), 2_000);

    // The micro projection is a scale of the accumulator, not of the minor unit, so it does not
    // move with the currency — and it is still unfloored where the minor projection floors.
    assert_eq!(micros_of(2_000_000_000), 2_000_000);
    assert_eq!(minor_of(u128::MAX, jpy), i64::MAX, "saturates, never wraps");
}

/// A card prices one cell in two currencies NATIVELY: two configured integers, and the answer in
/// each is that integer times the quantity. Neither figure is the other through a rate — the rates
/// are chosen so that no plausible cross-rate could produce both.
#[test]
fn a_cell_prices_in_each_currency_natively_with_no_cross_rate() {
    let jpy = CurrencyCode::new("JPY").expect("a three-letter code");
    let mut card = RateCard::from_micro_rates([(LaneClass::new("m", INPUT), 2.0)], 3);
    card.set_rate(LaneClass::new("m", INPUT), jpy, 300.0);
    card.set_terms(jpy, busbar_contract::tariff::FeeTerms::flat(7));

    let report = usage(&[(INPUT, 1_000)]);
    let in_usd = priced_in(&card, "m", &report, 1, STANDARD_TIER_BP, CurrencyCode::USD)
        .expect("the card names USD");
    let in_jpy =
        priced_in(&card, "m", &report, 1, STANDARD_TIER_BP, jpy).expect("the card names JPY");

    // 1000 x 2000 nano-units, plus a three-cent fee at ten million nano-units a cent.
    assert_eq!(in_usd.pre_tier_nanos, 2_000_000 + 30_000_000);
    assert_eq!(in_usd.minor(), 3);
    // 1000 x 300000 nano-units, plus a seven-yen fee at a billion nano-units a yen.
    assert_eq!(in_jpy.pre_tier_nanos, 300_000_000 + 7_000_000_000);
    assert_eq!(in_jpy.minor(), 7);
    assert_eq!(in_jpy.currency, jpy);
}

/// **A CURRENCY THE CARD DOES NOT NAME IS A REFUSAL.** Never a zero — a zero would serve the
/// request for free — and never a conversion, because there is no rate in this crate that could
/// perform one.
#[test]
fn a_currency_the_card_does_not_name_refuses_rather_than_converting() {
    let eur = CurrencyCode::new("EUR").expect("a three-letter code");
    let card = RateCard::from_micro_rates([(LaneClass::new("m", INPUT), 2.0)], 3);
    assert!(card.prices_currency(CurrencyCode::USD));
    assert!(!card.prices_currency(eur));

    let report = usage(&[(INPUT, 1_000)]);
    let refused = priced_in(&card, "m", &report, 1, STANDARD_TIER_BP, eur)
        .expect_err("a card that does not name a currency cannot answer in it");
    assert_eq!(
        refused,
        Unpriceable::CurrencyNotPriced {
            card_seq: crate::HistorySeq(0),
            currency: eur,
        }
    );
}

/// The legacy cent spelling and the generalised projection are the same function at the same
/// currency. If they ever stopped being, every 1.5.5 figure would move.
#[test]
fn the_cent_projection_is_the_minor_projection_at_usd() {
    for nanos in [0u128, 1, 9_999_999, 10_000_000, 123_456_789, u128::MAX] {
        assert_eq!(crate::cents_of(nanos), minor_of(nanos, CurrencyCode::USD));
    }
}
