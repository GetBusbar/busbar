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
    card.set_fee(jpy, 7);

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

/// **PRESENT BUT UNPRICED IS NEVER A SILENT ZERO** — the flat fee's half of the rule the lane has
/// obeyed since there was a lane.
///
/// A card can name a currency for its RATES and stay silent about the flat fee in that same
/// currency: [`RateCard::set_rate`] records the currency, [`RateCard::set_fee`] records the fee, and
/// nothing obliges a caller to do both. Such a card passes [`RateCard::prices_currency`], so the
/// currency guard upstream lets the request through, and the fee is then read out of a map that does
/// not hold it. Read as a zero, every request bills its fees at nothing and says nothing about it:
/// silent under-billing, which is the one outcome this crate refuses everywhere else. A lane a
/// present card does not name refuses; a currency a present card names no fee in must refuse in the
/// SAME shape — visible on the line for a read, an [`Unpriceable`] for settlement.
#[test]
fn a_fee_currency_the_card_is_silent_about_is_never_a_silent_zero() {
    let eur = CurrencyCode::new("EUR").expect("a three-letter code");
    // Priced in EUR for the lane; silent in EUR for the fee.
    let mut card = RateCard::from_micro_rates([(LaneClass::new("m", INPUT), 2.0)], 3);
    card.set_rate(LaneClass::new("m", INPUT), eur, 5.0);

    // The card NAMES the currency, so the currency refusal does not catch this one.
    assert!(card.prices_currency(eur));
    // …and the fee in it is a silence rather than a figure. `None` is not zero and never becomes it.
    assert_eq!(card.fee_for(CurrencyCode::USD), Some(3));
    assert_eq!(card.fee_for(eur), None);
    assert!(card.fee_unpriced(eur));
    assert!(!card.fee_unpriced(CurrencyCode::USD));
    assert_eq!(card.fee_unit_price_nanos(eur), None);

    // THE READ POSTURE prices the fee at nothing and SAYS SO, exactly as it does for a class the
    // card is silent about: never a silent nothing, always a visible one.
    let report = usage(&[(INPUT, 1_000)]);
    let read = priced_in(&card, "m", &report, 4, STANDARD_TIER_BP, eur)
        .expect("a read reports the silence per line rather than refusing");
    assert!(read.fee_unpriced);
    let fee_line = read
        .lines
        .iter()
        .find(|l| l.class == crate::FEE_CLASS)
        .expect("the fee is a line of the answer, not a scalar");
    assert!(fee_line.unpriced);
    assert_eq!(fee_line.quantity, 4);
    assert_eq!(fee_line.amount_nanos, 0);
    assert!(read.unpriced_classes().contains(&crate::FEE_CLASS));
    // Four fees at a silence contribute nothing, so the whole answer is the lane's tokens: the
    // figure a caller that ignored the flag would post as a bill.
    assert_eq!(read.pre_tier_nanos, 5_000_000);

    // THE SETTLEMENT POSTURE REFUSES, in the same family and the same shape an unpriced lane
    // refuses in. This is the assertion that stops the node billing four fees at zero in silence.
    let history = crate::History::opening(card.clone(), 0);
    let posting = crate::Posting::from_usage("m", &report, 4, STANDARD_TIER_BP, 0, 0);
    let refused = crate::price_fail_closed(&history.current(), &posting, eur)
        .expect_err("a fee the card is silent about is a refusal, not a free request");
    assert_eq!(
        refused,
        Unpriceable::FeeUnpriced {
            card_seq: crate::HistorySeq(0),
            currency: eur,
        }
    );

    // The currency the card DOES name a fee in is untouched by any of this.
    let usd = priced_in(&card, "m", &report, 4, STANDARD_TIER_BP, CurrencyCode::USD)
        .expect("the card names a fee in USD");
    assert!(!usd.fee_unpriced);
    assert_eq!(usd.pre_tier_nanos, 2_000_000 + 4 * 30_000_000);
}
