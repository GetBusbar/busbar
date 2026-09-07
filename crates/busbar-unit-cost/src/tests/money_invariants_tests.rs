// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The money invariants of the cost unit, stated one clause at a time.
//!
//! What is pinned here is the arithmetic nobody sees go wrong: the currency's own rounding scale,
//! the tier at the top of the range, the window boundaries a dated card is resolved across, and the
//! four independent ways a cached figure can disagree with the lookup that supersedes it.
//!
//! The cache comparison in particular is a disjunction of four clauses, and a disjunction is only
//! pinned by cases in which exactly ONE clause is true: with two clauses true at once, an `and`
//! answers the same as an `or` and the test says nothing. So each field gets a case of its own.

use crate::currency::CurrencyCode;
use crate::history::{Author, CardEntryDraft, History, HistorySeq};
use crate::posting::{apply_tier, CachedPrice, Posting, Quantity, STANDARD_TIER_BP};
use crate::project::{cents_of, micros_of, minor_of};
use crate::rate::{CellPrices, LaneClass, RateCard, TierRates};
use crate::{price, Unpriceable};

use super::{card, usage, INPUT, OUTPUT};

const LANE: &str = "lane-a";

/// A currency reads as its three letters, in a diagnostic and in a rendered figure alike.
///
/// A currency that printed nothing is a bill labelled with no currency at all, which is the one
/// thing a multi-currency deployment's invoice may not be.
#[test]
fn a_currency_reads_as_its_three_letters() {
    assert_eq!(format!("{}", CurrencyCode::USD), "USD");
    assert_eq!(format!("{:?}", CurrencyCode::USD), "USD");

    let jpy = CurrencyCode::new("jpy").expect("three ascii letters are a code");
    assert_eq!(format!("{jpy}"), "JPY", "a code folds to upper case");
    assert_eq!(format!("{jpy:?}"), "JPY");
    assert_eq!(jpy.as_str(), "JPY");
    assert_ne!(format!("{jpy}"), format!("{}", CurrencyCode::USD));
}

/// **THE ROUNDING SCALE IS THE CURRENCY'S**, and it is one truncating divide at that scale.
///
/// A yen is its own minor unit and a dinar has three decimal places. Truncating a yen figure at the
/// dollar's scale would bill a hundredth of what was earned; truncating a dinar figure at it would
/// bill ten times too much.
#[test]
fn a_total_truncates_at_its_own_currencys_minor_unit() {
    let jpy = CurrencyCode::new("JPY").expect("a code");
    let bhd = CurrencyCode::new("BHD").expect("a code");
    let clf = CurrencyCode::new("CLF").expect("a code");
    let eur = CurrencyCode::new("EUR").expect("a code");

    // One major unit, in nano-units of the major unit.
    let one_major: u128 = 1_000_000_000;
    assert_eq!(
        minor_of(one_major, CurrencyCode::USD),
        100,
        "a dollar is 100 cents"
    );
    assert_eq!(minor_of(one_major, jpy), 1, "a yen is its own minor unit");
    assert_eq!(minor_of(one_major, bhd), 1_000, "a dinar is 1000 fils");
    assert_eq!(minor_of(one_major, clf), 10_000);
    assert_eq!(
        minor_of(one_major, eur),
        100,
        "a currency the table does not name rounds like a dollar"
    );

    // The scale itself, stated: the divisor is ten to the ninth less the minor exponent.
    assert_eq!(CurrencyCode::USD.nanos_per_minor(), 10_000_000);
    assert_eq!(jpy.nanos_per_minor(), 1_000_000_000);
    assert_eq!(bhd.nanos_per_minor(), 1_000_000);
    assert_eq!(clf.nanos_per_minor(), 100_000);
    assert_eq!(CurrencyCode::USD.minor_exponent(), 2);
    assert_eq!(jpy.minor_exponent(), 0);
    assert_eq!(bhd.minor_exponent(), 3);
    assert_eq!(clf.minor_exponent(), 4);
    assert_eq!(eur.minor_exponent(), 2);
}

/// The divide TRUNCATES and never rounds up: a fractional minor unit the quantities did not reach
/// is dropped, in every currency.
#[test]
fn a_fractional_minor_unit_is_dropped_not_rounded_up() {
    let jpy = CurrencyCode::new("JPY").expect("a code");
    // One nano-unit short of a whole cent, and of a whole yen.
    assert_eq!(minor_of(9_999_999, CurrencyCode::USD), 0);
    assert_eq!(minor_of(10_000_000, CurrencyCode::USD), 1);
    assert_eq!(minor_of(19_999_999, CurrencyCode::USD), 1);
    assert_eq!(minor_of(999_999_999, jpy), 0);
    assert_eq!(minor_of(1_000_000_000, jpy), 1);
}

/// The minor projection is FLOORED at zero and the micro projection is NOT, and the difference is
/// load-bearing for the two endpoints that read them.
#[test]
fn the_minor_projection_floors_and_the_micro_projection_does_not() {
    assert_eq!(minor_of(0, CurrencyCode::USD), 0);
    assert_eq!(cents_of(0), 0);
    assert_eq!(micros_of(0), 0);

    // At the top of the range both SATURATE rather than wrapping: a figure that wrapped would land
    // negative, and the floor below would then read an over-the-top spend as free.
    assert_eq!(minor_of(u128::MAX, CurrencyCode::USD), i64::MAX);
    assert_eq!(cents_of(u128::MAX), i64::MAX);
    assert_eq!(micros_of(u128::MAX), i64::MAX);
    let jpy = CurrencyCode::new("JPY").expect("a code");
    assert_eq!(minor_of(u128::MAX, jpy), i64::MAX);
}

/// **THE TIER IS ONE MULTIPLY AND ONE DIVIDE, IN THAT ORDER.**
///
/// A sum of per-line floors undercharges: two lines of five at half price are two floors of two,
/// which is four, where the single divide over ten is five. And a tier at the top of the range
/// saturates rather than wrapping through zero.
#[test]
fn the_tier_multiplies_before_it_divides_and_saturates_at_the_top() {
    // Full price is the identity.
    assert_eq!(apply_tier(12_345, STANDARD_TIER_BP), 12_345);
    assert_eq!(STANDARD_TIER_BP, 10_000);

    // Half price over ten is five, not two floors of two.
    assert_eq!(apply_tier(10, 5_000), 5);
    assert_eq!(apply_tier(5, 5_000) + apply_tier(5, 5_000), 4);

    // A tier just under full price on a small amount does not round to nothing.
    assert_eq!(apply_tier(10_000, 9_999), 9_999);
    assert_eq!(
        apply_tier(1, 9_999),
        0,
        "and it truncates rather than rounding"
    );

    // Nothing at any tier is nothing; a tier of nothing is free.
    assert_eq!(apply_tier(0, 9_999), 0);
    assert_eq!(apply_tier(999_999, 0), 0);

    // At the ceiling the multiply saturates, so the answer pins at the top rather than wrapping
    // back down near zero — which is to say, rather than billing as free.
    assert_eq!(
        apply_tier(u128::MAX, 20_000),
        u128::MAX / u128::from(STANDARD_TIER_BP)
    );
    // A tier ABOVE full price on a figure at the ceiling still answers something enormous rather
    // than something small: a wrapping multiply would have landed near zero.
    assert!(apply_tier(u128::MAX, 20_000) > u128::from(u64::MAX));
    assert!(apply_tier(u128::MAX, u32::MAX) > u128::from(u64::MAX));
}

/// A quantity times a rate saturates rather than wrapping, and so does the running sum.
///
/// An adversarially large report pins at the top instead of landing back near zero.
#[test]
fn an_adversarial_report_pins_at_the_top_rather_than_billing_as_free() {
    let mut big =
        RateCard::from_micro_rates_in(CurrencyCode::USD, [(LaneClass::new(LANE, INPUT), 0.0)], 0);
    // A rate near the top of what a card can hold, against the largest quantity a line can carry.
    // (A rate config could not have meant reads as zero, so the figure has to be a real one.)
    big.set_rate(LaneClass::new(LANE, INPUT), CurrencyCode::USD, 1.0e16);
    let posting = Posting {
        lane: LANE.to_string(),
        quantities: vec![
            Quantity::new(INPUT, u64::MAX),
            Quantity::new(INPUT, u64::MAX),
        ],
        fee_count: u64::MAX,
        tier_bp: u32::MAX,
        arrived_ms: 0,
        arrived_mono: 0,
        estimated: false,
        cached: None,
    };
    let history = History::opening(big, 0);
    let priced = price(&history.current(), &posting, CurrencyCode::USD)
        .expect("a one-currency card prices in its own currency");

    assert!(priced.priced_nanos > 0, "a saturating total is never free");
    assert_eq!(
        priced.minor(),
        i64::MAX,
        "and it pins at the top of the display range"
    );
    assert!(
        priced.minor() >= 0,
        "a saturated total never reads as a credit"
    );
}

/// A rate that config could not have meant is read as ZERO, never as the top of the range.
///
/// Casting a float outside the target range to an integer saturates, and a saturated rate would be
/// an astronomical overcharge rather than the intended defence.
#[test]
fn a_rate_config_could_not_have_meant_is_read_as_nothing() {
    use crate::rate::nano_rate;
    assert_eq!(nano_rate(1.0), 1_000);
    assert_eq!(nano_rate(0.0005), 1, "half a thousandth rounds to one");
    assert_eq!(nano_rate(0.0004), 0, "and less than half rounds to none");
    assert_eq!(nano_rate(0.0), 0);
    assert_eq!(
        nano_rate(-1.0),
        0,
        "a negative rate is refused, not negated"
    );
    assert_eq!(nano_rate(f64::INFINITY), 0);
    assert_eq!(nano_rate(f64::NAN), 0);
    assert_eq!(
        nano_rate(f64::MAX),
        0,
        "a config typo with too many zeros is not a rate"
    );
}

/// **THE FEE IS COUNTED PER BILLABLE REQUEST**, and a posting that carries none pays none.
///
/// The fee is a usage line like any other, so its amount is its count times its unit price and it
/// joins the sum before the single truncation.
#[test]
fn the_fee_is_charged_once_per_billable_request_and_never_otherwise() {
    // Five cents a request, and no token rates at all.
    let priced_card = card(LANE, 0.0, 0.0, 5);
    let history = History::opening(priced_card, 0);
    let view = history.current();

    let fee_only = |fee_count: u64| {
        let posting = Posting::from_usage(
            LANE,
            &usage(&[(INPUT, 0)]),
            fee_count,
            STANDARD_TIER_BP,
            0,
            0,
        );
        price(&view, &posting, CurrencyCode::USD)
            .expect("a one-currency card prices in its own currency")
    };

    assert_eq!(fee_only(0).minor(), 0, "no billable request, no fee");
    assert_eq!(fee_only(1).minor(), 5);
    assert_eq!(fee_only(3).minor(), 15);
    assert_eq!(fee_only(3).fee_count, 3);

    // The fee line is the last line, named, and priced at an exact multiple of one minor unit.
    let answer = fee_only(2);
    let fee_line = answer.lines.last().expect("the fee line is always there");
    assert_eq!(fee_line.class, crate::posting::FEE_CLASS);
    assert_eq!(fee_line.quantity, 2);
    assert_eq!(fee_line.unit_price_nanos, 5 * 10_000_000);
    assert_eq!(fee_line.amount_nanos, 2 * 5 * 10_000_000);
    assert!(!fee_line.unpriced, "the fee is never an unpriced line");
}

/// A configured fee is CLAMPED at zero: no request may bill a negative amount.
#[test]
fn a_negative_configured_fee_is_clamped_and_never_credits_a_budget() {
    assert_eq!(RateCard::absent(-500).per_request_fee(CurrencyCode::USD), 0);
    assert_eq!(
        RateCard::from_micro_rates([(LaneClass::new(LANE, INPUT), 1.0)], -500)
            .per_request_fee(CurrencyCode::USD),
        0
    );
    let mut card = RateCard::absent(0);
    card.set_fee(CurrencyCode::USD, -1);
    assert_eq!(card.per_request_fee(CurrencyCode::USD), 0);
    assert_eq!(card.fee_unit_price_nanos(CurrencyCode::USD), 0);

    // And a positive fee lifts to nano-units by the currency's own scale.
    card.set_fee(CurrencyCode::USD, 7);
    assert_eq!(card.fee_unit_price_nanos(CurrencyCode::USD), 70_000_000);
    let jpy = CurrencyCode::new("JPY").expect("a code");
    card.set_fee(jpy, 7);
    assert_eq!(card.fee_unit_price_nanos(jpy), 7_000_000_000);
}

/// **A CARD IS RESOLVED AT EXACTLY THE EFFECTIVE INSTANT**: `from` is inclusive, `until` exclusive.
///
/// One millisecond either side of a boundary is a different card and therefore a different bill,
/// so both edges are stated rather than one.
#[test]
fn a_card_is_in_force_from_its_first_instant_and_not_at_its_last() {
    let mut history = History::new();
    // The first card prices instants [1000, 2000); the second from 2000, open-ended.
    let first = history.append(CardEntryDraft {
        effective_from: 1_000,
        effective_until: Some(2_000),
        card: card(LANE, 1.0, 1.0, 0),
        appended_at: 1_000,
        author: Author::Opening,
    });
    let second = history.append(CardEntryDraft {
        effective_from: 2_000,
        effective_until: None,
        card: card(LANE, 2.0, 2.0, 0),
        appended_at: 2_000,
        author: Author::Config { policy_epoch: 1 },
    });
    let view = history.current();

    assert!(
        view.card_at(999).is_none(),
        "before the first instant is a hole"
    );
    assert_eq!(
        view.card_at(1_000).map(|(s, _)| s),
        Some(first),
        "the first instant is inside"
    );
    assert_eq!(
        view.card_at(1_999).map(|(s, _)| s),
        Some(first),
        "the last instant is inside"
    );
    assert_eq!(
        view.card_at(2_000).map(|(s, _)| s),
        Some(second),
        "the closing instant belongs to the next entry, not this one"
    );
    assert_eq!(view.card_at(u64::MAX).map(|(s, _)| s), Some(second));

    // The entry itself answers with the window it was appended with, both halves.
    let entry = view.entry_at(1_500).expect("an entry covers this instant");
    assert_eq!(entry.seq(), first);
    assert_eq!(entry.effective_from(), 1_000);
    assert_eq!(entry.effective_until(), Some(2_000));
    assert_eq!(entry.appended_at(), 1_000);
    assert!(entry.covers(1_000) && entry.covers(1_999));
    assert!(!entry.covers(999) && !entry.covers(2_000));

    let open_ended = view
        .entry_at(9_999)
        .expect("an open-ended entry covers everything after it");
    assert_eq!(open_ended.seq(), second);
    assert_eq!(
        open_ended.effective_until(),
        None,
        "open-ended is not a closed window"
    );
    assert!(open_ended.covers(u64::MAX));
    assert_eq!(open_ended.author(), &Author::Config { policy_epoch: 1 });
}

/// A hole in the record is a REFUSAL and never a zero. Pricing a gap as free is how a node serves
/// value for nothing across an amendment it has not made yet.
#[test]
fn a_hole_in_the_record_refuses_rather_than_pricing_at_nothing() {
    let mut history = History::new();
    history.append(CardEntryDraft {
        effective_from: 1_000,
        effective_until: None,
        card: card(LANE, 1.0, 1.0, 0),
        appended_at: 1_000,
        author: Author::Opening,
    });
    let posting = Posting::from_usage(LANE, &usage(&[(INPUT, 10)]), 1, STANDARD_TIER_BP, 500, 500);
    assert_eq!(
        price(&history.current(), &posting, CurrencyCode::USD),
        Err(Unpriceable::NoCardInForce { at: 500 })
    );

    // An empty history is a hole at every instant, and it says so.
    let empty = History::new();
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert_eq!(
        empty.head(),
        None,
        "an empty history has no head, not head zero"
    );
    assert!(empty.current().is_empty());
    assert!(empty.current().entry_at(0).is_none());
}

/// A history with entries in it is NOT empty, and its head is the newest entry's own number.
///
/// The pair matters: a predicate frozen at "empty" would let a caller read a real card history as a
/// deployment that has read no configuration.
#[test]
fn a_history_with_entries_is_not_empty_and_names_its_head() {
    let history = History::opening(card(LANE, 1.0, 1.0, 0), 42);
    assert!(!history.is_empty());
    assert_eq!(history.len(), 1);
    assert_eq!(history.head(), Some(HistorySeq::OPENING));
    assert!(!history.current().is_empty());
    assert_eq!(history.current().entries().len(), 1);
    assert!(history.current().entry_at(0).is_some());
    assert_eq!(history.entries()[0].appended_at(), 42);
    assert_eq!(history.entries()[0].author(), &Author::Opening);
    assert_eq!(history.entries()[0].effective_from(), 0);
    assert_eq!(history.entries()[0].effective_until(), None);
}

/// An entry's number is the number the journal, the marker and the store all spell.
///
/// It is the card's whole identity, so a `get` that answered a constant would name one card for
/// every entry in the history — and an invoice would be re-derivable against the wrong one.
#[test]
fn an_entry_number_is_the_number_it_was_assigned() {
    let mut history = History::new();
    for at in 0..5u64 {
        let seq = history.append(CardEntryDraft {
            effective_from: at * 100,
            effective_until: None,
            card: card(LANE, 1.0, 1.0, 0),
            appended_at: at * 100,
            author: Author::Opening,
        });
        assert_eq!(seq.get(), at, "the number is dense and monotone");
        assert_eq!(seq, HistorySeq(at));
        assert_eq!(seq.to_string(), at.to_string());
    }
    assert_eq!(HistorySeq::OPENING.get(), 0);
    assert_eq!(HistorySeq(7).get(), 7);
    assert_eq!(HistorySeq(7).to_string(), "7");
    assert_ne!(HistorySeq(7).get(), HistorySeq(8).get());
}

/// **THE AMENDMENT OUT-RANKS THE ENTRY IT CORRECTS**, and the older snapshot still answers with the
/// older card.
#[test]
fn an_amendment_out_ranks_what_it_corrects_without_rewriting_it() {
    let mut history = History::new();
    let original = history.append(CardEntryDraft {
        effective_from: 0,
        effective_until: None,
        card: card(LANE, 1.0, 1.0, 0),
        appended_at: 0,
        author: Author::Opening,
    });
    // A back-dated amendment: written later, effective from an instant already covered.
    let amendment = history.append(CardEntryDraft {
        effective_from: 0,
        effective_until: None,
        card: card(LANE, 2.0, 2.0, 0),
        appended_at: 9_000,
        author: Author::Amend {
            operator_fingerprint: "op".to_string(),
            reason_hash: [3u8; 32],
        },
    });

    assert_eq!(
        history.current().card_at(1_000).map(|(s, _)| s),
        Some(amendment)
    );
    assert_eq!(
        history.snapshot(original).card_at(1_000).map(|(s, _)| s),
        Some(original),
        "an older snapshot still answers with the older card"
    );
    // The back-date is visible: written at 9000, effective from 0.
    let current = history.current();
    let entry = current.entry_at(0).expect("an entry covers zero");
    assert_eq!(entry.appended_at(), 9_000);
    assert_eq!(entry.effective_from(), 0);
    assert_ne!(entry.appended_at(), entry.effective_from());
    // A snapshot above the head sees the whole history rather than refusing.
    assert_eq!(history.snapshot(HistorySeq(99)).entries().len(), 2);
    assert_eq!(history.snapshot(HistorySeq(99)).seq(), HistorySeq(99));
}

/// A card names the currencies it was priced in, and a cell names the ones IT was priced in.
///
/// A card that named no currency at all would refuse every request, and one whose list did not
/// track its rates would answer for a currency it cannot price.
#[test]
fn a_card_and_a_cell_name_the_currencies_they_price() {
    let jpy = CurrencyCode::new("JPY").expect("a code");
    let mut card =
        RateCard::from_micro_rates_in(CurrencyCode::USD, [(LaneClass::new(LANE, INPUT), 2.0)], 1);
    assert_eq!(
        card.currencies().collect::<Vec<_>>(),
        vec![CurrencyCode::USD]
    );
    assert!(card.prices_currency(CurrencyCode::USD));
    assert!(!card.prices_currency(jpy));

    card.set_rate(LaneClass::new(LANE, INPUT), jpy, 300.0);
    let named: Vec<_> = card.currencies().collect();
    assert_eq!(named.len(), 2);
    assert!(named.contains(&CurrencyCode::USD) && named.contains(&jpy));
    assert!(card.prices_currency(jpy));

    // A cell is priced natively per currency: no pivot, no derived rate.
    let mut cell = CellPrices::single(CurrencyCode::USD, 2_000);
    assert_eq!(cell.nanos_per_unit(CurrencyCode::USD), Some(2_000));
    assert_eq!(
        cell.nanos_per_unit(jpy),
        None,
        "an unpriced currency is a refusal, not a zero"
    );
    assert_eq!(
        cell.currencies().collect::<Vec<_>>(),
        vec![CurrencyCode::USD]
    );
    assert_ne!(cell, CellPrices::default());
    cell.set(jpy, 300_000);
    assert_eq!(cell.currencies().count(), 2);
    assert_eq!(cell.nanos_per_unit(jpy), Some(300_000));
}

/// A currency the card does not name is REFUSED. There is no cross-rate here and never was.
#[test]
fn a_currency_the_card_does_not_name_is_refused_not_converted() {
    let jpy = CurrencyCode::new("JPY").expect("a code");
    let history = History::opening(card(LANE, 1.0, 1.0, 0), 0);
    let posting = Posting::from_usage(LANE, &usage(&[(INPUT, 10)]), 1, STANDARD_TIER_BP, 0, 0);
    assert_eq!(
        price(&history.current(), &posting, jpy),
        Err(Unpriceable::CurrencyNotPriced {
            card_seq: HistorySeq::OPENING,
            currency: jpy,
        })
    );
}

/// The four configured tier rates land on the four classes they price, in that order.
///
/// A card keyed by names the usage report does not use prices every line at zero, which the ledger
/// identity reads as a node that delivered value for free.
#[test]
fn the_configured_tier_rates_land_on_the_classes_they_price() {
    let card = RateCard::from_config(
        Some([(
            LANE,
            TierRates {
                input: 1.0,
                output: 2.0,
                cache_read: 3.0,
                cache_write: 4.0,
            },
        )]),
        0,
    );
    let rates = card
        .lane_rates(LANE, CurrencyCode::USD)
        .expect("the card names this lane");
    assert_eq!(rates.nanos_per_unit(crate::rate::CLASS_INPUT), 1_000);
    assert_eq!(rates.nanos_per_unit(crate::rate::CLASS_OUTPUT), 2_000);
    assert_eq!(rates.nanos_per_unit(crate::rate::CLASS_CACHE_READ), 3_000);
    assert_eq!(rates.nanos_per_unit(crate::rate::CLASS_CACHE_WRITE), 4_000);
    assert_eq!(rates.currency(), CurrencyCode::USD);
    assert!(card.pricing_enabled());

    // Four distinct rates on four distinct names: a fan-out that collapsed them would agree with
    // itself and with nothing else.
    let all = [
        rates.nanos_per_unit(crate::rate::CLASS_INPUT),
        rates.nanos_per_unit(crate::rate::CLASS_OUTPUT),
        rates.nanos_per_unit(crate::rate::CLASS_CACHE_READ),
        rates.nanos_per_unit(crate::rate::CLASS_CACHE_WRITE),
    ];
    assert_eq!(all.len(), 4);
    assert!(all.windows(2).all(|w| w[0] != w[1]));

    // No card configured at all is an ABSENT card, not the absence of one: the fee still posts.
    let none = RateCard::from_config(None::<Vec<(&str, TierRates)>>, 9);
    assert!(!none.pricing_enabled());
    assert_eq!(none.per_request_fee(CurrencyCode::USD), 9);
    assert!(
        !none.lane_unpriced("anything"),
        "nothing is missing from a card that is not there"
    );
}

/// **A CACHED FIGURE IS NEVER A BILL**, and it diverges on ANY ONE of the four things it records.
///
/// Each case moves exactly one field. With two fields moved at once a conjunction answers the same
/// as a disjunction, and the case would pin nothing.
#[test]
fn a_cache_diverges_on_any_one_of_the_four_fields_alone() {
    let jpy = CurrencyCode::new("JPY").expect("a code");
    let history = History::opening(card(LANE, 1.0, 1.0, 3), 0);
    let mut posting = Posting::from_usage(LANE, &usage(&[(INPUT, 10)]), 1, STANDARD_TIER_BP, 0, 0);
    let answer = price(&history.current(), &posting, CurrencyCode::USD)
        .expect("a one-currency card prices in its own currency");
    let agreeing = answer.as_cache(HistorySeq::OPENING);

    // A posting with no cache never disagrees; a cache that matches never disagrees.
    assert!(!posting.cache_diverges(&answer));
    posting.cached = Some(agreeing);
    assert!(!posting.cache_diverges(&answer));

    // The currency alone.
    posting.cached = Some(CachedPrice {
        currency: jpy,
        ..agreeing
    });
    assert!(
        posting.cache_diverges(&answer),
        "a cache in another currency is not this answer"
    );

    // The card entry alone.
    posting.cached = Some(CachedPrice {
        card_seq: HistorySeq(7),
        ..agreeing
    });
    assert!(
        posting.cache_diverges(&answer),
        "a cache against another card is not this answer"
    );

    // The pre-tier sum alone.
    posting.cached = Some(CachedPrice {
        pre_tier_nanos: agreeing.pre_tier_nanos + 1,
        ..agreeing
    });
    assert!(
        posting.cache_diverges(&answer),
        "a cache whose pre-tier sum moved is stale"
    );

    // The priced figure alone — the one that moves money.
    posting.cached = Some(CachedPrice {
        priced_nanos: agreeing.priced_nanos + 1,
        ..agreeing
    });
    assert!(
        posting.cache_diverges(&answer),
        "a cache whose charge moved is stale"
    );

    // And the figure a reader must use is the lookup's, whatever the cache says.
    posting.cached = Some(CachedPrice {
        priced_nanos: 0,
        pre_tier_nanos: 0,
        ..agreeing
    });
    assert_eq!(
        posting
            .priced_nanos(&history.current(), CurrencyCode::USD)
            .expect("the lookup answers"),
        answer.priced_nanos,
        "a corrupted cache cannot become a bill"
    );
    assert!(answer.priced_nanos > 0);
}

/// The cache a lookup would be stored as names the snapshot it was computed against.
#[test]
fn a_stored_cache_names_the_snapshot_it_was_computed_against() {
    let history = History::opening(card(LANE, 1.0, 2.0, 1), 0);
    let posting = Posting::from_usage(
        LANE,
        &usage(&[(INPUT, 4), (OUTPUT, 2)]),
        1,
        STANDARD_TIER_BP,
        0,
        0,
    );
    let answer = price(&history.current(), &posting, CurrencyCode::USD)
        .expect("a one-currency card prices in its own currency");
    let cache = answer.as_cache(HistorySeq(3));

    assert_eq!(cache.history_seq, HistorySeq(3));
    assert_eq!(cache.card_seq, answer.card_seq);
    assert_eq!(cache.currency, answer.currency);
    assert_eq!(cache.pre_tier_nanos, answer.pre_tier_nanos);
    assert_eq!(cache.priced_nanos, answer.priced_nanos);
    // Four units at one micro, two at two micros, plus a one-cent fee, all before the truncation.
    assert_eq!(answer.pre_tier_nanos, 4 * 1_000 + 2 * 2_000 + 10_000_000);
    assert_eq!(answer.minor(), 1);
}
