// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Clause one and clause four: the single conversion from a configured decimal to an integer rate,
//! and the pin that makes a posting immune to a later card edit.

use super::*;
use crate::{
    nano_rate, price, Author, CardEntryDraft, CurrencyCode, History, HistorySeq, LaneClass,
    Posting, RateCard, STANDARD_TIER_BP,
};

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

/// A finite value can still be too large for a `u64` to hold — a config typo with too many zeros,
/// not an infinity. The bare cast saturates just as it would for an infinite input: a garbage
/// billing rate at the top of the range rather than the zero the doc promises for a value nobody
/// can price. Finite-but-overflowing must clamp to zero exactly like the non-finite case, not slip
/// through because `is_finite()` alone said yes.
#[test]
fn nano_rate_clamps_a_finite_but_overflowing_rate_to_zero_not_the_maximum() {
    // 1e18 micro-units per unit, times a thousand, is 1e21 — finite, and far past `u64::MAX`
    // (~1.8e19).
    assert_eq!(nano_rate(1e18), 0);
    // Comfortably inside range still converts normally: the clamp must not swallow legitimate
    // large-but-representable rates.
    assert_eq!(nano_rate(1e12), 1_000_000_000_000_000);
}

/// The card carries the integer rates straight through, per class, with no swapping between them.
#[test]
fn card_carries_integer_rates_per_class() {
    let c = card4("quad", [1.0, 2.0, 0.5, 4.0], 0);
    let r = c
        .lane_rates("quad", CurrencyCode::USD)
        .expect("the lane is priced");
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
    let none = RateCard::absent(3);
    assert!(!none.pricing_enabled());
    assert!(
        !none.lane_unpriced("anything"),
        "with no card there is nothing to be missing from"
    );
    let view = none
        .lane_rates("anything", CurrencyCode::USD)
        .expect("a zero-rate view");
    assert_eq!(view.nanos_per_unit(INPUT), 0);

    let present = card("known", 1.0, 1.0, 0);
    assert!(present.pricing_enabled());
    assert!(!present.lane_unpriced("known"));
    assert!(present.lane_unpriced("mystery"));
    assert!(present.lane_rates("mystery", CurrencyCode::USD).is_none());
}

/// A negative configured fee clamps to nothing at resolve. No request may bill a negative amount,
/// which would credit a budget bucket back toward headroom.
#[test]
fn negative_per_request_fee_clamps_to_zero() {
    let c = RateCard::absent(-5);
    let t = c.fee_terms(CurrencyCode::USD).expect("the card names USD");
    assert_eq!((t.transaction, t.entry), (0, 0));
}

/// The fee is charged in MINOR UNITS and lifted to nano-units once, at the pricing site — so every
/// fee amount is an exact multiple of ten million nano-units, which is what makes summing it in
/// before the single truncation give the same cents as adding it afterwards.
#[test]
fn a_fee_amount_is_an_exact_multiple_of_one_minor_unit() {
    let c = RateCard::absent(3);
    let priced = crate::tests::priced(
        &c,
        "m",
        &crate::tests::usage(&[]),
        1,
        crate::STANDARD_TIER_BP,
    );
    assert_eq!(priced.pre_tier_nanos, 30_000_000);
    assert_eq!(priced.pre_tier_nanos % crate::NANOS_PER_CENT, 0);
}

/// **AN EDIT PRICES WHAT HAPPENS AFTER IT, NOT WHAT HAPPENED BEFORE IT.**
///
/// The card that used to be pinned for the life of a hold is now an entry of the history, and the
/// pin is the instant the unit arrived. An operator who halves a rate appends a second entry
/// effective from the moment of the edit; the unit that arrived before it still resolves to entry
/// zero and still prices at the old rate, at every snapshot, forever. That is the whole of the
/// behaviour change registered for this release, stated as one case.
#[test]
fn an_appended_entry_prices_later_instants_and_moves_nothing_earlier() {
    let at_boot = RateCard::from_micro_rates([(LaneClass::new("m", INPUT), 10.0)], 0);
    let corrected = RateCard::from_micro_rates([(LaneClass::new("m", INPUT), 5.0)], 0);

    let mut history = History::opening(at_boot, 0);
    assert_eq!(history.head(), Some(HistorySeq(0)));
    let second = history.append(CardEntryDraft {
        effective_from: 5_000,
        effective_until: None,
        card: corrected,
        appended_at: 5_000,
        author: Author::Config { policy_epoch: 1 },
    });
    assert_eq!(
        second,
        HistorySeq(1),
        "the seq is dense and assigned on append"
    );

    let report = usage(&[(INPUT, 1_000_000)]);
    let before = Posting::from_usage("m", &report, 0, 0, STANDARD_TIER_BP, 4_999, 4_999);
    let after = Posting::from_usage("m", &report, 0, 0, STANDARD_TIER_BP, 5_000, 5_000);

    let view = history.current();
    let earlier = price(&view, &before, CurrencyCode::USD).expect("entry zero covers it");
    let later = price(&view, &after, CurrencyCode::USD).expect("entry one covers it");
    assert_eq!(earlier.card_seq, HistorySeq(0));
    assert_eq!(
        earlier.minor(),
        1000,
        "the unit that arrived first did not move"
    );
    assert_eq!(later.card_seq, HistorySeq(1));
    assert_eq!(
        later.minor(),
        500,
        "the unit that arrived after pays the new rate"
    );

    // And the older snapshot still answers the older way for BOTH instants, which is what makes an
    // invoice cut against it reproducible.
    let at_zero = history.snapshot(HistorySeq(0));
    assert_eq!(
        price(&at_zero, &after, CurrencyCode::USD)
            .expect("entry zero is open-ended")
            .minor(),
        1000,
        "a snapshot taken before the edit cannot see the edit"
    );
}
