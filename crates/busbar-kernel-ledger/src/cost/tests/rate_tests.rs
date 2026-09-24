// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Clause one and clause four: the single conversion from a configured decimal to an integer rate,
//! and the pin that makes a posting immune to a later card edit.

use super::*;
use crate::cost::{
    nano_rate, price, Author, CardEntryDraft, History, HistorySeq, LaneClass, Posting, RateCard,
    STANDARD_TIER_BP,
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

/// **THE BOUNDARY IS `2^64`, AND `u64::MAX as f64` IS NOT IT.**
///
/// `u64::MAX` is `2^64 - 1`: an odd integer sixty-four bits wide. An `f64` carries a fifty-three bit
/// mantissa, so that value is NOT REPRESENTABLE and `u64::MAX as f64` rounds — UP — to exactly
/// `2^64`. A guard spelled `v <= u64::MAX as f64` therefore admits a finite `v == 2^64`, which is
/// one past the largest integer a `u64` holds, and the `v as u64` beneath it SATURATES to
/// `u64::MAX`. That is the astronomical overcharge the doc on [`nano_rate`] promises this function
/// never produces, arriving at the single input the guard exists to stop. There is exactly ONE
/// `f64` in the gap the wrong spelling opens, and this test is standing on it.
///
/// It is reachable from operator config, not just from a unit test: `RateCard::from_micro_rates_in`
/// and `set_rate` both convert a configured decimal through here, so a card quoting `2^64 / 1000`
/// micro-units per unit is the whole of it.
///
/// WHY THIS SURVIVED, which is the more useful half. The test that NAMES this case
/// ([`nano_rate_clamps_a_finite_but_overflowing_rate_to_zero_not_the_maximum`], above) feeds `1e18`
/// — whose `×1000` is `1e21`, some thirty doublings past the ceiling — and so steps clean over the
/// one point that fails. A case that is merely far outside the range does not test a boundary; only
/// a case ON the boundary does.
///
/// This is a correction to the guard's own stated contract and nothing more. It does not settle what
/// an out-of-range configured rate OUGHT to do — #42 rules that an unpriced class REFUSES rather
/// than silently answering zero, so neither `u64::MAX` nor `0` is the ruled answer, and the finding
/// that says so (U-1) stays open.
#[test]
fn nano_rate_refuses_the_one_value_past_the_ceiling_that_the_max_cast_admits() {
    // The premise, asserted rather than trusted: the cast rounds UP, past what it names.
    assert_eq!(
        u64::MAX as f64,
        2.0_f64.powi(64),
        "u64::MAX as f64 rounds up to 2^64 — the whole defect is this one step"
    );

    // The admitted micro-rate: the value whose ×1000 lands exactly on 2^64. This is, character for
    // character, the `CEILING_MICRO` the cross-crate agreement test has been feeding both copies.
    let admitted_micro = (u64::MAX as f64) / 1000.0;
    assert_eq!(
        (admitted_micro * 1000.0).round(),
        2.0_f64.powi(64),
        "this case proves nothing unless it lands exactly on 2^64"
    );
    assert_eq!(
        nano_rate(admitted_micro),
        0,
        "a rate of 2^64 nano-units is one past what a u64 holds: it must price at NOTHING, \
         not saturate to u64::MAX ({})",
        u64::MAX
    );

    // BYTE-NEUTRALITY AT THE SAME EDGE. The correction moves exactly one f64 and no other. The
    // largest value the conversion could ever legitimately return is still returned: 2^64 - 2048 is
    // the last f64 below the ceiling, and a rate a whisker under the top must convert, not fall to
    // zero along with the one past it.
    let last_below = f64::from_bits(2.0_f64.powi(64).to_bits() - 1);
    assert_eq!(
        last_below, 18_446_744_073_709_549_568.0,
        "the last f64 strictly below 2^64 is 2^64 - 2048"
    );
    let near_ceiling_micro = last_below / 1000.0;
    assert_eq!(
        nano_rate(near_ceiling_micro),
        18_446_744_073_709_547_520,
        "a rate just under the ceiling still converts — the correction narrows the door by one \
         value, it does not close it"
    );
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
    let none = RateCard::absent(3);
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
    let c = RateCard::absent(-5);
    assert_eq!(c.fee(), 0);
    assert_eq!(c.fee_unit_price_nanos(), 0);
    // A fee CONFIGURED at nothing is a PRICED nothing — #77(5)'s explicit zero row. Since #66 a
    // card carries exactly one fee and every constructor sets it, so there is no longer a silence
    // this could be confused with: the absent key that used to be readable as zero is gone.
    let mut set = RateCard::absent(9);
    set.set_fee(-1);
    assert_eq!(set.fee(), 0, "`set_fee` clamps through the same gate");
}

/// The fee's unit price is its cents lifted to nano-units — an exact multiple of ten million,
/// which is what makes summing it in before the single truncation give the same cents as adding it
/// afterwards.
#[test]
fn fee_line_unit_price_is_cents_lifted_to_nano_units() {
    let c = RateCard::absent(3);
    assert_eq!(c.fee_unit_price_nanos(), 30_000_000);
    assert_eq!(c.fee_unit_price_nanos() % crate::cost::NANOS_PER_CENT, 0);
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
    let before = Posting::from_usage("m", &report, 0, STANDARD_TIER_BP, 4_999, 4_999);
    let after = Posting::from_usage("m", &report, 0, STANDARD_TIER_BP, 5_000, 5_000);

    let view = history.current();
    let earlier = price(&view, &before).expect("entry zero covers it");
    let later = price(&view, &after).expect("entry one covers it");
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
        price(&at_zero, &after)
            .expect("entry zero is open-ended")
            .minor(),
        1000,
        "a snapshot taken before the edit cannot see the edit"
    );
}

/// ITEM 22: A RATE THE CARD CANNOT HOLD IS NOT A RATE OF ZERO.
///
/// `0.0004` micro-units a unit is below the half-nano-unit quantum; `$0.10/GB` priced per byte is
/// `0.00009313`. `nano_rate` maps both to `0` (it has no error channel), and the card used to record
/// that `0` as a PRICED cell — so the class billed as nothing while the card claimed to price it, and
/// #42's refusal could never fire. The card now records it UNPRICED: the lane is named, the class is
/// silent, the one function REFUSES a hit on it, and the cell is listed for boot validation.
#[test]
fn a_sub_quantum_rate_is_unpriced_on_the_card_and_refuses_never_priced_at_zero() {
    let per_byte = 0.10 * 1_000_000.0 / 1_073_741_824.0; // $0.10/GB in micro-units a byte
    let card = RateCard::from_micro_rates(
        [
            (LaneClass::new("m", "bytes"), per_byte),
            (LaneClass::new("m", "tiny"), 0.0004),
            (LaneClass::new("m", "output"), 2.0),
            (LaneClass::new("m", "free"), 0.0),
        ],
        0,
    );
    let rates = card.lane_rates("m").expect("the lane is named");
    assert!(
        !rates.class_priced("bytes"),
        "never priced-at-zero while claiming priced"
    );
    assert!(!rates.class_priced("tiny"));
    assert!(rates.class_priced("output"));
    assert!(
        rates.class_priced("free"),
        "a rate CONFIGURED at zero is the explicit zero row (#77(5)), not a refusal"
    );
    assert_eq!(
        card.refused_cells(),
        &[LaneClass::new("m", "bytes"), LaneClass::new("m", "tiny")]
    );

    // The one function refuses a hit on the unrepresentable class instead of pricing it at zero.
    let history = History::opening(card, 0);
    let one = crate::cost::price_ledger(
        &[crate::cost::LedgerEntry::new("m", 0)
            .with_whole("output", 10)
            .with_whole("bytes", 1_000_000_000)],
        &history,
    );
    assert!(
        matches!(one, Err(crate::cost::MoneyError::ClassUnpriced { ref class, .. }) if class == "bytes"),
        "#42: a hit class the card cannot price REFUSES; got {one:?}"
    );

    // And a representable rate is byte-identical to the quantisation it always had (#44).
    assert_eq!(crate::cost::representable_nano_rate(0.0005), Some(1));
    assert_eq!(crate::cost::representable_nano_rate(0.0015), Some(2));
    assert_eq!(crate::cost::representable_nano_rate(0.0004), None);
    assert_eq!(crate::cost::representable_nano_rate(0.0), Some(0));
    assert_eq!(crate::cost::representable_nano_rate(f64::MAX), None);
}
