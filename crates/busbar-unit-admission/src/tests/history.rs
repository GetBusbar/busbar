// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door against a dated rate-card history.
//!
//! Every case here is one of two claims. **The card in force THEN**: a hold is sized from the
//! snapshot the root pinned at admission, resolved at the unit's own arrival instant, and an entry
//! appended after that pin cannot move it. **Sizing is accounting, never a second door**: no arm of
//! it refuses, no arm converts a currency, and a reservation that turns out too small tops up or
//! overdrafts rather than failing a request the decision admitted.

use busbar_caps::{step::Admit, AdmitToken, Hold, KernelSeal, PrincipalId};
use busbar_unit_cost::{
    price_at_card, Author, CardEntryDraft, CurrencyCode, History, HistorySeq, LaneClass, RateCard,
};

use super::*;
use crate::estimate::{HoldContext, HoldPosture};
use crate::{ClassEstimate, Estimate};

const LANE: &str = "gpt-4";
const OTHER_LANE: &str = "gpt-4-mini";
const CLASS: &str = "input";

/// The instant the opening entry is sealed at, and the instant a mid-window entry takes effect.
const OPENED_AT: u64 = 1_700_000_000_000;
const EDITED_AT: u64 = 1_700_000_500_000;

fn jpy() -> CurrencyCode {
    CurrencyCode::new("JPY").expect("JPY is a code")
}

fn eur() -> CurrencyCode {
    CurrencyCode::new("EUR").expect("EUR is a code")
}

/// A card pricing one class on one lane at `micro` micro-units per unit, in USD.
fn card_at(micro: f64, fee: i64) -> RateCard {
    RateCard::from_micro_rates([(LaneClass::new(LANE, CLASS), micro)], fee)
}

/// The estimate of a unit expected to consume `quantity` of the priced class.
///
/// `max_unit_price_nanos` is deliberately absurd. Nothing in the lookup path may read it: the price
/// is the CARD's, and a case that passed because the estimate's own figure leaked into the answer
/// would prove nothing about where the money came from.
fn estimate(quantity: u64, fee_nanos: u64) -> Estimate {
    Estimate {
        per_class: vec![ClassEstimate {
            class: CLASS.to_string(),
            quantity,
            max_unit_price_nanos: u64::MAX,
        }],
        fee_nanos,
    }
}

fn ctx<'a>(lanes: &'a [&'a str], currency: CurrencyCode, arrived_ms: u64) -> HoldContext<'a> {
    HoldContext {
        lanes,
        currency,
        fee_count: 1,
        tier_bp: STANDARD_TIER_BP,
        arrived_ms,
        arrived_mono: 42,
    }
}

/// An estimate is the kernel's own floor, not a figure a destination reported, and the posting it
/// builds says so. There is no argument that could make it say anything else — the mark is a
/// constant on the constructor — because a reservation that travelled onward as a measurement would
/// tell the ledger a guess was evidence.
#[test]
fn the_posting_an_estimate_builds_is_marked_estimated() {
    let posting = estimate(1_000, 0).as_posting(LANE, 1, STANDARD_TIER_BP, OPENED_AT, 42);
    assert!(posting.estimated, "an estimate is estimated");
    assert_eq!(posting.lane, LANE, "the card is keyed by lane");
    assert_eq!(
        posting.arrived_ms, OPENED_AT,
        "the instant dates the record"
    );
    assert_eq!(posting.arrived_mono, 42, "the monotonic reading orders it");
    assert_eq!(posting.fee_count, 1);
    assert_eq!(posting.quantities.len(), 1);
    assert_eq!(posting.quantities[0].class, CLASS);
    assert_eq!(posting.quantities[0].amount, 1_000);
    assert!(posting.cached.is_none(), "nothing has priced it yet");
}

/// THE ROW'S CENTRAL CLAIM. A unit is sized at the card the ROOT PINNED, resolved at the unit's own
/// arrival instant — not at the head of a history read later.
///
/// The history here has two entries: the opening card, and a hundredfold card appended mid-window.
/// A unit that arrived before the edit prices at the opening card under either snapshot. A unit that
/// arrives AFTER it prices at the opening card under the pinned snapshot and at the new one under
/// the head — and the pinned answer is the one a request in flight must get, because an apply
/// landing mid-body may not change what that request is reading.
#[test]
fn the_hold_is_sized_at_the_pinned_snapshot_not_at_a_later_head() {
    let mut history = History::opening(card_at(10.0, 0), OPENED_AT);
    let pinned = history.head().expect("the opening entry is the head");
    history.append(CardEntryDraft {
        effective_from: EDITED_AT,
        effective_until: None,
        card: card_at(1_000.0, 0),
        appended_at: EDITED_AT,
        author: Author::Config { policy_epoch: 1 },
    });

    let e = estimate(1_000, 0);
    let after_the_edit = EDITED_AT + 1;

    // 1 000 units at 10 micro-units each: the rate converts once, at ten thousand nano-units per
    // unit, so ten million nano-units.
    let pinned_size = e.size_at_arrival(
        &history.snapshot(pinned),
        &ctx(&[LANE], CurrencyCode::USD, after_the_edit),
    );
    assert_eq!(
        pinned_size.nanos(),
        10_000_000,
        "the pinned card is the opening card"
    );
    assert_eq!(pinned_size.card_seq(), Some(pinned));

    // The same instant against the head resolves the appended entry — a hundredfold.
    let head = history.current();
    let head_size = e.size_at_arrival(&head, &ctx(&[LANE], CurrencyCode::USD, after_the_edit));
    assert_eq!(
        head_size.nanos(),
        1_000_000_000,
        "the head resolves the new entry"
    );
    assert_ne!(
        head_size.card_seq(),
        pinned_size.card_seq(),
        "two different entries, so a pin that leaked would be visible"
    );

    // A unit that arrived BEFORE the edit prices at the opening card under either snapshot: the
    // entry prices what happens after it, never what happened before it.
    let before = e.size_at_arrival(&head, &ctx(&[LANE], CurrencyCode::USD, OPENED_AT + 1));
    assert_eq!(before.nanos(), 10_000_000);
    assert_eq!(before.card_seq(), Some(pinned));
}

/// The sizing is the LOOKUP's arithmetic, reached with the card already resolved, plus exactly one
/// thing of its own: the ceiling. This is that agreement stated as an equality — the hold and the
/// bill are the same multiply-and-sum, and the only figure that may differ is the last divide.
#[test]
fn hold_sizing_rounds_up_where_pricing_truncates() {
    // A thousandth of a micro-unit per unit is one nano-unit per unit: the finest rate the one
    // conversion can express.
    let history = History::opening(card_at(0.001, 0), OPENED_AT);
    let view = history.current();
    let (card_seq, card) = view
        .card_at(OPENED_AT)
        .expect("the opening entry covers it");

    // The two roundings only separate on a remainder, so the case is built to leave one: a single
    // unit at the smallest rate the conversion can express is one nano-unit, and 3 334 basis points
    // of one nano-unit is 0.3334 — nothing at all if it truncates, one if it rounds up.
    let tier = 3_334;
    let e = estimate(1, 0);
    let c = HoldContext {
        lanes: &[LANE],
        currency: CurrencyCode::USD,
        fee_count: 0,
        tier_bp: tier,
        arrived_ms: OPENED_AT,
        arrived_mono: 0,
    };
    let hold = e
        .hold_nanos_at_card(card_seq, card, &c, LANE)
        .expect("the card prices the lane");
    let posting = e.as_posting(LANE, 0, tier, OPENED_AT, 0);
    let priced = price_at_card(card_seq, card, &posting, CurrencyCode::USD).expect("priced");

    assert_eq!(priced.priced_nanos, 0, "pricing truncates");
    assert_eq!(hold, 1, "a hold rounds up");
    assert_eq!(
        hold,
        u64::try_from(priced.priced_nanos).expect("small") + 1,
        "the asymmetry is exactly one nano-unit here, and it is deliberate: over-reserving costs \
         headroom the unit gives back, over-billing costs money"
    );
    // The pre-tier sums are the SAME sum. Only the last divide differs.
    assert_eq!(priced.pre_tier_nanos, 1);
}

/// A hole in the pinned snapshot is the fee-only 1.5.5 posture, and never a refusal.
///
/// 1.5.5 had no history and so had no hole; a deployment that configured no rate card priced every
/// token class at zero and still billed the flat fee, and admitted the request. Failing closed here
/// would refuse a request the previous release admitted, which is the one thing the door may not do.
/// The condition is REPORTED instead, because an operator cannot see it from the figure.
#[test]
fn no_card_in_force_sizes_fee_only_and_never_refuses() {
    let history = History::new();
    let e = estimate(1_000_000, 250);
    let size = e.size_at_arrival(
        &history.current(),
        &ctx(&[LANE], CurrencyCode::USD, OPENED_AT),
    );

    assert_eq!(
        size.nanos(),
        250,
        "the flat fee alone, through the tier: no token class prices at anything"
    );
    assert_eq!(size.posture(), HoldPosture::NoCardInForce { at: OPENED_AT });
    assert_eq!(size.card_seq(), None, "no entry was resolved");

    // And the door still says yes. A pricer resolved against the same hole is the fee-only pricer:
    // no rate table, so nothing is `model_unpriced`, so nothing fails closed on it.
    let p = Pricer::resolved_at(
        &history.current(),
        OPENED_AT,
        CurrencyCode::USD,
        25,
        Some(BTreeMap::from([(
            "m".to_string(),
            RateNanos::from_micros_per_token(10.0, 10.0, 0.0, 0.0),
        )])),
    );
    assert!(!p.pricing_enabled(), "no card in force is no card");
    assert!(
        !p.model_unpriced("anything-at-all"),
        "there is no card for a model to be missing from"
    );
    assert_eq!(p.card_seq(), None);
    assert_eq!(p.price_per_request_cents(), 25, "the fee still applies");

    let d = door();
    let t = table(&[(
        "g",
        group_cfg(None, true, vec![limit(LimitMetric::Budget, 100, Some(DAY))]),
    )]);
    let c = chain(&t, "vk_hole", Some("g"));
    assert!(
        d.try_admit(&p, &c, "", OPENED_AT).is_ok(),
        "a hole in the history never refuses a request 1.5.5 admitted"
    );
}

/// A pricer resolved against a covered instant carries the entry it resolved to, and the rate table
/// it was handed. The seq is a read-back seam and nothing in the decision consults it.
#[test]
fn a_resolved_pricer_names_the_entry_it_was_judged_at() {
    let history = History::opening(card_at(10.0, 0), OPENED_AT);
    let rates = BTreeMap::from([(
        "m".to_string(),
        RateNanos::from_micros_per_token(10.0, 0.0, 0.0, 0.0),
    )]);
    let p = Pricer::resolved_at(
        &history.current(),
        OPENED_AT,
        CurrencyCode::USD,
        0,
        Some(rates),
    );
    assert_eq!(p.card_seq(), Some(HistorySeq::OPENING));
    assert_eq!(p.currency(), CurrencyCode::USD);
    assert!(p.pricing_enabled());
    assert!(
        p.model_unpriced("unknown"),
        "the fail-closed rule is untouched"
    );
    assert!(!p.model_unpriced("m"));
}

/// **NO CROSS-RATE.** A card prices each currency natively, and the door reads the one the node
/// declared. The two rates here are not proportional to any plausible exchange rate and the fees
/// differ in scale as well as in value, so no conversion of one answer could produce the other.
#[test]
fn each_currency_prices_natively_with_no_cross_rate() {
    let mut card =
        RateCard::from_micro_rates_in(CurrencyCode::USD, [(LaneClass::new(LANE, CLASS), 10.0)], 25);
    // A yen rate that is neither a round multiple of the dollar rate nor anything an exchange
    // could produce from it, and a fee in whole yen — a zero-exponent currency's minor unit.
    card.set_rate(LaneClass::new(LANE, CLASS), jpy(), 7.0);
    card.set_fee(jpy(), 3);
    let history = History::opening(card, OPENED_AT);
    let view = history.current();
    let e = estimate(1_000, 0);

    // USD: 1 000 units at 10 000 nano-units per micro-unit-of-rate → 10 nanos/unit → 10 000, plus a
    // 25-cent fee at 10^7 nanos per cent.
    let usd = e.size_at_arrival(&view, &ctx(&[LANE], CurrencyCode::USD, OPENED_AT));
    assert_eq!(usd.nanos(), 10_000_000 + 250_000_000);
    // JPY: 1 000 units at 7 nanos/unit → 7 000, plus a 3-yen fee at 10^9 nanos per yen.
    let jpy_size = e.size_at_arrival(&view, &ctx(&[LANE], jpy(), OPENED_AT));
    assert_eq!(jpy_size.nanos(), 7_000_000 + 3_000_000_000);

    assert_eq!(
        usd.card_seq(),
        jpy_size.card_seq(),
        "one entry, two native prices"
    );
}

/// A currency the card in force does not name is never a converted figure, and never a refusal at
/// the door either: a bucket whose declared currency the card cannot price is a BOOT refusal, so a
/// unit reaching the door under one means the node is already in a state an operator has to see.
/// The size falls back to the fee the node knows, and the posture names the currency.
#[test]
fn a_currency_the_card_does_not_price_is_never_converted() {
    let history = History::opening(card_at(10.0, 25), OPENED_AT);
    let e = estimate(1_000, 250);
    let size = e.size_at_arrival(&history.current(), &ctx(&[LANE], eur(), OPENED_AT));

    assert_eq!(
        size.posture(),
        HoldPosture::CurrencyNotPriced {
            card_seq: HistorySeq::OPENING,
            currency: eur(),
        }
    );
    assert_eq!(
        size.nanos(),
        250,
        "the fee the node knows, not a conversion"
    );
    // The USD answer is 10 000 000 + 250 000 000. Nothing resembling a scaled version of it
    // appears, because nothing scaled anything.
    assert_ne!(size.nanos(), 10_000_000 + 250_000_000);
}

/// Over a destination set the hold takes the DEAREST lane, not the first and not the mean: a
/// reservation that is too small has to top up, and one that is too large costs nothing but headroom
/// the unit gives straight back.
#[test]
fn the_hold_takes_the_dearest_lane_the_unit_may_reach() {
    let card = RateCard::from_micro_rates(
        [
            (LaneClass::new(LANE, CLASS), 10.0),
            (LaneClass::new(OTHER_LANE, CLASS), 90.0),
        ],
        0,
    );
    let history = History::opening(card, OPENED_AT);
    let view = history.current();
    let e = estimate(1_000, 0);

    let both = e.size_at_arrival(
        &view,
        &ctx(&[LANE, OTHER_LANE], CurrencyCode::USD, OPENED_AT),
    );
    let reversed = e.size_at_arrival(
        &view,
        &ctx(&[OTHER_LANE, LANE], CurrencyCode::USD, OPENED_AT),
    );
    assert_eq!(both.nanos(), 90_000_000, "the dearest of the two");
    assert_eq!(
        reversed.nanos(),
        both.nanos(),
        "and it does not depend on the order"
    );
    assert_eq!(
        e.size_at_arrival(&view, &ctx(&[LANE], CurrencyCode::USD, OPENED_AT))
            .nanos(),
        10_000_000,
        "one lane is that lane's own price"
    );
}

/// A lane a present card is silent about prices its classes at nothing and is not a refusal HERE.
/// The fail-closed rule for it is the door's own, where it has been since 1.5.5, and sizing does not
/// duplicate it — a second copy would be a second door.
#[test]
fn an_unpriced_lane_sizes_fee_only_and_leaves_the_refusal_where_it_was() {
    let history = History::opening(card_at(10.0, 0), OPENED_AT);
    let e = estimate(1_000, 0);
    let size = e.size_at_arrival(
        &history.current(),
        &ctx(&["a-lane-nobody-priced"], CurrencyCode::USD, OPENED_AT),
    );

    assert_eq!(size.nanos(), 0, "no rate, so nothing to reserve");
    assert_eq!(
        size.posture(),
        HoldPosture::Priced {
            card_seq: HistorySeq::OPENING
        },
        "the card was resolved; it is the lane that is unpriced"
    );

    // The refusal that DOES exist for it is the pricer's, unchanged.
    let p = card(0, &[("m", 10.0, 0.0)]);
    assert!(p.model_unpriced("a-model-nobody-priced"));
}

/// The prices that sized a reservation are consumed and discarded, and the reservation keeps a
/// QUANTITY of nano-units. Nothing about which card produced it travels on it.
#[test]
fn a_hold_carries_a_quantity_of_nano_units_and_no_price_of_record() {
    let history = History::opening(card_at(10.0, 25), OPENED_AT);
    let sized = estimate(1_000, 0).size_at_arrival(
        &history.current(),
        &ctx(&[LANE], CurrencyCode::USD, OPENED_AT),
    );
    let seal = KernelSeal::acquire_for_kernel();
    let admit: AdmitToken<Admit> = AdmitToken::mint(&seal);
    let hold = Hold::open(&admit, PrincipalId::new("vk_shape"), sized.nanos());

    // The prices that sized it are consumed and discarded. What the reservation keeps is a
    // QUANTITY of nano-units, and a card, a history entry or a currency landing on it would make it
    // a price of record — a second figure that could disagree with the lookup about what a unit
    // cost, which is the whole thing the design removes.
    let rendered = format!("{hold:?}");
    for banned in ["card", "seq", "currency", "rate", "version", "history"] {
        assert!(
            !rendered.contains(banned),
            "a hold named `{banned}`: {rendered}"
        );
    }
    assert!(rendered.contains("reserved"), "it keeps the quantity");
    settle(hold, &seal);
}

/// **A HOLD IS A RESERVATION, NOT A PRICE OF RECORD.** An undersized one tops up out of what the
/// principal's slice still holds and carries whatever nothing can back as an overdraft. The unit
/// runs to its end either way: there is no arm of a spend that refuses.
#[test]
fn an_undersized_hold_tops_up_then_overdrafts_and_never_refuses() {
    let history = History::opening(card_at(10.0, 0), OPENED_AT);
    let e = estimate(1_000, 0);
    let sized = e.size_at_arrival(
        &history.current(),
        &ctx(&[LANE], CurrencyCode::USD, OPENED_AT),
    );
    assert_eq!(sized.nanos(), 10_000_000);

    let seal = KernelSeal::acquire_for_kernel();
    let admit: AdmitToken<Admit> = AdmitToken::mint(&seal);
    let mut hold = Hold::open(&admit, PrincipalId::new("vk_top"), sized.nanos());

    // The unit consumed three times what the estimate guessed. Two million nano-units of slice are
    // left, so the reservation grows by that and the rest is carried out as an overdraft.
    let spend = hold.spend(30_000_000, 2_000_000);
    assert_eq!(spend.accrued, 30_000_000, "a spend is never trimmed");
    assert_eq!(spend.topped_up, 2_000_000, "what the slice could back");
    assert_eq!(spend.overdraft, 18_000_000, "and what nothing could");
    assert_eq!(hold.overdraft(), 18_000_000);

    // A slice with nothing in it is not a refusal either.
    let mut spent_out = Hold::open(&admit, PrincipalId::new("vk_top2"), 0);
    let all_overdraft = spent_out.spend(5_000, 0);
    assert_eq!(all_overdraft.accrued, 5_000);
    assert_eq!(all_overdraft.overdraft, 5_000);
    settle(hold, &seal);
    settle(spent_out, &seal);
}

/// Settle a hold a test is done with, rather than dropping money on the floor.
fn settle(hold: Hold, seal: &KernelSeal) {
    let _ = busbar_caps::Posted::settle(
        hold,
        0,
        &busbar_caps::Usage::report(&busbar_caps::UsageToken::mint(seal), Vec::new())
            .expect("an empty report is within the bound"),
        &busbar_caps::LedgerToken::mint(seal),
    );
}

/// An amend moves what a past unit is BILLED. It can never retroactively refuse a unit that was
/// served, and it cannot move the figure a request in flight was judged at: the door holds a pinned
/// snapshot, and an entry appended after the pin is not in it.
#[test]
fn an_amend_never_retroactively_refuses_or_resizes_a_unit_in_flight() {
    let mut history = History::opening(card_at(10.0, 0), OPENED_AT);
    let pinned = history.head().expect("opening");
    let view_seq = history.snapshot(pinned).seq();
    let e = estimate(1_000, 0);
    let before = e
        .size_at_arrival(
            &history.snapshot(pinned),
            &ctx(&[LANE], CurrencyCode::USD, OPENED_AT),
        )
        .nanos();

    let d = door();
    let t = table(&[(
        "g",
        group_cfg(None, true, vec![limit(LimitMetric::Budget, 100, Some(DAY))]),
    )]);
    let c = chain(&t, "vk_amend", Some("g"));
    let p = Pricer::resolved_at(
        &history.snapshot(pinned),
        OPENED_AT,
        CurrencyCode::USD,
        0,
        None,
    );
    assert!(
        d.try_admit(&p, &c, "", OPENED_AT).is_ok(),
        "admitted under the pinned card"
    );

    // A signed amend back-dates a hundredfold card over the window the unit is in.
    history.append(CardEntryDraft {
        effective_from: 0,
        effective_until: None,
        card: card_at(1_000.0, 0),
        appended_at: EDITED_AT,
        author: Author::Amend {
            operator_fingerprint: "op".to_string(),
            reason_hash: [0u8; 32],
        },
    });

    // The pinned view has not moved: same seq, same entry, same size.
    let after = history.snapshot(pinned);
    assert_eq!(after.seq(), view_seq, "the pin is a snapshot, not a head");
    assert_eq!(
        e.size_at_arrival(&after, &ctx(&[LANE], CurrencyCode::USD, OPENED_AT))
            .nanos(),
        before,
        "an entry appended after the pin is not in the pin"
    );
    // And the request is still admitted — the decision is never re-run.
    assert!(d.try_admit(&p, &c, "", OPENED_AT).is_ok());
    // The head, which is what SETTLEMENT reads, does see it.
    assert_eq!(
        e.size_at_arrival(
            &history.current(),
            &ctx(&[LANE], CurrencyCode::USD, OPENED_AT)
        )
        .nanos(),
        1_000_000_000
    );
}

/// The estimate's own sizing — the pre-lookup path a caller with no history uses — is untouched,
/// and its ceiling is the same single divide the lookup path takes. One rounding rule, three
/// callers.
#[test]
fn the_estimate_s_own_sizing_is_unchanged() {
    let e = Estimate {
        per_class: vec![
            ClassEstimate {
                class: "a".to_string(),
                quantity: 5,
                max_unit_price_nanos: 1,
            },
            ClassEstimate {
                class: "b".to_string(),
                quantity: 5,
                max_unit_price_nanos: 1,
            },
        ],
        fee_nanos: 0,
    };
    assert_eq!(e.pre_tier_nanos(), 10);
    // Half price over the SUM is five, where two per-line ceilings would be six.
    assert_eq!(e.hold_nanos(5_000), 5);
    assert_eq!(e.hold_nanos(STANDARD_TIER_BP), 10);
    // A remainder rounds up, once.
    assert_eq!(e.hold_nanos(5_001), 6);
}
