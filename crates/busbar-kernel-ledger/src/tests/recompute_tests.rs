// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A booked line and the one lookup that prices it. The line carries quantities and an instant and
//! never a price (#71, #77(3)), so what is tested is the lookup's answer: the origin rule on the fee
//! line, a hole in the history refusing rather than pricing at zero, the tier rule, and an overflow
//! refusing rather than wrapping. (The cached-price arbitration that once lived here had nothing in
//! production to arbitrate and was deleted; the boot reconciliation re-derives every settled figure
//! from the journal's counts instead.)

use crate::cost::{Author, CardEntryDraft, History, LaneClass, RateCard};
use busbar_contract::caps::MeterClassId;

use crate::cost::checked_apply_tier;
use crate::recompute::{price_line, Divergence, Posting, PostingOrigin, PricedLine, BASIS_POINTS};

use super::fixtures::key;

/// The lane every line in this module is served on.
const LANE: &str = "lane-a";
/// The instant every line arrives at, unless a test moves it on purpose.
const ARRIVED_MS: u64 = 1_767_225_600_000;
/// A discount tier, not the neutral value: the tier arithmetic at ten thousand basis points is the
/// identity function, and a fixture priced only there would pass with the tier projection missing.
const DISCOUNT_TIER_BP: u32 = 9_000;

/// The card the opening entry seals: two classes on one lane, and a flat fee.
fn opening_card() -> RateCard {
    RateCard::from_micro_rates(
        [
            (LaneClass::new(LANE, "tokens_in"), 2.0),
            (LaneClass::new(LANE, "tokens_out"), 5.0),
        ],
        1,
    )
}

fn line() -> Posting {
    Posting {
        node: 1,
        node_seq: 1,
        key: key("b"),
        window_start: 1,
        lane: LANE.to_string(),
        lines: vec![
            PricedLine {
                class: MeterClassId::new("tokens_in"),
                quantity: 1_000,
            },
            PricedLine {
                class: MeterClassId::new("tokens_out"),
                quantity: 200,
            },
        ],
        fee_count: 1,
        tier_bp: DISCOUNT_TIER_BP,
        arrived_ms: ARRIVED_MS,
        origin: PostingOrigin::Client,
    }
}

fn priced(line: &Posting, history: &History) -> Result<u128, Divergence> {
    let head = history.head().expect("the fixture's history has a head");
    let view = history.snapshot(head);
    price_line(line, &view, line.tier_bp)
        .map(|p| p.priced_nanos)
        .map_err(crate::recompute::divergence_of)
}

#[test]
fn the_fee_line_is_zero_for_work_no_client_asked_for() {
    let history = History::opening(opening_card(), 0);
    let mut internal = line();
    internal.origin = PostingOrigin::Internal;
    assert!(
        priced(&internal, &history).expect("prices") < priced(&line(), &history).expect("prices"),
        "an internally originated line must not be charged the request fee"
    );
}

#[test]
fn on_a_deployment_with_no_rate_card_the_fee_line_is_the_whole_price() {
    let history = History::opening(RateCard::absent(250), 0);
    let mut fees = line();
    fees.tier_bp = BASIS_POINTS;
    fees.fee_count = 3;
    assert!(
        priced(&fees, &history).expect("prices") > 0,
        "the fee still posts"
    );
    fees.fee_count = 0;
    assert_eq!(priced(&fees, &history), Ok(0));
}

#[test]
fn a_hole_in_the_history_is_a_refusal_and_never_a_zero() {
    let mut history = History::new();
    history.append(CardEntryDraft {
        effective_from: ARRIVED_MS + 1,
        effective_until: None,
        card: opening_card(),
        appended_at: 0,
        author: Author::Opening,
    });
    assert_eq!(
        priced(&line(), &history),
        Err(Divergence::NoCardInForce { at: ARRIVED_MS })
    );
}

/// The tier rule is the one function the bill is computed with (`cost::checked_apply_tier`, which
/// the one function's accumulator applies).
#[test]
fn the_tier_rounds_to_nearest_and_never_divides_first() {
    assert_eq!(
        checked_apply_tier(1, 9_999),
        Some(1),
        "0.9999 is nearer 1 than 0"
    );
    assert_eq!(checked_apply_tier(10_000, 9_999), Some(9_999));
    assert_eq!(checked_apply_tier(3, 5_000), Some(2));
    assert_eq!(checked_apply_tier(10_000, 9_000), Some(9_000));
}

#[test]
fn the_neutral_tier_is_the_identity_at_the_ceiling() {
    assert_eq!(checked_apply_tier(u128::MAX, BASIS_POINTS), Some(u128::MAX));
    assert_eq!(checked_apply_tier(10_000, 9_999), Some(9_999));
}

/// A figure too large to hold is refused (item 28), never wrapped and never pinned at a ceiling.
#[test]
fn a_figure_too_large_to_hold_is_refused_rather_than_wrapped() {
    let history = History::opening(
        RateCard::from_micro_rates([(LaneClass::new(LANE, "tokens_in"), 1.0e16)], 0),
        0,
    );
    let mut big = line();
    big.tier_bp = BASIS_POINTS;
    big.lines = vec![
        PricedLine {
            class: MeterClassId::new("tokens_in"),
            quantity: u64::MAX,
        },
        PricedLine {
            class: MeterClassId::new("tokens_in"),
            quantity: u64::MAX,
        },
    ];
    assert_eq!(priced(&big, &history), Err(Divergence::Overflow));
}
