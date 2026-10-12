// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE FEE-LANE RESOLUTION (#44, #47): the settlement lookup (`price_at_card`) and the one
//! function's accumulator (`Tally::row`) price a plane's fee lane the same way, because both ask
//! `RateCard::lane_pricing`.
//!
//! They used to disagree. On a fee lane `"<plane>\u{1f}"` whose plane card is PRESENT, the lookup
//! looked up the empty lane, found nothing, flagged the whole lane unpriced and priced only the
//! posting's fee count, so settlement (`price_fail_closed`) REFUSED a fee unit every read priced at
//! the plane's fee. On an ABSENT plane card the lookup's lines showed a fee unit at a unit price of
//! nothing while the figure carried the fee.

use crate::cost::{
    compose_plane_cards, plane_fee_lane, price_at_card, price_fail_closed, HistorySeq, LaneClass,
    PlaneFees, Posting, Quantity, RateCard, Tally, TierRates, NANOS_PER_CENT, PER_REQUEST,
    PER_SESSION, STANDARD_TIER_BP,
};

/// The lane plane `p` serves traffic on.
const LANE: &str = "lane-p";

/// A composed card: a flat card (fee 5), plane `p` with a PRESENT card (one lane, `calls` priced)
/// and its own fees (3 a request, 40 a session), and plane `s` with fees (2 a request) and NO card.
fn card() -> RateCard {
    use std::collections::BTreeMap;
    let flat = BTreeMap::from([(
        "lane-flat".to_string(),
        TierRates {
            input: 1.0,
            ..TierRates::default()
        },
    )]);
    let planes = BTreeMap::from([(
        "p".to_string(),
        BTreeMap::from([(LANE.to_string(), TierRates::default())]),
    )]);
    let map = compose_plane_cards(Some(&flat), &planes).expect("a composed map");
    RateCard::from_config(Some(map.iter().map(|(lane, t)| (lane.as_str(), *t))), 5)
        .with_unit_rates([(
            LaneClass::new(format!("p{}{LANE}", crate::cost::PLANE_LANE_SEP), "calls"),
            7_000,
        )])
        .with_plane_fees([
            (
                "p",
                PlaneFees {
                    per_request: 3,
                    per_session: 40,
                },
            ),
            (
                "s",
                PlaneFees {
                    per_request: 2,
                    per_session: 0,
                },
            ),
        ])
}

fn posting(lane: String, quantities: &[(&str, u64)], fee_count: u64) -> Posting {
    Posting {
        lane,
        quantities: quantities
            .iter()
            .map(|(class, amount)| Quantity::new(*class, *amount))
            .collect(),
        fee_count,
        tier_bp: STANDARD_TIER_BP,
        arrived_ms: 0,
        arrived_mono: 0,
        estimated: false,
        cached: None,
    }
}

/// What the accumulator alone makes of the same posting, in whole nano-units.
fn tallied(card: &RateCard, p: &Posting) -> Result<u128, crate::cost::MoneyError> {
    let mut tally = Tally::at_card(card);
    tally.row(
        &p.lane,
        p.arrived_ms,
        p.tier_bp,
        p.quantities
            .iter()
            .map(|q| (q.class.as_str(), crate::cost::whole(q.amount))),
        crate::cost::whole(p.fee_count),
    )?;
    crate::cost::nanos_of_exact(tally.exact()?)
}

/// A present plane card: four request units and one session on `p`'s fee lane are 4 × 3 + 1 × 40
/// minor units, on the settlement lookup exactly as on the accumulator, and settlement does not
/// refuse them.
#[test]
fn a_fee_lane_on_a_present_plane_card_prices_the_same_on_settlement_and_on_every_read() {
    let card = card();
    let p = posting(
        plane_fee_lane("p"),
        &[(PER_REQUEST, 4), (PER_SESSION, 1)],
        0,
    );
    let expected = (4 * 3 + 40) * NANOS_PER_CENT;

    assert_eq!(tallied(&card, &p), Ok(expected), "the accumulator's figure");
    let priced = price_at_card(HistorySeq::OPENING, &card, &p).expect("the lookup answers");
    assert!(
        !priced.lane_unpriced,
        "a plane's fee lane is not a lane its card forgot"
    );
    assert_eq!(
        priced.priced_nanos, expected,
        "the settlement lookup's figure is the accumulator's"
    );
    let unit = |class: &str| {
        priced
            .lines
            .iter()
            .find(|l| l.class == class)
            .map(|l| (l.unit_price_nanos, l.unpriced))
    };
    assert_eq!(unit(PER_REQUEST), Some((3 * NANOS_PER_CENT, false)));
    assert_eq!(unit(PER_SESSION), Some((40 * NANOS_PER_CENT, false)));

    let history = crate::cost::History::opening(card, 0);
    assert_eq!(
        price_fail_closed(&history.current(), &p).map(|p| p.priced_nanos),
        Ok(expected),
        "settlement must not refuse a fee unit every read prices"
    );
}

/// An absent plane card: plane `s` bills its fee units at its own fee, and the lookup's line says
/// so rather than showing a unit price of nothing beside a figure that carries the fee.
#[test]
fn a_fee_lane_on_an_absent_plane_card_shows_the_fee_it_bills() {
    let card = card();
    let p = posting(plane_fee_lane("s"), &[(PER_REQUEST, 5)], 0);
    let expected = 5 * 2 * NANOS_PER_CENT;
    assert_eq!(tallied(&card, &p), Ok(expected));
    let priced = price_at_card(HistorySeq::OPENING, &card, &p).expect("the lookup answers");
    assert_eq!(priced.priced_nanos, expected);
    let line = priced
        .lines
        .iter()
        .find(|l| l.class == PER_REQUEST)
        .expect("the fee unit is a line");
    assert_eq!(line.unit_price_nanos, 2 * NANOS_PER_CENT);
    assert_eq!(line.amount_nanos, expected);
    assert!(!line.unpriced);
}

/// A class that is not a fee class on a present card's fee lane stays a refusal on both paths, and
/// an ordinary lane on the same card is untouched by the fee-lane rule.
#[test]
fn a_stray_class_on_a_fee_lane_still_refuses_and_an_ordinary_lane_is_untouched() {
    let card = card();
    let stray = posting(plane_fee_lane("p"), &[("calls", 1)], 0);
    assert!(matches!(
        tallied(&card, &stray),
        Err(crate::cost::MoneyError::ClassUnpriced { .. })
    ));
    let priced = price_at_card(HistorySeq::OPENING, &card, &stray).expect("the read posture");
    assert!(priced
        .lines
        .iter()
        .any(|l| l.class == "calls" && l.unpriced));

    // `calls` at 7,000 nano-units on p's served lane, plus two requests at p's fee of 3.
    let served = posting(
        format!("p{}{LANE}", crate::cost::PLANE_LANE_SEP),
        &[("calls", 2)],
        2,
    );
    let expected = 2 * 7_000 + 2 * 3 * NANOS_PER_CENT;
    assert_eq!(tallied(&card, &served), Ok(expected));
    let priced = price_at_card(HistorySeq::OPENING, &card, &served).expect("priced");
    assert_eq!(priced.priced_nanos, expected);
    assert!(!priced.lane_unpriced);
}
