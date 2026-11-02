// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Clause one and clause four: the single conversion from a configured decimal to an integer rate,

use super::*;
use crate::cost::{nano_rate, History, LaneClass, RateCard, STANDARD_TIER_BP};

/// $ RED (OWNER rule 21, #81): THE CONVERSION NEVER ROUNDS. The card holds integer nano-units, so

#[test]
fn nano_rate_refuses_a_rate_that_is_not_a_whole_number_of_nano_units() {
    for refused in [0.0015, 0.0014, 0.0005, 0.5005, 0.5015, 0.1 + 0.2, 1.0001] {
        assert_eq!(
            nano_rate(refused),
            0,
            "{refused} µ/unit has no integer nano-rate"
        );
        assert_eq!(
            crate::cost::representable_nano_rate(refused),
            None,
            "{refused} µ/unit is a rate the card cannot hold — never rounded to one it can"
        );
    }
    for (micro, nanos) in [
        (0.001, 1),
        (0.3, 300),
        (0.1, 100),
        (0.2, 200),
        (2.5, 2_500),
        (3.125, 3_125),
    ] {
        assert_eq!(
            nano_rate(micro),
            nanos,
            "{micro} µ/unit is exactly {nanos} nano-units"
        );
    }
}

/// The clamp is "finite AND positive", not "finite OR positive". An infinite rate — reachable from

#[test]
fn nano_rate_clamps_a_non_finite_positive_rate_to_zero_not_the_maximum() {
    assert_eq!(nano_rate(f64::INFINITY), 0);
    assert_eq!(nano_rate(f64::NAN), 0);
    assert_eq!(nano_rate(-1.0), 0, "a negative rate is not a discount");
}

/// A finite value can still be too large for a `u64` to hold — a config typo with too many zeros,

#[test]
fn nano_rate_clamps_a_finite_but_overflowing_rate_to_zero_not_the_maximum() {
    assert_eq!(nano_rate(1e18), 0);

    assert_eq!(nano_rate(1e12), 1_000_000_000_000_000);
}

/// **THE CEILING IS THE INTEGER'S, CHECKED — NOT A FLOAT CAST'S.**

#[test]
fn nano_rate_ceiling_is_a_checked_integer_multiply() {
    assert_eq!(
        nano_rate(18_446_744_073_709_548.0),
        18_446_744_073_709_548_000,
        "the last rate under the ceiling converts exactly, with no float drift"
    );
    assert_eq!(
        nano_rate(18_446_744_073_709_556.0),
        0,
        "one past what a u64 of nano-units holds prices at NOTHING, never u64::MAX"
    );
    assert_eq!(
        nano_rate(2.0_f64.powi(64)),
        0,
        "the old cast's premise case"
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

/// The fee's unit price is its cents lifted to nano-units — an exact multiple of ten million,

#[test]
fn fee_line_unit_price_is_cents_lifted_to_nano_units() {
    let c = RateCard::absent(3);
    assert_eq!(c.fee_unit_price_nanos(), 30_000_000);
    assert_eq!(c.fee_unit_price_nanos() % crate::cost::NANOS_PER_CENT, 0);
}

/// ITEM 22: A RATE THE CARD CANNOT HOLD IS NOT A RATE OF ZERO.

#[test]
fn a_sub_quantum_rate_is_unpriced_on_the_card_and_refuses_never_priced_at_zero() {
    let per_byte = 0.10 * 1_000_000.0 / 1_073_741_824.0;
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

    assert_eq!(crate::cost::representable_nano_rate(0.001), Some(1));
    assert_eq!(crate::cost::representable_nano_rate(0.002), Some(2));
    assert_eq!(crate::cost::representable_nano_rate(0.0005), None);
    assert_eq!(crate::cost::representable_nano_rate(0.0015), None);
    assert_eq!(crate::cost::representable_nano_rate(0.0004), None);
    assert_eq!(crate::cost::representable_nano_rate(0.0), Some(0));
    assert_eq!(crate::cost::representable_nano_rate(f64::MAX), None);
}

/// A LANE'S RATES PRICE NO USAGE REPORT: a report is a spend, and every spend is `Tally`'s.

#[test]
fn a_report_is_priced_by_the_spend_fold_and_a_silent_class_refuses() {
    let card = RateCard::from_micro_rates([(LaneClass::new("m", "input"), 2.5)], 0);
    let mut priced = crate::cost::Tally::at_card(&card);
    priced
        .row(
            "m",
            0,
            STANDARD_TIER_BP,
            [("input", crate::cost::whole(1_000))],
            crate::cost::whole(0),
        )
        .expect("a priced class prices");
    assert_eq!(
        crate::cost::nanos_of_exact(priced.exact().expect("in range")),
        Ok(2_500_000),
        "1,000 units at 2.5 micro-units is 2,500,000 nano-units"
    );

    let mut silent = crate::cost::Tally::at_card(&card);
    assert!(
        matches!(
            silent.row(
                "m",
                0,
                STANDARD_TIER_BP,
                [("input", crate::cost::whole(1_000)), ("output", crate::cost::whole(7))],
                crate::cost::whole(0),
            ),
            Err(crate::cost::MoneyError::ClassUnpriced { ref class, .. }) if class == "output"
        ),
        "a class the present card is silent about refuses; it is never sized at nothing"
    );
}

/// **A CORRECTED CARD IS THE CARD WITH THE NAMED CELLS SET** (#79): every other lane,

#[test]
fn a_corrected_card_keeps_everything_it_does_not_name() {
    use crate::cost::TierRates;
    let tiers = |input: u64, output: u64| TierRates {
        input: Some(input),
        output: Some(output),
        ..TierRates::default()
    };
    let card = RateCard::from_config(
        Some([
            ("lane-g", tiers(2_000, 8_000)),
            ("lane-c", tiers(3_000, 15_000)),
            ("plane-b\u{1f}search", tiers(5_000, 6_000)),
        ]),
        3,
    );
    let nanos = |card: &RateCard, lane: &str, class: &str| {
        card.lane_rates(lane)
            .filter(|r| r.class_priced(class))
            .map(|r| r.nanos_per_unit(class))
    };

    let corrected = card
        .corrected([(LaneClass::new("lane-g", "input"), 1_000)], None)
        .expect("the flat card is present");
    assert_eq!(nanos(&corrected, "lane-g", "input"), Some(1_000));
    assert_eq!(nanos(&corrected, "lane-g", "output"), Some(8_000));
    assert_eq!(nanos(&corrected, "lane-c", "output"), Some(15_000));
    assert_eq!(
        nanos(&corrected, "plane-b\u{1f}search", "input"),
        Some(5_000)
    );
    assert_eq!(corrected.fee(), 3, "a fee it does not name is kept");

    let corrected = card
        .corrected(
            [(LaneClass::new("plane-b\u{1f}search", "input"), 9_000)],
            Some(7),
        )
        .expect("plane-b's card is present");
    assert_eq!(
        nanos(&corrected, "plane-b\u{1f}search", "input"),
        Some(9_000)
    );
    assert_eq!(
        nanos(&corrected, "plane-b\u{1f}search", "output"),
        Some(6_000)
    );
    assert_eq!(
        nanos(&corrected, "lane-g", "input"),
        Some(2_000),
        "the flat card is untouched"
    );
    assert_eq!(corrected.fee(), 7, "a named fee replaces the fee");

    assert!(
        card.corrected([(LaneClass::new("plane-c\u{1f}hop", "bytes"), 1)], None)
            .is_none(),
        "a plane with no card of its own has billing off; a correction cannot switch it on"
    );
    assert!(
        RateCard::absent(3)
            .corrected([(LaneClass::new("lane-g", "input"), 1)], None)
            .is_none(),
        "an absent flat card has nowhere for a cell to land"
    );
    assert!(
        card.corrected([(LaneClass::new("plane-b\u{1f}", "input"), 1)], None)
            .is_none(),
        "a cell naming no lane"
    );
    assert_eq!(
        RateCard::absent(3)
            .corrected(std::iter::empty(), Some(5))
            .map(|c| (c.fee(), c.pricing_enabled())),
        Some((5, false)),
        "a fee alone corrects an absent card's fee and leaves billing off"
    );
}

/// **A CORRECTED CELL IS NO LONGER A REFUSED ONE** (#79, #42). A card that could not represent

#[test]
fn a_correction_that_prices_a_refused_cell_takes_it_off_the_refused_list() {
    use crate::cost::TierRates;

    let unrepresentable = crate::cost::representable_nano_rate(0.0001);
    let card = RateCard::from_config(
        Some([
            (
                "lane-g",
                TierRates {
                    input: unrepresentable,
                    output: unrepresentable,
                    ..TierRates::default()
                },
            ),
            (
                "plane-b\u{1f}search",
                TierRates {
                    input: unrepresentable,
                    output: Some(1_000),
                    ..TierRates::default()
                },
            ),
        ]),
        0,
    );
    let plane_refused = |card: &RateCard| {
        card.plane_lane("plane-b\u{1f}search")
            .0
            .refused_cells()
            .to_vec()
    };
    assert_eq!(
        card.refused_cells(),
        [
            LaneClass::new("lane-g", "input"),
            LaneClass::new("lane-g", "output")
        ]
    );
    assert_eq!(plane_refused(&card), [LaneClass::new("search", "input")]);

    let corrected = card
        .corrected(
            [
                (LaneClass::new("lane-g", "input"), 1_000),
                (LaneClass::new("plane-b\u{1f}search", "input"), 9_000),
            ],
            None,
        )
        .expect("both cards are present");
    assert_eq!(
        corrected.refused_cells(),
        [LaneClass::new("lane-g", "output")],
        "the corrected cell is priced, so it is not refused; the cell it did not name still is"
    );
    assert!(
        plane_refused(&corrected).is_empty(),
        "the plane's corrected cell is not refused either"
    );
}
