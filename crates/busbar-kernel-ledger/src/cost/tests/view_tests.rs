// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE ONE TEST.** A known ledger × a known card history → a known figure.

use busbar_contract::count::Count;

use crate::cost::{
    price_exact, price_in_view, price_ledger, Author, CardEntryDraft, History, LaneClass,
    LedgerEntry, Money, MoneyError, RateCard,
};

use super::{CACHE_READ, INPUT, OUTPUT};

/// The lane every case below serves on.
const LANE: &str = "lane-4o";

/// **CARD A**, in force from instant zero: input at 3 micro-units a token, output at 16, a flat fee
fn card_a() -> RateCard {
    RateCard::from_micro_rates(
        [
            (LaneClass::new(LANE, INPUT), 3.0),
            (LaneClass::new(LANE, OUTPUT), 16.0),
        ],
        2,
    )
}

/// **CARD B**, appended effective from instant 1,000,000: input at 1, output at 4, a fee of 1.
fn card_b() -> RateCard {
    RateCard::from_micro_rates(
        [
            (LaneClass::new(LANE, INPUT), 1.0),
            (LaneClass::new(LANE, OUTPUT), 4.0),
        ],
        1,
    )
}

/// **THE KNOWN CARD HISTORY**: card A from zero, card B appended from instant 1,000,000.
fn known_history() -> History {
    let mut history = History::opening(card_a(), 0);
    history.append(CardEntryDraft {
        effective_from: 1_000_000,
        effective_until: None,
        card: card_b(),
        appended_at: 1_000_000,
        author: Author::Config { policy_epoch: 1 },
    });
    history
}

/// **THE KNOWN LEDGER SLICE**: two rows of identical consumption, one on each side of the edit.
fn known_ledger() -> Vec<LedgerEntry> {
    vec![
        LedgerEntry::new(LANE, 500_000)
            .with_whole(INPUT, 1_000)
            .with_count(OUTPUT, Count::parse("27.5").expect("27.5 is a decimal"))
            .with_fee_count(1),
        LedgerEntry::new(LANE, 2_000_000)
            .with_whole(INPUT, 1_000)
            .with_count(OUTPUT, Count::parse("27.5").expect("27.5 is a decimal"))
            .with_fee_count(1),
    ]
}

#[test]
fn a_known_ledger_times_a_known_card_history_is_a_known_figure() {
    let figure = price_ledger(&known_ledger(), &known_history())
        .expect("every line of the known slice is priced by the card in force at its own instant");

    assert_eq!(figure.micros(), 34_550, "money = f(ledger, card history)");
    assert_eq!(figure.to_decimal_string(), "0.034550");

    assert_eq!(figure.minor(), 3);
}

#[test]
fn the_known_figure_is_exact_at_scale_six() {
    let exact =
        price_exact(&known_ledger(), &known_history().current()).expect("the known slice prices");

    assert_eq!(exact % 1_000_000_000, 0);
    assert_eq!(exact / 1_000_000_000, 34_550);
}

#[test]
fn publishing_a_card_leaves_every_prior_posting_byte_identical() {
    let before = History::opening(card_a(), 0);
    let row_one = &known_ledger()[..1];

    let priced_before = price_ledger(row_one, &before).expect("prices");
    let priced_after = price_ledger(row_one, &known_history()).expect("prices");

    assert_eq!(
        priced_before, priced_after,
        "#79: publishing reprices nothing"
    );
    assert_eq!(priced_before.micros(), 23_440);
}

/// An item costs the card in effect at its own instant on either side of a price change.
#[test]
fn an_item_costs_the_card_in_effect_at_its_own_instant_on_either_side_of_a_price_change() {
    const T: u64 = 1_000_000;
    let at = |instant: u64| {
        price_ledger(
            &[LedgerEntry::new(LANE, instant).with_whole(INPUT, 1_000)],
            &known_history(),
        )
        .expect("prices")
        .micros()
    };
    assert_eq!(
        at(T - 1),
        3_000,
        "before the change: card A, 3 micro-units a token"
    );
    assert_eq!(
        at(T),
        1_000,
        "from the change: card B, 1 micro-unit a token"
    );
    assert_eq!(at(T + 1), 1_000, "after the change: card B");
}

#[test]
fn pricing_flat_at_the_newest_card_is_a_different_and_wrong_figure() {
    let flat = History::opening(card_b(), 0);
    let flat_figure = price_ledger(&known_ledger(), &flat).expect("prices");

    assert_eq!(flat_figure.micros(), 22_220, "both rows at card B");
    assert_eq!(
        price_ledger(&known_ledger(), &known_history())
            .expect("prices")
            .micros(),
        34_550,
        "each row at the card in force when it arrived"
    );

    assert_eq!(34_550 - flat_figure.micros(), 12_330);
}

#[test]
fn a_back_dated_correction_reprices_exactly_its_window_and_nothing_outside_it() {
    let mut history = known_history();

    history.append(CardEntryDraft {
        effective_from: 400_000,
        effective_until: Some(600_000),
        card: RateCard::from_micro_rates(
            [
                (LaneClass::new(LANE, INPUT), 6.0),
                (LaneClass::new(LANE, OUTPUT), 32.0),
            ],
            2,
        ),
        appended_at: 9_000_000,
        author: Author::Amend {
            reason_hash: [0u8; 32],
        },
    });

    let figure = price_ledger(&known_ledger(), &history).expect("prices");

    assert_eq!(figure.micros(), 26_880 + 11_110);
}

#[test]
fn a_present_card_silent_about_the_lane_refuses() {
    let history = History::opening(card_a(), 0);
    let slice = vec![LedgerEntry::new("a-model-nobody-priced", 0).with_whole(OUTPUT, 1_000)];
    assert!(matches!(
        price_ledger(&slice, &history),
        Err(MoneyError::LaneUnpriced { .. })
    ));
}

#[test]
fn a_present_card_silent_about_a_hit_class_refuses() {
    let history = History::opening(card_a(), 0);
    let slice = vec![LedgerEntry::new(LANE, 0).with_whole(CACHE_READ, 1_000_000)];
    assert!(matches!(
        price_ledger(&slice, &history),
        Err(MoneyError::ClassUnpriced { .. })
    ));
}

#[test]
fn an_open_meter_class_the_card_prices_is_charged_not_dropped() {
    let card = RateCard::from_micro_rates(
        [
            (LaneClass::new(LANE, OUTPUT), 2.0),
            (LaneClass::new(LANE, "hops"), 5.0),
        ],
        0,
    );
    let history = History::opening(card, 0);
    let slice = vec![LedgerEntry::new(LANE, 0)
        .with_whole(OUTPUT, 100)
        .with_whole("hops", 1_000)];

    assert_eq!(
        price_ledger(&slice, &history)
            .expect("both classes are priced")
            .micros(),
        5_200
    );
}

#[test]
fn no_card_at_all_is_billing_off_and_the_flat_fee_still_posts() {
    let history = History::opening(RateCard::absent(2), 0);
    let slice = vec![LedgerEntry::new(LANE, 0)
        .with_whole(OUTPUT, 1_000_000)
        .with_fee_count(3)];
    assert_eq!(
        price_ledger(&slice, &history)
            .expect("an absent card prices everything at nothing")
            .micros(),
        60_000,
        "3 requests × 2 minor units = 60,000 micro-units, and no token charge"
    );
}

#[test]
fn a_hole_in_the_history_refuses_rather_than_costing_nothing() {
    let mut history = History::new();
    history.append(CardEntryDraft {
        effective_from: 1_000,
        effective_until: None,
        card: card_a(),
        appended_at: 1_000,
        author: Author::Config { policy_epoch: 0 },
    });
    let slice = vec![LedgerEntry::new(LANE, 0).with_whole(OUTPUT, 1_000)];
    assert!(matches!(
        price_ledger(&slice, &history),
        Err(MoneyError::NoCardInForce { at: 0 })
    ));
}

/// **THE ONE FUNCTION TAKES NO DENOMINATION, SO NO READ CAN ASK FOR A SECOND SCALE.**
#[test]
fn the_same_slice_against_the_same_history_is_one_figure_with_no_scale_to_choose() {
    let history = History::opening(card_a(), 0);
    let slice = vec![LedgerEntry::new(LANE, 0).with_whole(OUTPUT, 1_000)];
    let once = price_ledger(&slice, &history).expect("the card prices the lane");
    let twice = price_ledger(&slice, &history).expect("the card prices the lane");
    assert_eq!(once, twice);
    assert!(!once.is_zero(), "a real figure, not two zeros agreeing");

    assert_eq!(
        once.minor(),
        once.micros() / i128::from(crate::cost::MICROS_PER_CENT)
    );
}

/// The conditions under which every implementation in the tree is supposed to answer the same
#[test]
fn a_single_entry_history_prices_micro_units_and_fees_exactly() {
    let card = super::card4(LANE, [3.0, 16.0, 0.5, 4.0], 2);
    let history = History::opening(card, 0);
    let usage = [(INPUT, 1_000u64), (OUTPUT, 250), (CACHE_READ, 7_000)];

    let slice = vec![usage
        .iter()
        .fold(LedgerEntry::new(LANE, 0), |e, (class, q)| {
            e.with_whole(*class, *q)
        })
        .with_fee_count(3)];
    let one = price_in_view(&slice, &history.current()).expect("prices");

    assert_eq!(
        one.micros(),
        70_500,
        "1,000×3 + 250×16 + 7,000×0.5 + 3×2×10,000"
    );
}

#[test]
fn a_single_entry_history_projects_whole_minor_units_once() {
    let card = super::card4(LANE, [3.0, 16.0, 0.5, 4.0], 2);
    let history = History::opening(card, 0);
    let usage = [(INPUT, 1_000_000u64), (OUTPUT, 250_000)];

    let slice = vec![usage
        .iter()
        .fold(LedgerEntry::new(LANE, 0), |e, (class, q)| {
            e.with_whole(*class, *q)
        })
        .with_fee_count(3)];
    let one = price_in_view(&slice, &history.current()).expect("prices");

    assert_eq!(
        one.minor(),
        706,
        "(1,000,000×3 + 250,000×16) / 10,000 + 3×2"
    );
}

#[test]
fn a_total_does_not_depend_on_the_order_the_rows_arrived_in() {
    let history = known_history();
    let mut forward = known_ledger();
    forward.push(
        LedgerEntry::new(LANE, 1_500_000)
            .with_count(OUTPUT, Count::parse("0.000001").expect("a decimal"))
            .with_fee_count(0),
    );
    let mut reversed = forward.clone();
    reversed.reverse();

    assert_eq!(
        price_exact(&forward, &history.current()),
        price_exact(&reversed, &history.current()),
    );
}

#[test]
fn a_fraction_of_a_micro_unit_is_kept_across_lines_not_floored_per_line() {
    let card = RateCard::from_micro_rates(
        [
            (LaneClass::new(LANE, INPUT), 0.5),
            (LaneClass::new(LANE, OUTPUT), 0.5),
        ],
        0,
    );
    let history = History::opening(card, 0);
    let slice = vec![LedgerEntry::new(LANE, 0)
        .with_whole(INPUT, 1)
        .with_whole(OUTPUT, 1)];
    assert_eq!(price_ledger(&slice, &history).expect("prices").micros(), 1);
}

#[test]
fn a_seconds_reading_where_milliseconds_belong_resolves_to_the_wrong_card() {
    let history = known_history();
    let ms = vec![LedgerEntry::new(LANE, 2_000_000).with_whole(OUTPUT, 1_000)];
    let secs = vec![LedgerEntry::new(LANE, 2_000).with_whole(OUTPUT, 1_000)];

    assert_eq!(
        price_ledger(&ms, &history).expect("prices").micros(),
        4_000,
        "card B, correctly"
    );
    assert_eq!(
        price_ledger(&secs, &history).expect("prices").micros(),
        16_000,
        "card A, because 2,000 milliseconds is before card B's instant"
    );
}

#[test]
fn an_overflowing_total_refuses_rather_than_saturating() {
    let card = RateCard::from_micro_rates([(LaneClass::new(LANE, OUTPUT), 1.0e16)], 0);
    let history = History::opening(card, 0);
    let huge = Count::from_micros(i128::MAX / 2);
    let slice = vec![LedgerEntry::new(LANE, 0).with_count(OUTPUT, huge)];
    assert_eq!(
        price_ledger(&slice, &history),
        Err(MoneyError::Overflow),
        "a saturated total is a wrong total that looks like a right one"
    );
}

#[test]
fn money_spells_itself_without_a_float() {
    assert_eq!(Money::from_micros(34_510).to_decimal_string(), "0.034510");
    assert_eq!(
        Money::from_micros(1_000_000).to_decimal_string(),
        "1.000000"
    );
    assert_eq!(Money::from_micros(-1).to_decimal_string(), "-0.000001");
    assert_eq!(Money::ZERO.to_decimal_string(), "0.000000");
}

/// A composed card: the flat card prices `lane-4o` input at 3; the plane `p` prices its own
fn per_plane_card(flat: bool, plane: bool) -> RateCard {
    per_plane_card_with_fee(flat, plane, 0)
}

/// [`per_plane_card`] with the flat card's `per_request_fee:` configured at `fee` — the card is
fn per_plane_card_with_fee(flat: bool, plane: bool, fee: i64) -> RateCard {
    use crate::cost::{compose_plane_cards, TierRates};
    use std::collections::BTreeMap;
    let flat_card = BTreeMap::from([(
        LANE.to_string(),
        (
            TierRates {
                input: Some(3_000),
                ..TierRates::default()
            },
            None,
        ),
    )]);
    let plane_card = BTreeMap::from([(LANE.to_string(), (TierRates::default(), Some(7_000)))]);
    let planes = if plane {
        BTreeMap::from([("p".to_string(), plane_card)])
    } else {
        BTreeMap::new()
    };
    let map = compose_plane_cards(flat.then_some(&flat_card), &planes);
    let card = RateCard::from_config(
        map.as_ref()
            .map(|m| m.iter().map(|(lane, (tiers, _))| (lane.as_str(), *tiers))),
        fee,
    );
    card.with_unit_rates(map.iter().flatten().filter_map(|(lane, (_, calls))| {
        calls.map(|nanos| (LaneClass::new(lane.as_str(), "calls"), nanos))
    }))
}

fn plane_row(lane: &str, class: &str, n: u64) -> Result<Money, MoneyError> {
    let card = per_plane_card(true, true);
    price_ledger(
        &[LedgerEntry::new(lane, 0).with_whole(class, n)],
        &History::opening(card, 0),
    )
}

#[test]
fn a_plane_card_prices_its_own_lane_and_the_flat_card_never_does() {
    let q = format!("p{}{LANE}", crate::cost::PLANE_LANE_SEP);

    assert_eq!(plane_row(&q, "calls", 5), Ok(Money::from_micros(35)));

    assert_eq!(plane_row(LANE, INPUT, 5), Ok(Money::from_micros(15)));
    assert!(matches!(
        plane_row(LANE, "calls", 5),
        Err(MoneyError::ClassUnpriced { .. })
    ));

    assert_eq!(plane_row(&q, INPUT, 5), Ok(Money::ZERO));
}

#[test]
fn a_present_plane_card_silent_about_a_lane_refuses() {
    let q = format!("p{}other", crate::cost::PLANE_LANE_SEP);
    assert!(matches!(
        plane_row(&q, "calls", 1),
        Err(MoneyError::LaneUnpriced { .. })
    ));
}

#[test]
fn each_plane_card_is_its_own_switch() {
    let q = format!("p{}{LANE}", crate::cost::PLANE_LANE_SEP);
    let price = |card: RateCard, lane: &str, class: &str| {
        price_ledger(
            &[LedgerEntry::new(lane, 0).with_whole(class, 5)],
            &History::opening(card, 0),
        )
    };

    assert_eq!(
        price(per_plane_card(true, false), &q, "calls"),
        Ok(Money::ZERO)
    );

    let plane_only = per_plane_card(false, true);
    assert!(!plane_only.pricing_enabled(), "the flat card is absent");
    assert_eq!(price(plane_only.clone(), LANE, INPUT), Ok(Money::ZERO));
    assert_eq!(price(plane_only, &q, "calls"), Ok(Money::from_micros(35)));

    let empty = crate::cost::compose_plane_cards::<TierPair>(
        None,
        &std::collections::BTreeMap::from([("p".to_string(), Default::default())]),
    );
    let card = RateCard::from_config(
        empty
            .as_ref()
            .map(|m| m.iter().map(|(lane, (tiers, _))| (lane.as_str(), *tiers))),
        0,
    );
    assert!(matches!(
        price(card, &q, "calls"),
        Err(MoneyError::LaneUnpriced { .. })
    ));
}

type TierPair = (crate::cost::TierRates, Option<u64>);

/// With no plane card the composed map IS the flat map, byte-identical (1.5.5 `rate_card:` loads as
#[test]
fn a_flat_card_alone_composes_to_itself() {
    use std::collections::BTreeMap;
    let none: BTreeMap<String, BTreeMap<String, u8>> = BTreeMap::new();
    let flat = BTreeMap::from([("m".to_string(), 1u8)]);
    assert_eq!(
        crate::cost::compose_plane_cards(Some(&flat), &none),
        Some(flat)
    );
    let empty: BTreeMap<String, u8> = BTreeMap::new();
    let card = RateCard::from_config(
        crate::cost::compose_plane_cards(Some(&empty), &none)
            .as_ref()
            .map(|m| {
                m.keys()
                    .map(|k| (k.as_str(), crate::cost::TierRates::default()))
            }),
        0,
    );
    assert!(
        card.pricing_enabled(),
        "`rate_card: {{}}` stays a present card"
    );
}

/// The composed card with fees: the flat card's `per_request_fee:` is 5; plane `t` charges
fn fee_card() -> RateCard {
    use crate::cost::PlaneFees;
    let card = per_plane_card_with_fee(true, true, 5);
    card.with_plane_fees([
        (
            "t",
            PlaneFees {
                per_request: 3,
                per_session: 0,
            },
        ),
        (
            "s",
            PlaneFees {
                per_request: 0,
                per_session: 40,
            },
        ),
    ])
}

fn fee_row(entry: LedgerEntry) -> Result<Money, MoneyError> {
    price_ledger(&[entry], &History::opening(fee_card(), 0))
}

/// One minor unit, in micro-units.
const MINOR: i128 = 10_000;

#[test]
fn a_planes_request_fee_charges_its_calls_and_the_flat_fee_charges_the_pools_plane() {
    use crate::cost::{plane_fee_lane, PER_REQUEST};

    let plane_calls = LedgerEntry::new(plane_fee_lane("t"), 0).with_whole(PER_REQUEST, 4);
    assert_eq!(fee_row(plane_calls), Ok(Money::from_micros(12 * MINOR)));

    let flat = LedgerEntry::new(LANE, 0).with_fee_count(2);
    assert_eq!(fee_row(flat), Ok(Money::from_micros(10 * MINOR)));

    let q = format!("t{}srv_read", crate::cost::PLANE_LANE_SEP);
    let qualified = LedgerEntry::new(q, 0).with_fee_count(2);
    assert_eq!(fee_row(qualified), Ok(Money::from_micros(6 * MINOR)));
}

#[test]
fn a_planes_session_fee_charges_one_per_session() {
    use crate::cost::{plane_fee_lane, PER_SESSION};
    let sessions = LedgerEntry::new(plane_fee_lane("s"), 0).with_whole(PER_SESSION, 3);
    assert_eq!(fee_row(sessions), Ok(Money::from_micros(120 * MINOR)));
}

#[test]
fn a_plane_without_fees_bills_no_fee() {
    use crate::cost::{plane_fee_lane, PER_REQUEST, PER_SESSION};

    let p = LedgerEntry::new(plane_fee_lane("p"), 0)
        .with_whole(PER_REQUEST, 7)
        .with_whole(PER_SESSION, 7);
    assert_eq!(fee_row(p), Ok(Money::ZERO));
    let q = format!("p{}{LANE}", crate::cost::PLANE_LANE_SEP);
    assert_eq!(
        fee_row(LedgerEntry::new(q, 0).with_fee_count(9)),
        Ok(Money::ZERO)
    );

    let none = LedgerEntry::new(plane_fee_lane("x"), 0).with_whole(PER_REQUEST, 7);
    assert_eq!(fee_row(none), Ok(Money::ZERO));
}

#[test]
fn a_fee_lane_carries_only_the_fee_classes() {
    use crate::cost::plane_fee_lane;

    let stray = LedgerEntry::new(plane_fee_lane("p"), 0).with_whole("calls", 1);
    assert!(matches!(
        fee_row(stray),
        Err(MoneyError::ClassUnpriced { .. })
    ));

    let off = LedgerEntry::new(plane_fee_lane("s"), 0).with_whole("calls", 1);
    assert_eq!(fee_row(off), Ok(Money::ZERO));
}

#[test]
fn plane_fees_leave_the_flat_card_byte_identical() {
    let row = LedgerEntry::new(LANE, 0)
        .with_whole(INPUT, 1_000)
        .with_fee_count(3);
    let flat = per_plane_card_with_fee(true, true, 5);
    assert_eq!(
        price_ledger(std::slice::from_ref(&row), &History::opening(flat, 0)),
        fee_row(row)
    );
}
