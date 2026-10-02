// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The dated budget ledger (OWNER RULING Q14, #79): a cell's segments price at the card in force
//! when each was earned, through the one function, and agree with the dated metering read.

use std::collections::BTreeMap;

use crate::cost::{
    price_in_view, Author, CardEntryDraft, History, LaneClass, LedgerEntry, MoneyError, RateCard,
    Tally, STANDARD_TIER_BP,
};
use crate::usage::{price_dated, DatedHistory, FeeEras};

/// The instant the card is edited, in milliseconds.
const EDIT_MS: u64 = 1_700_000_000_000;

/// A card pricing `input` on lane `m` at `micro` per token, with a flat fee.
fn card(micro: f64, fee_cents: i64) -> RateCard {
    RateCard::from_micro_rates([(LaneClass::new("m", "input"), micro)], fee_cents)
}

/// The opening card, then a configuration edit at [`EDIT_MS`].
fn edited(before: RateCard, after: RateCard) -> History {
    let mut history = History::opening(before, 0);
    history.append(CardEntryDraft {
        effective_from: EDIT_MS,
        effective_until: None,
        card: after,
        appended_at: EDIT_MS,
        author: Author::Config { policy_epoch: 1 },
    });
    history
}

fn input(n: u64) -> BTreeMap<String, u64> {
    BTreeMap::from([("input".to_string(), n)])
}

/// **THE WORKED EXAMPLE.** 300,000 tokens before an edit from 20 to 10 micro-units a token, 900,000
/// after. The card in force when each was earned prices them at 600 + 900 = 1,500; the current card
/// alone reprices all 1,200,000 at 1,200. The dated cell answers 1,500, and it is the SAME figure
/// the dated metering read's one function answers for the same consumption at the same instants.
#[test]
fn a_card_edit_mid_window_prices_each_segment_at_the_card_it_was_earned_under() {
    let history = edited(card(20.0, 0), card(10.0, 0));
    let live = card(10.0, 0);
    let (before, after) = (input(300_000), input(900_000));
    let dated = price_dated(
        [("m", 0, &before), ("m", EDIT_MS, &after)],
        [],
        0,
        &live,
        Some(DatedHistory {
            view: history.current(),
            now_ms: EDIT_MS + 60_000,
        }),
    )
    .expect("priced");
    assert_eq!(dated.minor_i64(), Ok(1_500));

    let metering_read = price_in_view(
        &[
            LedgerEntry::new("m", 0).with_whole("input", 300_000),
            LedgerEntry::new("m", EDIT_MS).with_whole("input", 900_000),
        ],
        &history.current(),
    )
    .expect("priced");
    assert_eq!(
        dated, metering_read,
        "the budget cell and the dated read agree"
    );

    let undated =
        price_dated([("m", 0, &before), ("m", 0, &after)], [], 0, &live, None).expect("priced");
    assert_eq!(
        undated.minor_i64(),
        Ok(1_200),
        "the undated derivation is what repriced history — this is the figure that was served"
    );
}

/// With no history installed every segment prices at the live card, which is exactly the one
/// function at that card — the undated derivation, to the micro-unit.
#[test]
fn with_no_history_the_cell_prices_as_the_undated_derivation() {
    let live = card(3.0, 2);
    let units = input(1_234_567);
    let mut tally = Tally::at_card(&live);
    tally
        .row(
            "m",
            0,
            STANDARD_TIER_BP,
            [("input", crate::cost::whole(1_234_567))],
            crate::cost::whole(0),
        )
        .unwrap();
    tally
        .fee(0, STANDARD_TIER_BP, crate::cost::whole(9))
        .unwrap();
    let dated = price_dated([("m", 0, &units)], [(0, 9)], 0, &live, None).unwrap();
    assert_eq!(dated, tally.money().unwrap());
}

/// The flat fee is dated too: requests admitted before the edit pay the old fee, after it the new.
#[test]
fn the_fee_base_splits_by_the_era_each_request_was_admitted_under() {
    let history = edited(card(0.0, 5), card(0.0, 7));
    let live = card(0.0, 7);
    let mut eras = FeeEras::default();
    eras.charge(0); // undated: the remainder
    eras.charge(0);
    eras.charge(EDIT_MS);
    let total = 3;
    let fees: Vec<(u64, u64)> = eras.split(total).collect();
    assert_eq!(fees, vec![(EDIT_MS, 1), (0, 2)]);
    let dated = price_dated(
        [],
        fees,
        0,
        &live,
        Some(DatedHistory {
            view: history.current(),
            now_ms: EDIT_MS + 1,
        }),
    )
    .unwrap();
    assert_eq!(dated.minor_i64(), Ok(2 * 5 + 7));
}

/// A refund returns the newest dated era's request first, then the undated remainder; the split
/// never goes negative.
#[test]
fn a_refund_takes_the_newest_era_first() {
    let mut eras = FeeEras::default();
    eras.charge(EDIT_MS);
    eras.charge(EDIT_MS + 5);
    eras.refund(); // the caller's total goes 2 -> 1 in the same step
    assert_eq!(
        eras.split(1).collect::<Vec<_>>(),
        vec![(EDIT_MS, 1), (EDIT_MS + 5, 0), (0, 0)]
    );
    eras.refund();
    eras.refund(); // nothing dated left: the caller's total carries it
    assert_eq!(
        eras.split(0).collect::<Vec<_>>(),
        vec![(EDIT_MS, 0), (EDIT_MS + 5, 0), (0, 0)]
    );
}

/// A segment whose era began before the window resolves at the window's start: the card in force
/// when the window opened, never an older one.
#[test]
fn an_era_older_than_the_window_resolves_at_the_window_start() {
    let history = edited(card(20.0, 0), card(10.0, 0));
    let live = card(10.0, 0);
    let units = input(100_000);
    let dated = price_dated(
        [("m", 0, &units)],
        [],
        EDIT_MS + 1_000,
        &live,
        Some(DatedHistory {
            view: history.current(),
            now_ms: EDIT_MS + 2_000,
        }),
    )
    .unwrap();
    assert_eq!(dated.minor_i64(), Ok(100));
}

/// The segment in force NOW prices at the caller's live card, which carries the open classes a
/// deployment configured (item 123); a present card silent about a hit class still REFUSES (#42)
/// for a segment resolved to an older entry.
#[test]
fn the_in_force_segment_prices_at_the_live_card_and_an_older_one_at_its_own() {
    let history = edited(card(1.0, 0), card(1.0, 0));
    let live = card(1.0, 0).with_unit_rates([(LaneClass::new("m", "search_units"), 1_000_000)]);
    let units = BTreeMap::from([("search_units".to_string(), 3u64)]);
    let view = history.current();
    let now = DatedHistory {
        view,
        now_ms: EDIT_MS + 1,
    };
    let live_era = price_dated([("m", EDIT_MS, &units)], [], 0, &live, Some(now)).unwrap();
    assert_eq!(live_era.micros_i64(), Ok(3_000));
    let old_era = price_dated([("m", 0, &units)], [], 0, &live, Some(now));
    assert!(
        matches!(old_era, Err(MoneyError::ClassUnpriced { .. })),
        "{old_era:?}"
    );
}

/// A hole in the history is a refusal, never a zero.
#[test]
fn a_segment_no_entry_covers_refuses() {
    let mut history = History::new();
    history.append(CardEntryDraft {
        effective_from: EDIT_MS,
        effective_until: None,
        card: card(1.0, 0),
        appended_at: EDIT_MS,
        author: Author::Config { policy_epoch: 0 },
    });
    let units = input(1);
    let got = price_dated(
        [("m", 0, &units)],
        [],
        0,
        &card(1.0, 0),
        Some(DatedHistory {
            view: history.current(),
            now_ms: EDIT_MS,
        }),
    );
    assert!(
        matches!(got, Err(MoneyError::NoCardInForce { at: 0 })),
        "{got:?}"
    );
}
