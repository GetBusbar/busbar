// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Prices each dated budget segment at the rate card in force when its usage occurred.

use std::collections::BTreeMap;

use crate::cost::{
    price_in_view, Author, CardEntryDraft, History, LaneClass, LedgerEntry, MoneyError, RateCard,
    Tally, STANDARD_TIER_BP,
};
use crate::usage::{price_dated, price_dated_raw, DatedHistory, FeeEras};

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
    let mut eras = FeeEras::<u64>::default();
    eras.charge(0);
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

/// MONEY-AUDIT D-3/F-5: a refund returns the fee of the era its request was CHARGED in, not the
#[test]
fn a_refund_takes_the_era_its_request_was_charged_in() {
    let (e1, e2) = (EDIT_MS, EDIT_MS + 5);
    let mut eras = FeeEras::<u64>::default();
    eras.charge(e1);
    eras.charge(e2);
    eras.refund(e1);
    assert_eq!(
        eras.split(1).collect::<Vec<_>>(),
        vec![(e1, 0), (e2, 1), (0, 0)],
        "the E1 request's fee came back; the E2 request is still billed at E2"
    );

    let mut eras = FeeEras::<u64>::default();
    eras.charge(0);
    eras.charge(e1);
    eras.refund(0);
    assert_eq!(eras.split(1).collect::<Vec<_>>(), vec![(e1, 1), (0, 0)]);
}

/// A segment whose era began before the window resolves at the window's start: the card in force
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

/// A Store confirmation may arrive after another window begins. The recorded serving identity
#[test]
fn exact_opening_and_config_counts_keep_their_prices_across_later_windows() {
    use crate::cost::RawRateEra;

    let history = edited(card(20.0, 5), card(10.0, 7));
    let old = RawRateEra::entry(0, history.entries()[0].id());
    let new = RawRateEra::entry(EDIT_MS, history.entries()[1].id());
    let units = input(100_000);
    let live = card(10.0, 7);
    let window_start = EDIT_MS + 1_000;
    let dated = Some(DatedHistory::of(&history, window_start));
    let mut fees = FeeEras::<RawRateEra>::default();
    fees.charge(old);
    fees.charge(new);
    assert_eq!(fees.dated(), &[(old, 1), (new, 1)]);
    let got = price_dated_raw(
        [("m", old, &units), ("m", new, &units)],
        fees.split(2),
        window_start,
        &live,
        dated,
    )
    .expect("both serving entries are known");
    assert_eq!(got.minor_i64(), Ok(200 + 100 + 5 + 7));

    let undated = price_dated([("m", 0, &units)], [(0, 1)], window_start, &live, dated)
        .expect("a legacy row resolves at its window start");
    assert_eq!(undated.minor_i64(), Ok(100 + 7));
    let other_node_live = card(20.0, 5);
    let current_entry = price_dated_raw(
        [("m", new, &units)],
        [(new, 1)],
        window_start,
        &other_node_live,
        dated,
    )
    .expect("the exact entry takes precedence over another node's live configuration");
    assert_eq!(current_entry.minor_i64(), Ok(100 + 7));
    fees.refund(old);
    assert_eq!(
        fees.split(1).collect::<Vec<_>>(),
        vec![(old, 0), (new, 1), (RawRateEra::legacy(0), 0)]
    );
    let restored = FeeEras::<RawRateEra>::of([(old, 1), (RawRateEra::legacy(0), 1)]);
    assert_eq!(
        restored.dated(),
        &[(old, 1)],
        "opening identity survives durable fee hydration"
    );
}

#[test]
fn a_nonzero_serving_era_before_the_window_keeps_its_original_card() {
    let mut history = edited(card(20.0, 0), card(10.0, 0));
    let later_edit = EDIT_MS + 1_000;
    history.append(CardEntryDraft {
        effective_from: later_edit,
        effective_until: None,
        card: card(1.0, 0),
        appended_at: later_edit,
        author: Author::Config { policy_epoch: 2 },
    });
    let units = input(100_000);
    let live = card(1.0, 0);
    let window_start = later_edit + 1_000;
    let got = price_dated(
        [("m", EDIT_MS, &units)],
        [],
        window_start,
        &live,
        Some(DatedHistory::of(&history, window_start)),
    )
    .expect("the timestamp names its unique original entry");
    assert_eq!(got.minor_i64(), Ok(100));
}

#[test]
fn an_amendment_uses_wall_window_and_never_the_live_configuration_card() {
    use crate::cost::{HistorySeq, RawRateEra};

    let mut history = edited(card(20.0, 5), card(10.0, 7));
    let old = RawRateEra::entry(0, history.entries()[0].id());
    let from = EDIT_MS + 1_000;
    let until = from + 1_000;
    history.append(CardEntryDraft {
        effective_from: from,
        effective_until: Some(until),
        card: card(3.0, 2),
        appended_at: until + 1_000,
        author: Author::Amend {
            reason_hash: [7; 32],
        },
    });
    let units = input(100_000);
    let live = card(10.0, 7);
    let price_at = |window_start, view| {
        price_dated_raw(
            [("m", old, &units)],
            [(old, 1)],
            window_start,
            &live,
            Some(DatedHistory { view, now_ms: from }),
        )
        .expect("the amendment and original card are recorded")
        .minor_i64()
    };
    assert_eq!(price_at(from - 1, history.current()), Ok(200 + 5));
    assert_eq!(price_at(from, history.current()), Ok(30 + 2));
    assert_eq!(price_at(until - 1, history.current()), Ok(30 + 2));
    assert_eq!(price_at(until, history.current()), Ok(200 + 5));
    assert_eq!(price_at(from, history.snapshot(HistorySeq(1))), Ok(200 + 5));
    let amendment_key = history.entries()[2].key();
    let mut voided = history.clone();
    voided.void(&amendment_key);
    assert_eq!(price_at(from, voided.current()), Ok(200 + 5));
}

#[test]
fn exact_provenance_prices_open_classes_and_every_fee_lane_through_tally() {
    use crate::cost::{plane_fee_lane, PlaneFees, RawRateEra, PER_REQUEST, PER_SESSION};

    const OPEN_CLASS: &str = "search_units";
    const PLANE: &str = "search";
    let old_card = card(2.0, 5)
        .with_unit_rates([(LaneClass::new("m", OPEN_CLASS), 3_000)])
        .with_plane_fees([(
            PLANE,
            PlaneFees {
                per_request: 7,
                per_session: 11,
            },
        )]);
    let new_card = card(1.0, 2)
        .with_unit_rates([(LaneClass::new("m", OPEN_CLASS), 1_000)])
        .with_plane_fees([(
            PLANE,
            PlaneFees {
                per_request: 1,
                per_session: 3,
            },
        )]);
    let history = edited(old_card.clone(), new_card.clone());
    let old = RawRateEra::entry(0, history.entries()[0].id());
    let units = BTreeMap::from([
        ("input".to_string(), 10_000),
        (OPEN_CLASS.to_string(), 20_000),
    ]);
    let plane_fees = BTreeMap::from([(PER_REQUEST.to_string(), 3), (PER_SESSION.to_string(), 2)]);
    let fee_lane = plane_fee_lane(PLANE);
    let got = price_dated_raw(
        [("m", old, &units), (fee_lane.as_str(), old, &plane_fees)],
        [(old, 2)],
        EDIT_MS + 1_000,
        &new_card,
        Some(DatedHistory::of(&history, EDIT_MS + 1_000)),
    )
    .expect("all counts use the old complete card");
    assert_eq!(got.minor_i64(), Ok(2 + 6 + 2 * 5 + 3 * 7 + 2 * 11));
}

#[test]
fn exact_provenance_missing_entry_and_overflow_still_refuse() {
    use crate::cost::{EntryKey, RawRateEra};

    let history = edited(card(2.0, 0), card(1.0, 0));
    let units = input(1);
    let missing = RawRateEra::entry(0, EntryKey::new(42, [1; 8], 0).id());
    let at = EDIT_MS + 1_000;
    let live = card(1.0, 0);
    assert_eq!(
        price_dated_raw(
            [("m", missing, &units)],
            [],
            at,
            &live,
            Some(DatedHistory::of(&history, at))
        ),
        Err(MoneyError::NoCardInForce { at })
    );
    let expensive = card(1.0, 0).with_unit_rates([(LaneClass::new("m", "input"), u64::MAX)]);
    let history = History::opening(expensive.clone(), 0);
    let old = RawRateEra::entry(0, history.entries()[0].id());
    let units = input(u64::MAX);
    assert_eq!(
        price_dated_raw(
            [("m", old, &units)],
            [],
            0,
            &expensive,
            Some(DatedHistory::of(&history, 0))
        ),
        Err(MoneyError::Overflow)
    );
}

#[test]
fn an_old_entry_row_can_straddle_a_nominal_configuration_cutover() {
    use crate::cost::RawRateEra;

    const BUCKET_MS: u64 = 1_000;
    let bucket_start = EDIT_MS;
    let cutover = bucket_start + BUCKET_MS / 2;
    let mut history = History::opening(card(20.0, 0), 0);
    let old = RawRateEra::entry(0, history.entries()[0].id());
    history.append(CardEntryDraft {
        effective_from: cutover,
        effective_until: None,
        card: card(10.0, 0),
        appended_at: cutover,
        author: Author::Config { policy_epoch: 1 },
    });

    let before = input(100_000);
    let after = input(200_000);
    let total = BTreeMap::from([("input".to_string(), before["input"] + after["input"])]);
    let live = card(10.0, 0);
    let got = price_dated_raw(
        [("m", old, &total)],
        [],
        bucket_start,
        &live,
        Some(DatedHistory::of(&history, bucket_start + BUCKET_MS)),
    )
    .expect("the exact old entry prices the entire aggregate");
    assert_eq!(got.minor_i64(), Ok(600));
    assert_eq!(
        history.current().correction_cut(
            cutover,
            Some(bucket_start + BUCKET_MS),
            bucket_start + BUCKET_MS,
            BUCKET_MS
        ),
        Some(cutover),
        "the nominal new entry does not prove the old aggregate was split at activation"
    );
    assert_eq!(
        history.current().correction_cut(
            bucket_start,
            Some(bucket_start + BUCKET_MS),
            bucket_start + BUCKET_MS,
            BUCKET_MS
        ),
        None,
        "the actual bucket boundary separates all raw rows"
    );
}
