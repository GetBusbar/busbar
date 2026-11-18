// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Prices each dated budget segment at the rate card in force when its usage occurred.

use std::collections::BTreeMap;

use crate::cost::{
    price_in_view, Author, CardEntryDraft, History, LaneClass, LedgerEntry, MoneyError, RateCard,
    Tally, STANDARD_TIER_BP,
};
use crate::cost::{Count, Money, RawRateEra};
use crate::usage::{price_dated_counts_raw, DatedHistory, FeeEras};

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

/// Price whole counts carrying exact provenance through the production entry point.
fn price_raw<'a>(
    rows: impl IntoIterator<Item = (&'a str, RawRateEra, &'a BTreeMap<String, u64>)>,
    fees: impl IntoIterator<Item = (RawRateEra, u64)>,
    window_start_ms: u64,
    live: &RateCard,
    dated: Option<DatedHistory<'_>>,
) -> Result<Money, MoneyError> {
    let rows: Vec<(&str, RawRateEra, BTreeMap<String, Count>)> = rows
        .into_iter()
        .map(|(lane, era, counts)| {
            let counts = counts
                .iter()
                .map(|(class, n)| (class.clone(), Count::from(*n)))
                .collect();
            (lane, era, counts)
        })
        .collect();
    let fees: Vec<(RawRateEra, u64)> = fees.into_iter().collect();
    price_dated_counts_raw(
        rows.iter().map(|(lane, era, counts)| (*lane, *era, counts)),
        fees,
        window_start_ms,
        live,
        dated,
    )
}

/// [`price_raw`] for rows and fees dated by a legacy timestamp era.
fn price_legacy<'a>(
    rows: impl IntoIterator<Item = (&'a str, u64, &'a BTreeMap<String, u64>)>,
    fees: impl IntoIterator<Item = (u64, u64)>,
    window_start_ms: u64,
    live: &RateCard,
    dated: Option<DatedHistory<'_>>,
) -> Result<Money, MoneyError> {
    price_raw(
        rows.into_iter()
            .map(|(lane, era, counts)| (lane, RawRateEra::legacy(era), counts)),
        fees.into_iter()
            .map(|(era, n)| (RawRateEra::legacy(era), n)),
        window_start_ms,
        live,
        dated,
    )
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
    let dated = price_legacy(
        [("m", 0, &before), ("m", EDIT_MS, &after)],
        [],
        0,
        &live,
        Some(DatedHistory {
            view: history.current(),
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
        price_legacy([("m", 0, &before), ("m", 0, &after)], [], 0, &live, None).expect("priced");
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
    let dated = price_legacy([("m", 0, &units)], [(0, 9)], 0, &live, None).unwrap();
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
    let dated = price_legacy(
        [],
        fees,
        0,
        &live,
        Some(DatedHistory {
            view: history.current(),
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
    let dated = price_legacy(
        [("m", 0, &units)],
        [],
        EDIT_MS + 1_000,
        &live,
        Some(DatedHistory {
            view: history.current(),
        }),
    )
    .unwrap();
    assert_eq!(dated.minor_i64(), Ok(100));
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
    let got = price_legacy(
        [("m", 0, &units)],
        [],
        0,
        &card(1.0, 0),
        Some(DatedHistory {
            view: history.current(),
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
    let history = edited(card(20.0, 5), card(10.0, 7));
    let old = RawRateEra::entry(0, history.entries()[0].id());
    let new = RawRateEra::entry(EDIT_MS, history.entries()[1].id());
    let units = input(100_000);
    let live = card(10.0, 7);
    let window_start = EDIT_MS + 1_000;
    let dated = Some(DatedHistory::of(&history));
    let mut fees = FeeEras::<RawRateEra>::default();
    fees.charge(old);
    fees.charge(new);
    assert_eq!(fees.dated(), &[(old, 1), (new, 1)]);
    let got = price_raw(
        [("m", old, &units), ("m", new, &units)],
        fees.split(2),
        window_start,
        &live,
        dated,
    )
    .expect("both serving entries are known");
    assert_eq!(got.minor_i64(), Ok(200 + 100 + 5 + 7));

    let undated = price_legacy([("m", 0, &units)], [(0, 1)], window_start, &live, dated)
        .expect("a legacy row resolves at its window start");
    assert_eq!(undated.minor_i64(), Ok(100 + 7));
    let other_node_live = card(20.0, 5);
    let current_entry = price_raw(
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
    let got = price_legacy(
        [("m", EDIT_MS, &units)],
        [],
        window_start,
        &live,
        Some(DatedHistory::of(&history)),
    )
    .expect("the timestamp names its unique original entry");
    assert_eq!(got.minor_i64(), Ok(100));
}

#[test]
fn an_amendment_uses_wall_window_and_never_the_live_configuration_card() {
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
        price_raw(
            [("m", old, &units)],
            [(old, 1)],
            window_start,
            &live,
            Some(DatedHistory { view }),
        )
        .expect("the amendment and original card are recorded")
        .minor_i64()
    };
    assert_eq!(price_at(from - 1, history.current()), Ok(200 + 5));
    assert_eq!(price_at(from, history.current()), Ok(30 + 2));
    assert_eq!(price_at(until - 1, history.current()), Ok(30 + 2));
    assert_eq!(price_at(until, history.current()), Ok(200 + 5));
    assert_eq!(
        price_at(from, history.snapshot(history.entries()[1].key())),
        Ok(200 + 5)
    );
    let amendment_key = history.entries()[2].key();
    let mut voided = history.clone();
    voided.void(&amendment_key);
    assert_eq!(price_at(from, voided.current()), Ok(200 + 5));
}

#[test]
fn exact_provenance_prices_open_classes_and_every_fee_lane_through_tally() {
    use crate::cost::{plane_fee_lane, PlaneFees, PER_REQUEST, PER_SESSION};

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
    let got = price_raw(
        [("m", old, &units), (fee_lane.as_str(), old, &plane_fees)],
        [(old, 2)],
        EDIT_MS + 1_000,
        &new_card,
        Some(DatedHistory::of(&history)),
    )
    .expect("all counts use the old complete card");
    assert_eq!(got.minor_i64(), Ok(2 + 6 + 2 * 5 + 3 * 7 + 2 * 11));
}

#[test]
fn exact_provenance_missing_entry_and_overflow_still_refuse() {
    use crate::cost::EntryKey;

    let history = edited(card(2.0, 0), card(1.0, 0));
    let units = input(1);
    let missing = RawRateEra::entry(0, EntryKey::new(42, [1; 8], 0).id());
    let at = EDIT_MS + 1_000;
    let live = card(1.0, 0);
    assert_eq!(
        price_raw(
            [("m", missing, &units)],
            [],
            at,
            &live,
            Some(DatedHistory::of(&history))
        ),
        Err(MoneyError::NoCardInForce { at })
    );
    let expensive = card(1.0, 0).with_unit_rates([(LaneClass::new("m", "input"), u64::MAX)]);
    let history = History::opening(expensive.clone(), 0);
    let old = RawRateEra::entry(0, history.entries()[0].id());
    let units = input(u64::MAX);
    assert_eq!(
        price_raw(
            [("m", old, &units)],
            [],
            0,
            &expensive,
            Some(DatedHistory::of(&history))
        ),
        Err(MoneyError::Overflow)
    );
}

#[test]
fn an_old_entry_row_can_straddle_a_nominal_configuration_cutover() {
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
    let got = price_raw(
        [("m", old, &total)],
        [],
        bucket_start,
        &live,
        Some(DatedHistory::of(&history)),
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

#[test]
fn measurement_dated_readback_prices_only_reported_classes_at_the_serving_entry() {
    use crate::cost::measurement_lane;
    let lane = measurement_lane("store", "primary");
    let measured_card =
        |nanos| RateCard::absent(99).with_unit_rates([(LaneClass::new(&lane, "input"), nanos)]);
    let live = measured_card(500);
    let history = edited(measured_card(125), live.clone());
    let old = RawRateEra::entry(0, history.entries()[0].id());
    let new = RawRateEra::entry(EDIT_MS, history.entries()[1].id());
    // This is BudgetCell.cur's raw-class shape: no manufactured token tiers or request fee.
    let counts = BTreeMap::from([("input".to_string(), Count::from_micros(8_000_000))]);
    let got = crate::usage::price_dated_counts_raw(
        [(lane.as_str(), old, &counts), (lane.as_str(), new, &counts)],
        [],
        EDIT_MS + 1_000,
        &live,
        Some(DatedHistory::of(&history)),
    )
    .unwrap();
    assert_eq!(got, Money::of_nanos(5_000).unwrap());
    let unpriced = BTreeMap::from([("output".to_string(), Count::from_micros(1_000_000))]);
    assert!(matches!(
        crate::usage::price_dated_counts_raw(
            [(lane.as_str(), old, &unpriced)],
            [],
            EDIT_MS + 1_000,
            &live,
            Some(DatedHistory::of(&history)),
        ),
        Err(MoneyError::ClassUnpriced { .. })
    ));
}

/// The fee eras against the list they replaced: a fixed pseudo-random run of charges and refunds
/// over a handful of eras (legacy zero included) gives the same rows in first-seen order, the same
/// counts, and the same split of any billable total.
#[test]
fn fee_eras_equal_the_list_they_replaced_over_a_random_run() {
    let mut state = 0x2545_F491_4F6C_DD1D_u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    // The list as it was: one entry per era in first-seen order, and the dated total.
    let mut model: Vec<(u64, u64)> = Vec::new();
    let mut total = 0u64;
    let mut eras = FeeEras::<u64>::default();
    for step in 0..4_000 {
        let roll = next();
        let era = (roll >> 8) % 6; // 0 is the implicit remainder
        if roll % 3 == 0 {
            eras.refund(era);
            if let Some((_, n)) = model.iter_mut().find(|(e, n)| *e == era && *n > 0) {
                *n -= 1;
                total -= 1;
            }
        } else {
            eras.charge(era);
            if era != 0 {
                match model.iter_mut().find(|(e, _)| *e == era) {
                    Some((_, n)) => *n += 1,
                    None => model.push((era, 1)),
                }
                total += 1;
            }
        }
        if step % 11 == 0 {
            assert_eq!(eras.dated(), model.as_slice(), "step {step}");
            let want: Vec<(u64, u64)> = model
                .iter()
                .copied()
                .chain([(0, 500u64.saturating_sub(total))])
                .collect();
            assert_eq!(eras.split(500).collect::<Vec<_>>(), want, "step {step}");
        }
    }
}

/// A split read back from durable rows keeps the first-seen order and finds each era again.
#[test]
fn fee_eras_read_back_are_found_by_era() {
    let mut eras = FeeEras::<u64>::of([(9, 2), (0, 5), (4, 0), (7, 1)]);
    assert_eq!(eras.dated(), &[(9, 2), (7, 1)]);
    eras.charge(7);
    eras.charge(5);
    eras.refund(9);
    assert_eq!(eras.dated(), &[(9, 1), (7, 2), (5, 1)]);
    assert_eq!(eras, FeeEras::<u64>::of([(9, 1), (7, 2), (5, 1)]));
}

/// A split built from counts that may each be refused is the split `of` builds from the same
/// counts, total included; the first refusal met ends it, and nothing after it is read.
#[test]
fn fee_eras_built_from_refusable_counts_are_the_same_split_or_the_first_refusal() {
    let rows = [(9u64, 2u64), (0, 5), (4, 0), (7, 1)];
    let built = FeeEras::<u64>::try_of(rows.into_iter().map(Ok::<_, &str>)).unwrap();
    assert_eq!(built, FeeEras::<u64>::of(rows));
    assert_eq!(built.dated(), &[(9, 2), (7, 1)]);
    assert_eq!(
        built.split(10).collect::<Vec<_>>(),
        FeeEras::<u64>::of(rows).split(10).collect::<Vec<_>>(),
        "the request total rides the split as it does when `of` builds it"
    );

    let mut read = 0;
    let refused = FeeEras::<u64>::try_of(
        [Ok((9, 2)), Err("second"), Err("third"), Ok((7, 1))]
            .into_iter()
            .inspect(|_| read += 1),
    );
    assert_eq!(refused, Err("second"));
    assert_eq!(read, 2, "the split stops reading at its first refusal");
}
