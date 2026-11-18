// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A cell's fee splits read where they lie. A correction used to fold each split into a map by
//! era to find a count, total a split and walk two splits' eras in order; it now reads the
//! splits themselves. These hold the two to the same answers, over splits in every order
//! requests can leave them in.

use super::*;
use busbar_kernel_ledger::cost::EntryId;

fn dated(at: u64) -> RawRateEra {
    RawRateEra::legacy(at)
}

fn entry(at: u64, id: u8) -> RawRateEra {
    RawRateEra {
        effective_from: at,
        entry_id: Some(EntryId([id; 12])),
    }
}

/// Splits as requests leave them: none, one era, ascending, descending, interleaved with one era
/// under two entries and one held at no count, and (never written, read the same) an era named
/// twice.
fn splits() -> Vec<Vec<(RawRateEra, u64)>> {
    vec![
        vec![],
        vec![(dated(5), 1)],
        vec![(dated(3), 1), (dated(4), 1), (dated(9), 2)],
        vec![(dated(9), 5), (dated(6), 3), (dated(3), 4)],
        vec![
            (dated(9), 5),
            (dated(3), 4),
            (entry(3, 7), 2),
            (dated(6), 0),
            (entry(3, 1), 8),
        ],
        vec![(dated(3), 1), (dated(9), 2), (dated(3), 7)],
        vec![(dated(u64::MAX), u64::MAX), (dated(1), u64::MAX)],
    ]
}

fn folded(split: &[(RawRateEra, u64)]) -> BTreeMap<RawRateEra, u64> {
    split.iter().copied().collect()
}

#[test]
fn a_split_read_where_it_lies_counts_and_totals_as_its_map_did() {
    for split in &splits() {
        let map = folded(split);
        assert_eq!(
            fee_total(split),
            map.values().map(|count| i128::from(*count)).sum::<i128>(),
            "{split:?}"
        );
        for (era, count) in &map {
            assert_eq!(fee_count(split, *era), *count, "{split:?} at {era:?}");
        }
        for absent in [dated(0), dated(2), entry(3, 2), entry(9, 7)] {
            assert_eq!(
                fee_count(split, absent),
                map.get(&absent).copied().unwrap_or(0),
                "{split:?} at {absent:?}"
            );
        }
    }
}

#[test]
fn the_eras_of_two_splits_come_ascending_and_once_as_their_maps_keys_did() {
    for a in &splits() {
        for b in &splits() {
            let (map_a, map_b) = (folded(a), folded(b));
            let union: Vec<RawRateEra> =
                crate::governance::sorted_union(map_a.keys().copied(), map_b.keys().copied())
                    .collect();
            let walked: Vec<RawRateEra> = eras_ascending(eras_of(a), eras_of(b)).collect();
            assert_eq!(walked, union, "{a:?} with {b:?}");
            // The eras of a split and the keys of a map of transfers, as the baseline is rebuilt.
            let walked: Vec<RawRateEra> =
                eras_ascending(eras_of(a), map_b.keys().copied()).collect();
            assert_eq!(walked, union, "{a:?} with the keys of {b:?}");
        }
    }
}

fn rows(split: &[(RawRateEra, u64)]) -> Vec<(RawEra, u64)> {
    split
        .iter()
        .map(|(era, count)| (RawEra::from(*era), *count))
        .collect()
}

#[test]
fn a_custody_fee_split_reads_back_in_its_stored_order() {
    let stored = [
        (dated(9), 5),
        (dated(3), 4),
        (entry(3, 7), 2),
        (entry(3, 1), 8),
    ];
    let read = fee_split(rows(&stored)).expect("the split reads back");
    assert_eq!(read.dated(), &stored);
    assert_eq!(read, RawFeeEras::of(stored));
    assert_eq!(
        fee_split(Vec::new()).expect("no eras"),
        RawFeeEras::default()
    );
}

/// A custody cell names each (model, era) once; the same model under another era is another row.
#[test]
fn a_custody_cell_naming_one_model_era_twice_is_refused() {
    let counted = |era: RawRateEra| {
        ModelCell::new(
            "m".into(),
            era,
            BTreeMap::from([("input".to_owned(), Count::from_integer(1).unwrap())]),
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .expect("a named model")
    };
    let cell = BudgetCell {
        models: vec![counted(dated(9)), counted(entry(9, 7)), counted(dated(3))],
        ..Default::default()
    };
    let record = RawCell::capture(&cell).expect("captures");
    assert_eq!(
        record
            .clone()
            .restore("bucket")
            .expect("three rows, each once")
            .models
            .len(),
        3
    );
    let mut repeated = record;
    let again = repeated.models[1].clone();
    repeated.models.push(again);
    let error = repeated
        .restore("bucket")
        .err()
        .expect("the repeated row is refused");
    assert_eq!(
        error.0.to_string(),
        "usage correction unresolved: duplicate raw model era in custody"
    );
}

#[test]
fn a_custody_fee_split_with_a_repeated_undated_or_empty_era_is_refused() {
    let refused = [
        vec![(dated(9), 5), (dated(3), 4), (dated(9), 1)],
        vec![(entry(3, 7), 2), (entry(3, 7), 2)],
        vec![(dated(9), 5), (dated(0), 4)],
        vec![(dated(0), 1)],
        vec![(dated(9), 5), (dated(3), 0)],
        vec![(dated(3), 0)],
    ];
    for split in &refused {
        let error = fee_split(rows(split)).expect_err("the split is refused");
        assert_eq!(
            error.0.to_string(),
            "usage correction unresolved: invalid raw fee era in custody",
            "{split:?}"
        );
    }
}
