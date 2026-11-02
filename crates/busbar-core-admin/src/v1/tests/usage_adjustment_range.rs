// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::super::fold_adjustments;
use busbar_contract::records::{MeteringRow, UNIT_INPUT};
use busbar_kernel::cost::{CostModel, History};
use busbar_kernel::governance::UsageAdjustment;
use std::collections::BTreeMap;

const KEY: &str = "adjustment-range-key";
const LANE: &str = "adjustment-range-model";
const PROVIDER: &str = "adjustment-range-provider";
const OTHER_ERA: u64 = 1;

fn zero_cost() -> CostModel {
    let rates = BTreeMap::from([(
        LANE.into(),
        busbar_kernel::config::RateEntryCfg {
            input_utok: 0.0,
            output_utok: 0.0,
            cache_read_utok: 0.0,
            cache_write_utok: 0.0,
            ..Default::default()
        },
    )]);
    CostModel::resolve_parts(Some(&rates), 0, &BTreeMap::new())
}

fn row(model: &str, era: u64, count: u64) -> MeteringRow {
    MeteringRow {
        key_id: KEY.into(),
        model: model.into(),
        provider: PROVIDER.into(),
        tokens_input: count,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        priced_from_ms: era,
        usage_units: BTreeMap::new(),
    }
}

fn adjustment(lane: &str, delta: i128) -> UsageAdjustment {
    UsageAdjustment {
        key_id: KEY.into(),
        lane: lane.into(),
        era: 0,
        entry_id: None,
        delta: BTreeMap::from([(UNIT_INPUT.into(), delta)]),
    }
}

#[test]
fn adjustments_at_one_timestamp_only_change_rows_of_their_recorded_entry() {
    let first_history = History::opening(zero_cost().card().clone(), 0);
    let second_history = History::opening(zero_cost().card().clone(), 1);
    let first_id = first_history.entries()[0].id();
    let second_id = second_history.entries()[0].id();
    assert_ne!(first_id, second_id);
    let mut first = row(LANE, 0, 7);
    first.pricing_version = first_id.metering_version();
    let mut second = row(LANE, 0, 9);
    second.pricing_version = second_id.metering_version();
    let mut rows = vec![second, row(LANE, 0, 11), first];
    let mut exact = adjustment(LANE, -2);
    exact.entry_id = Some(first_id);
    fold_adjustments(&mut rows, &[exact]).unwrap();
    assert_eq!(
        rows.iter().map(|row| row.tokens_input).collect::<Vec<_>>(),
        [9, 11, 5]
    );
    fold_adjustments(&mut rows, &[adjustment(LANE, 3)]).unwrap();
    assert_eq!(
        rows.iter().map(|row| row.tokens_input).collect::<Vec<_>>(),
        [9, 14, 5]
    );
}

#[test]
fn full_unsigned_negative_fold_spans_rows_and_keeps_other_eras_unchanged() {
    let mut rows = vec![
        row(LANE, 0, i64::MIN.unsigned_abs()),
        row(LANE, 0, i64::MAX as u64),
        row(LANE, OTHER_ERA, 1),
    ];
    fold_adjustments(&mut rows, &[adjustment(LANE, -i128::from(u64::MAX))])
        .expect("distributed subtraction");
    assert_eq!(
        rows.iter().map(|row| row.tokens_input).collect::<Vec<_>>(),
        vec![0, 0, 1]
    );
}

#[test]
fn empty_model_fold_keeps_full_unsigned_counts_and_rejects_out_of_range_magnitudes() {
    let mut rows = vec![row("", 0, 0)];
    fold_adjustments(&mut rows, &[adjustment("", i128::from(u64::MAX))]).expect("empty model lane");
    assert_eq!(rows[0].tokens_input, u64::MAX);
    let unchanged = rows.clone();
    for invalid in [
        i128::from(u64::MAX) + 1,
        -(i128::from(u64::MAX) + 1),
        i128::MIN,
    ] {
        assert!(fold_adjustments(&mut rows, &[adjustment("", invalid)]).is_err());
        assert_eq!(
            rows, unchanged,
            "magnitude refusal must not truncate or touch a column"
        );
    }
    assert!(fold_adjustments(&mut rows, &[adjustment("", 1)]).is_err());
    assert_eq!(
        rows, unchanged,
        "checked positive overflow preserves the column"
    );
}
