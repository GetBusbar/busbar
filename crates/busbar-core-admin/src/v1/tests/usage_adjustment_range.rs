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

fn row(model: &str, era: u64, count: i128) -> MeteringRow {
    MeteringRow {
        scale: 0,
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
        [9_000_000, 11_000_000, 5_000_000]
    );
    fold_adjustments(&mut rows, &[adjustment(LANE, 3)]).unwrap();
    assert_eq!(
        rows.iter().map(|row| row.tokens_input).collect::<Vec<_>>(),
        [9_000_000, 14_000_000, 5_000_000]
    );
}

#[test]
fn negative_fold_spans_rows_and_keeps_other_eras_unchanged() {
    let mut rows = vec![row(LANE, 0, 7), row(LANE, 0, 9), row(LANE, OTHER_ERA, 1)];
    fold_adjustments(&mut rows, &[adjustment(LANE, -16)]).expect("distributed subtraction");
    assert_eq!(
        rows.iter().map(|row| row.tokens_input).collect::<Vec<_>>(),
        vec![0, 0, 1_000_000]
    );
}

#[test]
fn empty_model_fold_keeps_scaled_counts_and_rejects_out_of_range_magnitudes() {
    let mut rows = vec![row("", 0, 0)];
    let maximum_whole = i128::MAX / 1_000_000;
    fold_adjustments(&mut rows, &[adjustment("", maximum_whole)]).expect("empty model lane");
    assert_eq!(rows[0].tokens_input, maximum_whole * 1_000_000);
    let unchanged = rows.clone();
    for invalid in [maximum_whole + 1, -(maximum_whole + 1), i128::MIN] {
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

#[test]
fn whole_adjustment_preserves_fractional_remainder_and_rejection_is_atomic() {
    let mut measured = row(LANE, 0, 27_500_000);
    measured.scale = 6;
    let mut rows = vec![measured];
    fold_adjustments(&mut rows, &[adjustment(LANE, -2)]).unwrap();
    assert_eq!(rows[0].tokens_input, 25_500_000);
    let before = rows.clone();
    assert!(fold_adjustments(&mut rows, &[adjustment(LANE, -26)]).is_err());
    assert_eq!(rows, before);
}

#[test]
fn fractional_adjustments_project_without_whole_unit_rounding() {
    let mut rows = vec![row(LANE, 0, 1)];
    let exact = UsageAdjustment {
        key_id: KEY.into(),
        lane: LANE.into(),
        era: 0,
        entry_id: None,
        delta: BTreeMap::from([(
            UNIT_INPUT.into(),
            busbar_contract::Count::parse("-0.000001").unwrap(),
        )]),
    };
    super::super::fold_adjustments_exact(&mut rows, &[exact]).unwrap();
    assert_eq!(rows[0].scale, 6);
    assert_eq!(rows[0].tokens_input, 999_999);
}

#[test]
fn exact_full_range_adjustments_preserve_wide_fractional_columns() {
    use busbar_contract::Count;
    let quantity = Count::parse("9007199254740993.000001").unwrap();
    let mut rows = vec![row(LANE, 0, 0)];
    let adjustment = |delta| UsageAdjustment {
        key_id: KEY.into(),
        lane: LANE.into(),
        era: 0,
        entry_id: None,
        delta: BTreeMap::from([(UNIT_INPUT.into(), delta), ("seconds".into(), delta)]),
    };
    super::super::fold_adjustments_exact(&mut rows, &[adjustment(quantity)]).unwrap();
    assert_eq!(rows[0].tokens_input, quantity.micros());
    assert_eq!(rows[0].usage_units["seconds"], quantity.micros());
    super::super::fold_adjustments_exact(&mut rows, &[adjustment(Count::from_micros(-1))]).unwrap();
    assert_eq!(rows[0].tokens_input, quantity.micros() - 1);
    assert_eq!(rows[0].usage_units["seconds"], quantity.micros() - 1);
}

#[test]
fn minimum_signed_adjustment_spans_rows_without_magnitude_narrowing() {
    use busbar_contract::Count;
    let mut first = row(LANE, 0, i128::MAX);
    first.scale = 6;
    let mut second = row(LANE, 0, 1);
    second.scale = 6;
    let mut rows = vec![first, second];
    let adjustment = UsageAdjustment {
        key_id: KEY.into(),
        lane: LANE.into(),
        era: 0,
        entry_id: None,
        delta: BTreeMap::from([(UNIT_INPUT.into(), Count::from_micros(i128::MIN))]),
    };
    super::super::fold_adjustments_exact(&mut rows, &[adjustment]).unwrap();
    assert_eq!(
        rows.iter().map(|row| row.tokens_input).collect::<Vec<_>>(),
        [0, 0]
    );
}

#[test]
fn exact_positive_overflow_leaves_all_columns_unchanged() {
    use busbar_contract::Count;
    let mut measured = row(LANE, 0, i128::MAX);
    measured.scale = 6;
    let mut rows = vec![measured];
    let before = rows.clone();
    let adjustment = UsageAdjustment {
        key_id: KEY.into(),
        lane: LANE.into(),
        era: 0,
        entry_id: None,
        delta: BTreeMap::from([(UNIT_INPUT.into(), Count::from_micros(1))]),
    };
    assert!(super::super::fold_adjustments_exact(&mut rows, &[adjustment]).is_err());
    assert_eq!(rows, before);
}
