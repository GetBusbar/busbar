// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::json;

fn unit(model: &str, input: i128) -> ExactUsageDelta {
    let mut delta = ExactUsageDelta::default();
    delta.unit(model, "input", input);
    delta
}
fn input(delta: &ExactUsageDelta, model: &str) -> i128 {
    delta
        .models
        .iter()
        .find(|row| row.model == model)
        .and_then(|row| row.usage_units.get("input"))
        .copied()
        .unwrap_or(0)
}

#[test]
fn net_positive_aggregate_does_not_hide_a_dependent_negative_era() {
    let era_a = RawRateEra::entry(10, EntryId([1; 12]));
    let era_b = RawRateEra::entry(10, EntryId([2; 12]));
    let a = era_model(era_a, "model");
    let b = era_model(era_b, "model");
    let mut dated = unit(&a, -3);
    dated.merge(&unit(&b, 5));
    let mut remaining = SegmentedUsage::of(&unit("model", 2), &dated).unwrap();
    let capacity = SegmentedUsage::of(&unit("model", 7), &unit(&a, 7)).unwrap();
    let held = remaining.take_negatives(Some(&capacity));
    let (held_plain, held_dated) = held.deltas();
    assert_eq!(input(&held_plain, "model"), -3);
    assert_eq!(input(&held_dated, &a), -3);
    let (send_plain, send_dated) = remaining.deltas();
    assert_eq!(input(&send_plain, "model"), 5);
    assert_eq!(input(&send_dated, &b), 5);
    assert_eq!(input(&send_dated, &a), 0);
}

#[test]
fn signed_wire_chunks_preserve_era_cancellation_above_i64() {
    let a = era_model(RawRateEra::legacy(1), "model");
    let b = era_model(RawRateEra::legacy(2), "model");
    let mut plain = unit("model", 2);
    let mut dated = unit(&a, -i128::from(i64::MAX) - 7);
    dated.merge(&unit(&b, i128::from(i64::MAX) + 9));
    let mut posted_plain = ExactUsageDelta::default();
    let mut posted_dated = ExactUsageDelta::default();
    for _ in 0..3 {
        if plain.is_zero() && dated.is_zero() {
            break;
        }
        let (chunk_plain, chunk_dated) = SegmentedUsage::of(&plain, &dated).unwrap().chunk();
        let raw_plain = ExactUsageDelta::from_signed(&chunk_plain);
        let raw_dated = ExactUsageDelta::from_signed(&chunk_dated);
        assert_eq!(
            input(&raw_plain, "model"),
            input(&raw_dated, &a) + input(&raw_dated, &b)
        );
        plain.subtract(&chunk_plain);
        dated.subtract(&chunk_dated);
        posted_plain.merge(&raw_plain);
        posted_dated.merge(&raw_dated);
    }
    assert!(plain.is_zero() && dated.is_zero());
    assert_eq!(input(&posted_plain, "model"), 2);
    assert_eq!(input(&posted_dated, &a), -i128::from(i64::MAX) - 7);
    assert_eq!(input(&posted_dated, &b), i128::from(i64::MAX) + 9);
}

#[test]
fn signed_wire_preserves_full_range_and_acknowledges_minimum() {
    for count in [i128::MIN, i128::MAX] {
        let mut debt = unit("model", count);
        let signed = debt.signed().expect("full signed Count fits wire");
        assert_eq!(signed.models[0].usage_units["input"], count);
        debt.subtract(&signed);
        assert!(debt.is_zero());
    }
}

#[test]
fn full_range_era_segments_stay_paired_in_one_operation() {
    let era = era_model(RawRateEra::legacy(1), "model");
    for count in [i128::MIN, i128::MAX] {
        let plain = unit("model", count);
        let dated = unit(&era, count);
        let (sent_plain, sent_dated) = SegmentedUsage::of(&plain, &dated).unwrap().chunk();
        assert_eq!(sent_plain.models[0].usage_units["input"], count);
        assert_eq!(sent_dated.models[0].usage_units["input"], count);
    }
}

#[test]
fn custody_json_preserves_full_signed_counts_through_origin_value_rewrite() {
    let delta = ExactUsageDelta {
        requests: i128::MAX,
        billable_requests: i128::MIN,
        ..unit("model", i128::MAX)
    };
    let encoded = json::to_vec(&delta).unwrap();
    let value: json::Value = json::parse_value(&encoded).unwrap();
    assert_eq!(value["requests"], i128::MAX.to_string());
    assert_eq!(value["billable_requests"], i128::MIN.to_string());
    let decoded: ExactUsageDelta = json::from_value(&value).unwrap();
    assert_eq!(decoded, delta);
}
