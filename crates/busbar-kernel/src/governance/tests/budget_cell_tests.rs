// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::state::durable_cell;
use super::*;

#[test]
fn prune_dead_models_drops_only_zero_token_fully_flushed_entries() {
    let tok = |n: u64| -> std::collections::BTreeMap<String, u64> {
        let mut m = std::collections::BTreeMap::new();
        if n != 0 {
            m.insert(busbar_contract::records::UNIT_INPUT.to_string(), n);
        }
        m
    };
    let mut cell = BudgetCell::fresh(0);
    cell.accrue("live-model", 0, &tok(10));
    cell.accrue("dead-model", 0, &tok(0));
    assert!(
        !cell.models.iter().any(|m| &*m.model == "dead-model"),
        "an all-zero accrual interns no row (UPG-H2)"
    );
    // A row whose counts were all taken back (e.g. a refund) is the dead entry prune removes.
    cell.accrue("dead-model", 0, &tok(2));
    cell.models
        .iter_mut()
        .find(|m| &*m.model == "dead-model")
        .expect("a counted accrual interns its row")
        .cur
        .clear();

    cell.accrue("flushed-model", 0, &tok(5));
    if let Some(m) = cell
        .models
        .iter_mut()
        .find(|m| &*m.model == "flushed-model")
    {
        m.flushed = m.cur.clone();
    }
    assert_eq!(cell.models.len(), 3, "all three interned before the prune");

    cell.prune_dead_models();

    let names: Vec<&str> = cell.models.iter().map(|m| &*m.model).collect();
    assert!(names.contains(&"live-model"), "live tokens kept: {names:?}");
    assert!(
        names.contains(&"flushed-model"),
        "flushed-but-nonzero kept: {names:?}"
    );
    assert!(
        !names.contains(&"dead-model"),
        "zero-token dead entry pruned: {names:?}"
    );
    assert_eq!(cell.models.len(), 2);

    cell.accrue("dead-model", 0, &tok(3));
    assert!(cell.models.iter().any(|m| &*m.model == "dead-model"));
}

#[test]
fn a_segment_pruned_mid_flush_still_flushes_its_refund() {
    let unit = "per_request";
    let one: std::collections::BTreeMap<String, u64> = [(unit.to_string(), 1)].into();
    let mut cell = BudgetCell::fresh(0);
    cell.accrue("fee-lane-double", 7, &one);

    let snapshot = cell.models.clone();
    cell.dirty = false;

    if let Some(m) = cell
        .models
        .iter_mut()
        .find(|m| &*m.model == "fee-lane-double")
    {
        m.cur.remove(unit);
    }
    cell.prune_dead_models();
    assert!(cell.models.is_empty(), "the refunded segment looked dead");

    cell.advance_model_baselines(&snapshot, false);
    cell.advance_model_baselines(&snapshot, true);
    assert!(cell.dirty, "the restored segment owes the store a write");
    let delta = cell.unflushed();
    let lane = delta
        .models
        .iter()
        .find(|m| m.model == "fee-lane-double")
        .expect("the segment's refund is still to be written");
    assert_eq!(lane.usage_units.get(unit), Some(&-1_000_000));
    let dated = cell.unflushed_eras();
    let dated_lane = dated
        .models
        .iter()
        .find(|model| model.model == "7\u{1f}fee-lane-double")
        .expect("the dated segment also keeps its refund");
    assert_eq!(dated_lane.usage_units.get(unit), Some(&-1_000_000));

    let settled = cell.models.clone();
    cell.advance_model_baselines(&settled, false);
    cell.advance_model_baselines(&settled, true);
    cell.prune_dead_models();
    assert!(cell.models.is_empty());
}

#[test]
fn fractional_counts_remain_exact_through_debt_and_mixed_scale_hydration() {
    use std::collections::BTreeMap;
    let era = RawRateEra::entry(7, EntryId([3; 12]));
    let units = BTreeMap::from([("input".into(), Count::parse("1.000001").unwrap())]);
    let mut cell = BudgetCell::fresh(0);
    cell.accrue_raw("model", era, &units).unwrap();
    cell.accrue_raw("model", era, &units).unwrap();
    assert_eq!(cell.total_tokens(), Count::parse("2.000002").unwrap());
    let plain = cell.unflushed();
    assert_eq!(plain.models[0].scale, COUNT_SCALE);
    assert_eq!(plain.models[0].usage_units["input"], 2_000_002);
    let dated = cell.unflushed_eras();
    assert_eq!(dated.models[0].scale, COUNT_SCALE);
    assert_eq!(dated.models[0].usage_units["input"], 2_000_002);

    let aggregate = busbar_contract::records::UsageLedger {
        requests: 3,
        billable_requests: 3,
        models: vec![busbar_contract::records::ModelTokens {
            model: "model".into(),
            scale: 0,
            usage_units: BTreeMap::from([("input".into(), 3)]),
        }],
    };
    let era_row = busbar_contract::records::UsageLedger {
        models: vec![
            busbar_contract::records::ModelTokens {
                model: era_model(era, "model"),
                scale: COUNT_SCALE,
                usage_units: BTreeMap::from([("input".into(), 2_000_002)]),
            },
            busbar_contract::records::ModelTokens {
                model: era_tag(era),
                scale: COUNT_SCALE,
                usage_units: BTreeMap::from([(ERA_FEE_UNIT.into(), 3_000_000)]),
            },
        ],
        ..Default::default()
    };
    let hydrated = durable_cell("", aggregate, era_row, 0).unwrap();
    assert_eq!(hydrated.total_tokens(), whole_count(3));
    assert_eq!(hydrated.requests, 3);
    assert_eq!(hydrated.billable_requests, 3);
    assert_eq!(hydrated.fee_eras.dated(), &[(era, 3)]);
    assert_eq!(
        hydrated.models.iter().find(|m| m.era == era).unwrap().cur["input"],
        Count::parse("2.000002").unwrap()
    );
    assert!(ExactUsageDelta::of(&hydrated, false).is_zero());
    assert!(ExactUsageDelta::of(&hydrated, true).is_zero());
}

#[test]
fn exact_count_overflow_refuses_without_partial_model_update() {
    use std::collections::BTreeMap;
    let era = RawRateEra::legacy(1);
    let mut cell = BudgetCell::fresh(0);
    cell.accrue_raw(
        "model",
        era,
        &BTreeMap::from([("z".into(), busbar_contract::count::MAX)]),
    )
    .unwrap();
    let rejected = BTreeMap::from([("a".into(), Count::ONE), ("z".into(), Count::EPSILON)]);
    assert_eq!(
        cell.accrue_raw("model", era, &rejected),
        Err(CountError::Overflow)
    );
    assert_eq!(cell.models[0].cur.len(), 1);
    assert_eq!(cell.models[0].cur["z"], busbar_contract::count::MAX);
}

#[test]
fn metering_chunk_preserves_full_count_range() {
    let n = Count::from_micros(i128::MAX);
    let key = (
        "key".into(),
        0,
        "model".into(),
        "provider".into(),
        1,
        String::new(),
        String::new(),
    );
    let counts = MeterCounts {
        requests: 1,
        tokens_input: n,
        ..Default::default()
    };
    let (first, rest) = super::metering_flush::metering_chunk(&key, &counts);
    assert_eq!(first.scale, COUNT_SCALE);
    assert_eq!(first.tokens_input, i128::MAX);
    assert_eq!(first.requests, 1);
    assert!(rest.is_zero());
}

#[test]
fn durable_usage_hydration_preserves_full_range_and_refuses_negative_totals() {
    use std::collections::BTreeMap;
    for raw in [i128::MAX, -1] {
        let row = busbar_contract::records::UsageLedger {
            models: vec![busbar_contract::records::ModelTokens {
                model: "wide".into(),
                scale: COUNT_SCALE,
                usage_units: BTreeMap::from([("input".into(), raw)]),
            }],
            ..Default::default()
        };
        let hydrated = durable_cell("", row, Default::default(), 0);
        if raw < 0 {
            assert!(hydrated.is_err());
        } else {
            assert_eq!(hydrated.unwrap().models[0].cur["input"].micros(), raw);
        }
    }
}

#[test]
fn durable_usage_hydration_refuses_negative_dated_totals() {
    use std::collections::BTreeMap;
    let era = busbar_contract::records::UsageLedger {
        models: vec![busbar_contract::records::ModelTokens {
            model: era_model(RawRateEra::legacy(1), "wide"),
            scale: COUNT_SCALE,
            usage_units: BTreeMap::from([("input".into(), -1)]),
        }],
        ..Default::default()
    };
    assert!(durable_cell("", Default::default(), era, 0).is_err());
}

/// UPG-H2 (`laneless-ledger-row`): the sealed constructor refuses only the poison shape.
#[test]
fn model_cell_new_refuses_only_an_unnamed_lane_with_no_count() {
    let era = RawRateEra::legacy(0);
    let none = std::collections::BTreeMap::new;
    let one = || {
        std::collections::BTreeMap::from([(
            busbar_contract::records::UNIT_INPUT.to_string(),
            Count::ONE,
        )])
    };
    assert!(
        ModelCell::new("".into(), era, none(), none(), none()).is_none(),
        "an unnamed lane with no count prices as LaneUnpriced and carries nothing"
    );
    for (cur, flushed, flushed_era) in [
        (one(), none(), none()),
        (none(), one(), none()),
        (none(), none(), one()),
    ] {
        assert!(
            ModelCell::new("".into(), era, cur, flushed, flushed_era).is_some(),
            "an unnamed lane WITH counts stays visible and fails closed"
        );
    }
    assert!(
        ModelCell::new("m".into(), era, none(), none(), none()).is_some(),
        "a named empty row is allowed (dated-era split, correction baselines)"
    );
}

/// UPG-H2: an all-zero accrual, named or not, leaves the cell without a new row.
#[test]
fn an_all_zero_accrual_interns_no_row() {
    let mut cell = BudgetCell::fresh(0);
    let zero = std::collections::BTreeMap::from([(
        busbar_contract::records::UNIT_INPUT.to_string(),
        Count::ZERO,
    )]);
    cell.accrue_raw("", RawRateEra::legacy(0), &zero).unwrap();
    cell.accrue_raw("", RawRateEra::legacy(0), &Default::default())
        .unwrap();
    cell.accrue_raw("m", RawRateEra::legacy(0), &zero).unwrap();
    assert!(cell.models.is_empty());
}

/// LINT-RULES R35 `row-from-no-counts` (LR-129): a lane row in a budget cell is a hit on that
/// lane, and every money read prices every row. So `accrue_raw` itself, the one way counts enter a
/// cell, creates a row only from a non-zero count; a zero-only report (an exhausted pool unit's
/// checkpoint names lane `""` with no counts) adds nothing, on the cell and on an open correction
/// branch alike, whichever caller reaches it.
#[test]
fn a_zero_only_accrual_creates_no_lane_row() {
    use std::collections::BTreeMap;
    let era = RawRateEra::legacy(0);
    let mut cell = BudgetCell::fresh(0);
    cell.accrue_raw("", era, &BTreeMap::new()).unwrap();
    cell.accrue_raw("m", era, &BTreeMap::from([("input".into(), Count::ZERO)]))
        .unwrap();
    assert!(
        cell.models.is_empty(),
        "no counts, no row: {:?}",
        cell.models.iter().map(|m| &*m.model).collect::<Vec<_>>()
    );

    cell.accrue_raw("m", era, &BTreeMap::from([("input".into(), Count::ONE)]))
        .unwrap();
    cell.accrue_raw("m", era, &BTreeMap::from([("input".into(), Count::ZERO)]))
        .unwrap();
    assert_eq!(cell.models.len(), 1, "a counted lane keeps its one row");
    assert_eq!(cell.models[0].cur["input"], Count::ONE);
}
