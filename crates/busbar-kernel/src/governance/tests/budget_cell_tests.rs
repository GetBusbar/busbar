// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
    assert_eq!(lane.usage_units.get(unit), Some(&-1));
    let dated = cell.unflushed_eras();
    let dated_lane = dated
        .models
        .iter()
        .find(|model| model.model == "7\u{1f}fee-lane-double")
        .expect("the dated segment also keeps its refund");
    assert_eq!(dated_lane.usage_units.get(unit), Some(&-1));

    let settled = cell.models.clone();
    cell.advance_model_baselines(&settled, false);
    cell.advance_model_baselines(&settled, true);
    cell.prune_dead_models();
    assert!(cell.models.is_empty());
}
