// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-kernel/src/governance/mod.rs`.

use super::*;

/// The sweep's `prune_dead_models` bounds the per-cell `models` Vec so a never-rolled cell
/// cannot accumulate a dead entry per model name ever seen. A model with live
/// tokens (or an unacked flush delta) is KEPT (enforcement/write-behind truth); a zero-token,
/// fully-flushed entry is DROPPED; a re-appearing model is simply re-interned by `accrue`.
#[test]
fn prune_dead_models_drops_only_zero_token_fully_flushed_entries() {
    let tok = |n: u64| -> std::collections::BTreeMap<String, u64> {
        let mut m = std::collections::BTreeMap::new();
        if n != 0 {
            m.insert(busbar_contract::records::UNIT_INPUT.to_string(), n);
        }
        m
    };
    let mut cell = BudgetCell::fresh(0); // the all-time cell that the sweep never ages out
    cell.accrue("live-model", 0, &tok(10)); // real tokens → must be KEPT
    cell.accrue("dead-model", 0, &tok(0)); // interned with zero tokens → dead, must be DROPPED
                                           // An entry that was charged then FLUSHED (cur == flushed, both non-zero) still carries the
                                           // window's enforcement total, so it must be KEPT.
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

    // A re-appearing model is re-interned on the next accrue (prune is not permanent).
    cell.accrue("dead-model", 0, &tok(3));
    assert!(cell.models.iter().any(|m| &*m.model == "dead-model"));
}

/// A FEE-LANE SEGMENT PRUNED WHILE ITS FLUSH IS IN FLIGHT STILL WRITES ITS REFUND. A plane's fee
/// unit accrues (+1), a flush snapshots it, a refund takes it back to empty, and the sweep prunes
/// the now-empty segment before the write is acknowledged. When the ack lands, the store holds the
/// +1, so the cell must still owe the store a -1. RED: the ack found no segment and advanced
/// nothing, so the cell's unflushed delta was empty and the store kept one extra fee unit.
#[test]
fn a_segment_pruned_mid_flush_still_flushes_its_refund() {
    let unit = "per_request";
    let one: std::collections::BTreeMap<String, u64> = [(unit.to_string(), 1)].into();
    let mut cell = BudgetCell::fresh(0);
    cell.accrue("fee-lane-double", 7, &one);
    // The flush snapshots the segment and writes it off the lock.
    let snapshot = cell.models.clone();
    cell.dirty = false;
    // Meanwhile: the refund takes the unit back, and the sweep prunes the empty segment.
    if let Some(m) = cell
        .models
        .iter_mut()
        .find(|m| &*m.model == "fee-lane-double")
    {
        m.cur.remove(unit);
    }
    cell.prune_dead_models();
    assert!(cell.models.is_empty(), "the refunded segment looked dead");
    // The write lands and is acknowledged.
    cell.advance_model_baselines(&snapshot);
    assert!(cell.dirty, "the restored segment owes the store a write");
    let delta = cell.unflushed();
    let lane = delta
        .models
        .iter()
        .find(|m| m.model == "fee-lane-double")
        .expect("the segment's refund is still to be written");
    assert_eq!(lane.usage_units.get(unit), Some(&-1));
    // Once that refund is acknowledged the segment is dead for good.
    let settled = cell.models.clone();
    cell.advance_model_baselines(&settled);
    cell.prune_dead_models();
    assert!(cell.models.is_empty());
}
