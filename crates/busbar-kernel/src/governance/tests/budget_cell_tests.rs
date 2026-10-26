// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-kernel/src/governance/mod.rs`.

use super::*;

/// The sweep's `prune_dead_models` bounds the per-cell `models` Vec so a never-rolled cell
/// cannot accumulate a dead entry per model name ever seen. A model with live counts is KEPT
/// (enforcement truth); a zero-count entry is DROPPED (what it emitted is in the shard's pending
/// map, never in the cell); a re-appearing model is simply re-interned by `accrue`.
#[test]
fn prune_dead_models_drops_only_zero_count_entries() {
    let tok = |n: u64| -> std::collections::BTreeMap<String, u64> {
        let mut m = std::collections::BTreeMap::new();
        if n != 0 {
            m.insert(busbar_contract::records::UNIT_INPUT.to_string(), n);
        }
        m
    };
    let mut cell = BudgetCell::fresh(0); // the all-time cell that the sweep never ages out
    cell.accrue("live-model", None, &tok(10)); // real tokens → must be KEPT
    cell.accrue("dead-model", None, &tok(0)); // interned with zero tokens → dead, must be DROPPED
    assert_eq!(cell.models.len(), 2, "both interned before the prune");

    cell.prune_dead_models();

    let names: Vec<&str> = cell.models.iter().map(|m| &*m.model).collect();
    assert!(names.contains(&"live-model"), "live tokens kept: {names:?}");
    assert!(
        !names.contains(&"dead-model"),
        "zero-token dead entry pruned: {names:?}"
    );
    assert_eq!(cell.models.len(), 1);

    // A re-appearing model is re-interned on the next accrue (prune is not permanent).
    cell.accrue("dead-model", None, &tok(3));
    assert!(cell.models.iter().any(|m| &*m.model == "dead-model"));
}
