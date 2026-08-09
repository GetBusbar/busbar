// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/governance/mod.rs`.

use super::*;

/// The sweep's `prune_dead_models` bounds the per-cell `models` Vec so a never-rolled cell
/// cannot accumulate a dead entry per model name ever seen. A model with live
/// tokens (or an unacked flush delta) is KEPT (enforcement/write-behind truth); a zero-token,
/// fully-flushed entry is DROPPED; a re-appearing model is simply re-interned by `accrue`.
#[test]
fn prune_dead_models_drops_only_zero_token_fully_flushed_entries() {
    let tok = |n: u64| busbar_api::TierTokens {
        input: n,
        output: 0,
        cache_read: 0,
        cache_write: 0,
    };
    let mut cell = BudgetCell::fresh(0); // the all-time cell that the sweep never ages out
    cell.accrue("live-model", &tok(10)); // real tokens → must be KEPT
    cell.accrue("dead-model", &tok(0)); // interned with zero tokens → dead, must be DROPPED
                                        // An entry that was charged then FLUSHED (cur == flushed, both non-zero) still carries the
                                        // window's enforcement total, so it must be KEPT.
    cell.accrue("flushed-model", &tok(5));
    if let Some(m) = cell
        .models
        .iter_mut()
        .find(|m| &*m.model == "flushed-model")
    {
        m.flushed = m.cur;
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
    cell.accrue("dead-model", &tok(3));
    assert!(cell.models.iter().any(|m| &*m.model == "dead-model"));
}
