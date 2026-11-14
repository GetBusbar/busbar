// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WASTE-CORE-LIFECYCLE W6: the budget flush locks and walks only the shards written since its
//! last tick, instead of every shard twice per 100 ms tick.

use super::*;
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

async fn gov() -> GovState {
    GovState::new_with_core(crate::real_store::core().await, None, None)
        .await
        .expect("native Store constructs")
}

fn counts(gov: &GovState) -> (u64, u64) {
    (
        gov.budget.flush_shard_locks.load(Ordering::Relaxed),
        gov.budget.flush_cells_visited.load(Ordering::Relaxed),
    )
}

fn seed_clean(gov: &GovState, cells: usize) {
    for index in 0..cells {
        let id = format!("vk_idle_{index}");
        gov.budget
            .write(&id)
            .insert(id.clone(), BudgetCell::fresh(0));
    }
}

fn accrue(gov: &GovState, id: &str) {
    let mut cells = gov.budget.write(id);
    let cell = cells
        .entry(id.to_string())
        .or_insert_with(|| BudgetCell::fresh(0));
    cell.accrue_raw(
        "m",
        RawRateEra::legacy(0),
        &BTreeMap::from([("input".into(), Count::ONE)]),
    )
    .unwrap();
    cell.dirty = true;
}

/// Three bucket ids that land in three distinct shards.
fn three_shards(gov: &GovState) -> Vec<String> {
    let mut seen = Vec::new();
    let mut ids = Vec::new();
    for index in 0.. {
        let id = format!("vk_written_{index}");
        let shard = gov.budget.shard_index(&id);
        if !seen.contains(&shard) {
            seen.push(shard);
            ids.push(id);
        }
        if ids.len() == 3 {
            break;
        }
    }
    ids
}

#[tokio::test]
async fn idle_budget_flush_takes_no_shard_locks() {
    let gov = gov().await;
    seed_clean(&gov, 10_000);
    // The first tick walks what seeding wrote.
    gov.flush_budgets().await;
    let before = counts(&gov);
    for _ in 0..10 {
        gov.flush_budgets().await;
    }
    let after = counts(&gov);
    assert_eq!(after.0 - before.0, 0, "an idle flush locks no budget shard");
    assert_eq!(after.1 - before.1, 0, "an idle flush visits no budget cell");
}

#[tokio::test]
async fn flush_visits_only_written_shards() {
    let gov = gov().await;
    seed_clean(&gov, 1_000);
    gov.flush_budgets().await;
    gov.flush_budgets().await;
    let ids = three_shards(&gov);
    for id in &ids {
        accrue(&gov, id);
    }
    let before = counts(&gov);
    gov.flush_budgets().await;
    let after = counts(&gov);
    assert!(
        after.0 - before.0 <= 6,
        "only the 3 written shards are locked, once per pass: {} locks",
        after.0 - before.0
    );
}
