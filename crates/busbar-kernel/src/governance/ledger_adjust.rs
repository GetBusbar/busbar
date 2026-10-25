// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE LEDGER'S ADMIN READ AND ITS ONE CORRECTION (MONEY-DESIGN §4, Busbar PR-C).
//!
//! Money is the ledger's counts x the rate card, computed in core. The ledger is these usage rows:
//! a bucket's cell in RAM, its durable row behind it. There is no second book, so the admin ledger
//! views price exactly what [`GovState::derived_bucket_usage`] prices, and an operator's
//! correction is a SIGNED DELTA on those same counts:
//!
//! - it names the card entry its counts were earned under (the segment's era, `entry_era`);
//! - it lands on every bucket an accrual of the unit would have landed on (the key's own, and each
//!   group bucket its pool participates in), all or nothing;
//! - it is applied to RAM `cur` at once, so every view and every admission sees it, and the
//!   write-behind flush carries it to the store as a signed `add_usage` delta — today's path, until
//!   the poster replaces it (PR-B2);
//! - an adjustment that would take any count of its segment below zero is REFUSED and nothing is
//!   applied, so no store floors the row while RAM goes negative (MONEY-REVIEW review 17, NB5).
//!
//! A child module of `state`, so it reaches that module's private helpers (`bucket_cell`,
//! `durable_cell`) exactly as a method written there would.

use super::*;

/// One bucket's current window, priced by the one function: what the admin ledger views serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PricedBucket {
    /// The window the cell holds, as the unix second it opens at (`0` = the all-time window).
    pub window_start: u64,
    /// Admitted requests in the window.
    pub requests: u64,
    /// Billable requests in the window: the fee base.
    pub billable_requests: u64,
    /// The cell's counts priced at the card each era was earned under, fee included, or the one
    /// function's refusal (a card silent about a lane or class, no card in force, out of range).
    pub spend: Result<busbar_kernel_ledger::cost::Money, MoneyError>,
}

/// One operator correction to a unit's counts, as signed deltas.
#[derive(Debug, Clone)]
pub struct Adjustment<'a> {
    /// The key whose counts are corrected.
    pub key_id: &'a str,
    /// The pool the unit was dispatched through (Q64/Q67): a group bucket takes the correction only
    /// if its pool participates, as the accrual did.
    pub pool: &'a str,
    /// The lane (model) the counts were earned on.
    pub model: &'a str,
    /// THE ENTRY: the era of the segment, the `effective_from` of the card entry the counts were
    /// priced with.
    pub entry_era: u64,
    /// The signed delta per class. Zero deltas are ignored.
    pub delta: &'a BTreeMap<String, i64>,
    /// The instant the correction lands at, wall seconds: picks each bucket's current window.
    pub now: u64,
}

/// Why an adjustment was refused. Nothing was applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdjustRefused {
    /// No key by that id.
    UnknownKey,
    /// The correction carries no non-zero delta.
    Empty,
    /// The delta would take a count of its segment below zero (or past `u64`).
    Exceeds {
        /// The bucket it would have landed on.
        bucket: String,
        /// The class.
        class: String,
        /// What the segment holds now.
        count: u64,
        /// The delta asked for.
        delta: i64,
    },
}

impl std::fmt::Display for AdjustRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdjustRefused::UnknownKey => f.write_str("no key by that id"),
            AdjustRefused::Empty => f.write_str("the adjustment moves no count"),
            AdjustRefused::Exceeds {
                bucket,
                class,
                count,
                delta,
            } => write!(
                f,
                "bucket `{bucket}` holds {count} `{class}` in that segment, and {delta} would take \
                 it out of range"
            ),
        }
    }
}

impl std::error::Error for AdjustRefused {}

impl GovState {
    /// **ONE BUCKET'S CURRENT WINDOW, PRICED** — the live cell, else the durable row read as the
    /// cell hydrated from it, priced at the card each era was earned under, the fee included. The
    /// same cell and the same function [`GovState::derived_bucket_usage`] answers from, kept in
    /// the money type rather than projected to whole minor units.
    ///
    /// # Errors
    ///
    /// The store could not read the durable row.
    pub fn priced_bucket(
        &self,
        cost: &crate::cost::CostModel,
        bucket_id: &str,
        budget_period: &str,
        now: u64,
    ) -> RecordStoreResult<PricedBucket> {
        let window = budget_window(budget_period, now);
        let cell = self.bucket_cell(bucket_id, window)?;
        Ok(PricedBucket {
            window_start: cell.window_start,
            requests: cell.requests,
            billable_requests: cell.billable_requests,
            spend: cell.spend(cost, true),
        })
    }

    /// **APPLY ONE OPERATOR CORRECTION** to the usage counts: every bucket an accrual of the unit
    /// lands on (the key's own, and each group bucket of its chain the pool participates in; the
    /// key's own alone when its group is missing, as accrual degrades), in its current window, in
    /// the segment of `model` and `entry_era`. Checked under every bucket's shard lock, taken in
    /// ascending shard order, and applied under the same locks: all of it or none of it.
    ///
    /// The delta reaches the store through the write-behind flush, as a signed `add_usage` delta.
    ///
    /// # Errors
    ///
    /// The store could not read a key or a durable row (outer); the correction was refused and
    /// nothing was applied (inner).
    pub fn adjust_usage(
        &self,
        cost: &crate::cost::CostModel,
        adj: &Adjustment<'_>,
    ) -> RecordStoreResult<Result<(), AdjustRefused>> {
        let delta: BTreeMap<&str, i64> = adj
            .delta
            .iter()
            .filter(|(_, d)| **d != 0)
            .map(|(class, d)| (class.as_str(), *d))
            .collect();
        if delta.is_empty() {
            return Ok(Err(AdjustRefused::Empty));
        }
        let Some(key) = self.store.get_key(adj.key_id)? else {
            return Ok(Err(AdjustRefused::UnknownKey));
        };
        // The buckets, as `record_usage` picks them.
        let mut buckets: Vec<(String, u64)> = match cost.chain_for(&key) {
            Ok(chain) => chain
                .iter()
                .filter(|b| b.applies_to_pool(adj.pool))
                .map(|b| (b.bucket_id.to_string(), budget_window(b.window, adj.now)))
                .collect(),
            Err(_) => vec![(
                adj.key_id.to_string(),
                budget_window(super::super::WINDOW_TOTAL, adj.now),
            )],
        };
        buckets.sort();
        buckets.dedup();
        // A bucket with no live cell for its window is read from the store first, OUTSIDE the
        // locks, as the cell boot would hydrate from it: the store already holds those counts, so
        // the flush baselines start level and only the correction is written.
        let mut hydrated: HashMap<String, BudgetCell> = HashMap::new();
        for (bucket_id, window) in &buckets {
            let live = (self.budget.read(bucket_id).get(bucket_id.as_str()))
                .is_some_and(|c| c.window_start >= *window);
            if !live {
                let mut cell = durable_cell(self.store.get_usage(bucket_id, *window)?, *window);
                cell.flushed_requests = cell.requests;
                cell.flushed_billable_requests = cell.billable_requests;
                for m in &mut cell.models {
                    m.flushed = m.cur.clone();
                }
                cell.last_touch = adj.now;
                hydrated.insert(bucket_id.clone(), cell);
            }
        }
        // Every bucket's shard, write-locked in ascending index order (the admission charge's
        // canonical order, so the two cannot deadlock), held across the check and the apply.
        let mut order: Vec<usize> = buckets
            .iter()
            .map(|(bucket_id, _)| self.budget.shard_index(bucket_id))
            .collect();
        order.sort_unstable();
        order.dedup();
        let mut guards: Vec<(usize, std::sync::RwLockWriteGuard<'_, HashMap<String, BudgetCell>>)> =
            order
                .iter()
                .map(|&sh| {
                    let map = self
                        .budget
                        .shard_at(sh)
                        .map
                        .write()
                        .unwrap_or_else(|p| p.into_inner());
                    (sh, map)
                })
                .collect();
        let map_of = |bucket_id: &str| -> usize {
            let sh = self.budget.shard_index(bucket_id);
            guards
                .iter()
                .position(|(s, _)| *s == sh)
                .expect("every bucket's shard is locked")
        };
        let at: Vec<usize> = buckets.iter().map(|(b, _)| map_of(b)).collect();
        // Install the hydrated cells where nothing newer appeared while the store was read.
        for ((bucket_id, window), i) in buckets.iter().zip(&at) {
            let map = &mut guards[*i].1;
            let stale = map
                .get(bucket_id.as_str())
                .is_none_or(|c| c.window_start < *window);
            if stale {
                if let Some(cell) = hydrated.remove(bucket_id) {
                    match map.get_mut(bucket_id.as_str()) {
                        // An older window's cell rolls first, so what it still owes is kept.
                        Some(old) => {
                            old.roll(*window);
                            let parked = std::mem::take(&mut old.rolled);
                            *old = cell;
                            old.rolled = parked;
                            old.dirty = !old.rolled.is_empty();
                        }
                        None => {
                            map.insert(bucket_id.clone(), cell);
                        }
                    }
                }
            }
        }
        // THE CHECK, every bucket first: a count of the segment taken below zero refuses the whole.
        for ((bucket_id, _), i) in buckets.iter().zip(&at) {
            let cell = guards[*i].1.get(bucket_id.as_str());
            let segment = cell.and_then(|c| {
                (c.models.iter()).find(|m| &*m.model == adj.model && m.era == adj.entry_era)
            });
            for (class, d) in &delta {
                let count = segment
                    .and_then(|m| m.cur.get(*class).copied())
                    .unwrap_or(0);
                if moved(count, *d).is_none() {
                    return Ok(Err(AdjustRefused::Exceeds {
                        bucket: bucket_id.clone(),
                        class: (*class).to_string(),
                        count,
                        delta: *d,
                    }));
                }
            }
        }
        // THE APPLY, under the same locks.
        for ((bucket_id, window), i) in buckets.iter().zip(&at) {
            let map = &mut guards[*i].1;
            let cell = map
                .entry(bucket_id.clone())
                .or_insert_with(|| BudgetCell::fresh(*window));
            let pos = (cell.models.iter())
                .position(|m| &*m.model == adj.model && m.era == adj.entry_era);
            let segment = match pos {
                Some(p) => &mut cell.models[p],
                None => {
                    cell.models.push(ModelCell {
                        model: std::sync::Arc::from(adj.model),
                        era: adj.entry_era,
                        cur: BTreeMap::new(),
                        flushed: BTreeMap::new(),
                    });
                    cell.models.last_mut().expect("just pushed")
                }
            };
            for (class, d) in &delta {
                let count = segment.cur.get(*class).copied().unwrap_or(0);
                let next = moved(count, *d).expect("checked under the same lock");
                if next == 0 {
                    segment.cur.remove(*class);
                } else {
                    segment.cur.insert((*class).to_string(), next);
                }
            }
            cell.dirty = true;
            cell.last_touch = adj.now;
        }
        Ok(Ok(()))
    }
}

/// `count` moved by `delta`, or `None` when that leaves `u64`.
fn moved(count: u64, delta: i64) -> Option<u64> {
    if delta >= 0 {
        count.checked_add(delta.unsigned_abs())
    } else {
        count.checked_sub(delta.unsigned_abs())
    }
}
