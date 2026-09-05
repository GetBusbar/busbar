// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ledger cells the decision reads and charges, and the one seam through which it reaches
//! them.
//!
//! A cell holds a bucket's counters for its current window: how many requests were admitted, how
//! many of those are still billable, and the per-model token counts. There is no money field
//! anywhere — spend is derived from tokens and the current rate table on every read, which is why
//! a rate correction reprices everything on the next request with no data fix.
//!
//! The cells are node-local: hydrated once at boot and never re-read on the request path. Two
//! nodes sharing one durable store therefore each admit up to the full cap until one of them
//! restarts. That is not an oversight being fixed here — it is the behaviour at the tag, and the
//! door reproduces it exactly.
//!
//! The seam is deliberately narrow. [`CellStore::lock`] hands back a locked view over a named set
//! of buckets, and the decision does BOTH its passes inside that one view: it checks every bucket,
//! and only if all of them pass does it charge every bucket, without ever letting go. Whoever
//! implements the store owns the locking strategy (sharding, canonical acquisition order, stale-cell
//! eviction); what it must guarantee is that no other admission can interleave between the two
//! passes for the same buckets.

use std::collections::BTreeMap;

use crate::price::{units_total, UNIT_CACHE_READ, UNIT_CACHE_WRITE, UNIT_INPUT, UNIT_OUTPUT};

/// One model's token counters inside a cell. Interned on first sight of a (bucket, model) pair, so
/// a bucket carries only the models it actually used and accrual after that is a linear scan over
/// a handful of entries plus integer adds.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ModelCell {
    model: String,
    units: BTreeMap<String, u64>,
}

/// A bucket's counters for its current window — the authoritative hot-path enforcement state.
///
/// Reset on rollover, so growth is bounded by the bucket count rather than by traffic.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LedgerCell {
    /// The epoch start of the window these counters belong to.
    pub window_start: u64,
    /// Admission count: incremented once per admitted request and NEVER refunded. This backs the
    /// requests cap, so a caller cannot escape it by hammering failing requests — each one still
    /// consumed a slot at admission.
    pub requests: u64,
    /// Billable request count: admitted requests minus refunds. This backs the flat-fee component
    /// of the derived spend, so the fee bills successes only. Charged alongside `requests` at
    /// admission; a failure decrements only this one.
    pub billable_requests: u64,
    /// Set whenever the cell is touched, for the write-behind flush the ledger runs off this path.
    pub dirty: bool,
    /// Wall-clock of the last accrual or admission charge, for the store's own eviction.
    pub last_touch: u64,
    models: Vec<ModelCell>,
}

impl LedgerCell {
    /// A zeroed cell for `window_start`.
    pub fn fresh(window_start: u64) -> Self {
        LedgerCell {
            window_start,
            ..Default::default()
        }
    }

    /// Accrue one response's keyed token counts under a model, interning the model on first sight
    /// and each unit key on first sight of that pair. Zero counts are not stored.
    pub fn accrue(&mut self, model: &str, units: &BTreeMap<String, u64>) {
        let cell = match self.models.iter_mut().position(|m| m.model == model) {
            Some(i) => &mut self.models[i],
            None => {
                self.models.push(ModelCell {
                    model: model.to_string(),
                    units: BTreeMap::new(),
                });
                self.models.last_mut().expect("just pushed")
            }
        };
        for (k, v) in units {
            if *v == 0 {
                continue;
            }
            let slot = cell.units.entry(k.clone()).or_insert(0);
            *slot = slot.saturating_add(*v);
        }
    }

    /// Borrowed (model, units) view for the spend derivation — the few multiply-adds the budget
    /// check runs.
    pub fn model_views(&self) -> impl Iterator<Item = (&str, &BTreeMap<String, u64>)> {
        self.models.iter().map(|m| (m.model.as_str(), &m.units))
    }

    /// Total current tokens across every model and every unit key — the counter the total-token
    /// cap reads.
    pub fn total_tokens(&self) -> u64 {
        self.models
            .iter()
            .fold(0u64, |acc, m| acc.saturating_add(units_total(&m.units)))
    }

    /// Current summed count of one unit key across models — a per-tier cap's counter.
    pub fn total_tier(&self, unit: &str) -> u64 {
        self.models.iter().fold(0u64, |acc, m| {
            acc.saturating_add(m.units.get(unit).copied().unwrap_or(0))
        })
    }

    /// Current uncached-input tokens.
    pub fn total_input(&self) -> u64 {
        self.total_tier(UNIT_INPUT)
    }

    /// Current output tokens.
    pub fn total_output(&self) -> u64 {
        self.total_tier(UNIT_OUTPUT)
    }

    /// Current cache-read tokens.
    pub fn total_cache_read(&self) -> u64 {
        self.total_tier(UNIT_CACHE_READ)
    }

    /// Current cache-write tokens.
    pub fn total_cache_write(&self) -> u64 {
        self.total_tier(UNIT_CACHE_WRITE)
    }

    /// Drop models carrying no tokens, so a never-rolling cell cannot grow one entry per model
    /// name ever seen. Removing an empty entry loses no enforcement truth.
    pub fn prune_empty_models(&mut self) {
        self.models.retain(|m| units_total(&m.units) != 0);
    }
}

/// A locked view over a set of buckets' cells, held across the check pass and the charge pass.
pub trait Cells {
    /// The cell for a bucket, if one exists. Absent means "nothing used yet".
    fn get(&self, bucket_id: &str) -> Option<&LedgerCell>;

    /// The cell for a bucket, mutably.
    fn get_mut(&mut self, bucket_id: &str) -> Option<&mut LedgerCell>;

    /// Insert a fresh cell for a bucket and hand it back. Called only when the bucket had no cell
    /// at all.
    fn insert_fresh(&mut self, bucket_id: &str, window: u64) -> &mut LedgerCell;
}

/// The store the decision reaches the cells through.
///
/// The implementer owns the locking. What it must guarantee: the view returned by `lock` covers
/// every named bucket, and nothing else may charge those buckets while the view is alive. That is
/// what makes the check and the charge one indivisible step, and it is the reason concurrent
/// requests at a cap boundary can never each read "under the cap" and all charge.
pub trait CellStore {
    /// The locked view.
    type Locked<'a>: Cells
    where
        Self: 'a;

    /// Lock the named buckets. Duplicate ids are permitted and mean the same bucket.
    fn lock<'a>(&'a self, bucket_ids: &[&str]) -> Self::Locked<'a>;
}

// ── a reference implementation ──────────────────────────────────────────────────────────────────

/// An in-memory store: one lock over one map.
///
/// This is the reference behaviour, not the production shape. A real store shards the map and
/// acquires the shards a chain touches in a canonical order so the multi-bucket critical section
/// is deadlock-free; this one takes a single lock, which is correct and simply less concurrent.
/// The decision cannot tell the difference, which is the point.
#[derive(Debug, Default)]
pub struct InMemoryCells {
    map: std::sync::Mutex<std::collections::HashMap<String, LedgerCell>>,
}

impl InMemoryCells {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// A snapshot of one bucket's cell, for tests and for admin reads.
    pub fn snapshot(&self, bucket_id: &str) -> Option<LedgerCell> {
        self.map
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(bucket_id)
            .cloned()
    }
}

/// The locked view [`InMemoryCells`] hands back.
#[derive(Debug)]
pub struct InMemoryLocked<'a> {
    guard: std::sync::MutexGuard<'a, std::collections::HashMap<String, LedgerCell>>,
}

impl Cells for InMemoryLocked<'_> {
    fn get(&self, bucket_id: &str) -> Option<&LedgerCell> {
        self.guard.get(bucket_id)
    }

    fn get_mut(&mut self, bucket_id: &str) -> Option<&mut LedgerCell> {
        self.guard.get_mut(bucket_id)
    }

    fn insert_fresh(&mut self, bucket_id: &str, window: u64) -> &mut LedgerCell {
        self.guard
            .entry(bucket_id.to_string())
            .or_insert_with(|| LedgerCell::fresh(window))
    }
}

impl CellStore for InMemoryCells {
    type Locked<'a> = InMemoryLocked<'a>;

    fn lock<'a>(&'a self, _bucket_ids: &[&str]) -> Self::Locked<'a> {
        InMemoryLocked {
            guard: self.map.lock().unwrap_or_else(|p| p.into_inner()),
        }
    }
}
