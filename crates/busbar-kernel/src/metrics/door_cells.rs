// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR PLANES' BREAKER CELLS, AS `/metrics` READS THEM. A door plane's egress walk trips the
//! cells of its own breaker unit (`busbar_kernel_breaker::BreakerUnit`, behind the walk's breaker
//! port), sealed with its egress for a generation. The composition root publishes each served
//! door plane's current egress here ([`DoorCells::publish`]), and `busbar_lane_state` reads every
//! cell those units have materialized, each from that cell alone, beside the kernel's own lane
//! cells.
//!
//! THE LABELS ARE STATED, NOT COMPOSED. 1.5.5's convention is `{pool, lane}`, pool the configured
//! pool's name (the model's, for a direct route) and lane the member's configured name, identical on
//! the gauge and the walk's counters so the two join (v1.5.5 `metrics.rs:214-217`, `:903-905`). A
//! door plane's egress carries the pair each of its cells is scraped under ([`DoorBreaker`]), stated
//! when the egress is sealed; this module renders those strings as they were stated and never builds
//! one.
//!
//! THE MONEY GAUGE'S `model` LABEL IS STATED THE SAME WAY. A door plane's money rows are ledgered
//! under its internal lane keys (`"<plane>\u{1f}<entry>"`, and its fee lane `"<plane>\u{1f}"`); the
//! egress carries, beside its breaker labels, the `model` label each of those keys is scraped under
//! ([`DoorBreaker::models`]). Those are kept across generations ([`DoorCells::model_labels`]): the
//! ledger keeps a key's history after an apply retires the entry, so its label stays known.
//!
//! A door plane whose breaker is the kernel's own lane store (the plane serving the `pools` map)
//! publishes no unit: its cells are scraped from the store, and its money rows are keyed bare.
//!
//! The set is carried across config applies with the `Arc` the `App` holds, and a plane's newer
//! generation replaces its older one, so a retired generation's cells are never scraped.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use busbar_contract::DestinationId;
use busbar_kernel_breaker::cell::BreakerState as CellState;
use busbar_kernel_breaker::BreakerUnit;

use crate::plane_driver::Egress;
use crate::store::BreakerState;

/// A door plane's own breaker, with the labels its cells are scraped under: `pools` maps each
/// pool key the walk keys a cell by to its stated `pool` label, `lanes` each member to its stated
/// `lane` label. A cell whose pool or member has no stated label is not scraped.
#[derive(Clone)]
pub struct DoorBreaker {
    /// The unit the walk trips.
    pub unit: Arc<BreakerUnit>,
    /// Pool key → the stated `pool` label.
    pub pools: HashMap<String, String>,
    /// Member → the stated `lane` label.
    pub lanes: HashMap<DestinationId, String>,
    /// Money ledger lane key → the stated `model` label its `busbar_bucket_tokens` series carry.
    pub models: HashMap<String, String>,
}

/// Every served door plane's breaker cells, by plane, and the `model` label every door plane has
/// stated for a money ledger lane key.
#[derive(Default)]
pub struct DoorCells {
    planes: RwLock<BTreeMap<String, DoorBreaker>>,
    /// Sticky: a newer generation adds or restates labels and never withdraws one.
    models: RwLock<HashMap<String, String>>,
}

impl DoorCells {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish `plane`'s current generation: the breaker its egress walk trips, with its stated
    /// labels. Replaces the generation published before it. An egress whose breaker is the kernel's
    /// own lane store (no unit of its own) withdraws the plane.
    /// The `model` labels the generation states are kept past it ([`Self::model_labels`]).
    pub fn publish(&self, plane: &str, egress: &Egress) {
        match &egress.cells {
            Some(breaker) => self.publish_breaker(plane, breaker.clone()),
            None => {
                self.planes
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(plane);
            }
        }
    }

    /// Publish `plane`'s breaker directly: what [`Self::publish`] reads off an egress.
    pub(crate) fn publish_breaker(&self, plane: &str, breaker: DoorBreaker) {
        self.models
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .extend(breaker.models.iter().map(|(k, v)| (k.clone(), v.clone())));
        self.planes
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(plane.to_string(), breaker);
    }

    /// READ-ONLY: the `model` label every door plane has stated for a money ledger lane key, as
    /// stated, including a retired generation's (its ledger history is still scraped).
    #[must_use]
    pub fn model_labels(&self) -> HashMap<String, String> {
        self.models
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// READ-ONLY: every cell the published units have materialized, with its own state and
    /// remaining cooldown, under its stated labels: `(pool, lane, state, cooldown)`. A destination
    /// whose lifetime budget is spent reads Open with a never-elapsing cooldown, as a dead lane does.
    #[must_use]
    pub fn cell_readings(&self, now: u64) -> Vec<(String, String, BreakerState, u64)> {
        let planes = self.planes.read().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        for published in planes.values() {
            for (pool, destination, cell) in published.unit.cells() {
                let (Some(pool_label), Some(lane_label)) = (
                    published.pools.get(&pool),
                    published.lanes.get(&destination),
                ) else {
                    continue;
                };
                let state = if matches!(published.unit.budget_remaining(destination), Some(0)) {
                    BreakerState::Open { until: u64::MAX }
                } else {
                    match cell.state() {
                        CellState::Closed => BreakerState::Closed,
                        CellState::Open { until } => BreakerState::Open { until },
                        CellState::HalfOpen => BreakerState::HalfOpen,
                    }
                };
                let cooldown = cell.cooldown_until().saturating_sub(now);
                out.push((pool_label.clone(), lane_label.clone(), state, cooldown));
            }
        }
        out
    }
}

#[cfg(test)]
#[path = "../tests/door_cells_tests.rs"]
mod tests;
