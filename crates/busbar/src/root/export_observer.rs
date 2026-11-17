// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Root-owned logical-instance reservations and retained first-loss evidence.
//! Producer handles and generation guards preserve a cell through retirement. Native audit
//! alone owns an accepted original; this service never retries an already transferred record.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::export_calls::{
    ExportLossFacts, ExportLossKind, ExportObservation, ExportObserver,
};
use busbar_kernel::audit::auditlog::{
    try_enqueue_export_failure, ExportAuditReceipt, MAX_PENDING_AUDIT,
};
use tokio::sync::{watch, Notify};

/// The five families all producers share. No producer chooses a label vocabulary.
use busbar_kernel::export::delivery::EXPORT_CUSTODY_TOTAL as CUSTODY;
use busbar_kernel::snapshot::{
    EXPORT_CAPTURE_REFUSALS_TOTAL as CAPTURE_REFUSALS, EXPORT_DROPPED_TOTAL as DROPPED,
    EXPORT_HELD_LINES as HELD, EXPORT_INTEGRITY_FAILURES_TOTAL as INTEGRITY_FAILURES,
};

#[derive(Default)]
struct FirstLoss<R> {
    facts: Option<ExportLossFacts>,
    receipt: Option<R>,
    confirmed: bool,
    retry_warned: bool,
}

impl<R> FirstLoss<R> {
    fn record(&mut self, facts: ExportLossFacts) -> bool {
        if self.facts.is_some() {
            return false;
        }
        self.facts = Some(facts);
        true
    }

    fn step(
        &mut self,
        transfer: impl FnOnce(&ExportLossFacts) -> Option<R>,
        confirmed: impl FnOnce(&R) -> bool,
    ) -> bool {
        if self.confirmed {
            return false;
        }
        let Some(facts) = self.facts.as_ref() else {
            return false;
        };
        if let Some(receipt) = self.receipt.as_ref() {
            if confirmed(receipt) {
                self.confirmed = true;
                return false;
            }
        } else if let Some(receipt) = transfer(facts) {
            self.receipt = Some(receipt);
            return false;
        }
        !std::mem::replace(&mut self.retry_warned, true)
    }

    fn settled(&self) -> bool {
        self.facts.is_none() || self.confirmed
    }
}

struct Cell {
    instance: String,
    state: Mutex<CellState>,
}

struct CellState {
    published: bool,
    first: FirstLoss<ExportAuditReceipt>,
}

struct State {
    cells: BTreeMap<String, Arc<Cell>>,
    intake: bool,
    late: u64,
}

/// One root owner, constructed before any export pump; no global observer slot.
pub(crate) struct ExportObservers {
    state: Mutex<State>,
    wake: Notify,
}

struct BoundObserver {
    owner: Arc<ExportObservers>,
    cell: Arc<Cell>,
}

/// An unpublished candidate owns all its reservations or none of them.
pub(crate) struct ExportReservation {
    owner: Arc<ExportObservers>,
    observers: BTreeMap<String, Arc<BoundObserver>>,
}

/// Retain with the serving generation until its producers have stopped.
pub(crate) struct ExportGeneration {
    observers: BTreeMap<String, Arc<BoundObserver>>,
}

impl ExportObservers {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                cells: BTreeMap::new(),
                intake: true,
                late: 0,
            }),
            wake: Notify::new(),
        })
    }

    /// Called before opening/publishing the complete candidate, including reloads.
    pub(crate) fn reserve(
        self: &Arc<Self>,
        names: impl IntoIterator<Item = String>,
    ) -> Result<ExportReservation, String> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if !state.intake {
            return Err(capacity_refusal("export observation intake has stopped"));
        }
        reclaim(&mut state, false);
        let mut unique = BTreeSet::new();
        for name in names {
            unique.insert(name);
            if unique.len() > MAX_PENDING_AUDIT {
                return Err(capacity_refusal(
                    "export observer reservation capacity exhausted",
                ));
            }
        }
        let new = unique
            .iter()
            .filter(|name| !state.cells.contains_key(*name))
            .count();
        if state.cells.len().saturating_add(new) > MAX_PENDING_AUDIT {
            return Err(capacity_refusal(
                "export observer reservation capacity exhausted",
            ));
        }
        let mut observers = BTreeMap::new();
        for name in unique {
            let cell = state.cells.entry(name.clone()).or_insert_with(|| {
                Arc::new(Cell {
                    instance: name.clone(),
                    state: Mutex::new(CellState {
                        published: false,
                        first: FirstLoss {
                            facts: None,
                            receipt: None,
                            confirmed: false,
                            retry_warned: false,
                        },
                    }),
                })
            });
            observers.insert(
                name,
                Arc::new(BoundObserver {
                    owner: Arc::clone(self),
                    cell: Arc::clone(cell),
                }),
            );
        }
        Ok(ExportReservation {
            owner: Arc::clone(self),
            observers,
        })
    }

    /// A bounded, synchronous ownership-transfer pass; never starts storage I/O.
    pub(crate) fn step(&self) {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        for cell in state.cells.values() {
            let mut held = cell.state.lock().unwrap_or_else(|error| error.into_inner());
            if held.first.step(
                |facts| try_enqueue_export_failure(facts).ok(),
                ExportAuditReceipt::is_confirmed,
            ) {
                notice(false, &cell.instance);
            }
        }
        drop(state);
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        reclaim(&mut state, false);
    }

    /// Root owns this worker's stop signal. Periodic wake guarantees retry without later loss.
    /// Stopping the worker never discards unresolved cells; #335 checks them before retirement.
    pub(crate) async fn run(self: Arc<Self>, stop: watch::Receiver<bool>) {
        self.run_with(stop, Self::step).await;
    }

    async fn run_with(self: Arc<Self>, mut stop: watch::Receiver<bool>, step: impl Fn(&Self)) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if *stop.borrow() {
                step(&self);
                return;
            }
            tokio::select! {
                biased;
                changed = stop.changed() => {
                    if changed.is_err() { step(&self); return; }
                }
                _ = interval.tick() => step(&self),
                _ = self.wake.notified() => step(&self),
            }
        }
    }

    /// Invoke only after the pump owner has proved producer quiescence. The same mutex guards
    /// every observation, so no in-progress callback can cross this boundary unnoticed.
    pub(crate) fn stop_intake(&self) {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .intake = false;
        self.wake.notify_one();
    }

    /// Positive shutdown completion needs closed intake and no late callbacks or retained loss.
    pub(crate) fn is_settled(&self) -> bool {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        !state.intake
            && state.late == 0
            && state.cells.values().all(|cell| {
                cell.state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .first
                    .settled()
            })
    }

    /// Immutable first facts for the existing shutdown failure report; no payload/secret data.
    pub(crate) fn unresolved(&self) -> Vec<ExportLossFacts> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state
            .cells
            .values()
            .filter_map(|cell| {
                let held = cell.state.lock().unwrap_or_else(|error| error.into_inner());
                (!held.first.settled())
                    .then(|| held.first.facts.clone())
                    .flatten()
            })
            .collect()
    }

    /// Exact saturated count for the root's incomplete-shutdown evidence.
    pub(crate) fn late_callbacks(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .late
    }
}

fn reclaim(state: &mut State, rollback: bool) {
    state.cells.retain(|_, cell| {
        if Arc::strong_count(cell) != 1 {
            return true;
        }
        let held = cell.state.lock().unwrap_or_else(|error| error.into_inner());
        if rollback {
            held.published || held.first.facts.is_some()
        } else {
            !held.first.settled()
        }
    });
}

fn capacity_refusal(detail: &str) -> String {
    busbar_kernel::diagnostics::coded::config_export_invalid(detail)
}

fn notice(first: bool, instance: &str) {
    busbar_kernel::diagnostics::export_loss(first, instance);
}

impl ExportReservation {
    pub(crate) fn observer(&self, name: &str) -> Option<Arc<dyn ExportObserver>> {
        self.observers
            .get(name)
            .map(|observer| Arc::clone(observer) as Arc<dyn ExportObserver>)
    }

    /// Call at actual successful generation publication; keep the returned guard in that generation.
    pub(crate) fn commit(mut self) -> ExportGeneration {
        for observer in self.observers.values() {
            observer
                .cell
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .published = true;
        }
        ExportGeneration {
            observers: std::mem::take(&mut self.observers),
        }
    }
}

impl Drop for ExportReservation {
    fn drop(&mut self) {
        self.observers.clear();
        let mut state = self
            .owner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        reclaim(&mut state, true);
    }
}

impl ExportGeneration {
    #[cfg(test)]
    pub(crate) fn observer(&self, name: &str) -> Option<Arc<dyn ExportObserver>> {
        self.observers
            .get(name)
            .map(|observer| Arc::clone(observer) as Arc<dyn ExportObserver>)
    }
}

impl Drop for ExportGeneration {
    fn drop(&mut self) {
        let owner = self
            .observers
            .values()
            .next()
            .map(|observer| Arc::clone(&observer.owner));
        self.observers.clear();
        if let Some(owner) = owner {
            owner.wake.notify_one();
        }
    }
}

impl ExportObserver for BoundObserver {
    fn observe(&self, observation: ExportObservation) {
        self.observe_at(observation, busbar_kernel::store::now());
    }
}

impl BoundObserver {
    fn observe_at(&self, observation: ExportObservation, observed_at: u64) {
        let mut state = self
            .owner
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !state.intake {
            if state.late == 0 {
                notice(false, &self.cell.instance);
            }
            state.late = state.late.saturating_add(1);
            return;
        }
        let instance = &self.cell.instance;
        let loss = match observation {
            ExportObservation::Dropped { reason, lines } if lines != 0 => {
                metrics::counter!(DROPPED, "instance" => instance.clone(), "reason" => reason.as_str()).increment(lines);
                Some((ExportLossKind::Dropped(reason), lines))
            }
            ExportObservation::Custody {
                stream,
                level,
                lines,
            } if lines != 0 => {
                metrics::counter!(CUSTODY, "instance" => instance.clone(), "stream" => stream.as_token(), "level" => level.as_str()).increment(lines);
                None
            }
            ExportObservation::CaptureRefused => {
                metrics::counter!(CAPTURE_REFUSALS, "instance" => instance.clone(), "reason" => "admission_rejected").increment(1);
                Some((ExportLossKind::CaptureRefused, 1))
            }
            ExportObservation::IntegrityFailed => {
                metrics::counter!(INTEGRITY_FAILURES, "instance" => instance.clone()).increment(1);
                Some((ExportLossKind::IntegrityFailed, 1))
            }
            ExportObservation::Held { lines } => {
                metrics::gauge!(HELD, "instance" => instance.clone(), "reason" => "key_unavailable").set(lines as f64);
                None
            }
            ExportObservation::Dropped { .. } | ExportObservation::Custody { .. } => None,
        };
        if let Some((kind, count)) = loss {
            let mut held = self
                .cell
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if held.first.record(ExportLossFacts {
                instance: instance.clone(),
                observed_at,
                count,
                kind,
            }) {
                notice(true, instance);
                self.owner.wake.notify_one();
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/export_observer.rs"]
mod tests;
