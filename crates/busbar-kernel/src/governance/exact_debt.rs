// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Raw write-behind debt stays exact even when one legacy signed batch cannot carry it.
use super::*;
use std::collections::BTreeMap;

#[derive(Clone, Default)]
pub(super) struct ExactModelDelta {
    pub(super) model: String,
    pub(super) usage_units: BTreeMap<String, i128>,
}
#[derive(Clone, Default)]
pub(super) struct ExactUsageDelta {
    pub(super) requests: i128,
    pub(super) billable_requests: i128,
    pub(super) models: Vec<ExactModelDelta>,
}
impl ExactUsageDelta {
    /// The next wire-representable part of every counter. No policy limit is imposed: successive
    /// chunks cover the entire exact debt using the existing signed integer domain.
    fn chunk(&self) -> UsageDelta {
        let part = |count: i128| count.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
        UsageDelta {
            requests: part(self.requests),
            billable_requests: part(self.billable_requests),
            models: self
                .models
                .iter()
                .filter_map(|model| {
                    let usage_units: BTreeMap<_, _> = model
                        .usage_units
                        .iter()
                        .filter(|(_, count)| **count != 0)
                        .map(|(unit, count)| (unit.clone(), part(*count)))
                        .collect();
                    (!usage_units.is_empty()).then(|| busbar_contract::records::ModelTokensDelta {
                        model: model.model.clone(),
                        usage_units,
                    })
                })
                .collect(),
        }
    }

    fn subtract(&mut self, chunk: &UsageDelta) {
        let mut acknowledged = Self::from_signed(chunk);
        acknowledged.requests = -acknowledged.requests;
        acknowledged.billable_requests = -acknowledged.billable_requests;
        for model in &mut acknowledged.models {
            for count in model.usage_units.values_mut() {
                *count = -*count;
            }
        }
        self.merge(&acknowledged);
    }

    pub(super) fn is_zero(&self) -> bool {
        self.requests == 0
            && self.billable_requests == 0
            && self
                .models
                .iter()
                .all(|model| model.usage_units.values().all(|count| *count == 0))
    }
    fn unit(&mut self, model: &str, unit: &str, change: i128) {
        if change == 0 {
            return;
        }
        let position = self.models.iter().position(|row| row.model == model);
        let row = match position {
            Some(position) => &mut self.models[position],
            None => {
                self.models.push(ExactModelDelta {
                    model: model.into(),
                    usage_units: BTreeMap::new(),
                });
                self.models.last_mut().expect("just inserted raw model")
            }
        };
        *row.usage_units.entry(unit.into()).or_default() += change;
    }
    pub(super) fn merge(&mut self, other: &Self) {
        self.requests += other.requests;
        self.billable_requests += other.billable_requests;
        for model in &other.models {
            for (unit, count) in &model.usage_units {
                self.unit(&model.model, unit, *count);
            }
        }
    }
    pub(super) fn from_signed(delta: &UsageDelta) -> Self {
        Self {
            requests: i128::from(delta.requests),
            billable_requests: i128::from(delta.billable_requests),
            models: delta
                .models
                .iter()
                .map(|model| ExactModelDelta {
                    model: model.model.clone(),
                    usage_units: model
                        .usage_units
                        .iter()
                        .map(|(unit, count)| (unit.clone(), i128::from(*count)))
                        .collect(),
                })
                .collect(),
        }
    }
    pub(super) fn signed(&self) -> Option<UsageDelta> {
        Some(UsageDelta {
            requests: i64::try_from(self.requests).ok()?,
            billable_requests: i64::try_from(self.billable_requests).ok()?,
            models: self
                .models
                .iter()
                .map(|model| {
                    Some(busbar_contract::records::ModelTokensDelta {
                        model: model.model.clone(),
                        usage_units: model
                            .usage_units
                            .iter()
                            .filter(|(_, count)| **count != 0)
                            .map(|(unit, count)| {
                                i64::try_from(*count)
                                    .ok()
                                    .map(|count| (unit.clone(), count))
                            })
                            .collect::<Option<_>>()?,
                    })
                })
                .collect::<Option<_>>()?,
        })
    }
    pub(super) fn of(cell: &BudgetCell, dated: bool) -> Self {
        let mut debt = Self::default();
        if !dated {
            debt.requests = i128::from(cell.requests) - i128::from(cell.flushed_requests);
            debt.billable_requests =
                i128::from(cell.billable_requests) - i128::from(cell.flushed_billable_requests);
        }
        for model in &cell.models {
            if dated && model.era == 0 {
                continue;
            }
            let name = if dated {
                format!("{}{ERA_MODEL_SEP}{}", model.era, model.model)
            } else {
                model.model.to_string()
            };
            let flushed = if dated {
                &model.flushed_era
            } else {
                &model.flushed
            };
            for unit in model
                .cur
                .keys()
                .chain(flushed.keys())
                .collect::<std::collections::BTreeSet<_>>()
            {
                debt.unit(
                    &name,
                    unit,
                    i128::from(model.cur.get(unit).copied().unwrap_or(0))
                        - i128::from(flushed.get(unit).copied().unwrap_or(0)),
                );
            }
        }
        if dated {
            let current: BTreeMap<_, _> = cell.fee_eras.dated().iter().copied().collect();
            let flushed: BTreeMap<_, _> = cell.flushed_fee_eras.dated().iter().copied().collect();
            for era in current
                .keys()
                .chain(flushed.keys())
                .collect::<std::collections::BTreeSet<_>>()
            {
                debt.unit(
                    &era.to_string(),
                    ERA_FEE_UNIT,
                    i128::from(current.get(era).copied().unwrap_or(0))
                        - i128::from(flushed.get(era).copied().unwrap_or(0)),
                );
            }
        }
        debt
    }
}

/// One immutable wire operation. Its identity remains paired with its body through errors,
/// unwinding, caller cancellation and a later flusher invocation.
#[derive(Clone)]
struct Chunk {
    op: busbar_contract::abi::store::OpId,
    plain: UsageDelta,
    dated: UsageDelta,
    started: std::time::Instant,
}

struct FlightDebt {
    plain: ExactUsageDelta,
    dated: ExactUsageDelta,
    chunk: Option<Chunk>,
    finished: bool,
}

/// A window's exact outbound debt. Cell baselines are capture watermarks while this owner exists;
/// only receipt-confirmed chunks leave this debt. This is raw write custody, never another book.
pub(super) struct BudgetFlushFlight {
    bucket: String,
    window: u64,
    debt: std::sync::Mutex<FlightDebt>,
    runner: std::sync::Mutex<Option<std::thread::ThreadId>>,
    runner_released: std::sync::Condvar,
}

struct FlightRun<'a>(&'a BudgetFlushFlight);
impl Drop for FlightRun<'_> {
    fn drop(&mut self) {
        *self.0.runner.lock().unwrap_or_else(|p| p.into_inner()) = None;
        self.0.runner_released.notify_all();
    }
}

pub(super) struct BudgetDeleteGuard<'a> {
    state: &'a GovState,
    bucket: String,
}
impl Drop for BudgetDeleteGuard<'_> {
    fn drop(&mut self) {
        self.state
            .deleting_budget_buckets
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.bucket);
    }
}

impl GovState {
    pub(super) fn hold_budget_flush_deletion(&self, bucket: &str) -> BudgetDeleteGuard<'_> {
        let _cells = self.budget.write(bucket);
        self.deleting_budget_buckets
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(bucket.into());
        BudgetDeleteGuard {
            state: self,
            bucket: bucket.into(),
        }
    }

    pub(super) fn budget_bucket_deleting(&self, bucket: &str) -> bool {
        self.deleting_budget_buckets
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(bucket)
    }

    /// Called with this bucket's shard held. Capable stores give every nonzero outbound delta
    /// retained custody. Legacy stores retain their ordinary path for representable debt;
    /// oversized debt still requires the existing exact batch primitive.
    pub(super) fn capture_budget_flushes(
        &self,
        bucket: &str,
        cell: &mut BudgetCell,
    ) -> Vec<Arc<BudgetFlushFlight>> {
        let mut captured = Vec::new();
        if self.budget_bucket_deleting(bucket) {
            return captured;
        }
        let mut windows = std::collections::BTreeSet::from([cell.window_start]);
        windows.extend(cell.rolled.iter().map(|(window, _)| *window));
        windows.extend(cell.rolled_eras.iter().map(|(window, _)| *window));
        for window in windows {
            if cell.flushing_windows.contains_key(&window)
                || cell
                    .correction
                    .as_ref()
                    .is_some_and(|branch| branch.window == window)
            {
                continue;
            }
            let mut plain = ExactUsageDelta::default();
            let mut dated = ExactUsageDelta::default();
            let mut requires_chunks = false;
            for (_, debt) in cell.rolled.iter().filter(|(at, _)| *at == window) {
                requires_chunks |= debt.signed().is_none();
                plain.merge(debt);
            }
            for (_, debt) in cell.rolled_eras.iter().filter(|(at, _)| *at == window) {
                requires_chunks |= debt.signed().is_none();
                dated.merge(debt);
            }
            if cell.window_start == window {
                let current = ExactUsageDelta::of(cell, false);
                let current_dated = ExactUsageDelta::of(cell, true);
                requires_chunks |= current.signed().is_none() || current_dated.signed().is_none();
                plain.merge(&current);
                dated.merge(&current_dated);
            }
            requires_chunks |= plain.signed().is_none() || dated.signed().is_none();
            if (plain.is_zero() && dated.is_zero())
                || (!requires_chunks && !self.store.supports_usage_batch_deduped())
            {
                continue;
            }
            let flight = Arc::new(BudgetFlushFlight {
                bucket: bucket.into(),
                window,
                debt: std::sync::Mutex::new(FlightDebt {
                    plain,
                    dated,
                    chunk: None,
                    finished: false,
                }),
                runner: std::sync::Mutex::new(None),
                runner_released: std::sync::Condvar::new(),
            });
            self.budget_flushes
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert((bucket.into(), window), flight.clone());
            captured.push(flight);
            cell.mutate(|cell| {
                cell.rolled.retain(|(at, _)| *at != window);
                cell.rolled_eras.retain(|(at, _)| *at != window);
                if cell.window_start == window {
                    // Ownership transfers to the flight, not to a durable acknowledgement. New
                    // semantic mutations stay beyond these exact capture watermarks.
                    cell.flushed_requests = cell.requests;
                    cell.flushed_billable_requests = cell.billable_requests;
                    cell.flushed_fee_eras = cell.fee_eras.clone();
                    for model in &mut cell.models {
                        model.flushed = model.cur.clone();
                        model.flushed_era = model.cur.clone();
                    }
                }
                cell.flushing += 1;
                *cell.flushing_windows.entry(window).or_default() += 1;
                cell.dirty = true;
            });
        }
        captured
    }

    fn drive_budget_flush_flight(
        &self,
        flight: &Arc<BudgetFlushFlight>,
        final_flush: bool,
    ) -> (usize, Option<RecordStoreError>) {
        {
            let current = std::thread::current().id();
            let mut runner = flight.runner.lock().unwrap_or_else(|p| p.into_inner());
            loop {
                match *runner {
                    None => {
                        *runner = Some(current);
                        break;
                    }
                    Some(owner) if final_flush && owner != current => {
                        // WriteBehind has no I/O deadline. The authoritative final caller must
                        // join an existing owner before reconciling its unknown result.
                        runner = flight
                            .runner_released
                            .wait(runner)
                            .unwrap_or_else(|p| p.into_inner());
                    }
                    Some(owner) => {
                        let reentrant_final = final_flush && owner == current;
                        drop(runner);
                        let message = if reentrant_final {
                            "final raw usage flush reentered its own active store call"
                        } else {
                            "raw usage chunk already in flight"
                        };
                        return (0, Some(RecordStoreError(message.into())));
                    }
                }
            }
        }
        let _running = FlightRun(flight);
        let mut confirmed = 0;
        loop {
            let chunk = {
                let mut debt = flight.debt.lock().unwrap_or_else(|p| p.into_inner());
                if debt.finished {
                    return (confirmed, None);
                }
                if debt.plain.is_zero() && debt.dated.is_zero() {
                    drop(debt);
                    let mut cells = self.budget.write(&flight.bucket);
                    if let Some(cell) = cells.get_mut(&flight.bucket) {
                        cell.mutate(|cell| {
                            cell.flushing = cell
                                .flushing
                                .checked_sub(1)
                                .expect("flight owns a snapshot");
                            let count = cell
                                .flushing_windows
                                .get_mut(&flight.window)
                                .expect("flight owns its window");
                            *count -= 1;
                            if *count == 0 {
                                cell.flushing_windows.remove(&flight.window);
                            }
                            cell.dirty |= !ExactUsageDelta::of(cell, false).is_zero()
                                || !ExactUsageDelta::of(cell, true).is_zero()
                                || !cell.rolled.is_empty()
                                || !cell.rolled_eras.is_empty();
                        });
                    }
                    flight
                        .debt
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .finished = true;
                    let mut flights = self
                        .budget_flushes
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    let address = (flight.bucket.clone(), flight.window);
                    if flights
                        .get(&address)
                        .is_some_and(|held| Arc::ptr_eq(held, flight))
                    {
                        flights.remove(&address);
                    }
                    drop(flights);
                    drop(cells);
                    return (confirmed, None);
                }
                if debt.chunk.is_none() {
                    debt.chunk = Some(Chunk {
                        op: crate::door::op_id(),
                        plain: debt.plain.chunk(),
                        dated: debt.dated.chunk(),
                        started: std::time::Instant::now(),
                    });
                }
                debt.chunk
                    .as_ref()
                    .expect("immutable chunk retained")
                    .clone()
            };
            if chunk.started.elapsed().as_secs()
                >= busbar_contract::abi::store::OP_ID_RETENTION_SECS
            {
                return (confirmed,Some(RecordStoreError("raw usage chunk receipt retention expired; exact debt and identity retained".into())));
            }
            let era_bucket = era_bucket(&flight.bucket);
            let mut cells = Vec::new();
            if !chunk.plain.is_zero() {
                cells.push((flight.bucket.as_str(), flight.window, chunk.plain.clone()));
            }
            if !chunk.dated.is_zero() {
                cells.push((era_bucket.as_str(), flight.window, chunk.dated.clone()));
            }
            // The immutable chunk is already owned before entering the store. No budget or flight
            // mutex spans a call that may pend, fail after commit, time out, or unwind.
            if let Err(error) = self.store.add_usage_batch_deduped(chunk.op, &cells) {
                return (confirmed, Some(error));
            }
            let mut debt = flight.debt.lock().unwrap_or_else(|p| p.into_inner());
            debt.plain.subtract(&chunk.plain);
            debt.dated.subtract(&chunk.dated);
            debt.chunk = None;
            confirmed += 1;
        }
    }

    pub(super) fn resume_budget_flushes(&self, final_flush: bool) -> (usize, Vec<String>) {
        let flights: Vec<_> = self
            .budget_flushes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .cloned()
            .collect();
        self.resume_budget_flush_list(flights, final_flush)
    }

    pub(super) fn resume_budget_flush_list(
        &self,
        flights: Vec<Arc<BudgetFlushFlight>>,
        final_flush: bool,
    ) -> (usize, Vec<String>) {
        let mut confirmed = 0;
        let mut errors = Vec::new();
        for flight in flights {
            let (done, error) = self.drive_budget_flush_flight(&flight, final_flush);
            confirmed += done;
            if let Some(error) = error {
                errors.push(format!("{}@{}: {error}", flight.bucket, flight.window));
            }
        }
        (confirmed, errors)
    }

    pub(super) fn settle_budget_flush_for_delete(&self, bucket: &str) -> RecordStoreResult<()> {
        let flights: Vec<_> = self
            .budget_flushes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|((id, _), _)| id == bucket)
            .map(|(_, flight)| flight.clone())
            .collect();
        for flight in flights {
            if let (_, Some(error)) = self.drive_budget_flush_flight(&flight, false) {
                return Err(error);
            }
        }
        Ok(())
    }
}
