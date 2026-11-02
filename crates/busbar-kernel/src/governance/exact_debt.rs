// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExactModelDelta {
    pub(super) model: String,
    #[serde(with = "decimal_units")]
    pub(super) usage_units: BTreeMap<String, i128>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExactUsageDelta {
    #[serde(with = "decimal_count")]
    pub(super) requests: i128,
    #[serde(with = "decimal_count")]
    pub(super) billable_requests: i128,
    pub(super) models: Vec<ExactModelDelta>,
}
impl ExactUsageDelta {
    pub(super) fn chunk(&self) -> UsageDelta {
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

    pub(super) fn subtract(&mut self, chunk: &UsageDelta) {
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
    pub(super) fn unit(&mut self, model: &str, unit: &str, change: i128) {
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
            if dated && model.era == RawRateEra::legacy(0) {
                continue;
            }
            let name = if dated {
                era_model(model.era, &model.model)
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
                    &era_tag(*era),
                    ERA_FEE_UNIT,
                    i128::from(current.get(era).copied().unwrap_or(0))
                        - i128::from(flushed.get(era).copied().unwrap_or(0)),
                );
            }
        }
        debt
    }
}

mod decimal_count {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(count: &i128, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&count.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<i128, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
mod decimal_units {
    use super::BTreeMap;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(
        units: &BTreeMap<String, i128>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        units
            .iter()
            .map(|(unit, count)| (unit, count.to_string()))
            .collect::<BTreeMap<_, _>>()
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<String, i128>, D::Error> {
        BTreeMap::<String, String>::deserialize(deserializer)?
            .into_iter()
            .map(|(unit, count)| {
                count
                    .parse()
                    .map(|count| (unit, count))
                    .map_err(serde::de::Error::custom)
            })
            .collect()
    }
}

/// The aggregate row and its dated siblings are two views of the same facts.
/// Allocation and chunking operate on these signed era segments, including the
/// exact undated remainder, then rebuild both views together.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum UsageSegment {
    Requests,
    Fee(Option<String>),
    Unit {
        model: String,
        unit: String,
        era: Option<String>,
    },
}

#[derive(Clone, Default)]
pub(super) struct SegmentedUsage(BTreeMap<UsageSegment, i128>);
impl SegmentedUsage {
    pub(super) fn of(plain: &ExactUsageDelta, dated: &ExactUsageDelta) -> RecordStoreResult<Self> {
        let invalid = || RecordStoreError("invalid aggregate/dated raw usage segments".into());
        if dated.requests != 0 || dated.billable_requests != 0 {
            return Err(invalid());
        }
        let mut legacy = plain.clone();
        let mut result = Self::default();
        let mut names = std::collections::BTreeSet::new();
        for model in &dated.models {
            if !names.insert(&model.model) {
                return Err(invalid());
            }
            if let Some((era, name)) = model.model.split_once(ERA_MODEL_SEP) {
                if name.is_empty() || parse_era_tag(era)?.is_none() {
                    return Err(invalid());
                }
                for (unit, count) in &model.usage_units {
                    result.0.insert(
                        UsageSegment::Unit {
                            model: name.into(),
                            unit: unit.clone(),
                            era: Some(era.into()),
                        },
                        *count,
                    );
                    legacy.unit(name, unit, -*count);
                }
            } else {
                if parse_era_tag(&model.model)?.is_none() {
                    return Err(invalid());
                }
                for (unit, count) in &model.usage_units {
                    if unit != ERA_FEE_UNIT {
                        return Err(invalid());
                    }
                    result
                        .0
                        .insert(UsageSegment::Fee(Some(model.model.clone())), *count);
                    legacy.billable_requests -= *count;
                }
            }
        }
        result.0.insert(UsageSegment::Requests, legacy.requests);
        result
            .0
            .insert(UsageSegment::Fee(None), legacy.billable_requests);
        names.clear();
        for model in &legacy.models {
            if !names.insert(&model.model) {
                return Err(invalid());
            }
            for (unit, count) in &model.usage_units {
                result.0.insert(
                    UsageSegment::Unit {
                        model: model.model.clone(),
                        unit: unit.clone(),
                        era: None,
                    },
                    *count,
                );
            }
        }
        Ok(result)
    }

    pub(super) fn deltas(&self) -> (ExactUsageDelta, ExactUsageDelta) {
        let mut plain = ExactUsageDelta::default();
        let mut dated = ExactUsageDelta::default();
        for (segment, count) in &self.0 {
            Self::add(&mut plain, &mut dated, segment, *count);
        }
        (plain, dated)
    }
    fn add(
        plain: &mut ExactUsageDelta,
        dated: &mut ExactUsageDelta,
        segment: &UsageSegment,
        count: i128,
    ) {
        match segment {
            UsageSegment::Requests => plain.requests += count,
            UsageSegment::Fee(era) => {
                plain.billable_requests += count;
                if let Some(era) = era {
                    dated.unit(era, ERA_FEE_UNIT, count);
                }
            }
            UsageSegment::Unit { model, unit, era } => {
                plain.unit(model, unit, count);
                if let Some(era) = era {
                    dated.unit(&format!("{era}{ERA_MODEL_SEP}{model}"), unit, count);
                }
            }
        }
    }
    pub(super) fn positive(&self) -> Self {
        Self(
            self.0
                .iter()
                .filter(|(_, count)| **count > 0)
                .map(|(segment, count)| (segment.clone(), *count))
                .collect(),
        )
    }
    pub(super) fn merge(&mut self, other: &Self) {
        for (segment, count) in &other.0 {
            *self.0.entry(segment.clone()).or_default() += *count;
        }
    }
    pub(super) fn take_negatives(&mut self, capacity: Option<&Self>) -> Self {
        let mut taken = Self::default();
        for (segment, count) in &mut self.0 {
            if *count >= 0 {
                continue;
            }
            let bound = capacity.map_or(i128::MAX, |capacity| {
                capacity.0.get(segment).copied().unwrap_or(0).max(0)
            });
            let amount = count.saturating_neg().min(bound);
            *count += amount;
            if amount != 0 {
                taken.0.insert(segment.clone(), -amount);
            }
        }
        taken
    }
    pub(super) fn is_zero(&self) -> bool {
        self.0.values().all(|count| *count == 0)
    }

    pub(super) fn chunk(&self) -> (UsageDelta, UsageDelta) {
        let mut plain = ExactUsageDelta::default();
        let mut dated = ExactUsageDelta::default();
        for (segment, count) in &self.0 {
            let current = match segment {
                UsageSegment::Requests => plain.requests,
                UsageSegment::Fee(_) => plain.billable_requests,
                UsageSegment::Unit { model, unit, .. } => plain
                    .models
                    .iter()
                    .find(|row| row.model == *model)
                    .and_then(|row| row.usage_units.get(unit))
                    .copied()
                    .unwrap_or(0),
            };
            let count = (*count)
                .clamp(i128::from(i64::MIN), i128::from(i64::MAX))
                .clamp(
                    i128::from(i64::MIN) - current,
                    i128::from(i64::MAX) - current,
                );
            Self::add(&mut plain, &mut dated, segment, count);
        }
        (
            plain.signed().expect("chunk aggregate bounded per field"),
            dated
                .signed()
                .expect("chunk dated segments bounded per field"),
        )
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

pub(super) struct BudgetFlushFlight {
    bucket: String,
    window: u64,
    debt: std::sync::Mutex<FlightDebt>,
    runner: BudgetFlushRunner,
    durable: Option<super::raw_recovery::DurableUsageFlight>,
}

/// A runner's ownership marker, never a mutex held across a store call. Both a whole flush and
/// each retained flight use this handoff so the final caller can join existing work.
#[derive(Default)]
pub(super) struct BudgetFlushRunner {
    owner: std::sync::Mutex<Option<std::thread::ThreadId>>,
    released: std::sync::Condvar,
}

pub(super) struct BudgetFlushRun<'a>(&'a BudgetFlushRunner);
impl Drop for BudgetFlushRun<'_> {
    fn drop(&mut self) {
        *self.0.owner.lock().unwrap_or_else(|p| p.into_inner()) = None;
        self.0.released.notify_all();
    }
}

impl BudgetFlushRunner {
    pub(super) fn enter(&self, final_flush: bool) -> Result<BudgetFlushRun<'_>, &'static str> {
        let current = std::thread::current().id();
        let mut owner = self.owner.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            match *owner {
                None => {
                    *owner = Some(current);
                    drop(owner);
                    return Ok(BudgetFlushRun(self));
                }
                Some(active) if final_flush && active != current => {
                    owner = self.released.wait(owner).unwrap_or_else(|p| p.into_inner());
                }
                Some(active) => {
                    let reentrant_final = final_flush && active == current;
                    drop(owner);
                    return Err(if reentrant_final {
                        "final budget flush reentered its own active store call"
                    } else {
                        "budget flush already in flight"
                    });
                }
            }
        }
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
            let correcting = cell
                .correction
                .as_ref()
                .is_some_and(|branch| branch.window == window);
            if cell.flushing_windows.contains_key(&window)
                || (correcting && !self.recovery_enabled())
            {
                continue;
            }
            let original = correcting.then(|| cell.clone());
            let correction_debt = if correcting {
                match Self::take_correction_positives(cell, window) {
                    Ok(Some(debt)) => Some(debt),
                    Ok(None) | Err(_) => continue,
                }
            } else {
                None
            };
            let mut plain = ExactUsageDelta::default();
            let mut dated = ExactUsageDelta::default();
            let mut requires_chunks = false;
            if let Some((correction_plain, correction_dated)) = correction_debt {
                plain = correction_plain;
                dated = correction_dated;
            } else {
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
                    requires_chunks |=
                        current.signed().is_none() || current_dated.signed().is_none();
                    plain.merge(&current);
                    dated.merge(&current_dated);
                }
            }
            requires_chunks |= plain.signed().is_none() || dated.signed().is_none();
            if (plain.is_zero() && dated.is_zero())
                || (!requires_chunks && !self.store.supports_usage_batch_deduped())
            {
                if let Some(original) = original {
                    *cell = original;
                }
                continue;
            }
            let durable = if self.recovery_enabled() {
                let prepared = if correcting {
                    Self::usage_recovery_child(bucket, window, plain.clone(), dated.clone())
                        .and_then(|child| {
                            let Some(child) = child else {
                                return Ok(super::raw_recovery::DurableUsageFlight {
                                    child: None,
                                    prerequisite: None,
                                    deferred_plain: ExactUsageDelta::default(),
                                    deferred_dated: ExactUsageDelta::default(),
                                });
                            };
                            let parent =
                                self.stage_correction_handoff(bucket, cell, window, child.clone())?;
                            Ok(super::raw_recovery::DurableUsageFlight {
                                child: Some(child),
                                prerequisite: Some(parent),
                                deferred_plain: ExactUsageDelta::default(),
                                deferred_dated: ExactUsageDelta::default(),
                            })
                        })
                } else {
                    self.capture_usage_recovery(bucket, window, plain.clone(), dated.clone())
                };
                match prepared {
                    Ok(flight) => Some(flight),
                    Err(_) => {
                        if let Some(original) = original {
                            *cell = original;
                        }
                        continue;
                    }
                }
            } else {
                None
            };
            let (deferred_plain, deferred_dated) = durable
                .as_ref()
                .map(|flight| (flight.deferred_plain.clone(), flight.deferred_dated.clone()))
                .unwrap_or_default();
            let flight = Arc::new(BudgetFlushFlight {
                bucket: bucket.into(),
                window,
                debt: std::sync::Mutex::new(FlightDebt {
                    plain,
                    dated,
                    chunk: None,
                    finished: false,
                }),
                runner: BudgetFlushRunner::default(),
                durable,
            });
            self.budget_flushes
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert((bucket.into(), window), flight.clone());
            captured.push(flight);
            cell.mutate(|cell| {
                if !correcting {
                    cell.rolled.retain(|(at, _)| *at != window);
                    cell.rolled_eras.retain(|(at, _)| *at != window);
                    if cell.window_start == window {
                        cell.flushed_requests = cell.requests;
                        cell.flushed_billable_requests = cell.billable_requests;
                        cell.flushed_fee_eras = cell.fee_eras.clone();
                        for model in &mut cell.models {
                            model.flushed = model.cur.clone();
                            model.flushed_era = model.cur.clone();
                        }
                    }
                    park_window(&mut cell.rolled, window, deferred_plain.clone());
                    park_window(&mut cell.rolled_eras, window, deferred_dated.clone());
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
        let _running = match flight.runner.enter(final_flush) {
            Ok(running) => running,
            Err(message) => return (0, Some(RecordStoreError(message.into()))),
        };
        let mut confirmed = 0;
        if let Some(durable) = &flight.durable {
            if let Err(error) = self.drive_durable_usage_flight(durable) {
                return (0, Some(error));
            }
            let mut debt = flight.debt.lock().unwrap_or_else(|p| p.into_inner());
            debt.plain = ExactUsageDelta::default();
            debt.dated = ExactUsageDelta::default();
            confirmed = usize::from(durable.child.is_some());
        }
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
                    let (plain, dated) = match SegmentedUsage::of(&debt.plain, &debt.dated) {
                        Ok(segments) => segments.chunk(),
                        Err(error) => return (confirmed, Some(error)),
                    };
                    debt.chunk = Some(Chunk {
                        op: crate::door::op_id(),
                        plain,
                        dated,
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
