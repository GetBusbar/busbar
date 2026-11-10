// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExactModelDelta {
    #[serde(default)]
    pub(super) scale: u32,
    pub(super) model: String,
    #[serde(with = "decimal_units")]
    pub(super) usage_units: BTreeMap<String, i128>,
}
impl<'de> serde::Deserialize<'de> for ExactModelDelta {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Stored {
            model: String,
            #[serde(default)]
            scale: u32,
            #[serde(with = "decimal_units")]
            usage_units: BTreeMap<String, i128>,
        }
        let row = Stored::deserialize(deserializer)?;
        Ok(Self {
            model: row.model,
            scale: COUNT_SCALE,
            usage_units: row
                .usage_units
                .into_iter()
                .map(|(k, n)| {
                    Count::from_stored(n, row.scale)
                        .map(|n| (k, n.micros()))
                        .map_err(serde::de::Error::custom)
                })
                .collect::<Result<_, _>>()?,
        })
    }
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
    pub(super) fn subtract(&mut self, chunk: &UsageDelta) {
        let acknowledged = Self::from_signed(chunk);
        self.requests = self
            .requests
            .checked_sub(acknowledged.requests)
            .expect("acknowledged request debt overflow");
        self.billable_requests = self
            .billable_requests
            .checked_sub(acknowledged.billable_requests)
            .expect("acknowledged fee debt overflow");
        for model in &acknowledged.models {
            for (unit, count) in &model.usage_units {
                self.subtract_unit(&model.model, unit, *count)
                    .expect("acknowledged raw debt overflow");
            }
        }
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
                    scale: COUNT_SCALE,
                    usage_units: BTreeMap::new(),
                });
                self.models.last_mut().expect("just inserted raw model")
            }
        };
        let slot = row.usage_units.entry(unit.into()).or_default();
        *slot = slot
            .checked_add(change)
            .expect("raw debt exceeds Count range");
    }
    fn subtract_unit(&mut self, model: &str, unit: &str, count: i128) -> Option<()> {
        if let Some(row) = self.models.iter_mut().find(|row| row.model == model) {
            let slot = row.usage_units.entry(unit.into()).or_default();
            *slot = slot.checked_sub(count)?;
        } else {
            self.unit(model, unit, count.checked_neg()?);
        }
        Some(())
    }
    pub(super) fn merge(&mut self, other: &Self) {
        self.requests = self
            .requests
            .checked_add(other.requests)
            .expect("request debt overflow");
        self.billable_requests = self
            .billable_requests
            .checked_add(other.billable_requests)
            .expect("fee debt overflow");
        for model in &other.models {
            for (unit, count) in &model.usage_units {
                self.unit(
                    &model.model,
                    unit,
                    Count::from_stored(*count, model.scale)
                        .expect("valid debt scale")
                        .micros(),
                );
            }
        }
    }
    pub(super) fn from_signed(delta: &UsageDelta) -> Self {
        Self::try_from_signed(delta).expect("internally generated raw debt has a valid scale")
    }

    pub(super) fn try_from_signed(delta: &UsageDelta) -> Result<Self, CountError> {
        Ok(Self {
            requests: i128::from(delta.requests),
            billable_requests: i128::from(delta.billable_requests),
            models: delta
                .models
                .iter()
                .map(|model| {
                    Ok(ExactModelDelta {
                        model: model.model.clone(),
                        scale: COUNT_SCALE,
                        usage_units: model
                            .usage_units
                            .iter()
                            .map(|(unit, count)| {
                                Count::from_stored(*count, model.scale)
                                    .map(|n| (unit.clone(), n.micros()))
                            })
                            .collect::<Result<_, _>>()?,
                    })
                })
                .collect::<Result<_, CountError>>()?,
        })
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
                        scale: COUNT_SCALE,
                        usage_units: model
                            .usage_units
                            .iter()
                            .filter(|(_, count)| **count != 0)
                            .map(|(unit, count)| {
                                Count::from_stored(*count, model.scale)
                                    .ok()
                                    .map(|count| (unit.clone(), count.micros()))
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
                    model
                        .cur
                        .get(unit)
                        .copied()
                        .unwrap_or_default()
                        .checked_sub(flushed.get(unit).copied().unwrap_or_default())
                        .expect("raw count difference overflow")
                        .micros(),
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
                    whole_count(current.get(era).copied().unwrap_or(0))
                        .checked_sub(whole_count(flushed.get(era).copied().unwrap_or(0)))
                        .expect("fee count difference overflow")
                        .micros(),
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
                    legacy
                        .subtract_unit(name, unit, *count)
                        .ok_or_else(invalid)?;
                }
            } else {
                if parse_era_tag(&model.model)?.is_none() {
                    return Err(invalid());
                }
                for (unit, count) in &model.usage_units {
                    if unit != ERA_FEE_UNIT {
                        return Err(invalid());
                    }
                    result.0.insert(
                        UsageSegment::Fee(Some(model.model.clone())),
                        *count / 1_000_000,
                    );
                    if *count % 1_000_000 != 0 {
                        return Err(invalid());
                    }
                    legacy.billable_requests = legacy
                        .billable_requests
                        .checked_sub(*count / 1_000_000)
                        .ok_or_else(invalid)?;
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
            UsageSegment::Requests => {
                plain.requests = plain
                    .requests
                    .checked_add(count)
                    .expect("request segments overflow")
            }
            UsageSegment::Fee(era) => {
                plain.billable_requests = plain
                    .billable_requests
                    .checked_add(count)
                    .expect("fee segments overflow");
                if let Some(era) = era {
                    dated.unit(
                        era,
                        ERA_FEE_UNIT,
                        count.checked_mul(1_000_000).expect("fee count fits Count"),
                    );
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
            let slot = self.0.entry(segment.clone()).or_default();
            *slot = slot.checked_add(*count).expect("raw segment overflow");
        }
    }
    pub(super) fn subtract(&mut self, other: &Self) -> RecordStoreResult<()> {
        let mut parts = self.0.clone();
        for (segment, count) in &other.0 {
            let current = parts.entry(segment.clone()).or_default();
            *current = current.checked_sub(*count).ok_or_else(|| {
                RecordStoreError("raw usage segment difference exceeds signed custody range".into())
            })?;
        }
        self.0 = parts;
        Ok(())
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
            let bound = u128::try_from(bound).expect("nonnegative raw segment capacity");
            let amount = i128::try_from(count.unsigned_abs().min(bound))
                .expect("raw segment capacity fits signed Count");
            *count = count
                .checked_add(amount)
                .expect("bounded raw segment refund");
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
            let count = match segment {
                UsageSegment::Requests | UsageSegment::Fee(_) => (*count).clamp(
                    i128::from(i64::MIN) - current,
                    i128::from(i64::MAX) - current,
                ),
                UsageSegment::Unit { .. } => match current.checked_add(*count) {
                    Some(_) => *count,
                    None if *count > 0 => i128::MAX - current,
                    None => i128::MIN - current,
                },
            };
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
    op: busbar_contract::records::OpId,
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

/// Serializes flush futures without blocking an executor thread. The guard also releases
/// ownership when a driver future is cancelled; retained debt stays in its flight.
#[derive(Default)]
pub(super) struct BudgetFlushRunner {
    owner: tokio::sync::Mutex<()>,
}

tokio::task_local! {
    static ACTIVE_FLUSH_RUNNERS: Vec<usize>;
}

pub(super) struct BudgetFlushRun<'a> {
    _owner: tokio::sync::MutexGuard<'a, ()>,
    identity: usize,
}
impl BudgetFlushRun<'_> {
    /// Task-local scope is installed only while this future is polled. Another
    /// future on the same executor/task can still join the active owner normally.
    pub(super) async fn scope<T>(&self, future: impl std::future::Future<Output = T>) -> T {
        let mut owners = ACTIVE_FLUSH_RUNNERS
            .try_with(Clone::clone)
            .unwrap_or_default();
        owners.push(self.identity);
        ACTIVE_FLUSH_RUNNERS.scope(owners, future).await
    }
}

impl BudgetFlushRunner {
    pub(super) fn is_running(&self) -> bool {
        self.owner.try_lock().is_err()
    }

    pub(super) fn try_enter(&self) -> Result<BudgetFlushRun<'_>, &'static str> {
        self.owner
            .try_lock()
            .map(|owner| BudgetFlushRun {
                _owner: owner,
                identity: self as *const Self as usize,
            })
            .map_err(|_| "budget flush already in flight")
    }

    pub(super) async fn enter(
        &self,
        final_flush: bool,
    ) -> Result<BudgetFlushRun<'_>, &'static str> {
        if final_flush {
            let identity = self as *const Self as usize;
            if ACTIVE_FLUSH_RUNNERS
                .try_with(|owners| owners.contains(&identity))
                .unwrap_or(false)
            {
                return Err("final flush reentered its own active Store call");
            }
            Ok(BudgetFlushRun {
                _owner: self.owner.lock().await,
                identity,
            })
        } else {
            self.try_enter()
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
        settled: &super::raw_recovery::ForeignSettledSnapshot,
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
                    Ok(None) => continue,
                    Err(e) => {
                        tracing::warn!(
                            bucket = bucket,
                            window = window,
                            error = ?e,
                            "take_correction_positives failed; \
                             skipping bucket this flush cycle"
                        );
                        continue;
                    }
                }
            } else {
                None
            };
            let mut plain = ExactUsageDelta::default();
            let mut dated = ExactUsageDelta::default();

            if let Some((correction_plain, correction_dated)) = correction_debt {
                plain = correction_plain;
                dated = correction_dated;
            } else {
                for (_, debt) in cell.rolled.iter().filter(|(at, _)| *at == window) {
                    plain.merge(debt);
                }
                for (_, debt) in cell.rolled_eras.iter().filter(|(at, _)| *at == window) {
                    dated.merge(debt);
                }
                if cell.window_start == window {
                    let current = ExactUsageDelta::of(cell, false);
                    let current_dated = ExactUsageDelta::of(cell, true);

                    plain.merge(&current);
                    dated.merge(&current_dated);
                }
            }

            if plain.is_zero() && dated.is_zero() {
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
                    self.capture_usage_recovery(
                        bucket,
                        window,
                        plain.clone(),
                        dated.clone(),
                        settled,
                    )
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

    async fn drive_budget_flush_flight(
        &self,
        flight: &Arc<BudgetFlushFlight>,
        final_flush: bool,
    ) -> (usize, Option<RecordStoreError>) {
        let _running = match flight.runner.enter(final_flush).await {
            Ok(running) => running,
            Err(message) => return (0, Some(RecordStoreError(message.into()))),
        };
        let core = match self.core_store() {
            Ok(core) => core,
            Err(error) => return (0, Some(error)),
        };
        let mut confirmed = 0;
        if let Some(durable) = &flight.durable {
            if let Err(error) = self.drive_durable_usage_flight(durable).await {
                return (0, Some(error));
            }
            let mut debt = flight.debt.lock().unwrap_or_else(|p| p.into_inner());
            debt.plain = ExactUsageDelta::default();
            debt.dated = ExactUsageDelta::default();
            confirmed = usize::from(durable.child.as_ref().is_some_and(|child| {
                self.recovery_event(child.operation_id)
                    .is_some_and(|event| event.state == recovery::RecoveryState::Settled)
            }));
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
                    if let Some(child) = flight
                        .durable
                        .as_ref()
                        .and_then(|durable| durable.child.as_ref())
                    {
                        self.forget_confirmed_recovery(child.operation_id);
                    }
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

            if let Err(error) = core
                .ledger()
                .add_usage_batch_deduped(chunk.op, &cells)
                .await
            {
                return (confirmed, Some(error));
            }
            let mut debt = flight.debt.lock().unwrap_or_else(|p| p.into_inner());
            debt.plain.subtract(&chunk.plain);
            debt.dated.subtract(&chunk.dated);
            debt.chunk = None;
            confirmed += 1;
        }
    }

    pub(super) async fn resume_budget_flushes(&self, final_flush: bool) -> (usize, Vec<String>) {
        let flights: Vec<_> = self
            .budget_flushes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .cloned()
            .collect();
        self.resume_budget_flush_list(flights, final_flush).await
    }

    pub(super) async fn resume_budget_flush_list(
        &self,
        flights: Vec<Arc<BudgetFlushFlight>>,
        final_flush: bool,
    ) -> (usize, Vec<String>) {
        let mut confirmed = 0;
        let mut errors = Vec::new();
        for flight in flights {
            let (done, error) = self.drive_budget_flush_flight(&flight, final_flush).await;
            confirmed += done;
            if let Some(error) = error {
                errors.push(format!("{}@{}: {error}", flight.bucket, flight.window));
            }
        }
        (confirmed, errors)
    }

    pub(super) async fn settle_budget_flush_for_delete_async(
        &self,
        bucket: &str,
    ) -> RecordStoreResult<()> {
        let flights: Vec<_> = self
            .budget_flushes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|((id, _), _)| id == bucket)
            .map(|(_, flight)| flight.clone())
            .collect();
        for flight in flights {
            if let (_, Some(error)) = self.drive_budget_flush_flight(&flight, false).await {
                return Err(error);
            }
        }
        if self.has_unsettled_raw_bucket(bucket)? {
            return Err(RecordStoreError(
                "deletion requires confirmed raw usage custody".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod recovery_math_tests {
    use super::*;

    fn unit(model: &str, input: i128) -> ExactUsageDelta {
        let mut delta = ExactUsageDelta::default();
        delta.unit(model, "input", input);
        delta
    }
    fn input(delta: &ExactUsageDelta, model: &str) -> i128 {
        delta
            .models
            .iter()
            .find(|row| row.model == model)
            .and_then(|row| row.usage_units.get("input"))
            .copied()
            .unwrap_or(0)
    }

    #[test]
    fn net_positive_aggregate_does_not_hide_a_dependent_negative_era() {
        let era_a = RawRateEra::entry(10, EntryId([1; 12]));
        let era_b = RawRateEra::entry(10, EntryId([2; 12]));
        let a = era_model(era_a, "model");
        let b = era_model(era_b, "model");
        let mut dated = unit(&a, -3);
        dated.merge(&unit(&b, 5));
        let mut remaining = SegmentedUsage::of(&unit("model", 2), &dated).unwrap();
        let capacity = SegmentedUsage::of(&unit("model", 7), &unit(&a, 7)).unwrap();
        let held = remaining.take_negatives(Some(&capacity));
        let (held_plain, held_dated) = held.deltas();
        assert_eq!(input(&held_plain, "model"), -3);
        assert_eq!(input(&held_dated, &a), -3);
        let (send_plain, send_dated) = remaining.deltas();
        assert_eq!(input(&send_plain, "model"), 5);
        assert_eq!(input(&send_dated, &b), 5);
        assert_eq!(input(&send_dated, &a), 0);
    }

    #[test]
    fn signed_wire_chunks_preserve_era_cancellation_above_i64() {
        let a = era_model(RawRateEra::legacy(1), "model");
        let b = era_model(RawRateEra::legacy(2), "model");
        let mut plain = unit("model", 2);
        let mut dated = unit(&a, -i128::from(i64::MAX) - 7);
        dated.merge(&unit(&b, i128::from(i64::MAX) + 9));
        let mut posted_plain = ExactUsageDelta::default();
        let mut posted_dated = ExactUsageDelta::default();
        for _ in 0..3 {
            if plain.is_zero() && dated.is_zero() {
                break;
            }
            let (chunk_plain, chunk_dated) = SegmentedUsage::of(&plain, &dated).unwrap().chunk();
            let raw_plain = ExactUsageDelta::from_signed(&chunk_plain);
            let raw_dated = ExactUsageDelta::from_signed(&chunk_dated);
            assert_eq!(
                input(&raw_plain, "model"),
                input(&raw_dated, &a) + input(&raw_dated, &b)
            );
            plain.subtract(&chunk_plain);
            dated.subtract(&chunk_dated);
            posted_plain.merge(&raw_plain);
            posted_dated.merge(&raw_dated);
        }
        assert!(plain.is_zero() && dated.is_zero());
        assert_eq!(input(&posted_plain, "model"), 2);
        assert_eq!(input(&posted_dated, &a), -i128::from(i64::MAX) - 7);
        assert_eq!(input(&posted_dated, &b), i128::from(i64::MAX) + 9);
    }

    #[test]
    fn signed_wire_preserves_full_range_and_acknowledges_minimum() {
        for count in [i128::MIN, i128::MAX] {
            let mut debt = unit("model", count);
            let signed = debt.signed().expect("full signed Count fits wire");
            assert_eq!(signed.models[0].usage_units["input"], count);
            debt.subtract(&signed);
            assert!(debt.is_zero());
        }
    }

    #[test]
    fn full_range_era_segments_stay_paired_in_one_operation() {
        let era = era_model(RawRateEra::legacy(1), "model");
        for count in [i128::MIN, i128::MAX] {
            let plain = unit("model", count);
            let dated = unit(&era, count);
            let (sent_plain, sent_dated) = SegmentedUsage::of(&plain, &dated).unwrap().chunk();
            assert_eq!(sent_plain.models[0].usage_units["input"], count);
            assert_eq!(sent_dated.models[0].usage_units["input"], count);
        }
    }

    #[test]
    fn custody_json_preserves_full_signed_counts_through_origin_value_rewrite() {
        let delta = ExactUsageDelta {
            requests: i128::MAX,
            billable_requests: i128::MIN,
            ..unit("model", i128::MAX)
        };
        let encoded = serde_json::to_vec(&delta).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(value["requests"], i128::MAX.to_string());
        assert_eq!(value["billable_requests"], i128::MIN.to_string());
        let decoded: ExactUsageDelta = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, delta);
    }
}

#[cfg(test)]
mod async_flush_ownership_tests {
    use super::BudgetFlushRunner;
    use std::sync::Arc;

    #[tokio::test]
    async fn final_flush_yields_until_the_active_future_releases_custody() {
        let runner = BudgetFlushRunner::default();
        let active = runner.try_enter().unwrap();
        let final_flush = runner.enter(true);
        tokio::pin!(final_flush);
        assert!(futures::poll!(&mut final_flush).is_pending());
        assert!(runner.try_enter().is_err());
        drop(active);
        let _joined = final_flush.await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_driver_releases_ownership_for_exact_retained_retry() {
        let runner = Arc::new(BudgetFlushRunner::default());
        let retained = runner.clone();
        let (entered, ready) = tokio::sync::oneshot::channel();
        let driver = tokio::spawn(async move {
            let _owner = retained.enter(true).await.unwrap();
            entered.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        ready.await.unwrap();
        assert!(runner.try_enter().is_err());
        driver.abort();
        assert!(driver.await.unwrap_err().is_cancelled());
        assert!(runner.try_enter().is_ok());
    }
}
