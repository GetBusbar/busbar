// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExactModelDelta {
    #[serde(default)]
    pub(crate) scale: u32,
    pub(crate) model: String,
    #[serde(with = "decimal_units")]
    pub(crate) usage_units: BTreeMap<String, i128>,
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
            usage_units: crate::off_path::governance::runtime::exact_debt_stored_units(
                row.usage_units,
                row.scale,
            )
            .map_err(serde::de::Error::custom)?,
        })
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExactUsageDelta {
    #[serde(with = "decimal_count")]
    pub(crate) requests: i128,
    #[serde(with = "decimal_count")]
    pub(crate) billable_requests: i128,
    pub(crate) models: Vec<ExactModelDelta>,
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
            && crate::off_path::governance::runtime::exact_debt_models_zero(&self.models)
    }
    pub(super) fn unit(&mut self, model: &str, unit: &str, change: i128) {
        if change == 0 {
            return;
        }
        let position =
            crate::off_path::governance::runtime::exact_debt_model_index(&self.models, model);
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
        if let Some(position) =
            crate::off_path::governance::runtime::exact_debt_model_index(&self.models, model)
        {
            let slot = self.models[position]
                .usage_units
                .entry(unit.into())
                .or_default();
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
        crate::off_path::governance::runtime::exact_debt_from_signed(delta)
    }
    pub(super) fn signed(&self) -> Option<UsageDelta> {
        crate::off_path::governance::runtime::exact_debt_signed(self)
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
            let flushed = if dated {
                &model.flushed_era
            } else {
                &model.flushed
            };
            // The undated row borrows the model name; the dated row names its era only once a
            // unit actually carries debt.
            let mut era_name: Option<String> = None;
            for unit in crate::governance::sorted_union(model.cur.keys(), flushed.keys()) {
                let change = model
                    .cur
                    .get(unit)
                    .copied()
                    .unwrap_or_default()
                    .checked_sub(flushed.get(unit).copied().unwrap_or_default())
                    .expect("raw count difference overflow")
                    .micros();
                if change == 0 {
                    continue;
                }
                let name = if dated {
                    era_name
                        .get_or_insert_with(|| era_model(model.era, &model.model))
                        .as_str()
                } else {
                    &*model.model
                };
                debt.unit(name, unit, change);
            }
        }
        if dated {
            let (current, flushed) = (cell.fee_eras.dated(), cell.flushed_fee_eras.dated());
            let count_at = |eras: &[(RawRateEra, u64)], era: RawRateEra| {
                eras.iter()
                    .find(|(at, _)| *at == era)
                    .map_or(0, |(_, n)| *n)
            };
            // Each era once, ascending (the order a set union yields), read straight from the
            // two short era lists.
            let mut after: Option<RawRateEra> = None;
            while let Some(era) = (current.iter().chain(flushed))
                .map(|(at, _)| *at)
                .filter(|at| after.is_none_or(|last| *at > last))
                .min()
            {
                after = Some(era);
                debt.unit(
                    &era_tag(era),
                    ERA_FEE_UNIT,
                    whole_count(count_at(current, era))
                        .checked_sub(whole_count(count_at(flushed, era)))
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
        // The decimal text is written straight into the output (the same JSON string).
        serializer.collect_str(count)
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
    /// A count written as its decimal string, in place.
    struct Decimal<'a>(&'a i128);
    impl Serialize for Decimal<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.collect_str(self.0)
        }
    }
    pub fn serialize<S: Serializer>(
        units: &BTreeMap<String, i128>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        // The map is already ordered by unit: stream it, each count as its decimal string.
        serializer.collect_map(units.iter().map(|(unit, count)| (unit, Decimal(count))))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<String, i128>, D::Error> {
        crate::off_path::governance::runtime::exact_debt_parse_units(
            BTreeMap::<String, String>::deserialize(deserializer)?,
        )
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
                    dated.unit(
                        &crate::off_path::governance::runtime::exact_debt_era_model(
                            era,
                            ERA_MODEL_SEP,
                            model,
                        ),
                        unit,
                        count,
                    );
                }
            }
        }
    }
    pub(super) fn positive(&self) -> Self {
        Self(crate::off_path::governance::runtime::exact_debt_positive(
            &self.0,
        ))
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
        crate::off_path::governance::runtime::exact_debt_all_zero(&self.0)
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
}

struct FlightDebt {
    plain: ExactUsageDelta,
    dated: ExactUsageDelta,
    chunk: Option<Chunk>,
    finished: bool,
}

pub(crate) struct BudgetFlushFlight {
    pub(crate) bucket: String,
    pub(crate) window: u64,
    debt: std::sync::Mutex<FlightDebt>,
    runner: BudgetFlushRunner,
    durable: Option<super::raw_recovery::DurableUsageFlight>,
    /// FEE-DEBT r1 original capture evidence, frozen under the source cell lock.
    fee: Option<Arc<super::fee_debt::FeeCapture>>,
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
            bucket: crate::off_path::governance::runtime::exact_debt_bucket(bucket),
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
        if self.budget_bucket_deleting(bucket) {
            return Vec::new();
        }
        let windows = crate::off_path::governance::runtime::exact_debt_flush_windows(
            cell.window_start,
            cell.rolled.iter().map(|(window, _)| *window),
            cell.rolled_eras.iter().map(|(window, _)| *window),
        );
        crate::off_path::governance::runtime::exact_debt_capture_windows(windows, |window| {
            self.capture_budget_flush(bucket, cell, settled, window)
        })
    }

    /// One window's flush flight, captured from the cell (the flusher, one call per window).
    fn capture_budget_flush(
        &self,
        bucket: &str,
        cell: &mut BudgetCell,
        settled: &super::raw_recovery::ForeignSettledSnapshot,
        window: u64,
    ) -> Option<Arc<BudgetFlushFlight>> {
        let correcting = cell
            .correction
            .as_ref()
            .is_some_and(|branch| branch.window == window);
        if cell.flushing_windows.contains_key(&window) || (correcting && !self.recovery_enabled()) {
            return None;
        }
        let original = correcting.then(|| cell.clone());
        let correction_debt = if correcting {
            match Self::take_correction_positives(cell, window) {
                Ok(Some(debt)) => Some(debt),
                Ok(None) => return None,
                Err(e) => {
                    tracing::warn!(
                        bucket = bucket,
                        window = window,
                        error = ?e,
                        "take_correction_positives failed; \
                         skipping bucket this flush cycle"
                    );
                    return None;
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
                return None;
            }
            return self.capture_fee_no_write(bucket, cell, window);
        }
        // Freeze the original fee cut with the debt it covers: a later mutation cannot join it.
        let fee = (!correcting && cell.fee_incarnation != 0).then(|| {
            super::fee_debt::FeeCapture::frozen(
                &self.fee_debt,
                bucket,
                cell.fee_incarnation,
                window,
                cell.fee_sequence,
                false,
            )
        });
        let durable = if self.recovery_enabled() {
            let prepared = if correcting {
                Self::usage_recovery_child(bucket, window, plain.clone(), dated.clone()).and_then(
                    |child| {
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
                    },
                )
            } else {
                self.capture_usage_recovery(bucket, window, plain.clone(), dated.clone(), settled)
            };
            match prepared {
                Ok(flight) => Some(flight),
                Err(_) => {
                    if let Some(original) = original {
                        *cell = original;
                    }
                    return None;
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
            bucket: crate::off_path::governance::runtime::exact_debt_bucket(bucket),
            window,
            debt: std::sync::Mutex::new(FlightDebt {
                plain,
                dated,
                chunk: None,
                finished: false,
            }),
            runner: BudgetFlushRunner::default(),
            durable,
            fee,
        });
        self.budget_flushes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert((bucket.into(), window), flight.clone());
        cell.mutate(|cell| {
            if !correcting {
                crate::off_path::governance::runtime::exact_debt_unpark(&mut cell.rolled, window);
                crate::off_path::governance::runtime::exact_debt_unpark(
                    &mut cell.rolled_eras,
                    window,
                );
                if cell.window_start == window {
                    cell.flushed_requests = cell.requests;
                    cell.flushed_billable_requests = cell.billable_requests;
                    cell.flushed_fee_eras.clone_from(&cell.fee_eras);
                    for model in &mut cell.models {
                        model.flushed.clone_from(&model.cur);
                        model.flushed_era.clone_from(&model.cur);
                    }
                }
                park_window(&mut cell.rolled, window, deferred_plain.clone());
                park_window(&mut cell.rolled_eras, window, deferred_dated.clone());
            }
            if !correcting {
                cell.fee_captured = cell.fee_sequence;
            }
            cell.flushing += 1;
            *cell.flushing_windows.entry(window).or_default() += 1;
            cell.dirty = true;
        });
        Some(flight)
    }

    /// FEE-DEBT r1 honest no-write result: observed original mutations whose exact plain and
    /// dated debt netted to zero inside this finite cut. The existing flight owner retains the
    /// immutable capture; it performs no Store write and is never labelled Applied.
    fn capture_fee_no_write(
        &self,
        bucket: &str,
        cell: &mut BudgetCell,
        window: u64,
    ) -> Option<Arc<BudgetFlushFlight>> {
        if cell.fee_obligations == 0
            || cell.fee_incarnation == 0
            || cell.fee_sequence <= cell.fee_captured
        {
            return None;
        }
        let fee = super::fee_debt::FeeCapture::frozen(
            &self.fee_debt,
            bucket,
            cell.fee_incarnation,
            window,
            cell.fee_sequence,
            true,
        );
        let flight = Arc::new(BudgetFlushFlight {
            bucket: crate::off_path::governance::runtime::exact_debt_bucket(bucket),
            window,
            debt: std::sync::Mutex::new(FlightDebt {
                plain: ExactUsageDelta::default(),
                dated: ExactUsageDelta::default(),
                chunk: None,
                finished: false,
            }),
            runner: BudgetFlushRunner::default(),
            durable: None,
            fee: Some(fee),
        });
        self.budget_flushes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert((bucket.into(), window), flight.clone());
        cell.mutate(|cell| {
            cell.fee_captured = cell.fee_sequence;
            cell.flushing += 1;
            *cell.flushing_windows.entry(window).or_default() += 1;
        });
        Some(flight)
    }

    pub(crate) async fn drive_budget_flush_flight(
        &self,
        flight: &Arc<BudgetFlushFlight>,
        final_flush: bool,
    ) -> (usize, Option<RecordStoreError>) {
        let _running = match flight.runner.enter(final_flush).await {
            Ok(running) => running,
            Err(message) => return (0, Some(RecordStoreError(message.into()))),
        };
        // FEE-DEBT r1: associate the retained capture with its original observers before this
        // flight can retire, with every budget, money and checkpoint lock released.
        if let Some(fee) = &flight.fee {
            self.fee_debt.associate(fee);
        }
        let core = match self.core_store() {
            Ok(core) => core,
            Err(error) => return (0, Some(error)),
        };
        let mut confirmed = 0;
        // Applied for fee evidence requires the actual original recovery child settled; an
        // absorbed prerequisite's monetary payload has no settled proof here, so it stays
        // unresolved rather than being labelled Applied by a kept Intent.
        let mut fee_applied = true;
        if let Some(durable) = &flight.durable {
            if let Err(error) = self.drive_durable_usage_flight(durable).await {
                return (0, Some(error));
            }
            fee_applied = durable.prerequisite.is_none()
                && durable.child.as_ref().is_none_or(|child| {
                    self.recovery_event(child.operation_id)
                        .is_some_and(|event| event.state == recovery::RecoveryState::Settled)
                });
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
                    let address = crate::off_path::governance::runtime::exact_debt_flight_address(
                        &flight.bucket,
                        flight.window,
                    );
                    if flights
                        .get(&address)
                        .is_some_and(|held| Arc::ptr_eq(held, flight))
                    {
                        flights.remove(&address);
                    }
                    drop(flights);
                    drop(cells);
                    if let Some(fee) = &flight.fee {
                        let deferred = flight.durable.as_ref().is_some_and(|durable| {
                            !durable.deferred_plain.is_zero() || !durable.deferred_dated.is_zero()
                        });
                        fee.finish(fee_applied, deferred);
                    }
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
                    });
                }
                debt.chunk
                    .as_ref()
                    .expect("immutable chunk retained")
                    .clone()
            };
            // At most the plain and the dated row: held inline, and the dated bucket is named only
            // when it carries debt.
            let era_bucket = (!chunk.dated.is_zero()).then(|| era_bucket(&flight.bucket));
            let mut cells: smallvec::SmallVec<[(&str, u64, UsageDelta); 2]> =
                smallvec::SmallVec::new();
            if !chunk.plain.is_zero() {
                cells.push((flight.bucket.as_str(), flight.window, chunk.plain.clone()));
            }
            if let Some(era_bucket) = &era_bucket {
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
        let flights = crate::off_path::governance::runtime::exact_debt_flights(
            self.budget_flushes
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .values(),
        );
        self.resume_budget_flush_list(flights, final_flush).await
    }

    pub(super) async fn resume_budget_flush_list(
        &self,
        flights: Vec<Arc<BudgetFlushFlight>>,
        final_flush: bool,
    ) -> (usize, Vec<String>) {
        crate::off_path::governance::runtime::exact_debt_resume_flights(self, flights, final_flush)
            .await
    }

    pub(super) async fn settle_budget_flush_for_delete_async(
        &self,
        bucket: &str,
    ) -> RecordStoreResult<()> {
        let flights = crate::off_path::governance::runtime::exact_debt_bucket_flights(
            &self
                .budget_flushes
                .lock()
                .unwrap_or_else(|p| p.into_inner()),
            bucket,
        );
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
#[path = "tests/exact_debt_recovery_math_tests.rs"]
mod recovery_math_tests;

#[cfg(test)]
#[path = "tests/exact_debt_async_flush_ownership_tests.rs"]
mod async_flush_ownership_tests;
