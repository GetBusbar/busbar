// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::records::correction::{self, Decision, Request, UsageAddress, UsageChange};
use busbar_contract::records::{ModelTokens, UsageLedger};

#[derive(Clone, PartialEq, Eq)]
struct Intent {
    pool: String,
    model: String,
    era: u64,
    entry_id: Option<[u8; 12]>,
    epoch: u64,
    delta: BTreeMap<String, i64>,
}
impl Intent {
    fn of(adj: &Adjustment<'_>) -> Self {
        Self {
            pool: adj.pool.into(),
            model: adj.model.into(),
            era: adj.entry_era,
            entry_id: adj.entry_id.map(|id| id.0),
            epoch: adj.card_epoch_ms,
            delta: adj.delta.clone(),
        }
    }
}

/// Exact immutable candidate retained until its durable outcome is definitive.
#[derive(Clone)]
pub(in crate::governance) struct PendingCorrection {
    request: Request,
    intent: Intent,
    targets: Vec<(String, u64)>,
    started: std::time::Instant,
    running: Arc<std::sync::atomic::AtomicBool>,
    settled: Arc<std::sync::Mutex<Option<Decision>>>,
}

struct Deciding(Arc<std::sync::atomic::AtomicBool>);
impl Drop for Deciding {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl PendingCorrection {
    pub(super) fn unresolved_day(&self) -> Option<u64> {
        self.settled
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_none()
            .then_some(self.request.day_start)
    }
}

fn unresolved(reason: &str) -> RecordStoreError {
    RecordStoreError(format!("usage correction unresolved: {reason}"))
}
fn exact<T>(result: Result<T, &'static str>) -> RecordStoreResult<T> {
    result.map_err(|reason| RecordStoreError(reason.into()))
}
fn address(bucket: &str, window: u64) -> UsageAddress {
    UsageAddress {
        bucket_id: bucket.into(),
        window_start: window,
    }
}

impl GovState {
    pub(in crate::governance::state) fn settle_correction_for_delete(
        &self,
        key: &str,
    ) -> RecordStoreResult<()> {
        let pending = self
            .corrections
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(key)
            .cloned();
        if let Some(pending) = pending {
            self.decide_usage_correction(&pending)?;
            self.corrections
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(key);
        }
        Ok(())
    }

    pub(super) fn resume_usage_correction(&self, adj: &Adjustment<'_>) -> RecordStoreResult<bool> {
        let pending = self
            .corrections
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(adj.key_id)
            .cloned();
        let Some(pending) = pending else {
            return Ok(false);
        };
        let decision = self.decide_usage_correction(&pending)?;
        self.corrections
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(adj.key_id);
        Ok(decision == Decision::Applied && pending.intent == Intent::of(adj))
    }

    fn decide_usage_correction(&self, pending: &PendingCorrection) -> RecordStoreResult<Decision> {
        if pending
            .running
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(unresolved(
                "the same immutable operation is already in flight",
            ));
        }
        let _running = Deciding(pending.running.clone());
        if let Some(decision) = *pending.settled.lock().unwrap_or_else(|p| p.into_inner()) {
            return Ok(decision);
        }
        if pending.started.elapsed().as_secs() >= busbar_contract::abi::store::OP_ID_RETENTION_SECS
        {
            return Err(unresolved(
                "receipt retention expired; exact operation custody retained",
            ));
        }

        let decision = self.store.apply_usage_correction(&pending.request)?;
        let mut order: Vec<_> = pending
            .targets
            .iter()
            .map(|(bucket, _)| self.budget.shard_index(bucket))
            .collect();
        order.sort_unstable();
        order.dedup();
        let mut guards: Vec<_> = order
            .iter()
            .map(|shard| {
                (
                    *shard,
                    self.budget
                        .shard_at(*shard)
                        .map
                        .write()
                        .unwrap_or_else(|p| p.into_inner()),
                )
            })
            .collect();

        for (bucket, window) in &pending.targets {
            let index = order
                .binary_search(&self.budget.shard_index(bucket))
                .expect("target shard held");
            let branch = guards[index]
                .1
                .get(bucket)
                .and_then(|cell| cell.correction.as_ref());
            if !branch.is_some_and(|branch| {
                branch.op_id == pending.request.op_id && branch.window == *window
            }) {
                return Err(unresolved("reserved raw cell custody missing"));
            }
        }
        for (bucket, _) in &pending.targets {
            let index = order
                .binary_search(&self.budget.shard_index(bucket))
                .expect("target shard held");
            let cell = guards[index]
                .1
                .get_mut(bucket)
                .expect("checked target cell");
            let branch = cell.correction.take().expect("checked reservation");
            if decision == Decision::Applied {
                *cell = branch.accepted;
            }
        }
        drop(guards);
        *pending.settled.lock().unwrap_or_else(|p| p.into_inner()) = Some(decision);
        Ok(decision)
    }

    pub(in crate::governance::state) fn retry_usage_corrections(&self) -> Vec<String> {
        let pending: Vec<_> = self
            .corrections
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .cloned()
            .collect();
        pending
            .into_iter()
            .filter_map(|pending| {
                self.decide_usage_correction(&pending)
                    .err()
                    .map(|error| format!("{}: {error}", pending.request.key_id))
            })
            .collect()
    }

    pub(super) fn correct_usage(
        &self,
        cost: &crate::cost::CostModel,
        adj: &Adjustment<'_>,
        delta: &BTreeMap<&str, i64>,
        day: u64,
    ) -> RecordStoreResult<Result<(), AdjustRefused>> {
        loop {
            let Some(key) = self.store.get_key(adj.key_id)? else {
                return Ok(Err(AdjustRefused::UnknownKey));
            };
            if key.deleted_at.is_some() {
                return Ok(Err(AdjustRefused::UnknownKey));
            }
            let mut owners: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
            let epoch = adj.card_epoch_ms / 1_000;
            let mut targets: Vec<(String, u64)> = match cost.chain_for(&key) {
                Ok(chain) => chain
                    .iter()
                    .filter(|bucket| bucket.applies_to_pool(adj.pool))
                    .map(|bucket| {
                        if let Some(group) = bucket.group_name {
                            owners
                                .entry(bucket.bucket_id.into())
                                .or_default()
                                .insert(group.into());
                        }
                        (bucket.bucket_id.into(), budget_window(bucket.window, epoch))
                    })
                    .collect(),
                Err(_) => vec![(
                    adj.key_id.into(),
                    budget_window(super::super::super::WINDOW_TOTAL, epoch),
                )],
            };
            targets.sort();
            targets.dedup();
            let mut snapshots = BTreeMap::new();
            for (bucket, window) in &targets {
                for name in [bucket.clone(), era_bucket(bucket)] {
                    let mut row = self.store.get_usage(&name, *window)?;
                    exact(correction::canonical_ledger(&mut row))?;
                    snapshots.insert(address(&name, *window), row);
                }
            }
            for bucket in [ADJUST_UP_BUCKET, ADJUST_DOWN_BUCKET] {
                let mut row = self.store.get_usage(bucket, day)?;
                exact(correction::canonical_ledger(&mut row))?;
                snapshots.insert(address(bucket, day), row);
            }
            let mut metering: Vec<_> = self
                .store
                .list_metering(day)?
                .into_iter()
                .filter(|row| row.key_id == adj.key_id)
                .collect();
            correction::canonical_metering(&mut metering);
            let metered_era = unique_metered_era(adj, &metering)?;
            if let Some(history) = crate::rate_apply::dated_history() {
                if metered_era.entry_id.is_some()
                    && history
                        .current()
                        .card_for_raw_era(metered_era, adj.card_epoch_ms)
                        .is_none()
                {
                    return Ok(Err(AdjustRefused::NoCardInForce {
                        at: adj.card_epoch_ms,
                    }));
                }
            }
            if let Err(refused) = check_metered(
                adj,
                delta,
                day,
                &metering,
                &snapshots[&address(ADJUST_UP_BUCKET, day)],
                &snapshots[&address(ADJUST_DOWN_BUCKET, day)],
                metered_era,
            ) {
                return Ok(Err(refused));
            }
            let mut order: Vec<_> = targets
                .iter()
                .map(|(bucket, _)| self.budget.shard_index(bucket))
                .collect();
            order.sort_unstable();
            order.dedup();
            let mut guards: Vec<_> = order
                .iter()
                .map(|shard| {
                    (
                        *shard,
                        self.budget
                            .shard_at(*shard)
                            .map
                            .write()
                            .unwrap_or_else(|p| p.into_inner()),
                    )
                })
                .collect();
            let mut replacements = snapshots.clone();
            let mut branches = Vec::new();
            for (bucket, window) in &targets {
                let index = order
                    .binary_search(&self.budget.shard_index(bucket))
                    .expect("target shard held");
                let live = guards[index].1.get(bucket);
                if live.is_some_and(|cell| cell.correction.is_some()) {
                    return Err(unresolved("another correction owns an affected bucket"));
                }
                if live.is_some_and(|cell| cell.flushing_windows.contains_key(window)) {
                    return Err(unresolved("an in-flight flush owns the target window"));
                }
                let plain_address = address(bucket, *window);
                let dated_address = address(&era_bucket(bucket), *window);
                let plain = &snapshots[&plain_address];
                let dated = &snapshots[&dated_address];
                let (mut before, mut plain_after, mut dated_after) =
                    capture_target(live, plain, dated, *window)?;
                if let Some(names) = owners.get(bucket) {
                    before.group_owners.extend(names.iter().cloned());
                }
                let target = durable_cell(plain_after.clone(), dated_after.clone(), *window)?;
                let segment = if metered_era.entry_id.is_some() {
                    target
                        .models
                        .iter()
                        .position(|m| &*m.model == adj.model && m.era == metered_era)
                } else {
                    segment_at(&target.models, adj.model, adj.card_epoch_ms)
                };
                if segment.is_none() && delta.values().any(|count| *count < 0) {
                    return Ok(Err(AdjustRefused::Unplaced {
                        bucket: bucket.clone(),
                        window: *window,
                        class: delta
                            .iter()
                            .find(|(_, count)| **count < 0)
                            .expect("negative delta")
                            .0
                            .to_string(),
                    }));
                }
                let era = segment.map_or(metered_era, |index| target.models[index].era);
                for (class, change) in delta {
                    let held = segment.map_or(0, |index| {
                        target.models[index].cur.get(*class).copied().unwrap_or(0)
                    });
                    if moved(held, *change).is_none() {
                        return Ok(Err(AdjustRefused::Exceeds {
                            bucket: bucket.clone(),
                            class: (*class).into(),
                            count: held,
                            delta: *change,
                        }));
                    }
                    exact(move_unit(
                        &mut plain_after,
                        adj.model,
                        class,
                        i128::from(*change),
                    ))?;
                    if era != RawRateEra::legacy(0) {
                        exact(move_unit(
                            &mut dated_after,
                            &era_model(era, adj.model),
                            class,
                            i128::from(*change),
                        ))?;
                    }
                }
                let mut accepted = if before.window_start == *window {
                    let mut accepted =
                        durable_cell(plain_after.clone(), dated_after.clone(), *window)?;
                    copy_custody(&before, &mut accepted);
                    accepted
                } else {
                    let mut accepted = before.clone();
                    accepted.rolled.retain(|(at, _)| at != window);
                    accepted.rolled_eras.retain(|(at, _)| at != window);
                    accepted
                };
                before.last_touch = adj.now;
                accepted.last_touch = adj.now;
                accepted.dirty = has_debt(&accepted);
                replacements.insert(plain_address, plain_after);
                replacements.insert(dated_address, dated_after);
                branches.push((bucket.clone(), *window, before, accepted));
            }
            let slot = adjustment_slot(adj.key_id, adj.model, metered_era);
            for (class, change) in delta {
                let bucket = if *change > 0 {
                    ADJUST_UP_BUCKET
                } else {
                    ADJUST_DOWN_BUCKET
                };
                exact(move_unit(
                    replacements
                        .get_mut(&address(bucket, day))
                        .expect("adjustment row read"),
                    &slot,
                    class,
                    i128::from(change.unsigned_abs()),
                ))?;
            }
            let request = Request {
                version: correction::VERSION,
                op_id: crate::door::op_id(),
                key_id: adj.key_id.into(),
                day_start: day,
                metering,
                usage: snapshots
                    .into_iter()
                    .map(|(address, expected)| {
                        let mut replacement =
                            replacements.remove(&address).expect("same raw row set");

                        correction::canonical_ledger(&mut replacement)
                            .expect("unique planned model identities");
                        UsageChange {
                            address,
                            expected,
                            replacement,
                        }
                    })
                    .collect(),
            };
            exact(request.encode())?;
            for (bucket, window, mut before, accepted) in branches {
                let index = order
                    .binary_search(&self.budget.shard_index(&bucket))
                    .expect("target shard held");
                before.correction = Some(Box::new(CorrectionBranch {
                    op_id: request.op_id,
                    window,
                    accepted,
                }));
                guards[index].1.insert(bucket, before);
            }
            let pending = PendingCorrection {
                request,
                intent: Intent::of(adj),
                targets,
                started: std::time::Instant::now(),
                running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                settled: Arc::new(std::sync::Mutex::new(None)),
            };
            self.corrections
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(adj.key_id.into(), pending.clone());
            drop(guards);
            let decision = self.decide_usage_correction(&pending)?;
            self.corrections
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(adj.key_id);
            match decision {
                Decision::Applied => return Ok(Ok(())),
                Decision::ConditionConflict => continue,
            }
        }
    }
}

fn unique_metered_era(adj: &Adjustment<'_>, rows: &[MeteringRow]) -> RecordStoreResult<RawRateEra> {
    let mut captured = None;
    for row in rows.iter().filter(|row| {
        row.priced_from_ms == adj.entry_era && metering_lane(&row.model, &row.provider) == adj.model
    }) {
        let id = match EntryId::parse_metering_version(&row.pricing_version) {
            Some(Some(id)) => Some(id),
            Some(None) => {
                return Err(RecordStoreError(
                    "malformed versioned metering provenance".into(),
                ))
            }
            None => None,
        };
        let era = RawRateEra {
            effective_from: row.priced_from_ms,
            entry_id: id,
        };
        if adj.entry_id.is_some_and(|expected| Some(expected) != era.entry_id) {
            continue;
        }
        if captured.is_some_and(|previous| previous != era) {
            return Err(RecordStoreError(
                "correction timestamp names multiple raw rate entries".into(),
            ));
        }
        captured = Some(era);
    }
    if adj.entry_id.is_some() && captured.is_none() {
        return Err(RecordStoreError(
            "correction names no matching exact metering rate entry".into(),
        ));
    }
    Ok(captured.unwrap_or_else(|| RawRateEra::legacy(adj.entry_era)))
}

fn check_metered(
    adj: &Adjustment<'_>,
    delta: &BTreeMap<&str, i64>,
    day: u64,
    metering: &[MeteringRow],
    up: &UsageLedger,
    down: &UsageLedger,
    era: RawRateEra,
) -> Result<(), AdjustRefused> {
    let lane: Vec<_> = metering
        .iter()
        .filter(|row| metering_lane(&row.model, &row.provider) == adj.model)
        .collect();
    if let Some(in_force) = lane
        .iter()
        .map(|row| row.priced_from_ms)
        .filter(|era| *era > adj.entry_era && *era <= adj.card_epoch_ms)
        .max()
    {
        return Err(AdjustRefused::NotInForce {
            named: adj.entry_era,
            in_force,
        });
    }
    let rows: Vec<_> = lane
        .into_iter()
        .filter(|row| {
            row.priced_from_ms == adj.entry_era
                && adj.entry_id.is_none_or(|id| {
                    EntryId::parse_metering_version(&row.pricing_version) == Some(Some(id))
                })
        })
        .collect();
    if rows.is_empty() {
        return Err(AdjustRefused::NotMetered { day });
    }
    let slot = adjustment_slot(adj.key_id, adj.model, era);
    for (class, change) in delta {
        let adjusted = |ledger: &UsageLedger| {
            ledger
                .models
                .iter()
                .find(|row| row.model == slot)
                .and_then(|row| row.usage_units.get(*class))
                .copied()
                .unwrap_or(0)
        };
        let count = rows
            .iter()
            .map(|row| i128::from(metered_count(row, class)))
            .sum::<i128>()
            + i128::from(adjusted(up))
            - i128::from(adjusted(down));
        if count + i128::from(*change) < 0 || count + i128::from(*change) > i128::from(u64::MAX) {
            return Err(AdjustRefused::Exceeds {
                bucket: format!("metering@{day}"),
                class: (*class).into(),
                count: u64::try_from(count).unwrap_or(0),
                delta: *change,
            });
        }
    }
    Ok(())
}

fn copy_custody(from: &BudgetCell, to: &mut BudgetCell) {
    to.group_owners = from.group_owners.clone();
    to.flushing = from.flushing;
    to.flushing_windows = from.flushing_windows.clone();
    to.rolled = from.rolled.clone();
    to.rolled_eras = from.rolled_eras.clone();
    to.last_touch = from.last_touch;
}
fn has_debt(cell: &BudgetCell) -> bool {
    !ExactUsageDelta::of(cell, false).is_zero()
        || !ExactUsageDelta::of(cell, true).is_zero()
        || !cell.rolled.is_empty()
        || !cell.rolled_eras.is_empty()
}

fn capture_target(
    live: Option<&BudgetCell>,
    plain: &UsageLedger,
    dated: &UsageLedger,
    window: u64,
) -> RecordStoreResult<(BudgetCell, UsageLedger, UsageLedger)> {
    let mut local = live.cloned().unwrap_or_else(|| BudgetCell::fresh(window));
    if local.window_start < window {
        local.roll(window);
    }
    let mut combined = plain.clone();
    let mut combined_dated = dated.clone();
    if local.window_start == window {
        exact(add_difference(
            &mut combined,
            local.requests,
            local.flushed_requests,
            true,
        ))?;
        exact(add_difference(
            &mut combined,
            local.billable_requests,
            local.flushed_billable_requests,
            false,
        ))?;
        let plain_debt = ExactUsageDelta::of(&local, false);
        for model in &plain_debt.models {
            for (unit, change) in &model.usage_units {
                exact(move_unit(&mut combined, &model.model, unit, *change))?;
            }
        }
        for model in &local.models {
            if model.era != RawRateEra::legacy(0) {
                exact(add_units_difference(
                    &mut combined_dated,
                    &era_model(model.era, &model.model),
                    &model.cur,
                    &model.flushed_era,
                ))?;
            }
        }
        let fees: BTreeMap<_, _> = local.fee_eras.dated().iter().copied().collect();
        let flushed: BTreeMap<_, _> = local.flushed_fee_eras.dated().iter().copied().collect();
        for era in fees
            .keys()
            .chain(flushed.keys())
            .collect::<std::collections::BTreeSet<_>>()
        {
            let difference = i128::from(fees.get(era).copied().unwrap_or(0))
                - i128::from(flushed.get(era).copied().unwrap_or(0));
            exact(move_unit(
                &mut combined_dated,
                &era_tag(*era),
                ERA_FEE_UNIT,
                difference,
            ))?;
        }
        let baseline = durable_cell(plain.clone(), dated.clone(), window)?;
        let mut before = durable_cell(combined.clone(), combined_dated.clone(), window)?;
        copy_custody(&local, &mut before);
        before.flushed_requests = baseline.requests;
        before.flushed_billable_requests = baseline.billable_requests;
        before.flushed_fee_eras = baseline.fee_eras;
        for model in &mut before.models {
            let base = baseline
                .models
                .iter()
                .find(|base| base.model == model.model && base.era == model.era);
            model.flushed = base.map(|base| base.cur.clone()).unwrap_or_default();
            model.flushed_era = model.flushed.clone();
        }

        for base in baseline.models {
            if !before
                .models
                .iter()
                .any(|model| model.model == base.model && model.era == base.era)
            {
                before.models.push(ModelCell {
                    model: base.model,
                    era: base.era,
                    cur: BTreeMap::new(),
                    flushed: base.cur.clone(),
                    flushed_era: base.cur,
                });
            }
        }
        before.dirty = has_debt(&before);
        Ok((before, combined, combined_dated))
    } else {
        for (_, delta) in local.rolled.iter().filter(|(at, _)| *at == window) {
            exact(apply_delta(&mut combined, delta))?;
        }
        for (_, delta) in local.rolled_eras.iter().filter(|(at, _)| *at == window) {
            exact(apply_delta(&mut combined_dated, delta))?;
        }
        Ok((local, combined, combined_dated))
    }
}

fn checked_move(count: u64, change: i128) -> Result<u64, &'static str> {
    u64::try_from(i128::from(count) + change).map_err(|_| "raw usage correction count out of range")
}
fn add_difference(
    row: &mut UsageLedger,
    current: u64,
    flushed: u64,
    requests: bool,
) -> Result<(), &'static str> {
    let slot = if requests {
        &mut row.requests
    } else {
        &mut row.billable_requests
    };
    *slot = checked_move(*slot, i128::from(current) - i128::from(flushed))?;
    Ok(())
}
fn add_units_difference(
    row: &mut UsageLedger,
    model: &str,
    current: &BTreeMap<String, u64>,
    flushed: &BTreeMap<String, u64>,
) -> Result<(), &'static str> {
    for unit in current
        .keys()
        .chain(flushed.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        move_unit(
            row,
            model,
            unit,
            i128::from(current.get(unit).copied().unwrap_or(0))
                - i128::from(flushed.get(unit).copied().unwrap_or(0)),
        )?;
    }
    Ok(())
}
fn move_unit(
    row: &mut UsageLedger,
    model: &str,
    unit: &str,
    change: i128,
) -> Result<(), &'static str> {
    if change == 0 {
        return Ok(());
    }
    let position = row
        .models
        .iter()
        .position(|candidate| candidate.model == model);
    let count = position
        .and_then(|position| row.models[position].usage_units.get(unit))
        .copied()
        .unwrap_or(0);
    let next = checked_move(count, change)?;
    if let Some(position) = position {
        if next == 0 {
            row.models[position].usage_units.remove(unit);
        } else {
            row.models[position].usage_units.insert(unit.into(), next);
        }
    } else if next != 0 {
        row.models.push(ModelTokens {
            model: model.into(),
            usage_units: BTreeMap::from([(unit.into(), next)]),
        });
    }
    Ok(())
}
fn apply_delta(row: &mut UsageLedger, delta: &ExactUsageDelta) -> Result<(), &'static str> {
    row.requests = checked_move(row.requests, delta.requests)?;
    row.billable_requests = checked_move(row.billable_requests, delta.billable_requests)?;
    for model in &delta.models {
        for (unit, count) in &model.usage_units {
            move_unit(row, &model.model, unit, *count)?;
        }
    }
    Ok(())
}
