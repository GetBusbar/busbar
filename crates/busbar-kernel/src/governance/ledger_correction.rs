// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::records::correction::{self, Decision, Request, UsageAddress, UsageChange};
use busbar_contract::records::{ModelTokens, UsageLedger};
use crate::governance::recovery::{
    RecoveryChild, RecoveryError, RecoveryEvent, RecoveryKind, RecoveryOrigin, RecoveryResolution,
    RecoveryState, RecoveryVerdict,
};

#[path = "ledger_correction_recovery.rs"]
mod recovery;

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
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
    sent_at: u64,
    started: std::time::Instant,
    running: Arc<std::sync::atomic::AtomicBool>,
    receipt: Arc<std::sync::Mutex<Option<Decision>>>,
    settled: Arc<std::sync::Mutex<Option<Decision>>>,
    recovery_event: Arc<std::sync::Mutex<Option<RecoveryEvent>>>,
    quarantined: bool,
}

struct Deciding(Arc<std::sync::atomic::AtomicBool>);
impl Drop for Deciding {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl PendingCorrection {
    fn receipt_retention_expired(&self, now: u64) -> bool {
        now < self.sent_at
            || now - self.sent_at >= busbar_contract::abi::store::OP_ID_RETENTION_SECS
            || self.started.elapsed().as_secs()
                >= busbar_contract::abi::store::OP_ID_RETENTION_SECS
    }

    pub(super) fn unresolved_day(&self) -> Option<u64> {
        if self.quarantined {
            return None;
        }
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
    pub(in crate::governance) fn quarantined_correction_owns_target(
        &self,
        bucket: &str,
        window: u64,
    ) -> bool {
        self.corrections.lock().unwrap_or_else(|p| p.into_inner()).values().any(|pending| {
            pending.quarantined && pending.targets.iter().any(|(target, at)| target == bucket && *at == window)
        })
    }

    pub(in crate::governance) fn stage_quarantined_correction_negatives(
        &self,
        bucket: &str,
        window: u64,
        plain: &mut ExactUsageDelta,
        dated: &mut ExactUsageDelta,
    ) -> RecordStoreResult<Option<RecoveryEvent>> {
        let pending: Vec<_> = self.corrections.lock().unwrap_or_else(|p| p.into_inner()).values()
            .filter(|pending| pending.quarantined && pending.targets.iter().any(|(target, at)| target == bucket && *at == window))
            .cloned().collect();
        for pending in pending {
            let mut retained = pending.recovery_event.lock().unwrap_or_else(|p| p.into_inner());
            let selected = self.recovery_event(pending.request.op_id.0)
                .ok_or_else(|| unresolved("quarantined correction has no selected parent"))?;
            if retained.as_ref() != Some(&selected) {
                return Err(unresolved("quarantined correction checkpoint is not yet selected"));
            }
            let mut custody = recovery::Custody::decode(&selected.payload)?;
            let Some((remaining_plain, remaining_dated)) = custody.absorb_negatives(bucket, window, plain, dated)? else {
                continue;
            };
            let state = if selected.state == RecoveryState::Intent {
                custody.mark_age_unknown();
                RecoveryState::LandedUnknown
            } else {
                selected.state
            };
            let event = self.new_recovery_event(selected.operation_id, selected.kind,
                selected.body_fingerprint, state, selected.first_sent_at_ms, custody.encode()?)
                .map_err(|error| unresolved(&error.to_string()))?;
            *retained = Some(event.clone());
            *plain = remaining_plain;
            *dated = remaining_dated;
            return Ok(Some(event));
        }
        Ok(None)
    }

    pub(in crate::governance) fn restore_correction_recovery(
        &self,
        event: &RecoveryEvent,
    ) -> RecordStoreResult<()> {
        let custody = recovery::Custody::decode(&event.payload)?;
        custody.validate_event(event)?;
        if let Some(existing) = self.corrections.lock().unwrap_or_else(|p| p.into_inner())
            .values().find(|pending| pending.request.op_id.0 == event.operation_id).cloned()
        {
            if existing.request.fingerprint() != event.body_fingerprint {
                return Err(unresolved("restored correction conflicts with its live operation"));
            }
            *existing.recovery_event.lock().unwrap_or_else(|p| p.into_inner()) = Some(event.clone());
            return Ok(());
        }
        if custody.is_terminal() {
            return Ok(());
        }
        // Historical aggregates are evidence, not a replacement for fresh Store hydration.
        let pending = custody.restore(self, event)?;
        let mut corrections = self.corrections.lock().unwrap_or_else(|p| p.into_inner());
        if corrections.contains_key(&pending.request.key_id) {
            return Err(unresolved("multiple unresolved corrections name the same key"));
        }
        corrections.insert(pending.request.key_id.clone(), pending);
        Ok(())
    }

    pub(in crate::governance) fn resolve_correction_recovery(
        &self,
        _cost: &crate::cost::CostModel,
        resolution: &RecoveryResolution,
    ) -> Result<(), RecoveryError> {
        self.confirm_pending_recovery(resolution.operation_id)
            .map_err(|error| RecoveryError::Unavailable(error.to_string()))?;
        let selected = self.recovery_event(resolution.operation_id)
            .ok_or_else(|| RecoveryError::Invalid("correction is not selected".into()))?;
        let pending = self.corrections.lock().unwrap_or_else(|p| p.into_inner())
            .values().find(|pending| pending.request.op_id.0 == resolution.operation_id).cloned()
            .ok_or_else(|| RecoveryError::Invalid("correction custody is not present".into()))?;
        if selected.body_fingerprint != resolution.body_fingerprint {
            return Err(RecoveryError::Conflict("correction fingerprint differs".into()));
        }
        if pending.running.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            return Err(RecoveryError::Conflict("original correction sender is still running".into()));
        }
        let _running = Deciding(pending.running.clone());
        let state = match resolution.verdict {
            RecoveryVerdict::Landed => RecoveryState::VerdictLanded,
            RecoveryVerdict::NotLanded => RecoveryState::VerdictNotLanded,
        };
        if selected.state == RecoveryState::LandedUnknown {
            if selected.revision != resolution.expected_revision {
                return Err(RecoveryError::Conflict("correction revision differs".into()));
            }
            let mut custody = recovery::Custody::decode(&selected.payload)
                .map_err(|error| RecoveryError::Invalid(error.to_string()))?;
            custody.record_verdict(resolution);
            let event = self.new_recovery_event(selected.operation_id, selected.kind,
                selected.body_fingerprint, state, selected.first_sent_at_ms,
                custody.encode().map_err(|error| RecoveryError::Invalid(error.to_string()))?)?;
            *pending.recovery_event.lock().unwrap_or_else(|p| p.into_inner()) = Some(event.clone());
            self.keep_recovery_event(&event)
                .map_err(|error| RecoveryError::Unavailable(error.to_string()))?;
        } else if selected.state != state {
            return Err(RecoveryError::Conflict("correction has a different definitive outcome".into()));
        }
        Err(RecoveryError::Unavailable(
            "audited verdict retained; conditional successor and residual handoff are not yet complete".into(),
        ))
    }

    /// Stage an exact parent-owned handoff while the caller still owns the target shard.
    /// Persistence and child publication happen after that shard lock is released.
    pub(in crate::governance) fn stage_correction_handoff(
        &self,
        bucket: &str,
        cell: &BudgetCell,
        window: u64,
        child: RecoveryChild,
    ) -> RecordStoreResult<RecoveryEvent> {
        let branch = cell.correction.as_ref()
            .filter(|branch| branch.window == window)
            .ok_or_else(|| unresolved("correction handoff has no reserved target"))?;
        let pending = self.corrections.lock().unwrap_or_else(|p| p.into_inner())
            .values().find(|pending| pending.request.op_id == branch.op_id).cloned()
            .ok_or_else(|| unresolved("correction handoff has no operation owner"))?;
        let mut retained = pending.recovery_event.lock().unwrap_or_else(|p| p.into_inner());
        let selected = self.recovery_event(branch.op_id.0)
            .ok_or_else(|| unresolved("correction handoff has no selected parent"))?;
        if retained.as_ref() != Some(&selected) || selected.state == RecoveryState::Settled {
            return Err(unresolved("correction parent checkpoint is not yet selected"));
        }
        let mut custody = recovery::Custody::decode(&selected.payload)?;
        custody.replace_target(bucket, cell, window, child)?;
        let event = self.new_recovery_event(
            selected.operation_id,
            selected.kind,
            selected.body_fingerprint,
            selected.state,
            selected.first_sent_at_ms,
            custody.encode()?,
        ).map_err(|error| unresolved(&error.to_string()))?;
        *retained = Some(event.clone());
        Ok(event)
    }

    /// Transfer only common positive mutations out of the two conditional branches.
    /// The caller holds the shard lock and installs immutable flight ownership before unlocking.
    pub(in crate::governance) fn take_correction_positives(
        cell: &mut BudgetCell,
        window: u64,
    ) -> RecordStoreResult<Option<(ExactUsageDelta, ExactUsageDelta)>> {
        recovery::take_positives(cell, window)
    }

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
            if decision == Decision::ConditionConflict && self.recovery_enabled() {
                let event = self.recovery_event(pending.request.op_id.0)
                    .ok_or_else(|| unresolved("settled correction parent is missing"))?;
                self.drive_recovery_children(&event)?;
                self.resume_raw_recovery()?;
                if !self.recovery_children_settled(&event)? {
                    return Err(unresolved("raw predecessor counts are not yet recorded"));
                }
            }
            return Ok(decision);
        }
        if pending.quarantined {
            self.confirm_pending_recovery(pending.request.op_id.0)?;
            let selected = self.recovery_event(pending.request.op_id.0)
                .ok_or_else(|| unresolved("quarantined correction has no selected event"))?;
            if selected.state == RecoveryState::Intent {
                let mut custody = recovery::Custody::decode(&selected.payload)?;
                custody.mark_age_unknown();
                let event = self.new_recovery_event(selected.operation_id, selected.kind,
                    selected.body_fingerprint, RecoveryState::LandedUnknown,
                    selected.first_sent_at_ms, custody.encode()?)
                    .map_err(|error| unresolved(&error.to_string()))?;
                *pending.recovery_event.lock().unwrap_or_else(|p| p.into_inner()) = Some(event.clone());
                self.keep_recovery_event(&event)?;
            }
            return Err(unresolved("historical correction is quarantined pending an audited verdict and fresh revalidation"));
        }
        let receipt = *pending.receipt.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(decision) = receipt {
            let terminal = pending.recovery_event.lock().unwrap_or_else(|p| p.into_inner())
                .as_ref().is_some_and(|event| event.state == RecoveryState::Settled);
            if !terminal {
                self.keep_correction_decision(pending, decision)?;
            }
            self.settle_usage_correction(pending, decision)?;
            return Ok(decision);
        }
        let current_state = pending.recovery_event.lock().unwrap_or_else(|p| p.into_inner())
            .as_ref().map(|event| event.state);
        if current_state == Some(RecoveryState::LandedUnknown) {
            self.keep_correction_recovery(pending, RecoveryState::LandedUnknown)?;
            return Err(unresolved("landed-unknown operation requires an audited verdict"));
        }
        self.keep_correction_recovery(pending, RecoveryState::Intent)?;
        let age = if self.recovery_enabled() {
            self.recovery_retention_expired(pending.request.op_id.0)
        } else {
            Some(pending.receipt_retention_expired(crate::store::now()))
        };
        if age != Some(false) || pending.receipt_retention_expired(crate::store::now()) {
            self.keep_correction_recovery(pending, RecoveryState::LandedUnknown)?;
            return Err(unresolved(if age.is_none() {
                "receipt age is unknown after restart; landed-unknown operation requires an audited verdict"
            } else {
                "receipt retention expired; landed-unknown operation requires an audited verdict"
            }));
        }

        let decision = match self.store.apply_usage_correction(&pending.request) {
            Ok(decision) => decision,
            Err(error) => {
                self.keep_correction_recovery(pending, RecoveryState::Intent)?;
                return Err(error);
            }
        };
        *pending.receipt.lock().unwrap_or_else(|p| p.into_inner()) = Some(decision);
        self.keep_correction_decision(pending, decision)?;
        self.settle_usage_correction(pending, decision)?;
        Ok(decision)
    }

    fn keep_correction_decision(
        &self,
        pending: &PendingCorrection,
        decision: Decision,
    ) -> RecordStoreResult<()> {
        self.keep_correction_recovery(pending, match decision {
            Decision::Applied => RecoveryState::Applied,
            Decision::ConditionConflict => RecoveryState::ConditionConflict,
        })
    }

    fn keep_correction_recovery(
        &self,
        pending: &PendingCorrection,
        state: RecoveryState,
    ) -> RecordStoreResult<()> {
        if !self.recovery_enabled() {
            return Ok(());
        }
        loop {
            let previous = pending.recovery_event.lock().unwrap_or_else(|p| p.into_inner()).clone();
            if let Some(event) = previous.as_ref() {
                // Confirm an immutable candidate before allocating its successor. The mutex is
                // released during I/O so a handoff cannot block a shard on this Store call.
                self.keep_recovery_event(event)?;
            }
            let payload = recovery::Custody::capture(self, pending)?.encode()?;
            let mut retained = pending.recovery_event.lock().unwrap_or_else(|p| p.into_inner());
            if *retained != previous {
                continue;
            }
            if previous.as_ref().is_some_and(|event| event.state == state && event.payload == payload) {
                return Ok(());
            }
            let event = self.new_recovery_event(
                pending.request.op_id.0,
                RecoveryKind::Correction,
                pending.request.fingerprint(),
                state,
                Some(pending.sent_at.saturating_mul(1_000)),
                payload,
            ).map_err(|error| unresolved(&error.to_string()))?;
            *retained = Some(event.clone());
            drop(retained);
            return self.keep_recovery_event(&event);
        }
    }

    /// Select a definitive raw branch only after the operation outcome is established.
    /// Common accruals, refunds and rolls have already updated both branches.
    fn settle_usage_correction(
        &self,
        pending: &PendingCorrection,
        decision: Decision,
    ) -> RecordStoreResult<()> {
        let terminal = if self.recovery_enabled() {
            Some(self.keep_correction_settlement(pending, decision)?)
        } else {
            None
        };
        let cuts: BTreeMap<_, _> = terminal.as_ref()
            .map(|event| recovery::Custody::decode(&event.payload)?.selected_cuts())
            .transpose()?.unwrap_or_default().into_iter()
            .map(|(bucket, window, cell)| ((bucket, window), cell)).collect();
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
        let mut selected = Vec::new();
        for (bucket, window) in &pending.targets {
            let index = order
                .binary_search(&self.budget.shard_index(bucket))
                .expect("target shard held");
            let cell = guards[index]
                .1
                .get(bucket)
                .expect("checked target cell");
            let branch = cell.correction.as_ref().expect("checked reservation");
            let mut chosen = if decision == Decision::Applied {
                branch.accepted.clone()
            } else {
                let mut chosen = cell.clone();
                chosen.correction = None;
                chosen
            };
            if let Some(cut) = cuts.get(&(bucket.clone(), *window)) {
                recovery::apply_selected_cut(&mut chosen, cut, *window)?;
            }
            selected.push((bucket.clone(), chosen));
        }
        for (bucket, chosen) in selected {
            let index = order.binary_search(&self.budget.shard_index(&bucket)).expect("target shard held");
            guards[index].1.insert(bucket, chosen);
        }
        drop(guards);
        *pending.settled.lock().unwrap_or_else(|p| p.into_inner()) = Some(decision);
        if let Some(terminal) = terminal {
            self.drive_recovery_children(&terminal)?;
            if decision == Decision::ConditionConflict {
                self.resume_raw_recovery()?;
                if !self.recovery_children_settled(&terminal)? {
                    return Err(unresolved("raw predecessor counts are not yet recorded"));
                }
            }
        }
        Ok(())
    }

    fn keep_correction_settlement(
        &self,
        pending: &PendingCorrection,
        decision: Decision,
    ) -> RecordStoreResult<RecoveryEvent> {
        loop {
            let previous = pending.recovery_event.lock().unwrap_or_else(|p| p.into_inner()).clone()
                .ok_or_else(|| unresolved("correction settlement has no immutable predecessor"))?;
            self.keep_recovery_event(&previous)?;
            if previous.state == RecoveryState::Settled {
                if !recovery::Custody::decode(&previous.payload)?.is_terminal() {
                    return Err(unresolved("settled correction still owns untransferred raw debt"));
                }
                return Ok(previous);
            }
            let custody = recovery::Custody::stage_settlement(self, pending, decision)?;
            let mut retained = pending.recovery_event.lock().unwrap_or_else(|p| p.into_inner());
            if retained.as_ref() != Some(&previous) {
                continue;
            }
            let event = self.new_recovery_event(previous.operation_id, previous.kind,
                previous.body_fingerprint, RecoveryState::Settled, previous.first_sent_at_ms,
                custody.encode()?).map_err(|error| unresolved(&error.to_string()))?;
            *retained = Some(event.clone());
            drop(retained);
            self.keep_recovery_event(&event)?;
            return Ok(event);
        }
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
                sent_at: crate::store::now(),
                started: std::time::Instant::now(),
                running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                receipt: Arc::new(std::sync::Mutex::new(None)),
                settled: Arc::new(std::sync::Mutex::new(None)),
                recovery_event: Arc::new(std::sync::Mutex::new(None)),
                quarantined: false,
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
