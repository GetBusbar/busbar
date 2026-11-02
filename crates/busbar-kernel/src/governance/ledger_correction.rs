// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::governance::recovery::{
    RecoveryChild, RecoveryError, RecoveryEvent, RecoveryKind, RecoveryOrigin, RecoveryResolution,
    RecoveryState, RecoveryVerdict,
};
use busbar_contract::records::correction::{self, Decision, Request, UsageAddress, UsageChange};
use busbar_contract::records::{ModelTokens, UsageLedger};

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
    parent_operation_id: Option<[u8; 16]>,
    authorization: Arc<std::sync::Mutex<Option<RecoveryEvent>>>,
    verdict_pending: Arc<std::sync::atomic::AtomicBool>,
}

pub(in crate::governance) struct CorrectionRecoveryRun(Arc<std::sync::atomic::AtomicBool>);
impl Drop for CorrectionRecoveryRun {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl PendingCorrection {
    fn receipt_retention_expired(&self, now: u64) -> bool {
        now < self.sent_at
            || now - self.sent_at >= busbar_contract::abi::store::OP_ID_RETENTION_SECS
            || self.started.elapsed().as_secs() >= busbar_contract::abi::store::OP_ID_RETENTION_SECS
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
    pub(in crate::governance) fn hold_foreign_correction_recovery(
        &self,
        operation_id: [u8; 16],
    ) -> Result<Option<CorrectionRecoveryRun>, RecoveryError> {
        let pending = self
            .corrections
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .find(|pending| pending.request.op_id.0 == operation_id)
            .cloned();
        let Some(pending) = pending else {
            return Ok(None);
        };
        if pending
            .running
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(RecoveryError::Conflict(
                "original correction sender is still running".into(),
            ));
        }
        Ok(Some(CorrectionRecoveryRun(pending.running.clone())))
    }

    /// Prepare foreign adoption transitions without performing persistence or runtime effects.
    pub(in crate::governance) fn stage_foreign_correction_verdict(
        event: &RecoveryEvent,
        resolution: &RecoveryResolution,
    ) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        resolution.validate_quiescence()?;
        if event.kind != RecoveryKind::Correction
            || event.operation_id != resolution.operation_id
            || event.body_fingerprint != resolution.body_fingerprint
            || event.revision != resolution.expected_revision
        {
            return Err(RecoveryError::Conflict(
                "foreign correction head differs".into(),
            ));
        }
        if resolution.actor.trim().is_empty()
            || resolution.actor.len() > 256
            || resolution.reason.trim().is_empty()
            || resolution.reason.len() > 4096
        {
            return Err(RecoveryError::Invalid(
                "foreign correction verdict requires an actor and reason".into(),
            ));
        }
        let mut custody = recovery::Custody::decode(&event.payload)
            .map_err(|error| RecoveryError::Invalid(error.to_string()))?;
        custody
            .validate_event(event)
            .map_err(|error| RecoveryError::Invalid(error.to_string()))?;
        let successor =
            |previous: &RecoveryEvent, state, payload| -> Result<RecoveryEvent, RecoveryError> {
                let next = RecoveryEvent {
                    operation_id: previous.operation_id,
                    revision: previous.revision.checked_add(1).ok_or_else(|| {
                        RecoveryError::Invalid("foreign correction revision exhausted".into())
                    })?,
                    previous_event: Some(previous.fingerprint()?),
                    kind: previous.kind,
                    body_fingerprint: previous.body_fingerprint,
                    state,
                    first_sent_at_ms: previous.first_sent_at_ms,
                    payload,
                };
                next.follows(Some(previous))?;
                Ok(next)
            };
        let desired = match resolution.verdict {
            RecoveryVerdict::Landed => RecoveryState::VerdictLanded,
            RecoveryVerdict::NotLanded => RecoveryState::VerdictNotLanded,
        };
        match event.state {
            RecoveryState::Settled => Ok(Vec::new()),
            RecoveryState::Applied | RecoveryState::VerdictLanded
                if resolution.verdict != RecoveryVerdict::Landed =>
            {
                Err(RecoveryError::Conflict(
                    "foreign correction already has a landed outcome".into(),
                ))
            }
            RecoveryState::ConditionConflict | RecoveryState::VerdictNotLanded
                if resolution.verdict != RecoveryVerdict::NotLanded =>
            {
                Err(RecoveryError::Conflict(
                    "foreign correction already has an unlanded outcome".into(),
                ))
            }
            RecoveryState::Intent | RecoveryState::LandedUnknown => {
                let mut events = Vec::new();
                let previous = if event.state == RecoveryState::Intent {
                    custody.mark_age_unknown();
                    let unknown = successor(
                        event,
                        RecoveryState::LandedUnknown,
                        custody
                            .encode()
                            .map_err(|error| RecoveryError::Invalid(error.to_string()))?,
                    )?;
                    events.push(unknown.clone());
                    unknown
                } else {
                    event.clone()
                };
                custody.record_verdict(resolution);
                events.push(successor(
                    &previous,
                    desired,
                    custody
                        .encode()
                        .map_err(|error| RecoveryError::Invalid(error.to_string()))?,
                )?);
                Ok(events)
            }
            _ => Ok(vec![successor(event, event.state, event.payload.clone())?]),
        }
    }

    fn correction_quarantine_events(&self) -> Vec<RecoveryEvent> {
        self.selected_recovery_events()
            .into_iter()
            .filter(|event| {
                event.kind == RecoveryKind::Correction
                    && match event.state {
                        RecoveryState::LandedUnknown
                        | RecoveryState::VerdictLanded
                        | RecoveryState::VerdictNotLanded => true,
                        RecoveryState::Intent => self
                            .recovery_retention_expired(event.operation_id)
                            .is_none(),
                        _ => false,
                    }
            })
            .collect()
    }

    pub(in crate::governance) fn quarantined_correction_owns_target(
        &self,
        bucket: &str,
        window: u64,
    ) -> bool {
        self.correction_quarantine_events().iter().any(|event| {
            recovery::Custody::decode(&event.payload).map_or(true, |custody| {
                custody.owns_quarantined_target(bucket, window)
            })
        })
    }

    pub(in crate::governance) fn stage_quarantined_correction_negatives(
        &self,
        bucket: &str,
        window: u64,
        plain: &mut ExactUsageDelta,
        dated: &mut ExactUsageDelta,
    ) -> RecordStoreResult<Option<RecoveryEvent>> {
        for selected in self.correction_quarantine_events() {
            let mut custody = recovery::Custody::decode(&selected.payload)?;
            if !custody.owns_quarantined_target(bucket, window) {
                continue;
            }
            let pending = self
                .corrections
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .values()
                .find(|pending| pending.request.op_id.0 == selected.operation_id)
                .cloned();
            if let Some(pending) = &pending {
                let retained = pending
                    .recovery_event
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone();
                if retained.as_ref() != Some(&selected) {
                    return Err(unresolved(
                        "quarantined correction checkpoint is not yet selected",
                    ));
                }
            }
            let Some((remaining_plain, remaining_dated)) =
                custody.absorb_negatives(bucket, window, plain, dated)?
            else {
                continue;
            };
            let state = if selected.state == RecoveryState::Intent {
                custody.mark_age_unknown();
                RecoveryState::LandedUnknown
            } else {
                selected.state
            };
            let event = self
                .new_recovery_event(
                    selected.operation_id,
                    selected.kind,
                    selected.body_fingerprint,
                    state,
                    selected.first_sent_at_ms,
                    custody.encode()?,
                )
                .map_err(|error| unresolved(&error.to_string()))?;
            if let Some(pending) = pending {
                *pending
                    .recovery_event
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = Some(event.clone());
            }
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
        if let Some(existing) = self
            .corrections
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .find(|pending| pending.request.op_id.0 == event.operation_id)
            .cloned()
        {
            if existing.request.fingerprint() != event.body_fingerprint {
                return Err(unresolved(
                    "restored correction conflicts with its live operation",
                ));
            }
            *existing
                .recovery_event
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = Some(event.clone());
            return Ok(());
        }
        if custody.is_terminal() {
            return Ok(());
        }
        // Historical aggregates are evidence, not a replacement for fresh Store hydration.
        let pending = custody.restore(self, event)?;
        let mut corrections = self.corrections.lock().unwrap_or_else(|p| p.into_inner());
        if corrections.contains_key(&pending.request.key_id) {
            return Err(unresolved(
                "multiple unresolved corrections name the same key",
            ));
        }
        corrections.insert(pending.request.key_id.clone(), pending);
        Ok(())
    }

    /// Resume retained correction work after fresh Store-backed budget hydration.
    pub fn resume_correction_verdicts(
        &self,
        cost: &crate::cost::CostModel,
    ) -> RecordStoreResult<()> {
        let mut first_error = None;
        for event in self.selected_recovery_events() {
            if event.kind != RecoveryKind::Correction || event.state == RecoveryState::Settled {
                continue;
            }
            if matches!(
                event.state,
                RecoveryState::Applied
                    | RecoveryState::ConditionConflict
                    | RecoveryState::VerdictLanded
                    | RecoveryState::VerdictNotLanded
            ) || (event.state == RecoveryState::Intent
                && self
                    .recovery_retention_expired(event.operation_id)
                    .is_none())
            {
                if let Err(error) = self.resume_adopted_correction(cost, event.operation_id) {
                    first_error.get_or_insert_with(|| unresolved(&error.to_string()));
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub(in crate::governance) fn resume_adopted_correction(
        &self,
        cost: &crate::cost::CostModel,
        operation_id: [u8; 16],
    ) -> Result<(), RecoveryError> {
        let unavailable = |error: RecordStoreError| RecoveryError::Unavailable(error.to_string());
        self.confirm_pending_recovery(operation_id)
            .map_err(unavailable)?;
        let event = self
            .recovery_event(operation_id)
            .ok_or_else(|| RecoveryError::Invalid("adopted correction is not selected".into()))?;
        if event.kind != RecoveryKind::Correction {
            return Err(RecoveryError::Invalid(
                "adopted operation is not a correction".into(),
            ));
        }
        let mut custody = recovery::Custody::decode(&event.payload).map_err(unavailable)?;
        custody.validate_event(&event).map_err(unavailable)?;
        match event.state {
            RecoveryState::Intent => {
                if self.recovery_retention_expired(operation_id).is_none() {
                    custody.mark_age_unknown();
                    let next = self.new_recovery_event(
                        operation_id,
                        event.kind,
                        event.body_fingerprint,
                        RecoveryState::LandedUnknown,
                        event.first_sent_at_ms,
                        custody.encode().map_err(unavailable)?,
                    )?;
                    self.keep_recovery_event(&next).map_err(unavailable)?;
                    if let Some(pending) = self
                        .corrections
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .values()
                        .find(|pending| pending.request.op_id.0 == operation_id)
                        .cloned()
                    {
                        *pending
                            .recovery_event
                            .lock()
                            .unwrap_or_else(|p| p.into_inner()) = Some(next);
                    }
                }
                Ok(())
            }
            RecoveryState::LandedUnknown => Ok(()),
            RecoveryState::VerdictLanded | RecoveryState::VerdictNotLanded => {
                let resolution = custody.retained_resolution(&event).map_err(unavailable)?;
                self.recovery().resolve(cost, resolution).map(|_| ())
            }
            RecoveryState::Applied | RecoveryState::ConditionConflict => {
                let decision = if event.state == RecoveryState::Applied {
                    Decision::Applied
                } else {
                    Decision::ConditionConflict
                };
                let pending = self
                    .corrections
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .values()
                    .find(|pending| pending.request.op_id.0 == operation_id)
                    .cloned();
                if let Some(pending) = pending.as_ref().filter(|pending| !pending.quarantined) {
                    *pending.receipt.lock().unwrap_or_else(|p| p.into_inner()) = Some(decision);
                    self.decide_usage_correction(pending).map_err(unavailable)?;
                    self.remove_correction_owner(pending);
                } else {
                    custody
                        .transfer_selected(decision, true)
                        .map_err(unavailable)?;
                    let next = self.new_recovery_event(
                        operation_id,
                        event.kind,
                        event.body_fingerprint,
                        RecoveryState::Settled,
                        event.first_sent_at_ms,
                        custody.encode().map_err(unavailable)?,
                    )?;
                    self.keep_recovery_event(&next).map_err(unavailable)?;
                    self.resume_recovery_children(&next).map_err(unavailable)?;
                    if let Some(pending) = pending.as_ref() {
                        self.remove_correction_owner(pending);
                        self.refresh_recovered_correction_targets(pending)
                            .map_err(unavailable)?;
                    }
                }
                Ok(())
            }
            RecoveryState::Settled => self.resume_recovery_children(&event).map_err(unavailable),
        }
    }

    pub(in crate::governance) fn resolve_correction_recovery(
        &self,
        cost: &crate::cost::CostModel,
        resolution: &RecoveryResolution,
    ) -> Result<(), RecoveryError> {
        resolution.validate_quiescence()?;
        let unavailable = |error: RecordStoreError| RecoveryError::Unavailable(error.to_string());
        self.confirm_pending_recovery(resolution.operation_id)
            .map_err(unavailable)?;
        let mut selected = self
            .recovery_event(resolution.operation_id)
            .ok_or_else(|| RecoveryError::Invalid("correction is not selected".into()))?;
        if selected.kind != RecoveryKind::Correction
            || selected.body_fingerprint != resolution.body_fingerprint
        {
            return Err(RecoveryError::Conflict(
                "correction fingerprint differs".into(),
            ));
        }
        let stored = recovery::Custody::decode(&selected.payload).map_err(unavailable)?;
        stored.validate_event(&selected).map_err(unavailable)?;
        let pending = self
            .corrections
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .find(|pending| pending.request.op_id.0 == resolution.operation_id)
            .cloned();
        let pending = match pending {
            Some(pending) => pending,
            None => stored
                .clone()
                .restore(self, &selected)
                .map_err(unavailable)?,
        };
        if pending
            .running
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(RecoveryError::Conflict(
                "original correction sender is still running".into(),
            ));
        }
        let _running = CorrectionRecoveryRun(pending.running.clone());
        let _claim = self.correction_claims.claim(pending.request.key_id.clone());
        let state = match resolution.verdict {
            RecoveryVerdict::Landed => RecoveryState::VerdictLanded,
            RecoveryVerdict::NotLanded => RecoveryState::VerdictNotLanded,
        };
        if selected.state == RecoveryState::LandedUnknown {
            if selected.revision != resolution.expected_revision {
                return Err(RecoveryError::Conflict(
                    "correction revision differs".into(),
                ));
            }
            let mut custody = if pending.quarantined {
                stored
            } else {
                recovery::Custody::capture(self, &pending).map_err(unavailable)?
            };
            custody.record_verdict(resolution);
            let event = self.new_recovery_event(
                selected.operation_id,
                selected.kind,
                selected.body_fingerprint,
                state,
                selected.first_sent_at_ms,
                custody.encode().map_err(unavailable)?,
            )?;
            *pending
                .recovery_event
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = Some(event.clone());
            self.keep_recovery_event(&event).map_err(unavailable)?;
            selected = event;
        } else if !matches!(
            selected.state,
            RecoveryState::VerdictLanded | RecoveryState::VerdictNotLanded | RecoveryState::Settled
        ) || !stored.verdict_matches(resolution)
        {
            return Err(RecoveryError::Conflict(
                "correction has a different audited outcome".into(),
            ));
        }
        pending.verdict_pending.store(true, Ordering::Release);
        let decision = if resolution.verdict == RecoveryVerdict::Landed {
            Decision::Applied
        } else {
            Decision::ConditionConflict
        };
        *pending.receipt.lock().unwrap_or_else(|p| p.into_inner()) = Some(decision);
        selected = self
            .keep_verdict_correction_cut(&pending, &selected, decision)
            .map_err(unavailable)?;
        let needs_selection = pending
            .settled
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_none();
        if !pending.quarantined && needs_selection {
            self.select_correction_cut(&pending, decision, Some(&selected))
                .map_err(unavailable)?;
        }
        self.resume_recovery_children(&selected)
            .map_err(unavailable)?;
        if resolution.verdict == RecoveryVerdict::NotLanded
            && selected.state != RecoveryState::Settled
        {
            self.finish_unlanded_correction(cost, &pending, &selected)
                .map_err(unavailable)?;
        }
        self.remove_correction_owner(&pending);
        self.refresh_recovered_correction_targets(&pending)
            .map_err(unavailable)?;
        Ok(())
    }

    fn keep_verdict_correction_cut(
        &self,
        pending: &PendingCorrection,
        previous: &RecoveryEvent,
        decision: Decision,
    ) -> RecordStoreResult<RecoveryEvent> {
        self.confirm_pending_recovery(previous.operation_id)?;
        let previous = self
            .recovery_event(previous.operation_id)
            .ok_or_else(|| unresolved("audited correction disappeared"))?;
        let stored = recovery::Custody::decode(&previous.payload)?;
        if stored.is_terminal() {
            return Ok(previous);
        }
        let mut custody = if pending.quarantined {
            stored
        } else {
            recovery::Custody::capture(self, pending)?
        };
        custody.transfer_selected(decision, decision == Decision::Applied)?;
        let state = if decision == Decision::Applied {
            RecoveryState::Settled
        } else {
            RecoveryState::VerdictNotLanded
        };
        let event = self
            .new_recovery_event(
                previous.operation_id,
                previous.kind,
                previous.body_fingerprint,
                state,
                previous.first_sent_at_ms,
                custody.encode()?,
            )
            .map_err(|error| unresolved(&error.to_string()))?;
        *pending
            .recovery_event
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(event.clone());
        self.keep_recovery_event(&event)?;
        Ok(event)
    }

    fn finish_unlanded_correction(
        &self,
        cost: &crate::cost::CostModel,
        pending: &PendingCorrection,
        parent: &RecoveryEvent,
    ) -> RecordStoreResult<()> {
        let custody = recovery::Custody::decode(&parent.payload)?;
        let already_applied = if let Some(id) = custody.repost_operation_id() {
            let child = self
                .recovery_event(id)
                .ok_or_else(|| unresolved("conditional successor is not selected"))?;
            if child.state != RecoveryState::Settled {
                return Err(unresolved(
                    "conditional successor remains unresolved; resolve its own exact operation",
                ));
            }
            recovery::Custody::decode(&child.payload)?.intent_applied()
        } else {
            false
        };
        if !self.recovery_children_settled(parent)? {
            return Err(unresolved(
                "original raw facts must be confirmed before conditional revalidation",
            ));
        }
        if !already_applied {
            let intent = &pending.intent;
            let adj = Adjustment {
                key_id: &pending.request.key_id,
                pool: &intent.pool,
                model: &intent.model,
                entry_era: intent.era,
                entry_id: intent.entry_id.map(EntryId),
                card_epoch_ms: intent.epoch,
                delta: &intent.delta,
                now: crate::store::now(),
            };
            let delta = intent
                .delta
                .iter()
                .filter(|(_, count)| **count != 0)
                .map(|(unit, count)| (unit.as_str(), *count))
                .collect();
            self.correct_usage_with_parent(
                cost,
                &adj,
                &delta,
                pending.request.day_start,
                Some(parent.operation_id),
            )?
            .map_err(|refused| {
                unresolved(&format!(
                    "fresh conditional correction refused: {refused:?}"
                ))
            })?;
        }
        self.confirm_pending_recovery(parent.operation_id)?;
        let latest = self
            .recovery_event(parent.operation_id)
            .ok_or_else(|| unresolved("conditional parent disappeared"))?;
        let mut custody = recovery::Custody::decode(&latest.payload)?;
        let child = self
            .recovery_event(
                custody
                    .repost_operation_id()
                    .ok_or_else(|| unresolved("conditional parent has no successor identity"))?,
            )
            .ok_or_else(|| unresolved("conditional successor disappeared"))?;
        if child.state != RecoveryState::Settled
            || !recovery::Custody::decode(&child.payload)?.intent_applied()
        {
            return Err(unresolved(
                "conditional successor has no definitive applied outcome",
            ));
        }
        custody.finish_repost()?;
        let event = self
            .new_recovery_event(
                latest.operation_id,
                latest.kind,
                latest.body_fingerprint,
                RecoveryState::Settled,
                latest.first_sent_at_ms,
                custody.encode()?,
            )
            .map_err(|error| unresolved(&error.to_string()))?;
        *pending
            .recovery_event
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(event.clone());
        self.keep_recovery_event(&event)?;
        self.resume_recovery_children(&event)?;
        if !self.recovery_children_settled(&event)? {
            return Err(unresolved(
                "revalidated correction has unconfirmed dependent negatives",
            ));
        }
        Ok(())
    }

    fn remove_correction_owner(&self, pending: &PendingCorrection) {
        let mut corrections = self.corrections.lock().unwrap_or_else(|p| p.into_inner());
        if corrections
            .get(&pending.request.key_id)
            .is_some_and(|current| current.request.op_id == pending.request.op_id)
        {
            corrections.remove(&pending.request.key_id);
        }
    }

    fn refresh_recovered_correction_targets(
        &self,
        pending: &PendingCorrection,
    ) -> RecordStoreResult<()> {
        for (bucket, window) in &pending.targets {
            let mut plain = self.store.get_usage(bucket, *window)?;
            let mut dated = self.store.get_usage(&era_bucket(bucket), *window)?;
            exact(correction::canonical_ledger(&mut plain))?;
            exact(correction::canonical_ledger(&mut dated))?;
            let mut cells = self.budget.write(bucket);
            let live = cells.get(bucket);
            if live.is_some_and(|cell| {
                cell.correction.is_some()
                    || cell.window_start != *window
                    || cell.flushing_windows.contains_key(window)
            }) {
                continue;
            }
            let (before, _, _) = capture_target(live, &plain, &dated, *window)?;
            cells.insert(bucket.clone(), before);
        }
        Ok(())
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
        let branch = cell
            .correction
            .as_ref()
            .filter(|branch| branch.window == window)
            .ok_or_else(|| unresolved("correction handoff has no reserved target"))?;
        let pending = self
            .corrections
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .find(|pending| pending.request.op_id == branch.op_id)
            .cloned()
            .ok_or_else(|| unresolved("correction handoff has no operation owner"))?;
        let mut retained = pending
            .recovery_event
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let selected = self
            .recovery_event(branch.op_id.0)
            .ok_or_else(|| unresolved("correction handoff has no selected parent"))?;
        if retained.as_ref() != Some(&selected) || selected.state == RecoveryState::Settled {
            return Err(unresolved(
                "correction parent checkpoint is not yet selected",
            ));
        }
        let mut custody = recovery::Custody::decode(&selected.payload)?;
        if custody.is_terminal() {
            return Err(unresolved(
                "correction raw cut is already authorized; retry after branch release",
            ));
        }
        custody.replace_target(bucket, cell, window, child)?;
        let event = self
            .new_recovery_event(
                selected.operation_id,
                selected.kind,
                selected.body_fingerprint,
                selected.state,
                selected.first_sent_at_ms,
                custody.encode()?,
            )
            .map_err(|error| unresolved(&error.to_string()))?;
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
        let _running = CorrectionRecoveryRun(pending.running.clone());
        if pending.verdict_pending.load(Ordering::Acquire) {
            return Err(unresolved(
                "audited correction verdict awaits conditional revalidation",
            ));
        }
        self.authorize_correction_parent(pending)?;
        if let Some(decision) = *pending.settled.lock().unwrap_or_else(|p| p.into_inner()) {
            if decision == Decision::ConditionConflict && self.recovery_enabled() {
                let event = self
                    .recovery_event(pending.request.op_id.0)
                    .ok_or_else(|| unresolved("settled correction parent is missing"))?;
                self.resume_recovery_children(&event)?;
                if !self.recovery_children_settled(&event)? {
                    return Err(unresolved("raw predecessor counts are not yet recorded"));
                }
            }
            return Ok(decision);
        }
        if pending.quarantined {
            self.confirm_pending_recovery(pending.request.op_id.0)?;
            let selected = self
                .recovery_event(pending.request.op_id.0)
                .ok_or_else(|| unresolved("quarantined correction has no selected event"))?;
            if selected.state == RecoveryState::Intent {
                let mut custody = recovery::Custody::decode(&selected.payload)?;
                custody.mark_age_unknown();
                let event = self
                    .new_recovery_event(
                        selected.operation_id,
                        selected.kind,
                        selected.body_fingerprint,
                        RecoveryState::LandedUnknown,
                        selected.first_sent_at_ms,
                        custody.encode()?,
                    )
                    .map_err(|error| unresolved(&error.to_string()))?;
                *pending
                    .recovery_event
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = Some(event.clone());
                self.keep_recovery_event(&event)?;
            }
            return Err(unresolved("historical correction is quarantined pending an audited verdict and fresh revalidation"));
        }
        let receipt = *pending.receipt.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(decision) = receipt {
            let terminal = pending
                .recovery_event
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_ref()
                .is_some_and(|event| event.state == RecoveryState::Settled);
            if !terminal {
                self.keep_correction_decision(pending, decision)?;
            }
            self.settle_usage_correction(pending, decision)?;
            return Ok(decision);
        }
        let current_state = pending
            .recovery_event
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|event| event.state);
        if current_state == Some(RecoveryState::LandedUnknown) {
            self.keep_correction_recovery(pending, RecoveryState::LandedUnknown)?;
            return Err(unresolved(
                "landed-unknown operation requires an audited verdict",
            ));
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
        self.keep_correction_recovery(
            pending,
            match decision {
                Decision::Applied => RecoveryState::Applied,
                Decision::ConditionConflict => RecoveryState::ConditionConflict,
            },
        )
    }

    fn authorize_correction_parent(&self, pending: &PendingCorrection) -> RecordStoreResult<()> {
        let Some(parent_id) = pending.parent_operation_id else {
            return Ok(());
        };
        if let Some(child) = self.recovery_event(pending.request.op_id.0) {
            if child.kind != RecoveryKind::Correction
                || child.body_fingerprint != pending.request.fingerprint()
            {
                return Err(unresolved(
                    "conditional successor has another immutable body",
                ));
            }
            self.validate_recovery_origin(&child)?;
            let mut retained = pending
                .recovery_event
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if retained.is_none() {
                *retained = Some(child);
            }
            return Ok(());
        }
        let authorized = pending
            .authorization
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let parent = if let Some(parent) = authorized {
            self.keep_recovery_event(&parent)?;
            parent
        } else {
            self.confirm_pending_recovery(parent_id)?;
            let parent = self
                .recovery_event(parent_id)
                .filter(|event| event.state == RecoveryState::VerdictNotLanded)
                .ok_or_else(|| unresolved("conditional successor has no not-landed verdict"))?;
            let child = RecoveryChild {
                operation_id: pending.request.op_id.0,
                kind: RecoveryKind::Correction,
                body_fingerprint: pending.request.fingerprint(),
                first_sent_at_ms: Some(pending.sent_at.saturating_mul(1_000)),
                payload: recovery::Custody::capture(self, pending)?.encode()?,
            };
            let mut custody = recovery::Custody::decode(&parent.payload)?;
            custody.attach_repost(child)?;
            let event = self
                .new_recovery_event(
                    parent.operation_id,
                    parent.kind,
                    parent.body_fingerprint,
                    parent.state,
                    parent.first_sent_at_ms,
                    custody.encode()?,
                )
                .map_err(|error| unresolved(&error.to_string()))?;
            *pending
                .authorization
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = Some(event.clone());
            self.keep_recovery_event(&event)?;
            event
        };
        self.drive_recovery_children(&parent)?;
        let child = self
            .recovery_event(pending.request.op_id.0)
            .ok_or_else(|| unresolved("conditional successor intent has not been selected"))?;
        if child.kind != RecoveryKind::Correction
            || child.body_fingerprint != pending.request.fingerprint()
        {
            return Err(unresolved(
                "conditional successor differs from its parent authorization",
            ));
        }
        *pending
            .recovery_event
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(child);
        Ok(())
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
            let previous = pending
                .recovery_event
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            if let Some(event) = previous.as_ref() {
                // Confirm an immutable candidate before allocating its successor. The mutex is
                // released during I/O so a handoff cannot block a shard on this Store call.
                self.keep_recovery_event(event)?;
            }
            let payload = recovery::Custody::capture(self, pending)?.encode()?;
            let mut retained = pending
                .recovery_event
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if *retained != previous {
                continue;
            }
            if previous
                .as_ref()
                .is_some_and(|event| event.state == state && event.payload == payload)
            {
                return Ok(());
            }
            let event = self
                .new_recovery_event(
                    pending.request.op_id.0,
                    RecoveryKind::Correction,
                    pending.request.fingerprint(),
                    state,
                    Some(pending.sent_at.saturating_mul(1_000)),
                    payload,
                )
                .map_err(|error| unresolved(&error.to_string()))?;
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
        self.select_correction_cut(pending, decision, terminal.as_ref())?;
        if let Some(terminal) = terminal {
            self.drive_recovery_children(&terminal)?;
            if decision == Decision::ConditionConflict {
                self.resume_recovery_children(&terminal)?;
                if !self.recovery_children_settled(&terminal)? {
                    return Err(unresolved("raw predecessor counts are not yet recorded"));
                }
            }
        }
        Ok(())
    }

    fn select_correction_cut(
        &self,
        pending: &PendingCorrection,
        decision: Decision,
        terminal: Option<&RecoveryEvent>,
    ) -> RecordStoreResult<()> {
        let cuts: BTreeMap<_, _> = terminal
            .map(|event| recovery::Custody::decode(&event.payload)?.selected_cuts())
            .transpose()?
            .unwrap_or_default()
            .into_iter()
            .map(|(bucket, window, cell)| ((bucket, window), cell))
            .collect();
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
            let cell = guards[index].1.get(bucket).expect("checked target cell");
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
            let index = order
                .binary_search(&self.budget.shard_index(&bucket))
                .expect("target shard held");
            guards[index].1.insert(bucket, chosen);
        }
        drop(guards);
        *pending.settled.lock().unwrap_or_else(|p| p.into_inner()) = Some(decision);
        Ok(())
    }

    fn keep_correction_settlement(
        &self,
        pending: &PendingCorrection,
        decision: Decision,
    ) -> RecordStoreResult<RecoveryEvent> {
        loop {
            let previous = pending
                .recovery_event
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
                .ok_or_else(|| unresolved("correction settlement has no immutable predecessor"))?;
            self.keep_recovery_event(&previous)?;
            if previous.state == RecoveryState::Settled {
                if !recovery::Custody::decode(&previous.payload)?.is_terminal() {
                    return Err(unresolved(
                        "settled correction still owns untransferred raw debt",
                    ));
                }
                return Ok(previous);
            }
            let custody = recovery::Custody::stage_settlement(self, pending, decision)?;
            let mut retained = pending
                .recovery_event
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if retained.as_ref() != Some(&previous) {
                continue;
            }
            let event = self
                .new_recovery_event(
                    previous.operation_id,
                    previous.kind,
                    previous.body_fingerprint,
                    RecoveryState::Settled,
                    previous.first_sent_at_ms,
                    custody.encode()?,
                )
                .map_err(|error| unresolved(&error.to_string()))?;
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
                if pending.quarantined {
                    if self
                        .recovery_event(pending.request.op_id.0)
                        .is_some_and(|event| event.state == RecoveryState::Intent)
                    {
                        let result = self.decide_usage_correction(&pending);
                        if !self
                            .recovery_event(pending.request.op_id.0)
                            .is_some_and(|event| event.state == RecoveryState::LandedUnknown)
                        {
                            return result
                                .err()
                                .map(|error| format!("{}: {error}", pending.request.key_id));
                        }
                    }
                    return self
                        .confirm_pending_recovery(pending.request.op_id.0)
                        .err()
                        .map(|error| format!("{}: {error}", pending.request.key_id));
                }
                if pending.verdict_pending.load(Ordering::Acquire) {
                    return None;
                }
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
        self.correct_usage_with_parent(cost, adj, delta, day, None)
    }

    fn correct_usage_with_parent(
        &self,
        cost: &crate::cost::CostModel,
        adj: &Adjustment<'_>,
        delta: &BTreeMap<&str, i64>,
        day: u64,
        parent_operation_id: Option<[u8; 16]>,
    ) -> RecordStoreResult<Result<(), AdjustRefused>> {
        if parent_operation_id.is_some() {
            if let Err(refused) = check_epoch(adj.card_epoch_ms, crate::store::now_ms()) {
                return Ok(Err(refused));
            }
            if !self.store.supports_usage_correction() {
                return Err(unresolved("usage corrections are unsupported"));
            }
            if let Some(history) = crate::rate_apply::dated_history() {
                if history.current().entry_at(adj.card_epoch_ms).is_none() {
                    return Ok(Err(AdjustRefused::NoCardInForce {
                        at: adj.card_epoch_ms,
                    }));
                }
            }
            if adj.entry_era > adj.card_epoch_ms {
                return Ok(Err(AdjustRefused::NotInForce {
                    named: adj.entry_era,
                    in_force: crate::rate_apply::effective_from_at(adj.card_epoch_ms),
                }));
            }
        }
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
                parent_operation_id,
                authorization: Arc::new(std::sync::Mutex::new(None)),
                verdict_pending: Arc::new(std::sync::atomic::AtomicBool::new(false)),
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
        if adj
            .entry_id
            .is_some_and(|expected| Some(expected) != era.entry_id)
        {
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
