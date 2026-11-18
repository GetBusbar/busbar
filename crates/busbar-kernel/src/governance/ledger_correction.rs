// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::cold::governance::ledger as ledger_cold;
use crate::governance::recovery::{
    RecoveryChild, RecoveryError, RecoveryEvent, RecoveryKind, RecoveryOrigin, RecoveryResolution,
    RecoveryState, RecoveryVerdict,
};
use crate::off_path::governance::ledger as ledger_off_path;
use busbar_contract::records::correction::{self, Decision, Request, UsageAddress};
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
    delta: BTreeMap<String, Count>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    action_id: Option<String>,
}
impl Intent {
    fn of(adj: &Adjustment<'_, Count>, action_id: Option<&str>) -> Self {
        Self {
            pool: adj.pool.into(),
            model: adj.model.into(),
            era: adj.entry_era,
            entry_id: adj.entry_id.map(|id| id.0),
            epoch: adj.card_epoch_ms,
            delta: adj.delta.clone(),
            action_id: action_id.map(Into::into),
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
    pub(in crate::governance) fn has_unsettled_persistence(&self) -> bool {
        if self.running.load(Ordering::Acquire) || self.verdict_pending.load(Ordering::Acquire) {
            return true;
        }
        if self
            .settled
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_none()
        {
            return true;
        }
        self.recovery_event
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .is_some_and(|event| event.state != RecoveryState::Settled)
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

fn unresolved(reason: impl std::fmt::Display) -> RecordStoreError {
    crate::governance::rendered_error(
        RecordStoreError,
        format_args!("usage correction unresolved: {reason}"),
    )
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
    /// The retained correction `owns` picks (recovery, operator verdicts and correction custody).
    fn retained_correction(
        &self,
        owns: impl Fn(&PendingCorrection) -> bool,
    ) -> Option<PendingCorrection> {
        ledger_off_path::ledger_corrections_find(
            &*self.corrections.lock().unwrap_or_else(|p| p.into_inner()),
            owns,
        )
    }

    pub(in crate::governance) fn validate_foreign_correction_verdict(
        &self,
        resolution: &RecoveryResolution,
    ) -> Result<(), RecoveryError> {
        resolution.validate_quiescence()?;
        let pending =
            self.retained_correction(|pending| pending.request.op_id.0 == resolution.operation_id);
        let receipt = pending
            .as_ref()
            .and_then(|pending| *pending.receipt.lock().unwrap_or_else(|p| p.into_inner()));
        let selected = self
            .recovery_event(resolution.operation_id)
            .and_then(|event| match event.state {
                RecoveryState::Applied => Some(Decision::Applied),
                RecoveryState::ConditionConflict => Some(Decision::ConditionConflict),
                _ => None,
            });
        let expected = if resolution.verdict == RecoveryVerdict::Landed {
            Decision::Applied
        } else {
            Decision::ConditionConflict
        };
        if receipt.is_some_and(|known| known != expected)
            || selected.is_some_and(|known| known != expected)
        {
            return Err(RecoveryError::Conflict(
                "requested verdict contradicts a definitive backend correction receipt".into(),
            ));
        }
        Ok(())
    }

    pub(in crate::governance) fn hold_foreign_correction_recovery(
        &self,
        operation_id: [u8; 16],
    ) -> Result<Option<CorrectionRecoveryRun>, RecoveryError> {
        let pending = self.retained_correction(|pending| pending.request.op_id.0 == operation_id);
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
        Ok(Some(CorrectionRecoveryRun(pending.running)))
    }

    /// Prepare foreign adoption transitions without performing persistence or runtime effects.
    pub(crate) fn stage_foreign_correction_verdict(
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
            .map_err(|error| crate::governance::rendered_error(RecoveryError::Invalid, error))?;
        custody
            .validate_event(event)
            .map_err(|error| crate::governance::rendered_error(RecoveryError::Invalid, error))?;
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
            RecoveryState::Intent => {
                custody.mark_age_unknown();
                let unknown = successor(
                    event,
                    RecoveryState::LandedUnknown,
                    custody.encode().map_err(|error| {
                        crate::governance::rendered_error(RecoveryError::Invalid, error)
                    })?,
                )?;
                custody.record_verdict(resolution);
                let verdict = successor(
                    &unknown,
                    desired,
                    custody.encode().map_err(|error| {
                        crate::governance::rendered_error(RecoveryError::Invalid, error)
                    })?,
                )?;
                Ok(vec![unknown, verdict])
            }
            RecoveryState::LandedUnknown => {
                custody.record_verdict(resolution);
                Ok(vec![successor(
                    event,
                    desired,
                    custody.encode().map_err(|error| {
                        crate::governance::rendered_error(RecoveryError::Invalid, error)
                    })?,
                )?])
            }
            _ => Ok(vec![successor(event, event.state, event.payload.clone())?]),
        }
    }

    /// The selected correction events still awaiting an outcome (quarantine), lazily, in
    /// selection order.
    fn correction_quarantine_events(&self) -> impl Iterator<Item = RecoveryEvent> + '_ {
        self.selected_recovery_events()
            .into_iter()
            .filter(move |event| {
                event.kind == RecoveryKind::Correction
                    && match event.state {
                        RecoveryState::LandedUnknown
                        | RecoveryState::VerdictLanded
                        | RecoveryState::VerdictNotLanded => true,
                        RecoveryState::Intent => !self.recovery_sent_here(event.operation_id),
                        _ => false,
                    }
            })
    }

    /// Remaining unknown positive exposure from selected correction owners only. No pending
    pub(in crate::governance) fn quarantined_correction_negative_capacity(
        &self,
        bucket: &str,
        window: u64,
    ) -> RecordStoreResult<(ExactUsageDelta, ExactUsageDelta)> {
        use crate::governance::exact_debt::SegmentedUsage;
        let mut capacity = SegmentedUsage::default();
        for event in self.correction_quarantine_events().filter(|event| {
            matches!(
                event.state,
                RecoveryState::Intent | RecoveryState::LandedUnknown
            )
        }) {
            let custody = recovery::Custody::decode(&event.payload)?;
            let (plain, dated) = custody.negative_capacity(bucket, window)?;
            capacity.merge(&SegmentedUsage::of(&plain, &dated)?);
        }
        Ok(capacity.positive().deltas())
    }

    pub(in crate::governance) fn stage_quarantined_correction_negatives(
        &self,
        bucket: &str,
        window: u64,
        plain: &mut ExactUsageDelta,
        dated: &mut ExactUsageDelta,
    ) -> RecordStoreResult<Option<RecoveryEvent>> {
        for selected in self.correction_quarantine_events().filter(|event| {
            matches!(
                event.state,
                RecoveryState::Intent | RecoveryState::LandedUnknown
            )
        }) {
            let mut custody = recovery::Custody::decode(&selected.payload)?;
            if !custody.owns_quarantined_target(bucket, window) {
                continue;
            }
            let Some((remaining_plain, remaining_dated)) =
                custody.absorb_negatives(bucket, window, plain, dated)?
            else {
                continue;
            };
            let pending = self
                .retained_correction(|pending| pending.request.op_id.0 == selected.operation_id);
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
                .map_err(unresolved)?;
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

    pub(crate) fn canonical_correction_receipt_digest(
        event: &RecoveryEvent,
    ) -> RecordStoreResult<[u8; 32]> {
        let custody = recovery::Custody::decode(&event.payload)?;
        custody.validate_event(event)?;
        Ok(custody.receipt_digest())
    }

    pub(in crate::governance) fn restore_correction_recovery(
        &self,
        event: &RecoveryEvent,
    ) -> RecordStoreResult<()> {
        let custody = recovery::Custody::decode(&event.payload)?;
        custody.validate_event(event)?;
        if let Some(existing) =
            self.retained_correction(|pending| pending.request.op_id.0 == event.operation_id)
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
    pub async fn resume_correction_verdicts(
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
                    | RecoveryState::LandedUnknown
            ) || (event.state == RecoveryState::Intent
                && !self.recovery_sent_here(event.operation_id))
            {
                if let Err(error) = self
                    .resume_adopted_correction(cost, event.operation_id)
                    .await
                {
                    first_error.get_or_insert_with(|| unresolved(error));
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub(in crate::governance) async fn resume_adopted_correction(
        &self,
        cost: &crate::cost::CostModel,
        operation_id: [u8; 16],
    ) -> Result<(), RecoveryError> {
        let unavailable = |error: RecordStoreError| {
            crate::governance::rendered_error(RecoveryError::Unavailable, error)
        };
        self.confirm_pending_recovery(operation_id)
            .await
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
                if !self.recovery_sent_here(operation_id) {
                    custody.mark_age_unknown();
                    let next = self.new_recovery_event(
                        operation_id,
                        event.kind,
                        event.body_fingerprint,
                        RecoveryState::LandedUnknown,
                        event.first_sent_at_ms,
                        custody.encode().map_err(unavailable)?,
                    )?;
                    self.keep_recovery_event(&next).await.map_err(unavailable)?;
                    if let Some(pending) =
                        self.retained_correction(|pending| pending.request.op_id.0 == operation_id)
                    {
                        *pending
                            .recovery_event
                            .lock()
                            .unwrap_or_else(|p| p.into_inner()) = Some(next);
                    }
                }
                self.resume_quarantined_common_positives(operation_id)
                    .await
                    .map_err(unavailable)?;
                Ok(())
            }
            RecoveryState::LandedUnknown => self
                .resume_quarantined_common_positives(operation_id)
                .await
                .map_err(unavailable),
            RecoveryState::VerdictLanded | RecoveryState::VerdictNotLanded => {
                let resolution = custody.retained_resolution(&event).map_err(unavailable)?;
                self.recovery().resolve(cost, resolution).await.map(|_| ())
            }
            RecoveryState::Applied | RecoveryState::ConditionConflict => {
                let decision = if event.state == RecoveryState::Applied {
                    Decision::Applied
                } else {
                    Decision::ConditionConflict
                };
                let pending =
                    self.retained_correction(|pending| pending.request.op_id.0 == operation_id);
                if let Some(pending) = pending.as_ref().filter(|pending| !pending.quarantined) {
                    let _running = self.hold_foreign_correction_recovery(operation_id)?;
                    *pending.receipt.lock().unwrap_or_else(|p| p.into_inner()) = Some(decision);
                    self.keep_correction_decision(pending, decision)
                        .await
                        .map_err(unavailable)?;
                    self.settle_usage_correction(pending, decision)
                        .await
                        .map_err(unavailable)?;
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
                    self.keep_recovery_event(&next).await.map_err(unavailable)?;
                    self.resume_recovery_children(&next)
                        .await
                        .map_err(unavailable)?;
                    if let Some(pending) = pending.as_ref() {
                        self.remove_correction_owner(pending);
                        self.refresh_recovered_correction_targets(pending)
                            .await
                            .map_err(unavailable)?;
                    }
                }
                Ok(())
            }
            RecoveryState::Settled => self
                .resume_recovery_children(&event)
                .await
                .map_err(unavailable),
        }
    }

    async fn resume_quarantined_common_positives(
        &self,
        operation_id: [u8; 16],
    ) -> RecordStoreResult<()> {
        let pending = self.retained_correction(|pending| {
            pending.request.op_id.0 == operation_id && pending.quarantined
        });
        let Some(pending) = pending else {
            return Ok(());
        };
        let _running = self
            .hold_foreign_correction_recovery(operation_id)
            .map_err(unresolved)?;
        self.confirm_pending_recovery(operation_id).await?;
        let mut selected = self
            .recovery_event(operation_id)
            .ok_or_else(|| unresolved("quarantined common positive has no selected owner"))?;
        if selected.state != RecoveryState::LandedUnknown {
            return Ok(());
        }
        let mut custody = recovery::Custody::decode(&selected.payload)?;
        if custody.release_common_positives()? {
            let next = self
                .new_recovery_event(
                    selected.operation_id,
                    selected.kind,
                    selected.body_fingerprint,
                    selected.state,
                    selected.first_sent_at_ms,
                    custody.encode()?,
                )
                .map_err(unresolved)?;
            *pending
                .recovery_event
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = Some(next.clone());
            self.keep_recovery_event(&next).await?;
            selected = next;
        }
        self.resume_recovery_children(&selected).await
    }

    pub(in crate::governance) async fn resolve_correction_recovery(
        &self,
        cost: &crate::cost::CostModel,
        resolution: &RecoveryResolution,
    ) -> Result<(), RecoveryError> {
        resolution.validate_quiescence()?;
        self.validate_foreign_correction_verdict(resolution)?;
        let unavailable = |error: RecordStoreError| {
            crate::governance::rendered_error(RecoveryError::Unavailable, error)
        };
        self.confirm_pending_recovery(resolution.operation_id)
            .await
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
        let pending =
            self.retained_correction(|pending| pending.request.op_id.0 == resolution.operation_id);
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
        let _claim = self
            .correction_claims
            .claim_async(pending.request.key_id.clone())
            .await;
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
            self.keep_recovery_event(&event)
                .await
                .map_err(unavailable)?;
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
            .await
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
            .await
            .map_err(unavailable)?;
        if resolution.verdict == RecoveryVerdict::NotLanded
            && selected.state != RecoveryState::Settled
        {
            self.finish_unlanded_correction(cost, &pending, &selected)
                .await
                .map_err(unavailable)?;
        }
        self.remove_correction_owner(&pending);
        self.refresh_recovered_correction_targets(&pending)
            .await
            .map_err(unavailable)?;
        Ok(())
    }

    async fn keep_verdict_correction_cut(
        &self,
        pending: &PendingCorrection,
        previous: &RecoveryEvent,
        decision: Decision,
    ) -> RecordStoreResult<RecoveryEvent> {
        self.confirm_pending_recovery(previous.operation_id).await?;
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
            .map_err(unresolved)?;
        *pending
            .recovery_event
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(event.clone());
        self.keep_recovery_event(&event).await?;
        Ok(event)
    }

    async fn finish_unlanded_correction(
        &self,
        cost: &crate::cost::CostModel,
        pending: &PendingCorrection,
        parent: &RecoveryEvent,
    ) -> RecordStoreResult<()> {
        let custody = recovery::Custody::decode(&parent.payload)?;
        let already_applied = if let Some(id) = custody.repost_operation_id() {
            let child = self.correction_successor_receipt(parent, &custody).await?;
            debug_assert_eq!(child.operation_id, id);
            if child.state != RecoveryState::Settled {
                return Err(unresolved(
                    "conditional successor remains unresolved; resolve its own exact operation",
                ));
            }
            recovery::Custody::decode(&child.payload)?.intent_applied()
        } else {
            false
        };
        if !self.recovery_children_settled(parent).await? {
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
            let delta = ledger_off_path::ledger_adjust_nonzero_delta(&intent.delta);
            self.correct_usage_with_parent(
                cost,
                &adj,
                &delta,
                pending.request.day_start,
                Some(parent.operation_id),
                intent.action_id.as_deref(),
            )
            .await?
            .map_err(|refused| {
                unresolved(format_args!(
                    "fresh conditional correction refused: {refused:?}"
                ))
            })?;
        }
        self.confirm_pending_recovery(parent.operation_id).await?;
        let latest = self
            .recovery_event(parent.operation_id)
            .ok_or_else(|| unresolved("conditional parent disappeared"))?;
        let mut custody = recovery::Custody::decode(&latest.payload)?;
        let child = self.correction_successor_receipt(&latest, &custody).await?;
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
            .map_err(unresolved)?;
        *pending
            .recovery_event
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(event.clone());
        self.keep_recovery_event(&event).await?;
        self.resume_recovery_children(&event).await?;
        if !self.recovery_children_settled(&event).await? {
            return Err(unresolved(
                "revalidated correction has unconfirmed dependent negatives",
            ));
        }
        Ok(())
    }

    async fn correction_successor_receipt(
        &self,
        parent: &RecoveryEvent,
        custody: &recovery::Custody,
    ) -> RecordStoreResult<RecoveryEvent> {
        let descriptor = custody
            .repost_descriptor()
            .ok_or_else(|| unresolved("conditional parent has no exact successor descriptor"))?;
        if let Some(child) = self.recovery_event(descriptor.operation_id) {
            if child.kind != descriptor.kind
                || child.body_fingerprint != descriptor.body_fingerprint
                || child.first_sent_at_ms != descriptor.first_sent_at_ms
                || child
                    .origin_reference()
                    .map_err(unresolved)?
                    .is_none_or(|origin| origin.operation_id != parent.operation_id)
            {
                return Err(unresolved(
                    "conditional successor does not match parent authorization",
                ));
            }
            self.validate_recovery_origin(&child).await?;
            return Ok(child);
        }
        self.observed_child_receipt(parent, descriptor)
            .await?
            .ok_or_else(|| {
                unresolved(
                    "conditional successor requires explicit foreign adoption before further work",
                )
            })
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

    async fn refresh_recovered_correction_targets(
        &self,
        pending: &PendingCorrection,
    ) -> RecordStoreResult<()> {
        for (bucket, window) in &pending.targets {
            let (mut plain, mut dated) = self
                .core_store()?
                .ledger()
                .get_usage_pair(bucket, &era_bucket(bucket), *window)
                .await?;
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
            let (before, _, _) = capture_target(bucket, live, &plain, &dated, *window)?;
            cells.insert(bucket.clone(), before);
        }
        Ok(())
    }

    /// Stage an exact parent-owned handoff while the caller still owns the target shard.
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
            .retained_correction(|pending| pending.request.op_id == branch.op_id)
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
            .map_err(unresolved)?;
        *retained = Some(event.clone());
        Ok(event)
    }

    /// Transfer only common positive mutations out of the two conditional branches.
    pub(in crate::governance) fn take_correction_positives(
        cell: &mut BudgetCell,
        window: u64,
    ) -> RecordStoreResult<Option<(ExactUsageDelta, ExactUsageDelta)>> {
        recovery::take_positives(cell, window)
    }

    pub(in crate::governance::state) async fn settle_correction_for_delete_async(
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
            self.decide_usage_correction(&pending).await?;
            if self.recovery_enabled() {
                let selected = self
                    .recovery_event(pending.request.op_id.0)
                    .ok_or_else(|| unresolved("deletion has no confirmed correction custody"))?;
                self.resume_recovery_children(&selected).await?;
                if !self.recovery_children_settled(&selected).await? {
                    return Err(unresolved(
                        "deletion requires confirmed raw correction descendants",
                    ));
                }
            }
            self.corrections
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(key);
        }
        Ok(())
    }

    pub(super) async fn resume_usage_correction(
        &self,
        adj: &Adjustment<'_, Count>,
        action_id: Option<&str>,
    ) -> RecordStoreResult<bool> {
        let pending = self
            .corrections
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(adj.key_id)
            .cloned();
        let Some(pending) = pending else {
            return Ok(false);
        };
        let decision = self.decide_usage_correction(&pending).await?;
        self.corrections
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(adj.key_id);
        Ok(decision == Decision::Applied && pending.intent == Intent::of(adj, action_id))
    }

    async fn decide_usage_correction(
        &self,
        pending: &PendingCorrection,
    ) -> RecordStoreResult<Decision> {
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
        self.authorize_correction_parent(pending).await?;
        let settled = *pending.settled.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(decision) = settled {
            if decision == Decision::ConditionConflict && self.recovery_enabled() {
                let event = self
                    .recovery_event(pending.request.op_id.0)
                    .ok_or_else(|| unresolved("settled correction parent is missing"))?;
                self.resume_recovery_children(&event).await?;
                if !self.recovery_children_settled(&event).await? {
                    return Err(unresolved("raw predecessor counts are not yet recorded"));
                }
            }
            return Ok(decision);
        }
        if pending.quarantined {
            self.confirm_pending_recovery(pending.request.op_id.0)
                .await?;
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
                    .map_err(unresolved)?;
                *pending
                    .recovery_event
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = Some(event.clone());
                self.keep_recovery_event(&event).await?;
            }
            return Err(unresolved(
                "historical correction is quarantined pending an audited verdict and fresh revalidation",
            ));
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
                self.keep_correction_decision(pending, decision).await?;
            }
            self.settle_usage_correction(pending, decision).await?;
            return Ok(decision);
        }
        let current_state = pending
            .recovery_event
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|event| event.state);
        if current_state == Some(RecoveryState::LandedUnknown) {
            self.keep_correction_recovery(pending, RecoveryState::LandedUnknown)
                .await?;
            return Err(unresolved(
                "landed-unknown operation requires an audited verdict",
            ));
        }
        self.keep_correction_recovery(pending, RecoveryState::Intent)
            .await?;
        // A send from this process is resent with its exact operation, however old: its slot is
        // held until it settles, so the store replays the recorded verdict (STORE-TRANSACTIONS N8).
        if self.recovery_enabled() && !self.recovery_sent_here(pending.request.op_id.0) {
            self.keep_correction_recovery(pending, RecoveryState::LandedUnknown)
                .await?;
            return Err(unresolved(
                "receipt age is unknown after restart; landed-unknown operation requires an audited verdict",
            ));
        }

        let decision = match self
            .core_store()?
            .ledger()
            .apply_usage_correction(&pending.request)
            .await
        {
            Ok(decision) => decision,
            Err(error) => {
                self.keep_correction_recovery(pending, RecoveryState::Intent)
                    .await?;
                return Err(error);
            }
        };
        *pending.receipt.lock().unwrap_or_else(|p| p.into_inner()) = Some(decision);
        self.keep_correction_decision(pending, decision).await?;
        self.settle_usage_correction(pending, decision).await?;
        Ok(decision)
    }

    async fn keep_correction_decision(
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
        .await
    }

    async fn authorize_correction_parent(
        &self,
        pending: &PendingCorrection,
    ) -> RecordStoreResult<()> {
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
            self.validate_recovery_origin(&child).await?;
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
            self.keep_recovery_event(&parent).await?;
            parent
        } else {
            self.confirm_pending_recovery(parent_id).await?;
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
                .map_err(unresolved)?;
            *pending
                .authorization
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = Some(event.clone());
            self.keep_recovery_event(&event).await?;
            event
        };
        self.drive_recovery_children(&parent).await?;
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

    async fn keep_correction_recovery(
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
                self.keep_recovery_event(event).await?;
            }
            let payload = recovery::Custody::capture(self, pending)?.encode()?;
            let event = {
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
                    .map_err(unresolved)?;
                *retained = Some(event.clone());
                event
            };
            return self.keep_recovery_event(&event).await;
        }
    }

    /// Select a definitive raw branch only after the operation outcome is established.
    async fn settle_usage_correction(
        &self,
        pending: &PendingCorrection,
        decision: Decision,
    ) -> RecordStoreResult<()> {
        let terminal = if self.recovery_enabled() {
            Some(self.keep_correction_settlement(pending, decision).await?)
        } else {
            None
        };
        self.select_correction_cut(pending, decision, terminal.as_ref())?;
        if let Some(terminal) = terminal {
            self.drive_recovery_children(&terminal).await?;
            if decision == Decision::ConditionConflict {
                self.resume_recovery_children(&terminal).await?;
                if !self.recovery_children_settled(&terminal).await? {
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
        let cuts = ledger_off_path::ledger_correction_cuts_by_target(
            terminal
                .map(|event| recovery::Custody::decode(&event.payload)?.selected_cuts())
                .transpose()?
                .unwrap_or_default(),
        );
        let order = ledger_off_path::ledger_correction_shard_order(
            pending
                .targets
                .iter()
                .map(|(bucket, _)| self.budget.shard_index(bucket)),
        );
        let mut guards = ledger_off_path::ledger_correction_hold_shards(&order, |shard| {
            self.budget.shard_at(shard).write()
        });

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
        let mut selected = ledger_off_path::ledger_correction_staging(pending.targets.len());
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

    async fn keep_correction_settlement(
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
            self.keep_recovery_event(&previous).await?;
            if previous.state == RecoveryState::Settled {
                if !recovery::Custody::decode(&previous.payload)?.is_terminal() {
                    return Err(unresolved(
                        "settled correction still owns untransferred raw debt",
                    ));
                }
                return Ok(previous);
            }
            let custody = recovery::Custody::stage_settlement(self, pending, decision)?;
            let event = {
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
                    .map_err(unresolved)?;
                *retained = Some(event.clone());
                event
            };
            self.keep_recovery_event(&event).await?;
            return Ok(event);
        }
    }

    pub(in crate::governance::state) async fn retry_usage_corrections(&self) -> Vec<String> {
        let pending = ledger_off_path::ledger_corrections_snapshot(
            &*self.corrections.lock().unwrap_or_else(|p| p.into_inner()),
        );
        let mut errors = ledger_off_path::ledger_correction_staging(pending.len());
        for pending in pending {
            if pending.quarantined {
                if self
                    .recovery_event(pending.request.op_id.0)
                    .is_some_and(|event| event.state == RecoveryState::Intent)
                {
                    let result = self.decide_usage_correction(&pending).await;
                    if !self
                        .recovery_event(pending.request.op_id.0)
                        .is_some_and(|event| event.state == RecoveryState::LandedUnknown)
                    {
                        if let Err(error) = result {
                            errors.push(ledger_cold::ledger_correction_retry_failure(
                                &pending.request.key_id,
                                &error,
                            ));
                        }
                        continue;
                    }
                }
                if let Err(error) = self.confirm_pending_recovery(pending.request.op_id.0).await {
                    errors.push(ledger_cold::ledger_correction_retry_failure(
                        &pending.request.key_id,
                        &error,
                    ));
                }
                continue;
            }
            if pending.verdict_pending.load(Ordering::Acquire) {
                continue;
            }
            if let Err(error) = self.decide_usage_correction(&pending).await {
                errors.push(ledger_cold::ledger_correction_retry_failure(
                    &pending.request.key_id,
                    &error,
                ));
            }
        }
        errors
    }

    pub(super) async fn correct_usage(
        &self,
        cost: &crate::cost::CostModel,
        adj: &Adjustment<'_, Count>,
        delta: &BTreeMap<&str, Count>,
        day: u64,
        action_id: Option<&str>,
    ) -> RecordStoreResult<Result<(), AdjustRefused>> {
        self.correct_usage_with_parent(cost, adj, delta, day, None, action_id)
            .await
    }

    async fn correct_usage_with_parent(
        &self,
        cost: &crate::cost::CostModel,
        adj: &Adjustment<'_, Count>,
        delta: &BTreeMap<&str, Count>,
        day: u64,
        parent_operation_id: Option<[u8; 16]>,
        action_id: Option<&str>,
    ) -> RecordStoreResult<Result<(), AdjustRefused>> {
        if parent_operation_id.is_some() {
            if let Err(refused) = check_epoch(adj.card_epoch_ms, crate::store::now_ms()) {
                return Ok(Err(refused));
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
        // Only use this while building private candidate rows. Once raw-cell custody is
        // installed below, failures must retain the existing unknown/recovery semantics.
        macro_rules! prepare {
            ($result:expr) => {
                match $result {
                    Ok(value) => value,
                    Err(error) => {
                        return Ok(Err(AdjustRefused::Preparation {
                            reason: crate::governance::rendered_error(
                                std::convert::identity,
                                error,
                            ),
                        }));
                    }
                }
            };
        }
        loop {
            let Some(key) = prepare!(self.core_store()?.identity().get_key(adj.key_id).await)
            else {
                return Ok(Err(AdjustRefused::UnknownKey));
            };
            if key.deleted_at.is_some() {
                return Ok(Err(AdjustRefused::UnknownKey));
            }
            let mut owners: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
            let epoch = adj.card_epoch_ms / 1_000;
            let targets = match cost.chain_for(&key) {
                Ok(chain) => ledger_off_path::ledger_correction_targets(
                    chain
                        .iter()
                        .filter(|bucket| bucket.applies_to_pool(adj.pool))
                        .map(|bucket| {
                            (
                                bucket.bucket_id,
                                budget_window(bucket.window, epoch),
                                bucket.group_name,
                            )
                        }),
                    &mut owners,
                ),
                Err(_) => ledger_off_path::ledger_correction_targets(
                    std::iter::once((
                        adj.key_id,
                        budget_window(super::super::super::WINDOW_TOTAL, epoch),
                        None,
                    )),
                    &mut owners,
                ),
            };
            let mut snapshots = BTreeMap::new();
            for (bucket, window) in &targets {
                for name in [bucket.clone(), era_bucket(bucket)] {
                    let mut row =
                        prepare!(self.core_store()?.ledger().get_usage(&name, *window).await);
                    prepare!(correction::canonical_ledger(&mut row));
                    snapshots.insert(address(&name, *window), row);
                }
            }
            for bucket in [ADJUST_UP_BUCKET, ADJUST_DOWN_BUCKET] {
                let mut row = prepare!(self.core_store()?.ledger().get_usage(bucket, day).await);
                prepare!(correction::canonical_ledger(&mut row));
                snapshots.insert(address(bucket, day), row);
            }
            let mut metering = ledger_off_path::ledger_correction_key_metering(
                prepare!(self.core_store()?.ledger().list_metering(day).await),
                adj.key_id,
            );
            correction::canonical_metering(&mut metering);
            let metered_era = prepare!(unique_metered_era(adj, &metering));
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
            let order = ledger_off_path::ledger_correction_shard_order(
                targets
                    .iter()
                    .map(|(bucket, _)| self.budget.shard_index(bucket)),
            );
            let pending = {
                let mut guards = ledger_off_path::ledger_correction_hold_shards(&order, |shard| {
                    self.budget.shard_at(shard).write()
                });
                let mut replacements = ledger_off_path::ledger_correction_replacements(&snapshots);
                let mut branches = ledger_off_path::ledger_correction_staging(targets.len());
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
                        prepare!(capture_target(bucket, live, plain, dated, *window));
                    if let Some(names) = owners.get(bucket) {
                        before.group_owners.extend(names.iter().cloned());
                    }
                    let target = prepare!(durable_cell(
                        bucket,
                        plain_after.clone(),
                        dated_after.clone(),
                        *window
                    ));
                    let segment = if metered_era.entry_id.is_some() {
                        target
                            .models
                            .iter()
                            .position(|m| &*m.model == adj.model && m.era == metered_era)
                    } else {
                        segment_at(&target.models, adj.model, adj.card_epoch_ms)
                    };
                    if segment.is_none() && delta.values().any(|count| *count < Count::ZERO) {
                        let (class, _) = delta
                            .iter()
                            .find(|(_, count)| **count < Count::ZERO)
                            .expect("negative delta");
                        return Ok(Err(ledger_cold::ledger_correction_unplaced(
                            bucket, *window, class,
                        )));
                    }
                    let era = segment.map_or(metered_era, |index| target.models[index].era);
                    for (class, change) in delta {
                        let held = segment.map_or(Count::ZERO, |index| {
                            target.models[index]
                                .cur
                                .get(*class)
                                .copied()
                                .unwrap_or_default()
                        });
                        if moved(held, *change).is_none() {
                            return Ok(Err(AdjustRefused::Exceeds {
                                bucket: bucket.clone(),
                                class: (*class).into(),
                                count: held,
                                delta: *change,
                            }));
                        }
                        prepare!(move_unit(
                            &mut plain_after,
                            adj.model,
                            class,
                            change.micros(),
                        ));
                        if era != RawRateEra::legacy(0) {
                            prepare!(move_unit(
                                &mut dated_after,
                                &era_model(era, adj.model),
                                class,
                                change.micros(),
                            ));
                        }
                    }
                    let mut accepted = if before.window_start == *window {
                        let mut accepted = prepare!(durable_cell(
                            bucket,
                            plain_after.clone(),
                            dated_after.clone(),
                            *window
                        ));
                        copy_custody(&before, &mut accepted);
                        accepted
                    } else {
                        let mut accepted = before.clone();
                        ledger_off_path::ledger_correction_release_window(
                            &mut accepted.rolled,
                            *window,
                        );
                        ledger_off_path::ledger_correction_release_window(
                            &mut accepted.rolled_eras,
                            *window,
                        );
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
                    let bucket = if *change > Count::ZERO {
                        ADJUST_UP_BUCKET
                    } else {
                        ADJUST_DOWN_BUCKET
                    };
                    prepare!(move_unit(
                        replacements
                            .get_mut(&address(bucket, day))
                            .expect("adjustment row read"),
                        &slot,
                        class,
                        prepare!(change
                            .micros()
                            .checked_abs()
                            .ok_or("adjustment magnitude overflow")),
                    ));
                }
                let request = Request {
                    version: correction::VERSION,
                    op_id: crate::door::op_id(),
                    key_id: adj.key_id.into(),
                    day_start: day,
                    metering,
                    usage: prepare!(ledger_off_path::ledger_correction_usage_changes(
                        snapshots,
                        &mut replacements
                    )),
                };
                prepare!(request.encode());
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
                let sent_at = ledger_off_path::ledger_correction_sent_clock();
                let pending = PendingCorrection {
                    request,
                    intent: Intent::of(adj, action_id),
                    targets,
                    sent_at,
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
                pending
            };
            let decision = self.decide_usage_correction(&pending).await?;
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

fn unique_metered_era(
    adj: &Adjustment<'_, Count>,
    rows: &[MeteringRow],
) -> RecordStoreResult<RawRateEra> {
    let mut captured = None;
    for row in rows.iter().filter(|row| {
        row.priced_from_ms == adj.entry_era && metering_lane(&row.model, &row.provider) == adj.model
    }) {
        let id = match EntryId::parse_metering_version(&row.pricing_version) {
            Some(Some(id)) => Some(id),
            Some(None) => {
                return Err(RecordStoreError(
                    "malformed versioned metering provenance".into(),
                ));
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
    adj: &Adjustment<'_, Count>,
    delta: &BTreeMap<&str, Count>,
    day: u64,
    metering: &[MeteringRow],
    up: &UsageLedger,
    down: &UsageLedger,
    era: RawRateEra,
) -> Result<(), AdjustRefused> {
    let in_lane = |row: &MeteringRow| metering_lane(&row.model, &row.provider) == adj.model;
    if let Some(in_force) = metering
        .iter()
        .filter(|row| in_lane(row))
        .map(|row| row.priced_from_ms)
        .filter(|era| *era > adj.entry_era && *era <= adj.card_epoch_ms)
        .max()
    {
        return Err(AdjustRefused::NotInForce {
            named: adj.entry_era,
            in_force,
        });
    }
    // The lane's rows dated with the named entry, read lazily from the day's metering.
    let dated = |row: &MeteringRow| {
        in_lane(row)
            && row.priced_from_ms == adj.entry_era
            && adj.entry_id.is_none_or(|id| {
                EntryId::parse_metering_version(&row.pricing_version) == Some(Some(id))
            })
    };
    if !metering.iter().any(&dated) {
        return Err(AdjustRefused::NotMetered { day });
    }
    let slot = adjustment_slot(adj.key_id, adj.model, era);
    for (class, change) in delta {
        let adjusted = |ledger: &UsageLedger| -> Option<Count> {
            match ledger.models.iter().find(|row| row.model == slot) {
                Some(row) => {
                    Count::from_stored(row.usage_units.get(*class).copied().unwrap_or(0), row.scale)
                        .ok()
                }
                None => Some(Count::ZERO),
            }
        };
        let count = metering
            .iter()
            .filter(|row| dated(row))
            .try_fold(Count::ZERO, |n, row| {
                n.checked_add(metered_count(row, class).ok()?).ok()
            })
            .and_then(|n| n.checked_add(adjusted(up)?).ok())
            .and_then(|n| n.checked_sub(adjusted(down)?).ok());
        let Some(count) = count else {
            return Err(ledger_cold::ledger_correction_metering_exceeds(
                day,
                class,
                Count::ZERO,
                *change,
            ));
        };
        if moved(count, *change).is_none() {
            return Err(ledger_cold::ledger_correction_metering_exceeds(
                day, class, count, *change,
            ));
        }
    }
    Ok(())
}

fn copy_custody(from: &BudgetCell, to: &mut BudgetCell) {
    to.group_owners.clone_from(&from.group_owners);
    to.flushing = from.flushing;
    to.flushing_windows.clone_from(&from.flushing_windows);
    to.rolled.clone_from(&from.rolled);
    to.rolled_eras.clone_from(&from.rolled_eras);
    to.last_touch = from.last_touch;
}
fn has_debt(cell: &BudgetCell) -> bool {
    !ExactUsageDelta::of(cell, false).is_zero()
        || !ExactUsageDelta::of(cell, true).is_zero()
        || !cell.rolled.is_empty()
        || !cell.rolled_eras.is_empty()
}

fn capture_target(
    bucket: &str,
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
        let (fees, flushed) = (local.fee_eras.dated(), local.flushed_fee_eras.dated());
        for era in eras_ascending(eras_of(fees), eras_of(flushed)) {
            let difference = i128::from(fee_count(fees, era)) - i128::from(fee_count(flushed, era));
            exact(move_unit(
                &mut combined_dated,
                &era_tag(era),
                ERA_FEE_UNIT,
                difference * 1_000_000,
            ))?;
        }
        let baseline = durable_cell(bucket, plain.clone(), dated.clone(), window)?;
        let mut before = durable_cell(bucket, combined.clone(), combined_dated.clone(), window)?;
        copy_custody(&local, &mut before);
        before.flushed_requests = baseline.requests;
        before.flushed_billable_requests = baseline.billable_requests;
        before.flushed_fee_eras = baseline.fee_eras;
        for model in &mut before.models {
            let base = baseline
                .models
                .iter()
                .find(|base| base.model == model.model && base.era == model.era);
            match base {
                Some(base) => model.flushed.clone_from(&base.cur),
                None => model.flushed.clear(),
            }
            model.flushed_era = model.flushed.clone();
        }

        for base in baseline.models {
            if !before
                .models
                .iter()
                .any(|model| model.model == base.model && model.era == base.era)
            {
                let (flushed, flushed_era) =
                    ledger_off_path::ledger_correction_baselines(&base.cur);
                before.models.extend(ModelCell::new(
                    base.model,
                    base.era,
                    BTreeMap::new(),
                    flushed,
                    flushed_era,
                ));
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
    u64::try_from(
        i128::from(count)
            .checked_add(change)
            .ok_or("raw usage correction count overflow")?,
    )
    .map_err(|_| "raw usage correction count out of range")
}

/// The eras a fee split names, as recorded.
fn eras_of(split: &[(RawRateEra, u64)]) -> impl Iterator<Item = RawRateEra> + Clone + '_ {
    split.iter().map(|(era, _)| *era)
}

/// The count a fee split holds for `era`, zero when it names no such era. A split names a few
/// eras in the order each was first charged, so it is read where it lies; were an era ever named
/// twice its later count stands, as it did when the split was folded into a map.
fn fee_count(split: &[(RawRateEra, u64)], era: RawRateEra) -> u64 {
    split
        .iter()
        .rev()
        .find(|(at, _)| *at == era)
        .map_or(0, |(_, count)| *count)
}

/// The requests a fee split's eras hold in all, each era counted once.
fn fee_total(split: &[(RawRateEra, u64)]) -> i128 {
    eras_ascending(eras_of(split), std::iter::empty())
        .map(|era| i128::from(fee_count(split, era)))
        .sum()
}

/// Every era `a` or `b` names, ascending and each once. Both name a few eras in no order, so the
/// next era is the least one after the last given: neither is sorted and neither is copied.
fn eras_ascending<A, B>(a: A, b: B) -> impl Iterator<Item = RawRateEra>
where
    A: Iterator<Item = RawRateEra> + Clone,
    B: Iterator<Item = RawRateEra> + Clone,
{
    let mut last: Option<RawRateEra> = None;
    std::iter::from_fn(move || {
        let next = a
            .clone()
            .chain(b.clone())
            .filter(|era| last.is_none_or(|after| *era > after))
            .min()?;
        last = Some(next);
        Some(next)
    })
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
    current: &BTreeMap<String, Count>,
    flushed: &BTreeMap<String, Count>,
) -> Result<(), &'static str> {
    for unit in crate::governance::sorted_union(current.keys(), flushed.keys()) {
        move_unit(
            row,
            model,
            unit,
            current
                .get(unit)
                .copied()
                .unwrap_or_default()
                .checked_sub(flushed.get(unit).copied().unwrap_or_default())
                .map_err(|_| "count difference overflow")?
                .micros(),
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
    // Normalize the entire touched model once; every unit in a row shares its scale.
    if let Some(position) = position {
        let model = &mut row.models[position];
        let normalized =
            ledger_off_path::ledger_correction_normalized_units(&model.usage_units, model.scale)?;
        model.usage_units = normalized;
        model.scale = COUNT_SCALE;
    }
    let count = position
        .and_then(|i| row.models[i].usage_units.get(unit))
        .copied()
        .unwrap_or(0);
    let next = count
        .checked_add(change)
        .ok_or("raw usage correction count overflow")?;
    if next < 0 {
        return Err("raw usage correction count out of range");
    }
    if let Some(position) = position {
        if next == 0 {
            row.models[position].usage_units.remove(unit);
        } else {
            row.models[position].usage_units.insert(unit.into(), next);
        }
    } else if next != 0 {
        row.models.push(ModelTokens {
            model: model.into(),
            scale: COUNT_SCALE,
            usage_units: ledger_off_path::ledger_correction_unit_map(unit, next),
        });
    }
    Ok(())
}
fn apply_delta(row: &mut UsageLedger, delta: &ExactUsageDelta) -> Result<(), &'static str> {
    // An overflow in a later model must not leave earlier raw counts acknowledged.
    let mut candidate = row.clone();
    candidate.requests = checked_move(candidate.requests, delta.requests)?;
    candidate.billable_requests =
        checked_move(candidate.billable_requests, delta.billable_requests)?;
    for model in &delta.models {
        for (unit, count) in &model.usage_units {
            move_unit(&mut candidate, &model.model, unit, *count)?;
        }
    }
    *row = candidate;
    Ok(())
}

#[cfg(test)]
#[path = "tests/ledger_correction_tests.rs"]
mod async_correction_boundaries;
