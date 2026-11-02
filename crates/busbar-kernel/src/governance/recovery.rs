// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryKind {
    Usage,
    Metering,
    Correction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryState {
    Intent,
    Applied,
    ConditionConflict,
    LandedUnknown,
    VerdictLanded,
    VerdictNotLanded,
    Settled,
}

/// An immutable, versioned custody transition. The payload contains raw operation
/// and dependency facts, never a derived price or credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryEvent {
    pub operation_id: [u8; 16],
    pub revision: u64,
    pub previous_event: Option<[u8; 32]>,
    pub kind: RecoveryKind,
    pub body_fingerprint: [u8; 32],
    pub state: RecoveryState,
    pub first_sent_at_ms: Option<u64>,
    pub payload: Vec<u8>,
}

/// Per-opened-Store persistence. A repeated operation/revision must name exactly
/// the same event; success confirms its full immutable identity in the Store.
pub trait RecoverySink: Send + Sync {
    fn persist(&self, event: &RecoveryEvent) -> Result<(), RecoveryError>;
    fn replay(&self) -> Result<Vec<RecoveryEvent>, RecoveryError>;

    /// Return one bounded summary per operation only AFTER verifying its complete
    /// current selected ancestry, including genesis, identities, legal states,
    /// predecessor fingerprints and every revision. Endpoint equality is not proof.
    fn replay_selections(&self) -> Result<Vec<RecoverySelection>, RecoveryError> {
        summarize_recovery_chains(self.replay()?)
    }

    /// Confirm exact membership in the CURRENT selected predecessor chain. An
    /// immutable journal candidate by itself never establishes this authority.
    fn verify_checkpoint(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        let events = self.replay()?;
        let present = events.iter().any(|selected| selected == event);
        summarize_recovery_chains(events)?;
        if present {
            Ok(())
        } else {
            Err(RecoveryError::Conflict(
                "recovery checkpoint is not in current selected ancestry".into(),
            ))
        }
    }

    /// Adopt through the same full ancestry proof, retaining only its verified
    /// initial and selected events at the caller. Production adapters stream it.
    fn adopt_verdict_selection(
        &self,
        resolution: &RecoveryResolution,
        transitions: &[RecoveryEvent],
    ) -> Result<RecoverySelection, RecoveryError> {
        let mut selections =
            summarize_recovery_chains(self.adopt_verdict(resolution, transitions)?)?;
        if selections.len() != 1 {
            return Err(RecoveryError::Invalid(
                "adoption must select exactly one operation".into(),
            ));
        }
        let selection = selections.pop().expect("one verified operation");
        if selection.selected.operation_id != resolution.operation_id {
            return Err(RecoveryError::Invalid(
                "adoption selected another operation".into(),
            ));
        }
        Ok(selection)
    }

    /// Foreign custody is visible without granting this process any write or send authority.
    fn inspect_foreign(&self) -> Result<Vec<RecoveryInspection>, RecoveryError> {
        Ok(Vec::new())
    }

    /// Verify a child's immutable origin against the parent's currently selected
    /// predecessor chain without granting ownership of that parent.
    fn verify_origin(&self, _event: &RecoveryEvent) -> Result<(), RecoveryError> {
        Err(RecoveryError::Unavailable(
            "recovery Store cannot verify external child origin".into(),
        ))
    }

    /// Select a fully journaled, audited ownership handover in one exact head CAS.
    /// The returned selected predecessor chain is the only authority to resume effects.
    fn adopt_verdict(
        &self,
        _resolution: &RecoveryResolution,
        _transitions: &[RecoveryEvent],
    ) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        Err(RecoveryError::Unavailable(
            "recovery Store does not support audited foreign custody adoption".into(),
        ))
    }
}

/// A summary issued only after the sink has verified the full CURRENT selected
/// predecessor chain. Keeping its endpoints does not replace that Store proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverySelection {
    pub initial: RecoveryEvent,
    pub selected: RecoveryEvent,
}

impl RecoverySelection {
    fn validate_identity(&self) -> Result<(), RecoveryError> {
        self.initial.follows(None)?;
        if self.initial.operation_id != self.selected.operation_id
            || self.initial.kind != self.selected.kind
            || self.initial.body_fingerprint != self.selected.body_fingerprint
            || self.initial.first_sent_at_ms != self.selected.first_sent_at_ms
            || (self.selected.revision == 0 && self.selected != self.initial)
            || (self.selected.revision > 0 && self.selected.previous_event.is_none())
        {
            return Err(RecoveryError::Invalid(
                "verified recovery selection has inconsistent endpoint identity".into(),
            ));
        }
        Ok(())
    }
}

fn summarize_recovery_chains(
    events: Vec<RecoveryEvent>,
) -> Result<Vec<RecoverySelection>, RecoveryError> {
    let mut selections = std::collections::BTreeMap::<[u8; 16], RecoverySelection>::new();
    for event in events {
        if let Some(selection) = selections.get_mut(&event.operation_id) {
            event.follows(Some(&selection.selected))?;
            selection.selected = event;
        } else {
            event.follows(None)?;
            selections.insert(
                event.operation_id,
                RecoverySelection {
                    initial: event.clone(),
                    selected: event,
                },
            );
        }
    }
    Ok(selections.into_values().collect())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryInspection {
    pub owner_node: u64,
    pub event: RecoveryEvent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryVerdict {
    Landed,
    NotLanded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryResolution {
    pub operation_id: [u8; 16],
    pub body_fingerprint: [u8; 32],
    pub expected_revision: u64,
    pub verdict: RecoveryVerdict,
    /// The operator attests that every sender of this operation is retired or disarmed.
    pub sender_quiesced: bool,
    /// The operator attests that every outstanding backend mutation for this operation settled.
    pub backend_quiesced: bool,
    pub actor: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryItem {
    /// Present for a readonly foreign inspection; local ownership remains in the Store adapter.
    pub owner_node: Option<u64>,
    pub operation_id: [u8; 16],
    pub body_fingerprint: [u8; 32],
    pub revision: u64,
    pub kind: RecoveryKind,
    pub state: RecoveryState,
    pub first_sent_at_ms: Option<u64>,
    pub can_resolve: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryError {
    Unavailable(String),
    Conflict(String),
    Invalid(String),
}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(reason) | Self::Conflict(reason) | Self::Invalid(reason) => {
                reason.fmt(f)
            }
        }
    }
}

impl std::error::Error for RecoveryError {}

impl RecoveryResolution {
    pub(super) fn validate_quiescence(&self) -> Result<(), RecoveryError> {
        if !self.sender_quiesced || !self.backend_quiesced {
            return Err(RecoveryError::Invalid(
                "recovery verdict requires explicit sender and backend quiescence attestations"
                    .into(),
            ));
        }
        Ok(())
    }
}

impl RecoveryEvent {
    pub fn fingerprint(&self) -> Result<[u8; 32], RecoveryError> {
        use sha2::Digest;
        let encoded = serde_json::to_vec(self)
            .map_err(|error| RecoveryError::Invalid(format!("invalid recovery event: {error}")))?;
        let mut digest = sha2::Sha256::new();
        digest.update(b"busbar.usage-recovery.event.v1\0");
        digest.update(&encoded);
        Ok(digest.finalize().into())
    }

    pub(super) fn checkpoint(
        &self,
        state: RecoveryState,
        payload: Vec<u8>,
    ) -> Result<Self, RecoveryError> {
        let next = Self {
            revision: self
                .revision
                .checked_add(1)
                .ok_or_else(|| RecoveryError::Invalid("recovery revision exhausted".into()))?,
            previous_event: Some(self.fingerprint()?),
            state,
            payload,
            ..self.clone()
        };
        next.follows(Some(self))?;
        Ok(next)
    }

    pub fn follows(&self, previous: Option<&Self>) -> Result<(), RecoveryError> {
        RecoveryLink::from_event(self).follows(previous)
    }
}

/// Metadata from an actually decoded and verified event, retained while a cold
/// ancestry scan releases historical payloads. It is never an application event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryLink {
    pub operation_id: [u8; 16],
    pub revision: u64,
    pub previous_event: Option<[u8; 32]>,
    pub kind: RecoveryKind,
    pub body_fingerprint: [u8; 32],
    pub state: RecoveryState,
    pub first_sent_at_ms: Option<u64>,
}

impl RecoveryLink {
    pub fn from_event(event: &RecoveryEvent) -> Self {
        Self {
            operation_id: event.operation_id,
            revision: event.revision,
            previous_event: event.previous_event,
            kind: event.kind,
            body_fingerprint: event.body_fingerprint,
            state: event.state,
            first_sent_at_ms: event.first_sent_at_ms,
        }
    }

    pub fn follows(&self, previous: Option<&RecoveryEvent>) -> Result<(), RecoveryError> {
        let invalid = || RecoveryError::Invalid("invalid recovery transition chain".into());
        let Some(previous) = previous else {
            return if self.revision == 0
                && self.previous_event.is_none()
                && self.state == RecoveryState::Intent
            {
                Ok(())
            } else {
                Err(invalid())
            };
        };
        if self.operation_id != previous.operation_id
            || self.kind != previous.kind
            || self.body_fingerprint != previous.body_fingerprint
            || self.first_sent_at_ms != previous.first_sent_at_ms
            || previous.revision.checked_add(1) != Some(self.revision)
            || self.previous_event != Some(previous.fingerprint()?)
        {
            return Err(invalid());
        }
        use RecoveryState::*;
        match (previous.state, self.state) {
            (Intent, Intent | Applied | ConditionConflict | LandedUnknown)
            | (
                LandedUnknown,
                LandedUnknown | Applied | ConditionConflict | VerdictLanded | VerdictNotLanded,
            )
            | (Applied, Applied | Settled)
            | (ConditionConflict, ConditionConflict | Settled)
            | (VerdictLanded, VerdictLanded | Settled)
            | (VerdictNotLanded, VerdictNotLanded | Settled) => Ok(()),
            _ => Err(invalid()),
        }
    }
}

/// In-memory selection mirrors the Store's selected predecessor chains. A pending
/// candidate is retained even when persistence returns an ambiguous error.
#[derive(Default)]
pub(super) struct RecoveryBook {
    sink: std::sync::OnceLock<std::sync::Arc<dyn RecoverySink>>,
    entries: std::sync::Mutex<std::collections::BTreeMap<[u8; 16], RecoveryEntry>>,
    attaching: super::BudgetFlushRunner,
    selection_epoch: std::sync::atomic::AtomicU64,
}

#[derive(Default)]
struct RecoveryEntry {
    initial: Option<RecoveryEvent>,
    selected: Option<RecoveryEvent>,
    ever_quarantined: bool,
    pending: Option<RecoveryEvent>,
    runner: std::sync::Arc<super::BudgetFlushRunner>,
    resolution_runner: std::sync::Arc<super::BudgetFlushRunner>,
    driver: std::sync::Arc<super::BudgetFlushRunner>,
    sent_clock: Option<std::time::Instant>,
    adoption: Option<RecoveryAdoption>,
}

#[derive(Clone)]
struct RecoveryAdoption {
    inspection: RecoveryInspection,
    resolution: RecoveryResolution,
    transitions: Vec<RecoveryEvent>,
    imported: bool,
}

impl RecoveryBook {
    pub(super) fn attached(&self) -> bool {
        self.sink.get().is_some()
    }

    fn selected(&self, operation_id: [u8; 16]) -> Option<RecoveryEvent> {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&operation_id)
            .and_then(|entry| entry.selected.clone())
    }

    fn replay(&self, sink: std::sync::Arc<dyn RecoverySink>) -> Result<(), RecoveryError> {
        let _attaching = self
            .attaching
            .enter(false)
            .map_err(|reason| RecoveryError::Conflict(reason.into()))?;
        if self.attached() {
            return Err(RecoveryError::Conflict(
                "recovery sink already attached".into(),
            ));
        }
        // This production-used sink method proves every legal predecessor in
        // the CURRENT selected chain before issuing each bounded summary.
        let selections = sink.replay_selections()?;
        let mut replayed = std::collections::BTreeMap::<[u8; 16], RecoveryEntry>::new();
        for selection in selections {
            selection.validate_identity()?;
            let operation_id = selection.selected.operation_id;
            let ever_quarantined = selection.selected.revision > 2
                || matches!(
                    selection.selected.state,
                    RecoveryState::LandedUnknown
                        | RecoveryState::VerdictLanded
                        | RecoveryState::VerdictNotLanded
                );
            if replayed
                .insert(
                    operation_id,
                    RecoveryEntry {
                        initial: Some(selection.initial),
                        selected: Some(selection.selected),
                        ever_quarantined,
                        ..Default::default()
                    },
                )
                .is_some()
            {
                return Err(RecoveryError::Invalid(
                    "recovery summaries repeat an operation".into(),
                ));
            }
        }
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        if !entries.is_empty() {
            return Err(RecoveryError::Conflict(
                "recovery sink must attach before operations are admitted".into(),
            ));
        }
        self.sink
            .set(sink)
            .map_err(|_| RecoveryError::Conflict("recovery sink already attached".into()))?;
        *entries = replayed;
        self.selection_epoch
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    fn stage(
        &self,
        operation_id: [u8; 16],
        kind: RecoveryKind,
        body_fingerprint: [u8; 32],
        state: RecoveryState,
        first_sent_at_ms: Option<u64>,
        payload: Vec<u8>,
    ) -> Result<RecoveryEvent, RecoveryError> {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let entry = entries.entry(operation_id).or_default();
        let event = RecoveryEvent {
            operation_id,
            revision: match entry.selected.as_ref() {
                Some(previous) => previous
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| RecoveryError::Invalid("recovery revision exhausted".into()))?,
                None => 0,
            },
            previous_event: entry
                .selected
                .as_ref()
                .map(RecoveryEvent::fingerprint)
                .transpose()?,
            kind,
            body_fingerprint,
            state,
            first_sent_at_ms,
            payload,
        };
        event.follows(entry.selected.as_ref())?;
        if event.revision == 0 && event.first_sent_at_ms.is_some() && entry.sent_clock.is_none() {
            entry.sent_clock = Some(std::time::Instant::now());
        }
        if let Some(pending) = &entry.pending {
            if pending != &event {
                return Err(RecoveryError::Conflict(
                    "an immutable recovery candidate still awaits selection".into(),
                ));
            }
        } else {
            entry.pending = Some(event.clone());
        }
        Ok(event)
    }

    fn keep(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        let sink = self
            .sink
            .get()
            .ok_or_else(|| RecoveryError::Unavailable("recovery Store is not attached".into()))?;
        let runner = {
            let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
            let entry = entries.entry(event.operation_id).or_default();
            if entry.selected.as_ref() != Some(event) {
                event.follows(entry.selected.as_ref())?;
                if let Some(pending) = &entry.pending {
                    if pending != event {
                        return Err(RecoveryError::Conflict(
                            "a different immutable recovery candidate awaits selection".into(),
                        ));
                    }
                } else {
                    entry.pending = Some(event.clone());
                }
            }
            entry.runner.clone()
        };
        let _running = runner
            .enter(false)
            .map_err(|reason| RecoveryError::Conflict(reason.into()))?;
        // No Book or budget mutex is held during Store I/O. The runner marker
        // prevents concurrent drivers, including reentrant Store callbacks.
        sink.persist(event)?;
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let entry = entries
            .get_mut(&event.operation_id)
            .expect("candidate retained");
        if entry.selected.as_ref() == Some(event) {
            return Ok(());
        }
        if entry.pending.as_ref() != Some(event) {
            return Err(RecoveryError::Conflict(
                "recovery candidate changed during persistence".into(),
            ));
        }
        event.follows(entry.selected.as_ref())?;
        if entry.initial.is_none() {
            entry.initial = Some(event.clone());
        }
        entry.ever_quarantined |= matches!(
            event.state,
            RecoveryState::LandedUnknown
                | RecoveryState::VerdictLanded
                | RecoveryState::VerdictNotLanded
        );
        entry.selected = entry.pending.take();
        self.selection_epoch
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        Ok(())
    }
}

impl RecoveryItem {
    fn from_event(event: &RecoveryEvent) -> Self {
        Self {
            owner_node: None,
            operation_id: event.operation_id,
            body_fingerprint: event.body_fingerprint,
            revision: event.revision,
            kind: event.kind,
            state: event.state,
            first_sent_at_ms: event.first_sent_at_ms,
            can_resolve: event.state == RecoveryState::LandedUnknown,
        }
    }
}

/// A borrowed administrative view; every mutation is driven by the owning GovState.
pub struct RecoveryAdmin<'a> {
    governance: &'a super::GovState,
}

impl RecoveryAdmin<'_> {
    pub fn resolve(
        &self,
        cost: &crate::cost::CostModel,
        resolution: RecoveryResolution,
    ) -> Result<RecoveryItem, RecoveryError> {
        resolution.validate_quiescence()?;
        if resolution.actor.trim().is_empty()
            || resolution.actor.len() > 256
            || resolution.reason.trim().is_empty()
            || resolution.reason.len() > 4096
        {
            return Err(RecoveryError::Invalid(
                "recovery verdict requires an actor and reason".into(),
            ));
        }
        let governance = self.governance;
        if !governance.recovery_book.attached() {
            return Err(RecoveryError::Unavailable(
                "recovery Store is not attached".into(),
            ));
        }
        let runner = governance
            .recovery_book
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(resolution.operation_id)
            .or_default()
            .resolution_runner
            .clone();
        let _running = runner
            .enter(false)
            .map_err(|reason| RecoveryError::Conflict(reason.into()))?;
        let cached = governance
            .recovery_book
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&resolution.operation_id)
            .and_then(|entry| entry.adoption.clone());
        if let Some(cached) = cached
            .as_ref()
            .filter(|cached| cached.resolution == resolution)
        {
            if cached.imported {
                let current = governance
                    .recovery_event(resolution.operation_id)
                    .ok_or_else(|| {
                        RecoveryError::Unavailable("adopted recovery selection disappeared".into())
                    })?;
                governance
                    .keep_recovery_event(&current)
                    .map_err(|error| RecoveryError::Unavailable(error.to_string()))?;
                return self.resume_adopted(cost, resolution.operation_id);
            }
            return self.adopt_foreign(cost, resolution, cached.clone());
        }
        if cached.as_ref().is_some_and(|cached| !cached.imported) {
            return Err(RecoveryError::Conflict(
                "an immutable foreign adoption still awaits confirmation".into(),
            ));
        }
        let inspections = governance.inspect_foreign_recovery()?;
        if let Some(inspection) = inspections
            .into_iter()
            .find(|inspection| inspection.event.operation_id == resolution.operation_id)
        {
            let event = &inspection.event;
            if event.body_fingerprint != resolution.body_fingerprint
                || event.revision != resolution.expected_revision
            {
                return Err(RecoveryError::Conflict(
                    "foreign recovery identity or revision differs".into(),
                ));
            }
            if event.state == RecoveryState::Settled {
                let mut item = RecoveryItem::from_event(event);
                item.owner_node = Some(inspection.owner_node);
                item.can_resolve = false;
                return Ok(item);
            }
            let transitions = match event.kind {
                RecoveryKind::Correction => {
                    super::GovState::stage_foreign_correction_verdict(event, &resolution)?
                }
                RecoveryKind::Usage | RecoveryKind::Metering => {
                    super::GovState::stage_foreign_raw_verdict(event, &resolution)?
                }
            };
            if transitions.is_empty() || transitions.len() > 2 {
                return Err(RecoveryError::Invalid(
                    "adoption must contain one or two immutable transitions".into(),
                ));
            }
            let adoption = RecoveryAdoption {
                inspection,
                resolution: resolution.clone(),
                transitions,
                imported: false,
            };
            governance
                .recovery_book
                .entries
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .entry(resolution.operation_id)
                .or_default()
                .adoption = Some(adoption.clone());
            return self.adopt_foreign(cost, resolution, adoption);
        }
        let selected = governance
            .recovery_event(resolution.operation_id)
            .ok_or_else(|| RecoveryError::Invalid("recovery operation is not selected".into()))?;
        if selected.body_fingerprint != resolution.body_fingerprint {
            return Err(RecoveryError::Conflict(
                "recovery operation fingerprint differs".into(),
            ));
        }
        if selected.state == RecoveryState::LandedUnknown
            && selected.revision != resolution.expected_revision
        {
            return Err(RecoveryError::Conflict(
                "recovery operation revision differs".into(),
            ));
        }
        match selected.kind {
            RecoveryKind::Correction => {
                governance.resolve_correction_recovery(cost, &resolution)?
            }
            RecoveryKind::Usage | RecoveryKind::Metering => {
                governance.resolve_raw_recovery(&resolution)?
            }
        }
        let event = governance
            .recovery_event(resolution.operation_id)
            .ok_or_else(|| RecoveryError::Unavailable("recovery selection disappeared".into()))?;
        Ok(RecoveryItem::from_event(&event))
    }

    fn adopt_foreign(
        &self,
        cost: &crate::cost::CostModel,
        resolution: RecoveryResolution,
        adoption: RecoveryAdoption,
    ) -> Result<RecoveryItem, RecoveryError> {
        let governance = self.governance;
        let driver = governance
            .recovery_driver(resolution.operation_id)
            .map_err(|error| RecoveryError::Unavailable(error.to_string()))?;
        let running = driver
            .enter(false)
            .map_err(|reason| RecoveryError::Conflict(reason.into()))?;
        let correction_guard = if adoption.inspection.event.kind == RecoveryKind::Correction {
            governance.hold_foreign_correction_recovery(resolution.operation_id)?
        } else {
            None
        };
        let known = governance
            .validate_foreign_known_outcome(&resolution, adoption.inspection.event.kind)
            .and_then(|_| {
                if adoption.inspection.event.kind == RecoveryKind::Correction {
                    governance.validate_foreign_correction_verdict(&resolution)
                } else {
                    Ok(())
                }
            });
        if let Err(error) = known {
            governance.clear_unselected_adoption(&resolution);
            return Err(error);
        }
        let sink =
            governance.recovery_book.sink.get().ok_or_else(|| {
                RecoveryError::Unavailable("recovery Store is not attached".into())
            })?;
        let selection = match sink.adopt_verdict_selection(&resolution, &adoption.transitions) {
            Ok(selection) => selection,
            Err(error) => {
                // Conflict is a definitive refusal of this exact prior head;
                // an ambiguous Store error retains the immutable candidate.
                if matches!(error, RecoveryError::Conflict(_)) {
                    governance.clear_unselected_adoption(&resolution);
                }
                return Err(error);
            }
        };
        governance.import_adopted_recovery(&adoption, selection)?;
        let selected = governance
            .recovery_event(resolution.operation_id)
            .ok_or_else(|| {
                RecoveryError::Unavailable("adopted recovery selection disappeared".into())
            })?;
        governance
            .validate_recovery_origin(&selected)
            .map_err(|error| RecoveryError::Invalid(error.to_string()))?;
        match selected.kind {
            RecoveryKind::Correction => governance.restore_correction_recovery(&selected),
            RecoveryKind::Usage | RecoveryKind::Metering => {
                governance.restore_raw_recovery(&selected)
            }
        }
        .map_err(|error| RecoveryError::Invalid(error.to_string()))?;
        drop(correction_guard);
        drop(running);
        self.resume_adopted(cost, resolution.operation_id)
    }

    fn resume_adopted(
        &self,
        cost: &crate::cost::CostModel,
        operation_id: [u8; 16],
    ) -> Result<RecoveryItem, RecoveryError> {
        let governance = self.governance;
        let event = governance.recovery_event(operation_id).ok_or_else(|| {
            RecoveryError::Unavailable("adopted recovery selection disappeared".into())
        })?;
        match event.kind {
            RecoveryKind::Correction => governance.resume_adopted_correction(cost, operation_id)?,
            RecoveryKind::Usage | RecoveryKind::Metering => {
                governance
                    .drive_raw_recovery(operation_id)
                    .map_err(|error| RecoveryError::Unavailable(error.to_string()))?;
                let current = governance.recovery_event(operation_id).ok_or_else(|| {
                    RecoveryError::Unavailable("adopted recovery selection disappeared".into())
                })?;
                governance
                    .resume_recovery_children(&current)
                    .map_err(|error| RecoveryError::Unavailable(error.to_string()))?;
            }
        }
        governance
            .recovery_event(operation_id)
            .as_ref()
            .map(RecoveryItem::from_event)
            .ok_or_else(|| {
                RecoveryError::Unavailable("adopted recovery selection disappeared".into())
            })
    }

    pub fn list(
        &self,
        after: Option<[u8; 16]>,
        limit: usize,
    ) -> Result<Vec<RecoveryItem>, RecoveryError> {
        if limit == 0 || limit > 1001 {
            return Err(RecoveryError::Invalid(
                "recovery list limit must be 1..=1001".into(),
            ));
        }
        if !self.governance.recovery_book.attached() {
            return Err(RecoveryError::Unavailable(
                "recovery Store is not attached".into(),
            ));
        }
        let mut items: std::collections::BTreeMap<_, _> = self
            .governance
            .selected_recovery_events()
            .into_iter()
            .filter(|event| event.state != RecoveryState::Settled)
            .map(|event| (event.operation_id, RecoveryItem::from_event(&event)))
            .collect();
        for inspection in self.governance.inspect_foreign_recovery()? {
            if inspection.event.state == RecoveryState::Settled {
                continue;
            }
            let mut item = RecoveryItem::from_event(&inspection.event);
            item.owner_node = Some(inspection.owner_node);
            item.can_resolve = false;
            items.insert(item.operation_id, item);
        }
        Ok(items
            .into_iter()
            .filter(|(id, _)| after.is_none_or(|after| *id > after))
            .take(limit)
            .map(|(_, item)| item)
            .collect())
    }
}

impl super::GovState {
    pub fn attach_recovery_sink(
        &self,
        sink: std::sync::Arc<dyn RecoverySink>,
    ) -> super::RecordStoreResult<()> {
        self.recovery_book
            .replay(sink)
            .map_err(|error| super::RecordStoreError(error.to_string()))?;
        for event in self.selected_recovery_events() {
            self.validate_recovery_origin(&event)?;
            match event.kind {
                RecoveryKind::Correction => self.restore_correction_recovery(&event)?,
                RecoveryKind::Usage | RecoveryKind::Metering => {
                    self.restore_raw_recovery(&event)?
                }
            }
        }
        // Fresh Store hydration remains authoritative. Registration never sends
        // a historical body or makes startup depend on an age-quarantine write.
        for event in self.selected_recovery_events() {
            self.forget_confirmed_recovery(event.operation_id);
        }
        Ok(())
    }

    pub fn recovery(&self) -> RecoveryAdmin<'_> {
        RecoveryAdmin { governance: self }
    }

    pub(super) fn recovery_enabled(&self) -> bool {
        self.recovery_book.attached()
    }

    pub(super) fn recovery_selection_epoch(&self) -> u64 {
        self.recovery_book
            .selection_epoch
            .load(std::sync::atomic::Ordering::Acquire)
    }

    pub(super) fn selected_recovery_events(&self) -> Vec<RecoveryEvent> {
        self.recovery_book
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .filter_map(|entry| entry.selected.clone())
            .collect()
    }

    /// Only a retained same-process monotonic clock authorizes receipt replay.
    /// Wall timestamps survive reboot as evidence, not as proof of receipt age.
    pub(super) fn recovery_retention_expired(&self, operation_id: [u8; 16]) -> Option<bool> {
        self.recovery_book
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&operation_id)
            .and_then(|entry| entry.sent_clock)
            .map(|sent| {
                sent.elapsed().as_secs() >= busbar_contract::abi::store::OP_ID_RETENTION_SECS
            })
    }

    pub(super) fn confirm_pending_recovery(
        &self,
        operation_id: [u8; 16],
    ) -> super::RecordStoreResult<()> {
        let pending = self
            .recovery_book
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&operation_id)
            .and_then(|entry| entry.pending.clone());
        if let Some(event) = pending {
            self.keep_recovery_event(&event)?;
        }
        Ok(())
    }

    /// Local successful roots need no live administrative custody after their
    /// flight is retired. Their immutable Store journals remain untouched.
    pub(super) fn forget_confirmed_recovery(&self, operation_id: [u8; 16]) {
        let mut entries = self
            .recovery_book
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let Some(entry) = entries.get(&operation_id) else {
            return;
        };
        let Some(event) = entry.selected.as_ref() else {
            return;
        };
        if event.kind == RecoveryKind::Correction
            || event.state != RecoveryState::Settled
            || entry.pending.is_some()
            || entry.ever_quarantined
            || event.revision > 2
            || entry.adoption.is_some()
        {
            return;
        }
        let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&event.payload) else {
            return;
        };
        if payload
            .get("origin")
            .is_some_and(|origin| !origin.is_null())
            || !payload
                .get("handoffs")
                .and_then(serde_json::Value::as_array)
                .is_some_and(Vec::is_empty)
        {
            return;
        }
        entries.remove(&operation_id);
        self.recovery_book
            .selection_epoch
            .fetch_add(1, std::sync::atomic::Ordering::Release);
    }

    pub(super) fn verify_external_recovery_origin(
        &self,
        event: &RecoveryEvent,
    ) -> super::RecordStoreResult<()> {
        self.recovery_book
            .sink
            .get()
            .ok_or_else(|| super::RecordStoreError("recovery Store is not attached".into()))?
            .verify_origin(event)
            .map_err(|error| super::RecordStoreError(error.to_string()))
    }

    fn clear_unselected_adoption(&self, resolution: &RecoveryResolution) {
        let mut entries = self
            .recovery_book
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = entries.get_mut(&resolution.operation_id) {
            if entry
                .adoption
                .as_ref()
                .is_some_and(|pending| !pending.imported && pending.resolution == *resolution)
            {
                entry.adoption = None;
            }
        }
    }

    fn validate_foreign_known_outcome(
        &self,
        resolution: &RecoveryResolution,
        kind: RecoveryKind,
    ) -> Result<(), RecoveryError> {
        let entries = self
            .recovery_book
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let Some(entry) = entries.get(&resolution.operation_id) else {
            return Ok(());
        };
        for event in entry.selected.iter().chain(entry.pending.iter()) {
            if event.kind != kind || event.body_fingerprint != resolution.body_fingerprint {
                return Err(RecoveryError::Conflict(
                    "foreign adoption would replace an immutable local operation identity".into(),
                ));
            }
            let known = match event.state {
                RecoveryState::Applied => Some(RecoveryVerdict::Landed),
                RecoveryState::ConditionConflict => Some(RecoveryVerdict::NotLanded),
                _ => None,
            };
            if known.is_some_and(|known| known != resolution.verdict) {
                return Err(RecoveryError::Conflict(
                    "foreign verdict contradicts a retained definitive backend result".into(),
                ));
            }
        }
        Ok(())
    }

    pub(super) fn inspect_foreign_recovery(
        &self,
    ) -> Result<Vec<RecoveryInspection>, RecoveryError> {
        self.recovery_book
            .sink
            .get()
            .ok_or_else(|| RecoveryError::Unavailable("recovery Store is not attached".into()))?
            .inspect_foreign()
    }

    fn import_adopted_recovery(
        &self,
        adoption: &RecoveryAdoption,
        selection: RecoverySelection,
    ) -> Result<(), RecoveryError> {
        // The sink's production selection method has already stream-verified the
        // full adopted selected chain. These checks preserve our local identity.
        selection.validate_identity()?;
        let operation_id = adoption.resolution.operation_id;
        if selection.selected.operation_id != operation_id
            || Some(&selection.selected) != adoption.transitions.last()
        {
            return Err(RecoveryError::Invalid(
                "adoption returned a different selected transition".into(),
            ));
        }
        loop {
            let previous = self.recovery_event(operation_id);
            if let Some(previous) = previous.as_ref() {
                // Verify exact CURRENT selected ancestry outside every Book and
                // shard mutex before replacing a locally confirmed predecessor.
                self.recovery_book
                    .sink
                    .get()
                    .ok_or_else(|| {
                        RecoveryError::Unavailable("recovery Store is not attached".into())
                    })?
                    .verify_checkpoint(previous)?;
            }
            let mut entries = self
                .recovery_book
                .entries
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let entry = entries.entry(operation_id).or_default();
            if entry.selected != previous {
                continue;
            }
            if entry
                .initial
                .as_ref()
                .is_some_and(|initial| *initial != selection.initial)
            {
                return Err(RecoveryError::Invalid(
                    "adopted selection replaces immutable initial custody".into(),
                ));
            }
            entry.initial = Some(selection.initial);
            entry.selected = Some(selection.selected);
            entry.pending = None;
            entry.sent_clock = None;
            entry.ever_quarantined = true;
            let mut confirmed = adoption.clone();
            confirmed.imported = true;
            entry.adoption = Some(confirmed);
            self.recovery_book
                .selection_epoch
                .fetch_add(1, std::sync::atomic::Ordering::Release);
            return Ok(());
        }
    }

    pub(super) fn foreign_recovery_receipt(
        &self,
        operation_id: [u8; 16],
    ) -> Result<Option<RecoveryEvent>, RecoveryError> {
        let Some(receipt) = self
            .inspect_foreign_recovery()?
            .into_iter()
            .find(|receipt| {
                receipt.event.operation_id == operation_id
                    && receipt.event.state == RecoveryState::Settled
            })
        else {
            return Ok(None);
        };
        self.recovery_book
            .sink
            .get()
            .expect("inspection requires sink")
            .verify_origin(&receipt.event)?;
        Ok(Some(receipt.event))
    }

    pub(super) fn verify_recovery_checkpoint(
        &self,
        event: &RecoveryEvent,
    ) -> super::RecordStoreResult<()> {
        let cached = self
            .recovery_book
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&event.operation_id)
            .is_some_and(|entry| {
                entry.initial.as_ref() == Some(event) || entry.selected.as_ref() == Some(event)
            });
        if cached {
            return Ok(());
        }
        self.recovery_book
            .sink
            .get()
            .ok_or_else(|| super::RecordStoreError("recovery Store is not attached".into()))?
            .verify_checkpoint(event)
            .map_err(|error| super::RecordStoreError(error.to_string()))
    }

    pub(super) fn recovery_driver(
        &self,
        operation_id: [u8; 16],
    ) -> super::RecordStoreResult<std::sync::Arc<super::BudgetFlushRunner>> {
        self.recovery_book
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&operation_id)
            .map(|entry| entry.driver.clone())
            .ok_or_else(|| super::RecordStoreError("recovery operation does not exist".into()))
    }

    pub(super) fn recovery_initial_event(&self, operation_id: [u8; 16]) -> Option<RecoveryEvent> {
        self.recovery_book
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&operation_id)
            .and_then(|entry| entry.initial.clone())
    }

    pub(super) fn recovery_ancestor(
        &self,
        operation_id: [u8; 16],
        fingerprint: [u8; 32],
    ) -> Option<RecoveryEvent> {
        self.recovery_book
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&operation_id)
            .and_then(|entry| {
                entry
                    .initial
                    .iter()
                    .chain(entry.selected.iter())
                    .find(|event| event.fingerprint().ok() == Some(fingerprint))
                    .cloned()
            })
    }

    pub(super) fn recovery_event(&self, operation_id: [u8; 16]) -> Option<RecoveryEvent> {
        self.recovery_book.selected(operation_id)
    }

    pub(super) fn new_recovery_event(
        &self,
        operation_id: [u8; 16],
        kind: RecoveryKind,
        body_fingerprint: [u8; 32],
        state: RecoveryState,
        first_sent_at_ms: Option<u64>,
        payload: Vec<u8>,
    ) -> Result<RecoveryEvent, RecoveryError> {
        self.recovery_book.stage(
            operation_id,
            kind,
            body_fingerprint,
            state,
            first_sent_at_ms,
            payload,
        )
    }

    pub(super) fn keep_recovery_event(
        &self,
        event: &RecoveryEvent,
    ) -> super::RecordStoreResult<()> {
        self.recovery_book
            .keep(event)
            .map_err(|error| super::RecordStoreError(error.to_string()))
    }
}

/// A sealed child template authorized by one selected parent checkpoint. The
/// child origin is derived AFTER selection, avoiding a circular event hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryChild {
    pub(super) operation_id: [u8; 16],
    pub(super) kind: RecoveryKind,
    pub(super) body_fingerprint: [u8; 32],
    pub(super) first_sent_at_ms: Option<u64>,
    pub(super) payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryOrigin {
    pub operation_id: [u8; 16],
    pub event_fingerprint: [u8; 32],
}

#[cfg(test)]
pub(in crate::governance) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    pub(in crate::governance) struct Journal {
        pub(in crate::governance) selected: Mutex<Vec<RecoveryEvent>>,
        pub(in crate::governance) fail_after_write: AtomicBool,
        foreign: Mutex<std::collections::BTreeMap<[u8; 16], (u64, Vec<RecoveryEvent>)>>,
        adoption_attempts: Mutex<Vec<(RecoveryResolution, Vec<RecoveryEvent>)>>,
        confirmed_adoptions:
            Mutex<std::collections::BTreeMap<[u8; 16], (RecoveryResolution, Vec<RecoveryEvent>)>>,
        lose_adoption_reply: AtomicBool,
    }
    impl RecoverySink for Journal {
        fn replay(&self) -> Result<Vec<RecoveryEvent>, RecoveryError> {
            Ok(self.selected.lock().unwrap().clone())
        }
        fn persist(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
            if self
                .foreign
                .lock()
                .unwrap()
                .contains_key(&event.operation_id)
            {
                return Err(RecoveryError::Conflict(
                    "foreign operation is readonly".into(),
                ));
            }
            let mut selected = self.selected.lock().unwrap();
            if !selected.contains(event) {
                selected.push(event.clone());
            }
            if self.fail_after_write.load(Ordering::Relaxed) {
                Err(RecoveryError::Unavailable(
                    "reply lost after selection".into(),
                ))
            } else {
                Ok(())
            }
        }
        fn inspect_foreign(&self) -> Result<Vec<RecoveryInspection>, RecoveryError> {
            Ok(self
                .foreign
                .lock()
                .unwrap()
                .values()
                .map(|(owner_node, events)| RecoveryInspection {
                    owner_node: *owner_node,
                    event: events.last().unwrap().clone(),
                })
                .collect())
        }
        fn adopt_verdict(
            &self,
            resolution: &RecoveryResolution,
            transitions: &[RecoveryEvent],
        ) -> Result<Vec<RecoveryEvent>, RecoveryError> {
            resolution.validate_quiescence()?;
            self.adoption_attempts
                .lock()
                .unwrap()
                .push((resolution.clone(), transitions.to_vec()));
            if let Some((previous, events)) = self
                .confirmed_adoptions
                .lock()
                .unwrap()
                .get(&resolution.operation_id)
            {
                if previous != resolution || events.as_slice() != transitions {
                    return Err(RecoveryError::Conflict(
                        "adoption differs from confirmed immutable candidate".into(),
                    ));
                }
                return Ok(self
                    .selected
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|event| event.operation_id == resolution.operation_id)
                    .cloned()
                    .collect());
            }
            let mut foreign = self.foreign.lock().unwrap();
            let (_, original) = foreign
                .get(&resolution.operation_id)
                .ok_or_else(|| RecoveryError::Conflict("foreign head disappeared".into()))?;
            let head = original.last().unwrap();
            if head.revision != resolution.expected_revision
                || head.body_fingerprint != resolution.body_fingerprint
            {
                return Err(RecoveryError::Conflict("foreign head changed".into()));
            }
            let mut chain = original.clone();
            for event in transitions {
                event.follows(chain.last())?;
                chain.push(event.clone());
            }
            foreign.remove(&resolution.operation_id);
            drop(foreign);
            self.selected.lock().unwrap().extend(chain.clone());
            self.confirmed_adoptions.lock().unwrap().insert(
                resolution.operation_id,
                (resolution.clone(), transitions.to_vec()),
            );
            if self.lose_adoption_reply.swap(false, Ordering::Relaxed) {
                return Err(RecoveryError::Unavailable(
                    "adoption selected but reply lost".into(),
                ));
            }
            Ok(chain)
        }
        fn verify_origin(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
            let owned: Vec<_> = self
                .selected
                .lock()
                .unwrap()
                .iter()
                .filter(|selected| selected.operation_id == event.operation_id)
                .cloned()
                .collect();
            let genesis = owned
                .first()
                .cloned()
                .or_else(|| {
                    self.foreign
                        .lock()
                        .unwrap()
                        .get(&event.operation_id)
                        .and_then(|(_, events)| events.first().cloned())
                })
                .unwrap_or_else(|| event.clone());
            if event.origin_reference()? != genesis.origin_reference()?
                || event.kind != genesis.kind
                || event.body_fingerprint != genesis.body_fingerprint
                || event.first_sent_at_ms != genesis.first_sent_at_ms
            {
                return Err(RecoveryError::Conflict("child identity changed".into()));
            }
            let Some(origin) = genesis.origin_reference()? else {
                return Ok(());
            };
            let parent = self
                .selected
                .lock()
                .unwrap()
                .iter()
                .find(|parent| {
                    parent.operation_id == origin.operation_id
                        && parent.fingerprint().ok() == Some(origin.event_fingerprint)
                })
                .cloned()
                .or_else(|| {
                    self.foreign
                        .lock()
                        .unwrap()
                        .get(&origin.operation_id)
                        .and_then(|(_, events)| {
                            events
                                .iter()
                                .find(|parent| {
                                    parent.fingerprint().ok() == Some(origin.event_fingerprint)
                                })
                                .cloned()
                        })
                })
                .ok_or_else(|| RecoveryError::Invalid("origin is not selected".into()))?;
            parent.authorizes_child(&genesis)
        }
    }
    impl Journal {
        fn make_foreign(&self, operation_id: [u8; 16], owner_node: u64) {
            let mut selected = self.selected.lock().unwrap();
            let chain = selected
                .iter()
                .filter(|event| event.operation_id == operation_id)
                .cloned()
                .collect();
            selected.retain(|event| event.operation_id != operation_id);
            self.foreign
                .lock()
                .unwrap()
                .insert(operation_id, (owner_node, chain));
        }
    }

    fn intent() -> RecoveryEvent {
        RecoveryEvent {
            operation_id: [1; 16],
            revision: 0,
            previous_event: None,
            kind: RecoveryKind::Usage,
            body_fingerprint: [2; 32],
            state: RecoveryState::Intent,
            first_sent_at_ms: Some(42),
            payload: vec![3],
        }
    }
    fn successor(previous: &RecoveryEvent, state: RecoveryState) -> RecoveryEvent {
        RecoveryEvent {
            revision: previous.revision + 1,
            previous_event: Some(previous.fingerprint().unwrap()),
            state,
            ..previous.clone()
        }
    }

    #[test]
    fn ambiguous_selection_retains_exact_candidate_until_confirmed() {
        let sink = Arc::new(Journal::default());
        let book = RecoveryBook::default();
        book.replay(sink.clone()).unwrap();
        let event = intent();
        sink.fail_after_write.store(true, Ordering::Relaxed);
        assert!(book.keep(&event).is_err());
        assert!(book.selected(event.operation_id).is_none());
        let mut different = event.clone();
        different.payload.push(9);
        assert!(matches!(
            book.keep(&different),
            Err(RecoveryError::Conflict(_))
        ));
        sink.fail_after_write.store(false, Ordering::Relaxed);
        book.keep(&event).unwrap();
        assert_eq!(book.selected(event.operation_id), Some(event.clone()));
        book.keep(&event).unwrap();
        sink.fail_after_write.store(true, Ordering::Relaxed);
        assert!(
            book.keep(&event).is_err(),
            "cached selected events still require Store authority confirmation"
        );
        assert_eq!(sink.selected.lock().unwrap().as_slice(), &[event]);
    }

    #[test]
    fn staged_candidate_survives_failed_persistence_and_cannot_change() {
        let sink = Arc::new(Journal::default());
        let book = RecoveryBook::default();
        book.replay(sink.clone()).unwrap();
        let event = intent();
        let stage = |payload| {
            book.stage(
                event.operation_id,
                event.kind,
                event.body_fingerprint,
                event.state,
                event.first_sent_at_ms,
                payload,
            )
        };
        assert_eq!(stage(event.payload.clone()).unwrap(), event);
        assert!(stage(vec![99]).is_err());
        sink.fail_after_write.store(true, Ordering::Relaxed);
        assert!(book.keep(&event).is_err());
        assert_eq!(stage(event.payload.clone()).unwrap(), event);
    }

    #[test]
    fn replay_rejects_gap_and_same_revision_fork() {
        let event = intent();
        for invalid in [
            RecoveryEvent {
                revision: 2,
                ..successor(&event, RecoveryState::Applied)
            },
            RecoveryEvent {
                payload: vec![99],
                ..event.clone()
            },
        ] {
            let sink = Arc::new(Journal::default());
            *sink.selected.lock().unwrap() = vec![event.clone(), invalid];
            assert!(RecoveryBook::default().replay(sink).is_err());
        }
    }

    #[test]
    fn raw_checkpoints_keep_definitive_decisions_until_custody_is_transferred() {
        let event = intent();
        for decision in [RecoveryState::Applied, RecoveryState::ConditionConflict] {
            let previous = successor(&event, decision);
            successor(&previous, decision)
                .follows(Some(&previous))
                .unwrap();
        }
        let unknown = successor(&event, RecoveryState::LandedUnknown);
        for decision in [
            RecoveryState::VerdictLanded,
            RecoveryState::VerdictNotLanded,
        ] {
            let previous = successor(&unknown, decision);
            successor(&previous, decision)
                .follows(Some(&previous))
                .unwrap();
            assert!(successor(&previous, RecoveryState::Intent)
                .follows(Some(&previous))
                .is_err());
        }
    }

    #[test]
    fn chain_identity_and_first_sent_time_never_reset() {
        let event = intent();
        for invalid in [
            RecoveryEvent {
                first_sent_at_ms: Some(43),
                ..successor(&event, RecoveryState::Applied)
            },
            RecoveryEvent {
                kind: RecoveryKind::Metering,
                ..successor(&event, RecoveryState::Applied)
            },
            RecoveryEvent {
                body_fingerprint: [8; 32],
                ..successor(&event, RecoveryState::Applied)
            },
        ] {
            assert!(invalid.follows(Some(&event)).is_err());
        }
    }
    fn raw_intent(gov: &super::super::GovState, requests: i128) -> RecoveryEvent {
        let child = super::super::GovState::usage_recovery_child(
            "recovery-bucket",
            0,
            super::super::ExactUsageDelta {
                requests,
                ..Default::default()
            },
            super::super::ExactUsageDelta::default(),
        )
        .unwrap()
        .unwrap();
        let event = gov
            .new_recovery_event(
                child.operation_id,
                child.kind,
                child.body_fingerprint,
                RecoveryState::Intent,
                child.first_sent_at_ms,
                child.payload,
            )
            .unwrap();
        gov.keep_recovery_event(&event).unwrap();
        event
    }

    #[test]
    fn restart_cannot_turn_recent_wall_time_into_receipt_age_authority() {
        use super::super::{GovState, RecordStore};
        let store = crate::real_store::store();
        let sink = Arc::new(Journal::default());
        let first = GovState::new(store.clone(), None).unwrap();
        first.attach_recovery_sink(sink.clone()).unwrap();
        first.resume_raw_recovery().unwrap();
        let intent = raw_intent(&first, 7);
        assert_eq!(
            first.recovery_retention_expired(intent.operation_id),
            Some(false)
        );
        drop(first);
        let restarted = GovState::new(store.clone(), None).unwrap();
        restarted.attach_recovery_sink(sink).unwrap();
        restarted.resume_raw_recovery().unwrap();
        assert_eq!(
            restarted.recovery_event(intent.operation_id).unwrap().state,
            RecoveryState::LandedUnknown
        );
        assert_eq!(
            restarted.recovery_retention_expired(intent.operation_id),
            None
        );
        let raw: serde_json::Value = serde_json::from_slice(
            &restarted
                .recovery_event(intent.operation_id)
                .unwrap()
                .payload,
        )
        .unwrap();
        assert_eq!(raw["age_unknown"], true);
        assert_eq!(store.get_usage("recovery-bucket", 0).unwrap().requests, 0);
    }

    #[test]
    fn unknown_usage_absorbs_negative_then_not_landed_reposts_only_net_raw_debt() {
        use super::super::{GovState, RecordStore};
        let store = crate::real_store::store();
        let sink = Arc::new(Journal::default());
        let original = GovState::new(store.clone(), None).unwrap();
        original.attach_recovery_sink(sink.clone()).unwrap();
        original.resume_raw_recovery().unwrap();
        let intent = raw_intent(&original, 7);
        drop(original);
        let gov = GovState::new(store.clone(), None).unwrap();
        gov.attach_recovery_sink(sink).unwrap();
        gov.resume_raw_recovery().unwrap();
        let negative = super::super::ExactUsageDelta {
            requests: -3,
            ..Default::default()
        };
        let captured = gov
            .capture_usage_recovery(
                "recovery-bucket",
                0,
                negative,
                super::super::ExactUsageDelta::default(),
            )
            .unwrap();
        assert!(captured.child.is_none());
        gov.drive_durable_usage_flight(&captured).unwrap();
        assert_eq!(store.get_usage("recovery-bucket", 0).unwrap().requests, 0);
        let unknown = gov.recovery_event(intent.operation_id).unwrap();
        gov.resolve_raw_recovery(&RecoveryResolution {
            operation_id: intent.operation_id,
            body_fingerprint: intent.body_fingerprint,
            expected_revision: unknown.revision,
            verdict: RecoveryVerdict::NotLanded,
            sender_quiesced: true,
            backend_quiesced: true,
            actor: "operator".into(),
            reason: "backend outcome independently checked".into(),
        })
        .unwrap();
        assert_eq!(store.get_usage("recovery-bucket", 0).unwrap().requests, 4);
        assert_eq!(
            gov.recovery_event(intent.operation_id).unwrap().state,
            RecoveryState::Settled
        );
    }

    #[test]
    fn selected_parent_checkpoint_reconstructs_exact_missing_usage_child() {
        use super::super::{GovState, RecordStore};
        let store = crate::real_store::store();
        let sink = Arc::new(Journal::default());
        let first = GovState::new(store.clone(), None).unwrap();
        first.attach_recovery_sink(sink.clone()).unwrap();
        first.resume_raw_recovery().unwrap();
        let intent = raw_intent(&first, 1);
        store
            .add_usage_batch_deduped(
                busbar_contract::abi::store::OpId(intent.operation_id),
                &[(
                    "recovery-bucket",
                    0,
                    super::super::UsageDelta {
                        requests: 1,
                        ..Default::default()
                    },
                )],
            )
            .unwrap();
        let child = GovState::usage_recovery_child(
            "child-bucket",
            0,
            super::super::ExactUsageDelta {
                requests: 7,
                ..Default::default()
            },
            super::super::ExactUsageDelta::default(),
        )
        .unwrap()
        .unwrap();
        let mut custody: super::super::raw_recovery::UsageCustody =
            serde_json::from_slice(&intent.payload).unwrap();
        custody.plain = Default::default();
        custody.handoffs.push(child.clone());
        let applied = first
            .new_recovery_event(
                intent.operation_id,
                intent.kind,
                intent.body_fingerprint,
                RecoveryState::Applied,
                intent.first_sent_at_ms,
                serde_json::to_vec(&custody).unwrap(),
            )
            .unwrap();
        first.keep_recovery_event(&applied).unwrap();
        assert!(first.recovery_event(child.operation_id).is_none());
        drop(first);
        let restarted = GovState::new(store.clone(), None).unwrap();
        restarted.attach_recovery_sink(sink).unwrap();
        restarted.resume_raw_recovery().unwrap();
        let restored = restarted.recovery_event(child.operation_id).unwrap();
        assert_eq!(restored.body_fingerprint, child.body_fingerprint);
        assert_eq!(store.get_usage("child-bucket", 0).unwrap().requests, 7);
        restarted.resume_raw_recovery().unwrap();
        assert_eq!(store.get_usage("child-bucket", 0).unwrap().requests, 7);
    }
    #[test]
    fn two_unknown_positives_cannot_release_each_others_dependent_negatives() {
        use super::super::{GovState, RecordStore};
        let store = crate::real_store::store();
        let sink = Arc::new(Journal::default());
        let original = GovState::new(store.clone(), None).unwrap();
        original.attach_recovery_sink(sink.clone()).unwrap();
        original.resume_raw_recovery().unwrap();
        let first = raw_intent(&original, 7);
        let second = raw_intent(&original, 11);
        drop(original);
        let gov = GovState::new(store.clone(), None).unwrap();
        gov.attach_recovery_sink(sink).unwrap();
        gov.resume_raw_recovery().unwrap();
        let captured = gov
            .capture_usage_recovery(
                "recovery-bucket",
                0,
                super::super::ExactUsageDelta {
                    requests: -18,
                    ..Default::default()
                },
                Default::default(),
            )
            .unwrap();
        assert!(captured.child.is_none());
        assert!(captured.deferred_plain.requests < 0);
        gov.drive_durable_usage_flight(&captured).unwrap();
        let remaining = gov
            .capture_usage_recovery(
                "recovery-bucket",
                0,
                captured.deferred_plain,
                captured.deferred_dated,
            )
            .unwrap();
        assert!(remaining.child.is_none());
        assert!(remaining.deferred_plain.is_zero());
        gov.drive_durable_usage_flight(&remaining).unwrap();
        for intent in [first, second] {
            let selected = gov.recovery_event(intent.operation_id).unwrap();
            gov.resolve_raw_recovery(&RecoveryResolution {
                operation_id: intent.operation_id,
                body_fingerprint: intent.body_fingerprint,
                expected_revision: selected.revision,
                verdict: RecoveryVerdict::NotLanded,
                sender_quiesced: true,
                backend_quiesced: true,
                actor: "operator".into(),
                reason: "neither original operation reached backend".into(),
            })
            .unwrap();
        }
        assert_eq!(store.get_usage("recovery-bucket", 0).unwrap().requests, 0);
    }

    #[test]
    fn unknown_chunk_transfers_never_sent_unsigned_remainder_to_fresh_children() {
        use super::super::{GovState, RecordStore};
        let store = crate::real_store::store();
        let sink = Arc::new(Journal::default());
        let original = GovState::new(store.clone(), None).unwrap();
        original.attach_recovery_sink(sink.clone()).unwrap();
        original.resume_raw_recovery().unwrap();
        let intent = raw_intent(&original, i128::from(u64::MAX));
        drop(original);
        let gov = GovState::new(store.clone(), None).unwrap();
        gov.attach_recovery_sink(sink).unwrap();
        gov.resume_raw_recovery().unwrap();
        assert_eq!(
            gov.recovery_event(intent.operation_id).unwrap().state,
            RecoveryState::LandedUnknown
        );
        assert_eq!(
            store.get_usage("recovery-bucket", 0).unwrap().requests,
            u64::MAX - i64::MAX as u64,
            "only the old sent chunk is unknown; never-sent remainder keeps progressing"
        );
    }
    #[test]
    fn verdict_without_both_quiescence_attestations_persists_nothing() {
        use super::super::{GovState, RecordStore};
        let store = crate::real_store::store();
        let sink = Arc::new(Journal::default());
        let original = GovState::new(store.clone(), None).unwrap();
        original.attach_recovery_sink(sink.clone()).unwrap();
        original.resume_raw_recovery().unwrap();
        let intent = raw_intent(&original, 7);
        drop(original);
        let gov = GovState::new(store.clone(), None).unwrap();
        gov.attach_recovery_sink(sink.clone()).unwrap();
        gov.resume_raw_recovery().unwrap();
        let selected = gov.recovery_event(intent.operation_id).unwrap();
        let count = sink.selected.lock().unwrap().len();
        let cost = crate::cost::CostModel::flat(0);
        for (sender_quiesced, backend_quiesced) in [(false, false), (false, true), (true, false)] {
            let resolution = RecoveryResolution {
                operation_id: intent.operation_id,
                body_fingerprint: intent.body_fingerprint,
                expected_revision: selected.revision,
                verdict: RecoveryVerdict::NotLanded,
                sender_quiesced,
                backend_quiesced,
                actor: "operator".into(),
                reason: "quiescence is not confirmed".into(),
            };
            assert!(matches!(
                gov.recovery().resolve(&cost, resolution.clone()),
                Err(RecoveryError::Invalid(_))
            ));
            assert!(matches!(
                gov.resolve_raw_recovery(&resolution),
                Err(RecoveryError::Invalid(_))
            ));
            assert_eq!(
                gov.recovery_event(intent.operation_id),
                Some(selected.clone())
            );
            assert_eq!(sink.selected.lock().unwrap().len(), count);
            assert_eq!(store.get_usage("recovery-bucket", 0).unwrap().requests, 0);
        }
    }

    #[test]
    fn attested_verdict_still_requires_same_process_driver_quiescence() {
        use super::super::GovState;
        let sink = Arc::new(Journal::default());
        let original = GovState::new(crate::real_store::store(), None).unwrap();
        original.attach_recovery_sink(sink.clone()).unwrap();
        original.resume_raw_recovery().unwrap();
        let intent = raw_intent(&original, 7);
        drop(original);
        let gov = GovState::new(crate::real_store::store(), None).unwrap();
        gov.attach_recovery_sink(sink.clone()).unwrap();
        gov.resume_raw_recovery().unwrap();
        let selected = gov.recovery_event(intent.operation_id).unwrap();
        let count = sink.selected.lock().unwrap().len();
        let driver = gov.recovery_driver(intent.operation_id).unwrap();
        let _running = driver.enter(false).unwrap();
        let resolution = RecoveryResolution {
            operation_id: intent.operation_id,
            body_fingerprint: intent.body_fingerprint,
            expected_revision: selected.revision,
            verdict: RecoveryVerdict::NotLanded,
            sender_quiesced: true,
            backend_quiesced: true,
            actor: "operator".into(),
            reason: "attestation alone cannot override a running driver".into(),
        };
        assert!(matches!(
            gov.recovery()
                .resolve(&crate::cost::CostModel::flat(0), resolution),
            Err(RecoveryError::Conflict(_))
        ));
        assert_eq!(gov.recovery_event(intent.operation_id), Some(selected));
        assert_eq!(sink.selected.lock().unwrap().len(), count);
    }
    #[test]
    fn retiring_a_successful_root_releases_ram_without_deleting_its_store_chain() {
        use super::super::{GovState, RecordStore};
        let store = crate::real_store::store();
        let sink = Arc::new(Journal::default());
        let gov = GovState::new(store.clone(), None).unwrap();
        gov.attach_recovery_sink(sink.clone()).unwrap();
        gov.resume_raw_recovery().unwrap();
        let intent = raw_intent(&gov, 7);
        gov.drive_raw_recovery(intent.operation_id).unwrap();
        let journal_len = sink.selected.lock().unwrap().len();
        assert_eq!(journal_len, 3);
        gov.forget_confirmed_recovery(intent.operation_id);
        assert!(gov.recovery_event(intent.operation_id).is_none());
        assert_eq!(sink.selected.lock().unwrap().len(), journal_len);
        drop(gov);
        let restarted = GovState::new(store.clone(), None).unwrap();
        restarted.attach_recovery_sink(sink.clone()).unwrap();
        restarted.resume_raw_recovery().unwrap();
        assert!(restarted.recovery_event(intent.operation_id).is_none());
        assert_eq!(store.get_usage("recovery-bucket", 0).unwrap().requests, 7);
        assert_eq!(sink.selected.lock().unwrap().len(), journal_len);
    }

    #[test]
    fn retiring_live_or_unknown_custody_cannot_discard_its_authority() {
        use super::super::GovState;
        let sink = Arc::new(Journal::default());
        let original = GovState::new(crate::real_store::store(), None).unwrap();
        original.attach_recovery_sink(sink.clone()).unwrap();
        original.resume_raw_recovery().unwrap();
        let intent = raw_intent(&original, 7);
        original.forget_confirmed_recovery(intent.operation_id);
        assert_eq!(
            original.recovery_event(intent.operation_id),
            Some(intent.clone())
        );
        drop(original);
        let gov = GovState::new(crate::real_store::store(), None).unwrap();
        gov.attach_recovery_sink(sink).unwrap();
        gov.resume_raw_recovery().unwrap();
        gov.forget_confirmed_recovery(intent.operation_id);
        assert_eq!(
            gov.recovery_event(intent.operation_id).unwrap().state,
            RecoveryState::LandedUnknown
        );
        let unknown = gov.recovery_event(intent.operation_id).unwrap();
        gov.resolve_raw_recovery(&RecoveryResolution {
            operation_id: intent.operation_id,
            body_fingerprint: intent.body_fingerprint,
            expected_revision: unknown.revision,
            verdict: RecoveryVerdict::NotLanded,
            sender_quiesced: true,
            backend_quiesced: true,
            actor: "operator".into(),
            reason: "original never reached backend".into(),
        })
        .unwrap();
        gov.forget_confirmed_recovery(intent.operation_id);
        assert_eq!(
            gov.recovery_event(intent.operation_id).unwrap().state,
            RecoveryState::Settled
        );
        gov.validate_recovery_origin(
            &gov.selected_recovery_events()
                .into_iter()
                .find(|event| event.operation_id != intent.operation_id)
                .unwrap(),
        )
        .unwrap();
    }
    #[test]
    fn foreign_adoption_lost_reply_retains_exact_children_and_sends_only_after_confirmation() {
        use super::super::{GovState, RecordStore};
        let store = crate::real_store::store();
        let sink = Arc::new(Journal::default());
        let original = GovState::new(store.clone(), None).unwrap();
        original.attach_recovery_sink(sink.clone()).unwrap();
        let intent = raw_intent(&original, 7);
        sink.make_foreign(intent.operation_id, 17);
        drop(original);
        let gov = GovState::new(store.clone(), None).unwrap();
        gov.attach_recovery_sink(sink.clone()).unwrap();
        assert!(
            gov.recovery_event(intent.operation_id).is_none(),
            "inspection grants no writable custody"
        );
        let listed = gov.recovery().list(None, 10).unwrap().pop().unwrap();
        assert_eq!(listed.owner_node, Some(17));
        assert!(!listed.can_resolve);
        let resolution = RecoveryResolution {
            operation_id: intent.operation_id,
            body_fingerprint: intent.body_fingerprint,
            expected_revision: intent.revision,
            verdict: RecoveryVerdict::NotLanded,
            sender_quiesced: true,
            backend_quiesced: true,
            actor: "adopter".into(),
            reason: "all old senders disarmed and backend mutations settled".into(),
        };
        let cost = crate::cost::CostModel::flat(0);
        sink.lose_adoption_reply.store(true, Ordering::Relaxed);
        assert!(matches!(
            gov.recovery().resolve(&cost, resolution.clone()),
            Err(RecoveryError::Unavailable(_))
        ));
        assert_eq!(
            store.get_usage("recovery-bucket", 0).unwrap().requests,
            0,
            "a selected adoption with an unknown reply cannot authorize local backend effects yet"
        );
        assert!(sink.inspect_foreign().unwrap().is_empty());
        let settled = gov.recovery().resolve(&cost, resolution.clone()).unwrap();
        assert_eq!(settled.state, RecoveryState::Settled);
        assert_eq!(settled.owner_node, None);
        assert_eq!(store.get_usage("recovery-bucket", 0).unwrap().requests, 7);
        let attempts = sink.adoption_attempts.lock().unwrap().clone();
        assert_eq!(attempts.len(), 2);
        assert_eq!(
            attempts[0], attempts[1],
            "retry must retain exact child IDs and raw candidate bytes"
        );
        gov.recovery().resolve(&cost, resolution).unwrap();
        assert_eq!(store.get_usage("recovery-bucket", 0).unwrap().requests, 7);
    }

    #[test]
    fn foreign_reaffirmation_preserves_original_decision_audit_and_rejects_opposite_choice() {
        use super::super::{GovState, RecordStore};
        let store = crate::real_store::store();
        let sink = Arc::new(Journal::default());
        let original = GovState::new(store.clone(), None).unwrap();
        original.attach_recovery_sink(sink.clone()).unwrap();
        let intent = raw_intent(&original, 7);
        let unknown = intent
            .checkpoint(RecoveryState::LandedUnknown, intent.payload.clone())
            .unwrap();
        original.keep_recovery_event(&unknown).unwrap();
        let old_resolution = RecoveryResolution {
            operation_id: intent.operation_id,
            body_fingerprint: intent.body_fingerprint,
            expected_revision: unknown.revision,
            verdict: RecoveryVerdict::NotLanded,
            sender_quiesced: true,
            backend_quiesced: true,
            actor: "original-operator".into(),
            reason: "original not-landed verdict".into(),
        };
        let verdict = GovState::stage_foreign_raw_verdict(&unknown, &old_resolution)
            .unwrap()
            .pop()
            .unwrap();
        original.keep_recovery_event(&verdict).unwrap();
        sink.make_foreign(intent.operation_id, 23);
        drop(original);
        let gov = GovState::new(store.clone(), None).unwrap();
        gov.attach_recovery_sink(sink.clone()).unwrap();
        let mut adoption = RecoveryResolution {
            expected_revision: verdict.revision,
            actor: "new-operator".into(),
            reason: "new ownership attestation".into(),
            ..old_resolution
        };
        let cost = crate::cost::CostModel::flat(0);
        adoption.verdict = RecoveryVerdict::Landed;
        assert!(matches!(
            gov.recovery().resolve(&cost, adoption.clone()),
            Err(RecoveryError::Conflict(_))
        ));
        assert!(sink.adoption_attempts.lock().unwrap().is_empty());
        adoption.verdict = RecoveryVerdict::NotLanded;
        gov.recovery().resolve(&cost, adoption.clone()).unwrap();
        let selected = gov.recovery_event(intent.operation_id).unwrap();
        let raw: serde_json::Value = serde_json::from_slice(&selected.payload).unwrap();
        assert_eq!(raw["verdict"]["actor"], "original-operator");
        assert_eq!(raw["verdict"]["reason"], "original not-landed verdict");
        assert_eq!(
            sink.adoption_attempts.lock().unwrap()[0].0.actor,
            "new-operator"
        );
        gov.recovery().resolve(&cost, adoption).unwrap();
        assert_eq!(store.get_usage("recovery-bucket", 0).unwrap().requests, 7);
    }
    #[test]
    fn foreign_settled_child_is_observed_as_receipt_without_adoption_or_reposting() {
        use super::super::{GovState, RecordStore};
        let store = crate::real_store::store();
        let sink = Arc::new(Journal::default());
        let original = GovState::new(store.clone(), None).unwrap();
        original.attach_recovery_sink(sink.clone()).unwrap();
        let intent = raw_intent(&original, 1);
        store
            .add_usage_batch_deduped(
                busbar_contract::abi::store::OpId(intent.operation_id),
                &[(
                    "recovery-bucket",
                    0,
                    super::super::UsageDelta {
                        requests: 1,
                        ..Default::default()
                    },
                )],
            )
            .unwrap();
        let child = GovState::usage_recovery_child(
            "receipt-child",
            0,
            super::super::ExactUsageDelta {
                requests: 7,
                ..Default::default()
            },
            Default::default(),
        )
        .unwrap()
        .unwrap();
        let mut custody: super::super::raw_recovery::UsageCustody =
            serde_json::from_slice(&intent.payload).unwrap();
        custody.plain = Default::default();
        custody.handoffs.push(child.clone());
        let applied = original
            .new_recovery_event(
                intent.operation_id,
                intent.kind,
                intent.body_fingerprint,
                RecoveryState::Applied,
                intent.first_sent_at_ms,
                serde_json::to_vec(&custody).unwrap(),
            )
            .unwrap();
        original.keep_recovery_event(&applied).unwrap();
        original.drive_recovery_children(&applied).unwrap();
        original.drive_raw_recovery(child.operation_id).unwrap();
        assert_eq!(store.get_usage("receipt-child", 0).unwrap().requests, 7);
        sink.make_foreign(child.operation_id, 42);
        drop(original);

        let gov = GovState::new(store.clone(), None).unwrap();
        gov.attach_recovery_sink(sink.clone()).unwrap();
        assert!(gov.recovery_event(child.operation_id).is_none());
        gov.resume_raw_recovery().unwrap();
        let settled = gov.recovery_event(intent.operation_id).unwrap();
        assert_eq!(settled.state, RecoveryState::Settled);
        assert!(gov.recovery_children_settled(&settled).unwrap());
        gov.resume_recovery_children(&settled).unwrap();
        assert!(
            gov.recovery_event(child.operation_id).is_none(),
            "readonly receipt grants no child write ownership"
        );
        assert!(sink.adoption_attempts.lock().unwrap().is_empty());
        assert_eq!(store.get_usage("receipt-child", 0).unwrap().requests, 7);
    }
    #[test]
    fn many_selected_revisions_keep_endpoints_and_verify_old_checkpoints_cold() {
        use super::super::{GovState, RecordStore};
        let store = crate::real_store::store();
        let sink = Arc::new(Journal::default());
        let gov = GovState::new(store.clone(), None).unwrap();
        gov.attach_recovery_sink(sink.clone()).unwrap();
        let initial = raw_intent(&gov, 7);
        let mut current = initial.clone();
        let mut old = None;
        for revision in 1..=256 {
            current = gov
                .new_recovery_event(
                    current.operation_id,
                    current.kind,
                    current.body_fingerprint,
                    RecoveryState::Intent,
                    current.first_sent_at_ms,
                    current.payload.clone(),
                )
                .unwrap();
            gov.keep_recovery_event(&current).unwrap();
            if revision == 64 {
                old = Some(current.clone());
            }
        }
        let old = old.unwrap();
        assert_eq!(
            gov.recovery_initial_event(initial.operation_id),
            Some(initial.clone())
        );
        assert_eq!(gov.recovery_event(initial.operation_id), Some(current));
        assert!(
            gov.recovery_ancestor(initial.operation_id, old.fingerprint().unwrap())
                .is_none(),
            "historical payloads are not retained in the live per-operation Book"
        );
        gov.verify_recovery_checkpoint(&old).unwrap();
        let owned = gov.recovery_book.entries.lock().unwrap();
        let entry = owned.get(&initial.operation_id).unwrap();
        assert!(entry.pending.is_none() && entry.adoption.is_none());
        assert_eq!(entry.initial.as_ref(), Some(&initial));
        drop(owned);
        assert_eq!(
            store.get_usage("recovery-bucket", 0).unwrap().requests,
            0,
            "ancestry verification performs no usage effect"
        );
    }

    #[test]
    fn compatibility_selection_and_checkpoint_proofs_reject_unselected_forks_and_gaps() {
        let sink = Journal::default();
        let initial = intent();
        let applied = successor(&initial, RecoveryState::Applied);
        let settled = successor(&applied, RecoveryState::Settled);
        *sink.selected.lock().unwrap() = vec![initial.clone(), applied.clone(), settled.clone()];
        let selections = sink.replay_selections().unwrap();
        assert_eq!(
            selections,
            vec![RecoverySelection {
                initial: initial.clone(),
                selected: settled
            }]
        );
        sink.verify_checkpoint(&applied).unwrap();
        let unselected = successor(&initial, RecoveryState::LandedUnknown);
        assert!(
            matches!(
                sink.verify_checkpoint(&unselected),
                Err(RecoveryError::Conflict(_))
            ),
            "an otherwise legal journal candidate is not current selected ancestry"
        );
        let gap = RecoveryEvent {
            revision: 2,
            ..applied
        };
        *sink.selected.lock().unwrap() = vec![initial, gap];
        assert!(
            matches!(sink.replay_selections(), Err(RecoveryError::Invalid(_))),
            "matching initial/current identity cannot replace full legal predecessor verification"
        );
    }
}
