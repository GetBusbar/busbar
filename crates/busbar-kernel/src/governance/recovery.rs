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
#[async_trait::async_trait]
pub trait RecoverySink: Send + Sync {
    async fn persist(&self, event: &RecoveryEvent) -> Result<(), RecoveryError>;
    async fn replay(&self) -> Result<Vec<RecoveryEvent>, RecoveryError>;

    /// Return one bounded summary per operation only AFTER verifying its complete
    async fn replay_selections(&self) -> Result<Vec<RecoverySelection>, RecoveryError> {
        summarize_recovery_chains(self.replay().await?)
    }

    /// Confirm exact membership in the CURRENT selected predecessor chain. An
    async fn verify_checkpoint(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        let events = self.replay().await?;
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

    /// Confirm exact selected ancestry AND current ownership by this sink. The
    async fn confirm_owned_checkpoint(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        let events = self.replay().await?;
        let present = events.iter().any(|selected| selected == event);
        summarize_recovery_chains(events)?;
        if present {
            Ok(())
        } else {
            Err(RecoveryError::Conflict(
                "recovery checkpoint is not in currently owned selected ancestry".into(),
            ))
        }
    }

    /// Adopt through the same full ancestry proof, retaining only its verified
    async fn adopt_verdict_selection(
        &self,
        resolution: &RecoveryResolution,
        transitions: &[RecoveryEvent],
    ) -> Result<RecoverySelection, RecoveryError> {
        let mut selections =
            summarize_recovery_chains(self.adopt_verdict(resolution, transitions).await?)?;
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
    async fn inspect_foreign(&self) -> Result<Vec<RecoveryInspection>, RecoveryError> {
        Ok(Vec::new())
    }

    /// Verify a child's immutable origin against the parent's currently selected
    async fn verify_origin(&self, _event: &RecoveryEvent) -> Result<(), RecoveryError> {
        Err(RecoveryError::Unavailable(
            "recovery Store cannot verify external child origin".into(),
        ))
    }

    /// Select a fully journaled, audited ownership handover in one exact head CAS.
    async fn adopt_verdict(
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
    crate::off_path::governance::runtime::recovery_summarize_chains(events)
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
        let mut digest = crate::hashing::Sha256::new();
        digest.update(b"busbar.usage-recovery.event.v1\0");
        busbar_contract::json::to_writer(super::DigestWriter(&mut digest), self).map_err(
            |error| {
                super::rendered_error(
                    RecoveryError::Invalid,
                    format_args!("invalid recovery event: {error}"),
                )
            },
        )?;
        Ok(digest.finalize())
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
pub(crate) struct RecoveryEntry {
    initial: Option<RecoveryEvent>,
    pub(crate) selected: Option<RecoveryEvent>,
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

impl RecoveryEntry {
    /// Whether this operation still holds custody work: a pending candidate, an unimported
    /// adoption, an unsettled selection or a running driver.
    pub(crate) fn unsettled(&self) -> bool {
        self.pending.is_some()
            || self
                .adoption
                .as_ref()
                .is_some_and(|adoption| !adoption.imported)
            || self
                .selected
                .as_ref()
                .is_some_and(|event| event.state != RecoveryState::Settled)
            || self.runner.is_running()
            || self.resolution_runner.is_running()
            || self.driver.is_running()
    }

    /// SHUTDOWN-HANG §5: a staged original not yet confirmed is `in_doubt`; a selected operation
    /// not yet Settled is durable custody the adopter settles.
    pub(crate) fn custody(&self) -> (bool, bool) {
        let staged = self.pending.is_some() || self.runner.is_running() || self.driver.is_running();
        let selected = self
            .selected
            .as_ref()
            .is_some_and(|event| event.state != RecoveryState::Settled);
        (staged, selected)
    }
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

    async fn replay(&self, sink: std::sync::Arc<dyn RecoverySink>) -> Result<(), RecoveryError> {
        let _attaching = self
            .attaching
            .enter(false)
            .await
            .map_err(|reason| RecoveryError::Conflict(reason.into()))?;
        if self.attached() {
            return Err(RecoveryError::Conflict(
                "recovery sink already attached".into(),
            ));
        }

        let selections = sink.replay_selections().await?;
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
            entry.sent_clock = Some(crate::cold::governance::runtime::recovery_first_send_clock());
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

    async fn keep(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        let sink = self
            .sink
            .get()
            .ok_or_else(|| RecoveryError::Unavailable("recovery Store is not attached".into()))?;
        let runner = {
            let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
            let entry = entries.entry(event.operation_id).or_default();
            // Already selected with nothing pending: re-persisting would only
            // re-read the head and replay history to prove a selection this
            // book already holds. Every later write (a child selection, a
            // successor) still runs its own guarded `persist`, so a takeover
            // fails closed there.
            if entry.selected.as_ref() == Some(event) && entry.pending.is_none() {
                return Ok(());
            }
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
            .await
            .map_err(|reason| RecoveryError::Conflict(reason.into()))?;

        sink.persist(event).await?;
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
    pub(crate) fn from_event(event: &RecoveryEvent) -> Self {
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
    pub async fn resolve(
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
            .await
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
                    .await
                    .map_err(|error| {
                        crate::governance::rendered_error(RecoveryError::Unavailable, error)
                    })?;
                return self.resume_adopted(cost, resolution.operation_id).await;
            }
            return self.adopt_foreign(cost, resolution, cached.clone()).await;
        }
        if cached.as_ref().is_some_and(|cached| !cached.imported) {
            return Err(RecoveryError::Conflict(
                "an immutable foreign adoption still awaits confirmation".into(),
            ));
        }
        let inspections = governance.inspect_foreign_recovery().await?;
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
            return self.adopt_foreign(cost, resolution, adoption).await;
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
                governance
                    .resolve_correction_recovery(cost, &resolution)
                    .await?
            }
            RecoveryKind::Usage | RecoveryKind::Metering => {
                governance.resolve_raw_recovery(&resolution).await?
            }
        }
        let event = governance
            .recovery_event(resolution.operation_id)
            .ok_or_else(|| RecoveryError::Unavailable("recovery selection disappeared".into()))?;
        Ok(RecoveryItem::from_event(&event))
    }

    async fn adopt_foreign(
        &self,
        cost: &crate::cost::CostModel,
        resolution: RecoveryResolution,
        adoption: RecoveryAdoption,
    ) -> Result<RecoveryItem, RecoveryError> {
        let governance = self.governance;
        let driver = governance
            .recovery_driver(resolution.operation_id)
            .map_err(|error| {
                crate::governance::rendered_error(RecoveryError::Unavailable, error)
            })?;
        let running = driver
            .enter(false)
            .await
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
        let selection = match sink
            .adopt_verdict_selection(&resolution, &adoption.transitions)
            .await
        {
            Ok(selection) => selection,
            Err(error) => {
                if matches!(error, RecoveryError::Conflict(_)) {
                    governance.clear_unselected_adoption(&resolution);
                }
                return Err(error);
            }
        };
        governance
            .import_adopted_recovery(&adoption, selection)
            .await?;
        let selected = governance
            .recovery_event(resolution.operation_id)
            .ok_or_else(|| {
                RecoveryError::Unavailable("adopted recovery selection disappeared".into())
            })?;
        governance
            .validate_recovery_origin(&selected)
            .await
            .map_err(|error| crate::governance::rendered_error(RecoveryError::Invalid, error))?;
        match selected.kind {
            RecoveryKind::Correction => governance.restore_correction_recovery(&selected),
            RecoveryKind::Usage | RecoveryKind::Metering => {
                governance.restore_raw_recovery(&selected)
            }
        }
        .map_err(|error| crate::governance::rendered_error(RecoveryError::Invalid, error))?;
        drop(correction_guard);
        drop(running);
        self.resume_adopted(cost, resolution.operation_id).await
    }

    async fn resume_adopted(
        &self,
        cost: &crate::cost::CostModel,
        operation_id: [u8; 16],
    ) -> Result<RecoveryItem, RecoveryError> {
        let governance = self.governance;
        let event = governance.recovery_event(operation_id).ok_or_else(|| {
            RecoveryError::Unavailable("adopted recovery selection disappeared".into())
        })?;
        match event.kind {
            RecoveryKind::Correction => {
                Box::pin(governance.resume_adopted_correction(cost, operation_id)).await?
            }
            RecoveryKind::Usage | RecoveryKind::Metering => {
                governance
                    .drive_raw_recovery(operation_id)
                    .await
                    .map_err(|error| {
                        crate::governance::rendered_error(RecoveryError::Unavailable, error)
                    })?;
                let current = governance.recovery_event(operation_id).ok_or_else(|| {
                    RecoveryError::Unavailable("adopted recovery selection disappeared".into())
                })?;
                governance
                    .resume_recovery_children(&current)
                    .await
                    .map_err(|error| {
                        crate::governance::rendered_error(RecoveryError::Unavailable, error)
                    })?;
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

    pub async fn list(
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
        let local = self.governance.selected_recovery_events();
        let foreign = self.governance.inspect_foreign_recovery().await?;
        Ok(crate::off_path::governance::runtime::recovery_list_page(
            local, foreign, after, limit,
        ))
    }
}

impl super::GovState {
    /// `(staged, selected)` counts of recovery custody at a non-retired exit (SHUTDOWN-HANG §5).
    pub(super) fn recovery_custody_counts(&self) -> (usize, usize) {
        let entries = self
            .recovery_book
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        crate::off_path::governance::runtime::recovery_custody_counts(entries.values())
    }

    pub(super) fn has_unsettled_recovery(&self) -> bool {
        self.recovery_book.attaching.is_running()
            || crate::off_path::governance::runtime::recovery_any_unsettled(
                self.recovery_book
                    .entries
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .values(),
            )
    }
    /// A terminal unit can outlive an ACK when its named checkpoint deletion was interrupted.
    /// Reload that exact receipt even when ordinary settled-root pruning dropped its RAM cache.
    pub(super) async fn restore_unit_terminal_receipt(
        &self,
        initial: &RecoveryEvent,
    ) -> super::RecordStoreResult<()> {
        if self.recovery_event(initial.operation_id).is_some() {
            return Ok(());
        }
        if self
            .recovery_book
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&initial.operation_id)
            .is_some_and(|entry| entry.pending.as_ref() == Some(initial))
        {
            // A freshly staged local operation (or an ambiguous initial ACK) can select its exact
            // retained candidate directly. Historical receipt scans are only a restart fallback.
            return Ok(());
        }
        let sink = self.recovery_book.sink.get().ok_or_else(|| {
            super::RecordStoreError("unit terminal receipt has no recovery Store".into())
        })?;
        let selected = sink
            .replay_selections()
            .await
            .map_err(crate::governance::store_error)?
            .into_iter()
            .find(|selection| selection.initial.operation_id == initial.operation_id);
        let Some(selection) = selected else {
            return Ok(());
        };
        selection
            .validate_identity()
            .map_err(crate::governance::store_error)?;
        if selection.initial != *initial {
            return Err(super::RecordStoreError(
                "unit terminal receipt differs from its persisted intent".into(),
            ));
        }
        let mut entries = self
            .recovery_book
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let entry = entries.entry(initial.operation_id).or_default();
        if entry.selected.is_none() {
            if entry
                .pending
                .as_ref()
                .is_some_and(|pending| pending != initial)
            {
                return Err(super::RecordStoreError(
                    "another unit terminal candidate is pending".into(),
                ));
            }
            entry.pending = None;
            entry.ever_quarantined = selection.selected.revision > 2
                || matches!(
                    selection.selected.state,
                    RecoveryState::LandedUnknown
                        | RecoveryState::VerdictLanded
                        | RecoveryState::VerdictNotLanded
                );
            entry.initial = Some(selection.initial);
            entry.selected = Some(selection.selected);
            self.recovery_book
                .selection_epoch
                .fetch_add(1, std::sync::atomic::Ordering::Release);
        }
        Ok(())
    }

    pub async fn attach_recovery_sink(
        &self,
        sink: std::sync::Arc<dyn RecoverySink>,
    ) -> super::RecordStoreResult<()> {
        self.recovery_book
            .replay(sink)
            .await
            .map_err(crate::governance::store_error)?;
        for event in self.selected_recovery_events() {
            self.validate_recovery_origin(&event).await?;
            match event.kind {
                RecoveryKind::Correction => self.restore_correction_recovery(&event)?,
                RecoveryKind::Usage | RecoveryKind::Metering => {
                    self.restore_raw_recovery(&event)?
                }
            }
        }

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
        crate::off_path::governance::runtime::recovery_selected_events(
            self.recovery_book
                .entries
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .values(),
        )
    }

    /// Move an operation's first send from this process `by` into the past.
    #[cfg(test)]
    pub(super) fn backdate_recovery_send(&self, operation_id: [u8; 16], by: std::time::Duration) {
        let mut entries = self
            .recovery_book
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let entry = entries
            .get_mut(&operation_id)
            .expect("a selected operation");
        let sent = entry.sent_clock.expect("sent from this process");
        entry.sent_clock = Some(sent.checked_sub(by).expect("a representable instant"));
    }

    /// Whether this process sent the operation, so it may resend it: its slot is held until it
    /// settles, however long ago it was sent. After a restart the send is unknown here and the
    /// operation lands unknown (a fact about custody, not a time rule).
    pub(super) fn recovery_sent_here(&self, operation_id: [u8; 16]) -> bool {
        self.recovery_book
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&operation_id)
            .is_some_and(|entry| entry.sent_clock.is_some())
    }

    pub(super) async fn confirm_pending_recovery(
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
            self.keep_recovery_event(&event).await?;
        }
        Ok(())
    }

    /// Local successful roots need no live administrative custody after their
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
        let Ok(payload) = busbar_contract::json::parse::<RootCustody>(&event.payload) else {
            return;
        };
        if payload.origin.is_some() || !payload.handoffs.is_empty_list() {
            return;
        }
        entries.remove(&operation_id);
        self.recovery_book
            .selection_epoch
            .fetch_add(1, std::sync::atomic::Ordering::Release);
    }

    pub(super) async fn verify_external_recovery_origin(
        &self,
        event: &RecoveryEvent,
    ) -> super::RecordStoreResult<()> {
        self.recovery_book
            .sink
            .get()
            .ok_or_else(|| super::RecordStoreError("recovery Store is not attached".into()))?
            .verify_origin(event)
            .await
            .map_err(crate::governance::store_error)
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

    pub(super) async fn inspect_foreign_recovery(
        &self,
    ) -> Result<Vec<RecoveryInspection>, RecoveryError> {
        self.recovery_book
            .sink
            .get()
            .ok_or_else(|| RecoveryError::Unavailable("recovery Store is not attached".into()))?
            .inspect_foreign()
            .await
    }

    async fn import_adopted_recovery(
        &self,
        adoption: &RecoveryAdoption,
        selection: RecoverySelection,
    ) -> Result<(), RecoveryError> {
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
                self.recovery_book
                    .sink
                    .get()
                    .ok_or_else(|| {
                        RecoveryError::Unavailable("recovery Store is not attached".into())
                    })?
                    .verify_checkpoint(previous)
                    .await?;
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

    pub(super) async fn foreign_recovery_receipt(
        &self,
        operation_id: [u8; 16],
    ) -> Result<Option<RecoveryEvent>, RecoveryError> {
        let Some(receipt) = self
            .inspect_foreign_recovery()
            .await?
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
            .verify_origin(&receipt.event)
            .await?;
        Ok(Some(receipt.event))
    }

    pub(super) async fn confirm_owned_recovery_checkpoint(
        &self,
        event: &RecoveryEvent,
    ) -> super::RecordStoreResult<()> {
        self.recovery_book
            .sink
            .get()
            .ok_or_else(|| super::RecordStoreError("recovery Store is not attached".into()))?
            .confirm_owned_checkpoint(event)
            .await
            .map_err(crate::governance::store_error)
    }

    pub(super) async fn verify_current_recovery_checkpoint(
        &self,
        event: &RecoveryEvent,
    ) -> super::RecordStoreResult<()> {
        self.recovery_book
            .sink
            .get()
            .ok_or_else(|| super::RecordStoreError("recovery Store is not attached".into()))?
            .verify_checkpoint(event)
            .await
            .map_err(crate::governance::store_error)
    }

    pub(super) async fn verify_recovery_checkpoint(
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
            .await
            .map_err(crate::governance::store_error)
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

    pub(super) async fn keep_recovery_event(
        &self,
        event: &RecoveryEvent,
    ) -> super::RecordStoreResult<()> {
        self.recovery_book
            .keep(event)
            .await
            .map_err(crate::governance::store_error)
    }
}

/// A sealed child template authorized by one selected parent checkpoint. The
/// Identity and actual native-clock birth fixed by the core migration adopter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MigratedChildContext {
    pub(crate) seed: [u8; 32],
    pub(crate) created_at_ms: u64,
}
impl MigratedChildContext {
    pub(super) fn identify(
        &self,
        parent: [u8; 16],
        child: &mut RecoveryChild,
        ordinal: usize,
    ) -> Result<(), RecoveryError> {
        use crate::hashing::Sha256;
        let mut hash = Sha256::new();
        hash.update(b"busbar.recovery.imported-unsent-child/1\0");
        hash.update(self.seed);
        hash.update(parent);
        hash.update((ordinal as u64).to_be_bytes());
        hash.update(child.body_fingerprint);
        hash.update([match child.kind {
            RecoveryKind::Usage => 1,
            RecoveryKind::Metering => 2,
            RecoveryKind::Correction => 3,
        }]);
        let digest: [u8; 32] = hash.finalize();
        let operation: [u8; 16] = digest[..16].try_into().expect("fixed digest");
        if operation == [0; 16] || operation == parent {
            return Err(RecoveryError::Invalid(
                "migrated child identity collision".into(),
            ));
        }
        child.operation_id = operation;
        child.first_sent_at_ms = Some(self.created_at_ms);
        Ok(())
    }
}

/// child origin is derived AFTER selection, avoiding a circular event hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryChild {
    pub(crate) operation_id: [u8; 16],
    pub(crate) kind: RecoveryKind,
    pub(crate) body_fingerprint: [u8; 32],
    pub(super) first_sent_at_ms: Option<u64>,
    pub(crate) payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryOrigin {
    pub operation_id: [u8; 16],
    pub event_fingerprint: [u8; 32],
}

/// The two facts a settled root's payload is read for, decoded without building a JSON tree:
/// whether it names a non-null `origin`, and whether `handoffs` is an empty list. Every other
/// field is skipped.
#[derive(Deserialize)]
struct RootCustody {
    #[serde(default)]
    origin: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    handoffs: Handoffs,
}

/// The shape of a payload's `handoffs` value: an empty list, or anything else (absent, null, a
/// non-empty list or another type).
#[derive(Default)]
enum Handoffs {
    EmptyList,
    #[default]
    Other,
}

impl Handoffs {
    fn is_empty_list(&self) -> bool {
        matches!(self, Self::EmptyList)
    }
}

impl<'de> Deserialize<'de> for Handoffs {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};
        struct Shape;
        impl<'de> Visitor<'de> for Shape {
            type Value = Handoffs;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Handoffs, A::Error> {
                let empty = seq.next_element::<IgnoredAny>()?.is_none();
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(if empty {
                    Handoffs::EmptyList
                } else {
                    Handoffs::Other
                })
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Handoffs, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(Handoffs::Other)
            }
            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Handoffs, E> {
                Ok(Handoffs::Other)
            }
            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Handoffs, E> {
                Ok(Handoffs::Other)
            }
            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Handoffs, E> {
                Ok(Handoffs::Other)
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Handoffs, E> {
                Ok(Handoffs::Other)
            }
            fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Handoffs, E> {
                Ok(Handoffs::Other)
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Handoffs, E> {
                Ok(Handoffs::Other)
            }
        }
        deserializer.deserialize_any(Shape)
    }
}

#[cfg(test)]
#[path = "tests/recovery_tests.rs"]
pub(in crate::governance) mod tests;
