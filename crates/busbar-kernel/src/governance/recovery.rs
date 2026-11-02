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

    /// Foreign custody is visible without granting this process any write or send authority.
    fn inspect_foreign(&self) -> Result<Vec<RecoveryInspection>, RecoveryError> {
        Ok(Vec::new())
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

    pub fn follows(&self, previous: Option<&Self>) -> Result<(), RecoveryError> {
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
}

#[derive(Default)]
struct RecoveryEntry {
    selected: Option<RecoveryEvent>,
    history: std::collections::BTreeMap<[u8; 32], RecoveryEvent>,
    pending: Option<RecoveryEvent>,
    runner: std::sync::Arc<super::BudgetFlushRunner>,
    resolution_runner: std::sync::Arc<super::BudgetFlushRunner>,
    driver: std::sync::Arc<super::BudgetFlushRunner>,
    sent_clock: Option<std::time::Instant>,
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
        // The sink returns only selected predecessor chains. Reject omissions,
        // forks and reordered revisions rather than reconstructing aggregate rows.
        let events = sink.replay()?;
        let mut replayed = std::collections::BTreeMap::<[u8; 16], RecoveryEntry>::new();
        for event in events {
            let entry = replayed.entry(event.operation_id).or_default();
            if entry.selected.as_ref() == Some(&event) {
                continue;
            }
            event.follows(entry.selected.as_ref())?;
            entry.history.insert(event.fingerprint()?, event.clone());
            entry.selected = Some(event);
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
        entry.history.insert(event.fingerprint()?, event.clone());
        entry.selected = entry.pending.take();
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
            .get(&resolution.operation_id)
            .ok_or_else(|| RecoveryError::Invalid("recovery operation does not exist".into()))?
            .resolution_runner
            .clone();
        let _running = runner
            .enter(false)
            .map_err(|reason| RecoveryError::Conflict(reason.into()))?;
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
        Ok(self
            .governance
            .recovery_book
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|(id, _)| after.is_none_or(|after| **id > after))
            .filter_map(|(_, entry)| entry.selected.as_ref())
            .filter(|event| event.state != RecoveryState::Settled)
            .take(limit)
            .map(RecoveryItem::from_event)
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
        for event in self.selected_recovery_events() {
            self.drive_recovery_children(&event)?;
        }
        self.resume_raw_recovery()?;
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
            || entry.history.values().any(|event| {
                !matches!(
                    event.state,
                    RecoveryState::Intent | RecoveryState::Applied | RecoveryState::Settled
                )
            })
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
            .and_then(|entry| entry.history.values().find(|event| event.revision == 0))
            .cloned()
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
            .and_then(|entry| entry.history.get(&fingerprint))
            .cloned()
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
pub(super) struct RecoveryOrigin {
    pub(super) operation_id: [u8; 16],
    pub(super) event_fingerprint: [u8; 32],
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
    }
    impl RecoverySink for Journal {
        fn replay(&self) -> Result<Vec<RecoveryEvent>, RecoveryError> {
            Ok(self.selected.lock().unwrap().clone())
        }
        fn persist(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
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
        use super::super::{GovState, MemoryStore, RecordStore};
        let store = Arc::new(MemoryStore::new());
        let sink = Arc::new(Journal::default());
        let first = GovState::new(store.clone(), None).unwrap();
        first.attach_recovery_sink(sink.clone()).unwrap();
        let intent = raw_intent(&first, 7);
        assert_eq!(
            first.recovery_retention_expired(intent.operation_id),
            Some(false)
        );
        drop(first);
        let restarted = GovState::new(store.clone(), None).unwrap();
        restarted.attach_recovery_sink(sink).unwrap();
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
        use super::super::{GovState, MemoryStore, RecordStore};
        let store = Arc::new(MemoryStore::new());
        let sink = Arc::new(Journal::default());
        let original = GovState::new(store.clone(), None).unwrap();
        original.attach_recovery_sink(sink.clone()).unwrap();
        let intent = raw_intent(&original, 7);
        drop(original);
        let gov = GovState::new(store.clone(), None).unwrap();
        gov.attach_recovery_sink(sink).unwrap();
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
        use super::super::{GovState, MemoryStore, RecordStore};
        let store = Arc::new(MemoryStore::new());
        let sink = Arc::new(Journal::default());
        let first = GovState::new(store.clone(), None).unwrap();
        first.attach_recovery_sink(sink.clone()).unwrap();
        let intent = raw_intent(&first, 1);
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
        let restored = restarted.recovery_event(child.operation_id).unwrap();
        assert_eq!(restored.body_fingerprint, child.body_fingerprint);
        assert_eq!(store.get_usage("child-bucket", 0).unwrap().requests, 7);
        restarted.resume_raw_recovery().unwrap();
        assert_eq!(store.get_usage("child-bucket", 0).unwrap().requests, 7);
    }
    #[test]
    fn two_unknown_positives_cannot_release_each_others_dependent_negatives() {
        use super::super::{GovState, MemoryStore, RecordStore};
        let store = Arc::new(MemoryStore::new());
        let sink = Arc::new(Journal::default());
        let original = GovState::new(store.clone(), None).unwrap();
        original.attach_recovery_sink(sink.clone()).unwrap();
        let first = raw_intent(&original, 7);
        let second = raw_intent(&original, 11);
        drop(original);
        let gov = GovState::new(store.clone(), None).unwrap();
        gov.attach_recovery_sink(sink).unwrap();
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
        use super::super::{GovState, MemoryStore, RecordStore};
        let store = Arc::new(MemoryStore::new());
        let sink = Arc::new(Journal::default());
        let original = GovState::new(store.clone(), None).unwrap();
        original.attach_recovery_sink(sink.clone()).unwrap();
        let intent = raw_intent(&original, i128::from(u64::MAX));
        drop(original);
        let gov = GovState::new(store.clone(), None).unwrap();
        gov.attach_recovery_sink(sink).unwrap();
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
        use super::super::{GovState, MemoryStore, RecordStore};
        let store = Arc::new(MemoryStore::new());
        let sink = Arc::new(Journal::default());
        let original = GovState::new(store.clone(), None).unwrap();
        original.attach_recovery_sink(sink.clone()).unwrap();
        let intent = raw_intent(&original, 7);
        drop(original);
        let gov = GovState::new(store.clone(), None).unwrap();
        gov.attach_recovery_sink(sink.clone()).unwrap();
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
        use super::super::{GovState, MemoryStore};
        let sink = Arc::new(Journal::default());
        let original = GovState::new(Arc::new(MemoryStore::new()), None).unwrap();
        original.attach_recovery_sink(sink.clone()).unwrap();
        let intent = raw_intent(&original, 7);
        drop(original);
        let gov = GovState::new(Arc::new(MemoryStore::new()), None).unwrap();
        gov.attach_recovery_sink(sink.clone()).unwrap();
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
        use super::super::{GovState, MemoryStore, RecordStore};
        let store = Arc::new(MemoryStore::new());
        let sink = Arc::new(Journal::default());
        let gov = GovState::new(store.clone(), None).unwrap();
        gov.attach_recovery_sink(sink.clone()).unwrap();
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
        assert!(restarted.recovery_event(intent.operation_id).is_none());
        assert_eq!(store.get_usage("recovery-bucket", 0).unwrap().requests, 7);
        assert_eq!(sink.selected.lock().unwrap().len(), journal_len);
    }

    #[test]
    fn retiring_live_or_unknown_custody_cannot_discard_its_authority() {
        use super::super::{GovState, MemoryStore};
        let sink = Arc::new(Journal::default());
        let original = GovState::new(Arc::new(MemoryStore::new()), None).unwrap();
        original.attach_recovery_sink(sink.clone()).unwrap();
        let intent = raw_intent(&original, 7);
        original.forget_confirmed_recovery(intent.operation_id);
        assert_eq!(
            original.recovery_event(intent.operation_id),
            Some(intent.clone())
        );
        drop(original);
        let gov = GovState::new(Arc::new(MemoryStore::new()), None).unwrap();
        gov.attach_recovery_sink(sink).unwrap();
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
}
