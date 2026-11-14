// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Running unit custody. Reports replace a hot snapshot; only the existing usage flush tick
//! writes it. A terminal snapshot owns exact raw operation identities until their durable ACKs.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use busbar_contract::Count;
use busbar_kernel_ledger::cost::{EntryId, RawRateEra};
use serde::{Deserialize, Serialize};

use super::recovery::{RecoveryEvent, RecoveryState};
use super::{GovState, RecordStoreError, RecordStoreResult};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitTarget {
    pub bucket: String,
    pub window: u64,
    pub group: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitCheckpoint {
    pub id: [u8; 16],
    pub revision: u64,
    pub unit: u64,
    pub principal: String,
    pub group: String,
    pub arrived: u64,
    pub lane: String,
    pub provider: Option<String>,
    pub era_at: u64,
    pub era_entry: Option<[u8; 12]>,
    pub units: BTreeMap<String, Count>,
    pub targets: Vec<UnitTarget>,
    pub metered: bool,
    pub ended: bool,
    pub terminal: Option<Vec<RecoveryEvent>>,
    pub audit: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measurement: Option<crate::host_measurement::MeasurementEvidence>,
    /// The provider answered but its final stated usage was not billed: the `ReasonCode` name that
    /// ended the unit first (`BUSBAR-5046`). Absent when nothing went unread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unread: Option<String>,
}

impl UnitCheckpoint {
    pub fn validate(&self) -> RecordStoreResult<()> {
        if let Some(evidence) = &self.measurement {
            evidence
                .validate(self)
                .map_err(|_| error("invalid host measurement origin"))?;
        }
        if self.principal.is_empty()
            || self
                .units
                .iter()
                .any(|(class, count)| class.is_empty() || count.is_negative())
        {
            return Err(error("invalid running money principal or quantity"));
        }
        let mut targets = std::collections::BTreeSet::new();
        if self.targets.iter().any(|target| {
            target.bucket.is_empty() || !targets.insert((&target.bucket, target.window))
        }) {
            return Err(error("duplicate or empty running money target"));
        }
        if let Some(events) = &self.terminal {
            if !self.ended {
                return Err(error("running checkpoint contains terminal operations"));
            }
            let mut operations = std::collections::BTreeSet::new();
            for event in events {
                event.follows(None).map_err(|e| failed(&e))?;
                if !operations.insert(event.operation_id) {
                    return Err(error("duplicate unit terminal operation"));
                }
            }
        }
        Ok(())
    }

    pub fn era(&self) -> RawRateEra {
        RawRateEra {
            effective_from: self.era_at,
            entry_id: self.era_entry.map(EntryId),
        }
    }
}

/// The root implements this with kernel-owned named Store slots and journal evidence.
#[async_trait::async_trait]
pub trait UnitCheckpointSink: Send + Sync {
    async fn persist(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()>;
    async fn remove(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()>;
    async fn replay(&self) -> RecordStoreResult<Vec<UnitCheckpoint>>;
    async fn recover_audit(&self, _snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        Ok(())
    }
}

mod book;

pub use book::UnitAuditMiss;
use book::{Pending, PendingBook};

#[derive(Default)]
pub(super) struct UnitCheckpointBook {
    sink: OnceLock<Arc<dyn UnitCheckpointSink>>,
    pending: PendingBook,
    flushing: tokio::sync::Mutex<()>,
}

/// A refusal from a lower layer, rendered once on the error path.
fn failed(cause: &dyn std::fmt::Display) -> RecordStoreError {
    #[expect(
        clippy::disallowed_methods,
        reason = "error: a refused checkpoint renders its message once"
    )]
    let message = cause.to_string();
    RecordStoreError(message)
}

fn error(message: &str) -> RecordStoreError {
    #[expect(
        clippy::disallowed_methods,
        reason = "error: a refused checkpoint renders its message once"
    )]
    let message = message.to_string();
    RecordStoreError(message)
}

impl GovState {
    /// Bind after usage recovery is attached and before admitting any units. A recovered running
    /// unit ends at its last confirmed report, without reconstructing an admission or a fee.
    pub async fn attach_unit_checkpoint_sink(
        &self,
        sink: Arc<dyn UnitCheckpointSink>,
    ) -> RecordStoreResult<()> {
        if !self.recovery_enabled() {
            return Err(error("running unit custody requires usage recovery"));
        }
        let recovered = sink.replay().await?;
        for snapshot in &recovered {
            snapshot.validate()?;
            sink.recover_audit(snapshot).await?;
        }
        self.unit_checkpoints
            .sink
            .set(sink)
            .map_err(|_| error("unit checkpoint sink already attached"))?;
        {
            let mut pending = self.unit_checkpoints.pending.lock();
            for mut snapshot in recovered {
                let persisted = Some(snapshot.revision);
                if !snapshot.ended {
                    snapshot.ended = true;
                    snapshot.revision = snapshot
                        .revision
                        .checked_add(1)
                        .ok_or_else(|| error("unit checkpoint revision exhausted"))?;
                }
                if pending
                    .insert(snapshot.id, Pending::recovered(snapshot, persisted))
                    .is_some()
                {
                    return Err(error("duplicate running unit checkpoint"));
                }
            }
        }
        if let Err(failed) = self.flush_unit_checkpoints().await {
            // busbar:expect(bp::state_scan, reason = "boot: the sink is attached once, before any unit is admitted")
            let owned = self.unit_checkpoints.pending.lock().all(|entry| {
                entry.persisted() == Some(entry.snapshot().revision)
                    && entry.snapshot().terminal.as_ref().is_some_and(|events| {
                        events
                            .iter()
                            .all(|event| self.recovery_event(event.operation_id).is_some())
                    })
            });
            if !owned {
                return Err(failed);
            }
            tracing::warn!(error = %failed, "recovered unit targets remain admission-blocked while durable usage custody awaits resolution");
        }
        Ok(())
    }

    /// Admission's question, answered from the book's recovered-target index without its lock.
    pub(super) fn unresolved_unit_target(&self, bucket: &str, window: u64) -> bool {
        self.unit_checkpoints.pending.blocks(bucket, window)
    }

    /// Synchronous shutdown barrier: reports and an active native flush retain
    /// custody even when no RPC is currently being polled.
    pub(super) fn has_unsettled_unit_checkpoints(&self) -> bool {
        !self.unit_checkpoints.pending.lock().is_empty()
            || self.unit_checkpoints.flushing.try_lock().is_err()
    }

    pub(crate) fn unit_checkpoint_pending(&self, id: &[u8; 16]) -> bool {
        self.unit_checkpoints.pending.lock().get(id).is_some()
    }

    /// Records the sequence of `unit`'s live audit line on its pending checkpoint. Zero or several
    /// live checkpoints for the unit is a counted miss; the caller then uses its cold lookup.
    pub fn note_unit_audit(&self, unit: u64, seq: u64) -> Result<(), UnitAuditMiss> {
        self.unit_checkpoints
            .pending
            .lock()
            .note_unit_audit(unit, seq)
    }

    /// The audit line sequence noted for checkpoint `id`, if any.
    pub fn unit_checkpoint_audit_seq(&self, id: &[u8; 16]) -> Option<u64> {
        self.unit_checkpoints
            .pending
            .lock()
            .get(id)
            .and_then(Pending::audit_seq)
    }

    /// `note_unit_audit` misses since boot.
    pub fn unit_audit_misses(&self) -> u64 {
        self.unit_checkpoints.pending.audit_misses()
    }

    pub fn unit_checkpoints_enabled(&self) -> bool {
        self.unit_checkpoints.sink.get().is_some()
    }

    /// No Store call occurs on a report, including a streamed piece.
    pub fn stage_unit_checkpoint(&self, mut snapshot: UnitCheckpoint) {
        if !self.unit_checkpoints_enabled() {
            return;
        }
        let mut pending = self.unit_checkpoints.pending.lock();
        match pending.edit(&snapshot.id) {
            Some(mut previous) if !previous.snapshot().ended => {
                // Exhaustion fails closed by keeping the last checkpoint; never wrap its identity.
                let Some(next) = previous.snapshot().revision.checked_add(1) else {
                    return;
                };
                snapshot.revision = next;
                previous.replace_snapshot(snapshot);
            }
            Some(_) => {}
            None => {
                pending.insert(snapshot.id, Pending::live(snapshot));
            }
        }
    }

    /// Returns true when durable unit custody owns this bill. The caller must then bypass the
    /// ordinary write-behind bill, whose independently generated operation IDs would duplicate it.
    pub fn finish_unit_checkpoint(&self, mut snapshot: UnitCheckpoint) -> bool {
        if !self.unit_checkpoints_enabled() {
            return false;
        }
        snapshot.ended = true;
        let mut pending = self.unit_checkpoints.pending.lock();
        let previous = pending.get(&snapshot.id);
        if previous.is_some_and(|p| p.snapshot().ended) {
            return true;
        }
        snapshot.revision = previous.map_or(0, |p| p.snapshot().revision.saturating_add(1));
        if snapshot.audit.is_none() {
            snapshot.audit = previous.and_then(|p| p.snapshot().audit.clone());
        }
        let persisted = previous.and_then(Pending::persisted);
        // Admission does not take the book's lock, so it may run between a failed apply and the
        // recovered insert. A failed apply changes no count, and the entry is still the
        // pre-finish live one, so such an admission sees exactly the pre-finish state.
        let entry = match self.apply_unit_checkpoint_live(&snapshot) {
            Ok(()) => Pending::terminal(snapshot, persisted),
            Err(failed) => {
                tracing::error!(unit = snapshot.unit, error = %failed,
                    "terminal unit hot accounting failed; exact durable custody retained");
                Pending::recovered(snapshot, persisted)
            }
        };
        pending.insert(entry.snapshot().id, entry);
        true
    }

    /// Called by the existing usage flusher, including its final shutdown pass.
    pub async fn flush_unit_checkpoints(&self) -> RecordStoreResult<()> {
        let Some(sink) = self.unit_checkpoints.sink.get() else {
            return Ok(());
        };
        let _flush = self.unit_checkpoints.flushing.lock().await;
        let ids = self.unit_checkpoints.pending.lock().ids();
        let mut first_error = None;
        for id in ids {
            if let Err(failed) = self.flush_unit_checkpoint(sink.as_ref(), id).await {
                tracing::warn!(checkpoint = %hex::encode(id), error = %failed,
                    "running money checkpoint remains unresolved and will retry");
                first_error.get_or_insert(failed);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn flush_unit_checkpoint(
        &self,
        sink: &dyn UnitCheckpointSink,
        id: [u8; 16],
    ) -> RecordStoreResult<()> {
        let (snapshot, persisted, recovered) = {
            let mut pending = self.unit_checkpoints.pending.lock();
            let Some(mut entry) = pending.edit(&id) else {
                return Ok(());
            };
            entry.snapshot().validate()?;
            if entry.snapshot().ended && entry.snapshot().terminal.is_none() {
                let events = self.unit_terminal_events(entry.snapshot())?;
                let revision = entry
                    .snapshot()
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| error("unit checkpoint revision exhausted"))?;
                entry.set_terminal(events, revision);
            }
            (
                entry.snapshot().clone(),
                entry.persisted(),
                entry.is_recovered(),
            )
        };
        if persisted != Some(snapshot.revision) {
            sink.persist(&snapshot).await?;
            if let Some(mut entry) = self.unit_checkpoints.pending.lock().edit(&id) {
                entry.set_persisted(snapshot.revision);
            }
        }
        let Some(events) = &snapshot.terminal else {
            return Ok(());
        };
        for initial in events {
            self.restore_unit_terminal_receipt(initial).await?;
            if self.recovery_event(initial.operation_id).is_none() {
                self.keep_recovery_event(initial).await?;
            } else if self.recovery_initial_event(initial.operation_id).as_ref() != Some(initial) {
                return Err(error(
                    "terminal unit operation identity differs from recovery custody",
                ));
            }
        }
        // Select every exact terminal operation before driving any. One ambiguous operation must
        // not strand its siblings without durable custody or hide the operator recovery surface.
        let mut first_error = None;
        for initial in events {
            if let Err(failed) = self.drive_raw_recovery(initial.operation_id).await {
                first_error.get_or_insert(failed);
            }
            if !self
                .recovery_event(initial.operation_id)
                .is_some_and(|e| e.state == RecoveryState::Settled)
            {
                first_error.get_or_insert_with(|| {
                    error("terminal unit awaits durable recovery acknowledgement")
                });
            }
        }
        if let Some(failed) = first_error {
            return Err(failed);
        }
        if recovered {
            self.refresh_recovered_unit_targets(&snapshot).await?;
        }
        sink.remove(&snapshot).await?;
        self.unit_checkpoints.pending.lock().remove(&id);
        for event in events {
            self.forget_confirmed_recovery(event.operation_id);
        }
        Ok(())
    }
}

#[cfg(test)]
impl GovState {
    /// Holds the book's lock, as the flusher's id snapshot and the request-path writers do.
    pub(crate) fn hold_unit_checkpoint_book(&self) -> impl Drop + '_ {
        self.unit_checkpoints.pending.hold()
    }

    /// The reference answer: a full walk of the book.
    pub(crate) fn reference_unresolved_unit_target(&self, bucket: &str, window: u64) -> bool {
        !self.unit_checkpoints.pending.lock().all(|entry| {
            !(entry.is_recovered()
                && entry
                    .snapshot()
                    .targets
                    .iter()
                    .any(|target| target.bucket == bucket && target.window == window))
        })
    }

    /// Entries the book has visited so far, across all its counted structures.
    pub(crate) fn unit_checkpoint_visits(&self) -> u64 {
        self.unit_checkpoints.pending.visits()
    }

    /// The book itself, for tests that drive its mutation surface directly.
    fn unit_checkpoint_book(&self) -> &PendingBook {
        &self.unit_checkpoints.pending
    }

    /// Rebuilds the derived indexes from the map and asserts them; returns the recovered count.
    pub(crate) fn check_unit_checkpoint_book(&self) -> usize {
        self.unit_checkpoints.pending.check();
        self.unit_checkpoints.pending.recovered_live()
    }
}

#[cfg(test)]
#[path = "tests/unit_checkpoint_book_tests.rs"]
mod book_tests;
