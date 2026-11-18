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
use crate::persistence::journal::runtime::Carried;

/// Units per flush batch (SHUTDOWN-HANG F3.3): the halt is read and the runtime yielded to between
/// batches, so a drain stops within one batch and the control thread waits at most one batch.
const UNIT_FLUSH_BATCH: usize = 128;

mod ordinary_completion;
pub mod partitions;
mod terminal_completion;
pub use ordinary_completion::OrdinaryTerminalCompletion;
pub(crate) use ordinary_completion::OrdinaryTerminalReservation;
pub use terminal_completion::SelectedTerminalCompletion;
use terminal_completion::TerminalSignal;

/// Terminal ownership is explicit. A refusal returns the entire unowned snapshot to its caller.
pub enum SelectedTransfer {
    Applied(Arc<UnitCheckpoint>),
    RetainedPending(Arc<UnitCheckpoint>),
    RejectedNotOwned {
        snapshot: Box<UnitCheckpoint>,
        error: RecordStoreError,
    },
}

/// Initial custody refused before publication, or the synchronous admission publication failed.
#[derive(Debug)]
pub(crate) enum SelectedActivationError<E> {
    Custody(RecordStoreError),
    Publish(E),
}

/// Dispatch custody validation failed, or the synchronous rate commitment was refused.
#[derive(Debug)]
pub(crate) enum SelectedCommitError<E> {
    Custody,
    Commit(E),
}

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
    /// Absent is the historical single-lane representation, never an inferred attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partitions: Option<partitions::PartitionedUsageV1>,
}

impl UnitCheckpoint {
    pub fn validate(&self) -> RecordStoreResult<()> {
        crate::off_path::governance::runtime::unit_checkpoint_validate(self)
    }

    pub fn era(&self) -> RawRateEra {
        RawRateEra {
            effective_from: self.era_at,
            entry_id: self.era_entry.map(EntryId),
        }
    }
}

/// One terminal unit's removal in a flush batch (SHUTDOWN-HANG F3.1). Not serialised: the hint is
/// RAM-only evidence from the root's seal, and `UnitCheckpoint` is unchanged.
pub struct UnitRemoval<'a> {
    pub snapshot: &'a UnitCheckpoint,
    /// The unit's live audit line as this process sealed it (F1a), when the root noted it.
    pub audit: Option<Carried>,
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
    /// One flush batch's phase P, a result per snapshot so one failure never fails its siblings.
    async fn persist_batch(&self, snapshots: &[UnitCheckpoint]) -> Vec<RecordStoreResult<()>> {
        let mut out = Vec::with_capacity(snapshots.len());
        for snapshot in snapshots {
            out.push(self.persist(snapshot).await);
        }
        out
    }
    /// One flush batch's phase R. The default drops the audit hint (the cold lookup).
    async fn remove_batch(&self, items: &[UnitRemoval<'_>]) -> Vec<RecordStoreResult<()>> {
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            out.push(self.remove(item.snapshot).await);
        }
        out
    }
}

mod book;

pub use book::UnitAuditMiss;
pub(crate) use book::UnitCustody;
use book::{Pending, PendingBook};

#[derive(Default)]
pub(super) struct UnitCheckpointBook {
    identity: Arc<()>,
    sink: OnceLock<Arc<dyn UnitCheckpointSink>>,
    pending: PendingBook,
    flushing: tokio::sync::Mutex<()>,
}

impl UnitCheckpointBook {
    /// The terminal-backlog mirror the admission gate reads (SHUTDOWN-HANG F4a).
    pub(super) fn terminal_counter(&self) -> Arc<std::sync::atomic::AtomicU64> {
        self.pending.terminal_counter()
    }
}

/// A checkpoint refusal, rendered once on the error path.
fn error(message: &str) -> RecordStoreError {
    crate::cold::governance::runtime::unit_checkpoint_refusal(message)
}

/// Keeps a new, unpublished entry invisible to flush until admission commits. Removal also
/// restores the book's indexes on an unwind; it never invokes Store or changes fee ownership.
struct InitialActivation<'a> {
    pending: book::PendingGuard<'a>,
    id: [u8; 16],
    committed: bool,
}

impl Drop for InitialActivation<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.pending.remove(&self.id);
        }
    }
}

impl GovState {
    /// Install initial custody and publish admission under the same book lock. The caller holds
    /// its Open shard throughout and must not reenter this book from `publish`. On refusal it
    /// retains responsibility for removing Open and releasing the original pending admission.
    /// No checkpoint can reach the flusher before the synchronous publication succeeds.
    pub(crate) fn activate_selected_checkpoint<R, E>(
        &self,
        snapshot: UnitCheckpoint,
        publish: impl FnOnce(Arc<UnitCheckpoint>) -> Result<R, E>,
    ) -> Result<R, SelectedActivationError<E>> {
        let validate = || -> RecordStoreResult<()> {
            let Some(parts) = &snapshot.partitions else {
                return Err(error("selected activation requires partitioned custody"));
            };
            if snapshot.revision != 0
                || snapshot.ended
                || snapshot.metered
                || snapshot.terminal.is_some()
                || parts.disposition != partitions::Disposition::Running
                || !parts.attempts.is_empty()
                || parts.session.is_some()
                || parts.far_end_answered
                || parts.caller_bytes_committed
                || parts.final_target.is_some()
                || !matches!(
                    &parts.fee,
                    partitions::CapturedFee::PendingOwner { .. }
                        | partitions::CapturedFee::NotOwner { .. }
                )
            {
                return Err(error("selected activation requires empty initial facts"));
            }
            snapshot.validate()?;
            parts.preflight_terminal_bound(snapshot.targets.len())?;
            self.validate_selected_terminal_capacity(&snapshot)
        };
        validate().map_err(SelectedActivationError::Custody)?;
        let mut pending = self.unit_checkpoints.pending.lock();
        if pending.get(&snapshot.id).is_some() {
            return Err(SelectedActivationError::Custody(error(
                "selected activation already has checkpoint custody",
            )));
        }
        let accepted = Arc::new(snapshot.clone());
        let id = snapshot.id;
        pending.insert(
            id,
            Pending::selected(snapshot, self.unit_checkpoints_enabled(), false),
        );
        let mut activation = InitialActivation {
            pending,
            id,
            committed: false,
        };
        let result = publish(accepted).map_err(SelectedActivationError::Publish)?;
        activation.committed = true;
        Ok(result)
    }

    /// Commit the last prepared attempt at the actual connector handoff. All validation and
    /// allocation precede `commit`; its success is followed only by infallible replacement of
    /// the existing live entry. Refusal leaves the predecessor unchanged. The caller retains
    /// its Open lock, borrows its reservation into this callback, and installs the returned Arc
    /// before sending. Lock order is Open, checkpoint book, then the callback's rate cells;
    /// the synchronous callback must not reenter this book.
    pub(crate) fn commit_selected_checkpoint<R, E>(
        &self,
        mut snapshot: UnitCheckpoint,
        expected_revision: u64,
        commit: impl FnOnce() -> Result<R, E>,
    ) -> Result<(Arc<UnitCheckpoint>, R), SelectedCommitError<E>> {
        use partitions::{Disposition, Finality, Transport};
        let mut pending = self.unit_checkpoints.pending.lock();
        let mut entry = pending
            .edit(&snapshot.id)
            .ok_or(SelectedCommitError::Custody)?;
        let preflight = || -> bool {
            let before = entry.snapshot();
            if before.revision != expected_revision
                || before.ended
                || before.terminal.is_some()
                || entry.is_recovered()
            {
                return false;
            }
            let Some(parts) = &before.partitions else {
                return false;
            };
            if parts.disposition != Disposition::Running {
                return false;
            }
            true
        };
        if !preflight() {
            return Err(SelectedCommitError::Custody);
        }
        let mut expected = entry.snapshot().clone();
        expected.revision = expected
            .revision
            .checked_add(1)
            .ok_or(SelectedCommitError::Custody)?;
        let parts = expected
            .partitions
            .as_mut()
            .ok_or(SelectedCommitError::Custody)?;
        let dispatch = parts
            .attempts
            .iter()
            .filter_map(|attempt| attempt.dispatch)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(SelectedCommitError::Custody)?;
        let last = parts
            .attempts
            .last_mut()
            .ok_or(SelectedCommitError::Custody)?;
        if last.transport != Transport::Prepared
            || last.dispatch.is_some()
            || last.finality != Finality::Live
        {
            return Err(SelectedCommitError::Custody);
        }
        last.transport = Transport::Committed;
        last.dispatch = Some(dispatch);
        snapshot.revision = expected.revision;
        if snapshot != expected {
            return Err(SelectedCommitError::Custody);
        }
        partitions::validate_successor(entry.snapshot(), &snapshot)
            .map_err(|_| SelectedCommitError::Custody)?;
        self.validate_selected_terminal_capacity(&snapshot)
            .map_err(|_| SelectedCommitError::Custody)?;
        let accepted = Arc::new(snapshot.clone());
        let committed = commit().map_err(SelectedCommitError::Commit)?;
        entry.replace_snapshot(snapshot);
        Ok((accepted, committed))
    }

    /// Publish one selected revision into the existing book, including RAM-only selected units.
    /// The money owner publishes the returned same revision into Open while retaining its lock.
    pub fn stage_selected_checkpoint(
        &self,
        mut snapshot: UnitCheckpoint,
        expected_revision: Option<u64>,
    ) -> RecordStoreResult<Arc<UnitCheckpoint>> {
        if snapshot.ended || snapshot.terminal.is_some() || snapshot.partitions.is_none() {
            return Err(error(
                "selected running publication requires a running selected snapshot",
            ));
        }
        let mut pending = self.unit_checkpoints.pending.lock();
        let previous = pending.get(&snapshot.id);
        if previous.map(|entry| entry.snapshot().revision) != expected_revision {
            return Err(error(
                "selected running publication has a stale predecessor",
            ));
        }
        if let Some(entry) = previous {
            snapshot.revision = entry.snapshot().revision;
            if &snapshot == entry.snapshot() {
                return Ok(Arc::new(snapshot));
            }
        }
        snapshot.revision = match previous {
            Some(entry) => entry
                .snapshot()
                .revision
                .checked_add(1)
                .ok_or_else(|| error("selected checkpoint revision exhausted"))?,
            None => 0,
        };
        snapshot.validate()?;
        if let Some(entry) = previous {
            partitions::validate_successor(entry.snapshot(), &snapshot)?;
        } else if let Some(parts) = &snapshot.partitions {
            parts.preflight_terminal_bound(snapshot.targets.len())?;
        }
        self.validate_selected_terminal_capacity(&snapshot)?;
        let accepted = Arc::new(snapshot.clone());
        match pending.edit(&snapshot.id) {
            Some(mut entry) => entry.replace_snapshot(snapshot),
            None => {
                pending.insert(
                    snapshot.id,
                    Pending::selected(snapshot, self.unit_checkpoints_enabled(), false),
                );
            }
        }
        Ok(accepted)
    }

    /// Transfer all terminal facts before the money owner removes Open or releases participation.
    /// A selected unit never falls back to a separate ordinary bill on a refused transfer.
    pub fn finish_selected_checkpoint(
        &self,
        snapshot: UnitCheckpoint,
        expected_revision: Option<u64>,
    ) -> SelectedTransfer {
        self.finish_selected_checkpoint_with_fee(snapshot, expected_revision, None)
    }

    pub fn finish_selected_checkpoint_with_fee(
        &self,
        mut snapshot: UnitCheckpoint,
        expected_revision: Option<u64>,
        completion: Option<Arc<partitions::SelectedFeeCompletion>>,
    ) -> SelectedTransfer {
        let mut pending = self.unit_checkpoints.pending.lock();
        if let Some(previous) = pending
            .get(&snapshot.id)
            .filter(|entry| entry.snapshot().ended)
        {
            snapshot.revision = previous.snapshot().revision;
            return if &snapshot == previous.snapshot() {
                SelectedTransfer::RetainedPending(Arc::new(previous.snapshot().clone()))
            } else {
                SelectedTransfer::RejectedNotOwned {
                    snapshot: Box::new(snapshot),
                    error: error("selected terminal custody is already frozen"),
                }
            };
        }
        let prepare = || -> RecordStoreResult<(u64, bool, Option<u64>)> {
            if !snapshot.ended || snapshot.partitions.is_none() || snapshot.terminal.is_some() {
                return Err(error(
                    "selected terminal transfer requires a complete unfrozen terminal",
                ));
            }
            let previous = pending.get(&snapshot.id);
            if previous.is_none() {
                return Err(error("selected terminal has no activated custody owner"));
            }
            if previous.map(|entry| entry.snapshot().revision) != expected_revision {
                return Err(error("selected terminal transfer has a stale predecessor"));
            }
            let revision = match previous {
                Some(entry) => entry
                    .snapshot()
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| error("selected checkpoint revision exhausted"))?,
                None => 0,
            };
            snapshot.validate()?;
            if snapshot
                .partitions
                .as_ref()
                .is_some_and(|parts| parts.fee.pending())
                && completion.is_none()
            {
                return Err(error(
                    "pending selected fee requires its nonparticipating observer",
                ));
            }
            partitions::ValidatedSelectedCheckpoint::try_from(&snapshot)?.project()?;
            self.validate_selected_terminal_capacity(&snapshot)?;
            if let Some(entry) = previous {
                partitions::validate_successor(entry.snapshot(), &snapshot)?;
            }
            Ok((
                revision,
                previous.map_or_else(
                    || self.unit_checkpoints_enabled(),
                    |entry| !entry.is_memory_selected(),
                ),
                previous.and_then(Pending::persisted),
            ))
        };
        let (revision, durable, persisted) = match prepare() {
            Ok(prepared) => prepared,
            Err(error) => {
                return SelectedTransfer::RejectedNotOwned {
                    snapshot: Box::new(snapshot),
                    error,
                }
            }
        };
        snapshot.revision = revision;
        let accepted = Arc::new(snapshot.clone());
        if snapshot
            .partitions
            .as_ref()
            .is_some_and(|parts| parts.fee.pending())
        {
            pending.insert(
                snapshot.id,
                Pending::selected(snapshot, durable, true).with_fee_completion(completion),
            );
            return SelectedTransfer::RetainedPending(accepted);
        }
        if durable {
            let applied = self.apply_unit_checkpoint_live(&snapshot).is_ok();
            let entry = if applied {
                Pending::terminal(snapshot, persisted)
            } else {
                Pending::recovered(snapshot, persisted)
            };
            pending.insert(entry.snapshot().id, entry.require_terminal_reader());
            SelectedTransfer::RetainedPending(accepted)
        } else if self.apply_selected_checkpoint_memory(&snapshot).is_ok() {
            pending.remove(&snapshot.id);
            SelectedTransfer::Applied(accepted)
        } else {
            pending.insert(
                snapshot.id,
                Pending::selected(snapshot, false, true).require_terminal_reader(),
            );
            SelectedTransfer::RetainedPending(accepted)
        }
    }

    /// Bind after usage recovery is attached and before admitting any units. A recovered running
    /// unit ends at its last confirmed report, without reconstructing an admission or a fee.
    pub async fn attach_unit_checkpoint_sink(
        &self,
        sink: Arc<dyn UnitCheckpointSink>,
    ) -> RecordStoreResult<()> {
        if !self.recovery_enabled() {
            return Err(error("running unit custody requires usage recovery"));
        }
        let mut recovered = sink.replay().await?;
        let persisted_versions: BTreeMap<_, _> = recovered
            .iter()
            .map(|snapshot| (snapshot.id, snapshot.revision))
            .collect();
        for snapshot in &mut recovered {
            snapshot.validate()?;
            if let Some(partitions) = &mut snapshot.partitions {
                if !snapshot.ended || partitions.fee.pending() {
                    partitions.recover_running();
                    snapshot.ended = true;
                    snapshot.revision = snapshot
                        .revision
                        .checked_add(1)
                        .ok_or_else(|| error("unit checkpoint revision exhausted"))?;
                }
            }
            if snapshot.partitions.is_some() && snapshot.terminal.is_none() {
                snapshot.terminal = Some(self.unit_terminal_events(snapshot)?);
                snapshot.revision = snapshot
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| error("unit checkpoint revision exhausted"))?;
                snapshot.validate()?;
            }
            self.validate_selected_terminal(snapshot)?;
            sink.recover_audit(snapshot).await?;
        }
        self.unit_checkpoints
            .sink
            .set(sink)
            .map_err(|_| error("unit checkpoint sink already attached"))?;
        {
            let mut pending = self.unit_checkpoints.pending.lock();
            for mut snapshot in recovered {
                // A selected running recovery was advanced before audit reconstruction above;
                // its recovered disposition must still be published, not treated as an ACK.
                let persisted = persisted_versions.get(&snapshot.id).copied();
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

    /// Every unit entry's custody facts, for a non-retired exit's classification.
    pub(crate) fn unit_checkpoint_states(&self) -> Vec<UnitCustody> {
        self.unit_checkpoints.pending.lock().custody_states()
    }

    /// Entries in custody, without copying them (the drain progress line).
    pub(crate) fn unit_checkpoint_count(&self) -> usize {
        self.unit_checkpoints.pending.lock().len()
    }

    /// Whether a unit flush pass holds the book's flush lock right now.
    pub(crate) fn unit_checkpoints_flushing(&self) -> bool {
        self.unit_checkpoints.flushing.try_lock().is_err()
    }

    pub(crate) fn unit_checkpoint_pending(&self, id: &[u8; 16]) -> bool {
        self.unit_checkpoints.pending.lock().get(id).is_some()
    }

    /// Records `unit`'s live audit line (its sequence and the chain hash the root sealed) on its
    /// pending checkpoint, so the removal reads that one line (SHUTDOWN-HANG F1a). Zero or several
    /// live checkpoints for the unit is a counted miss; the removal then uses its cold lookup.
    pub fn note_unit_audit(
        &self,
        unit: u64,
        seq: u64,
        hash: [u8; 32],
    ) -> Result<(), UnitAuditMiss> {
        self.unit_checkpoints
            .pending
            .lock()
            .note_unit_audit(unit, Carried { seq, hash })
    }

    /// The audit line hint noted for checkpoint `id`, if any.
    pub(crate) fn unit_checkpoint_audit_hint(&self, id: &[u8; 16]) -> Option<Carried> {
        self.unit_checkpoints
            .pending
            .lock()
            .get(id)
            .and_then(Pending::audit_hint)
    }

    /// The audit line sequence noted for checkpoint `id`, if any.
    pub fn unit_checkpoint_audit_seq(&self, id: &[u8; 16]) -> Option<u64> {
        self.unit_checkpoints
            .pending
            .lock()
            .get(id)
            .and_then(Pending::audit_seq)
    }

    /// The WAL `node_seq` of the oldest audit line a checkpoint in custody still names: the
    /// Ephemeral journal cut never passes the row before it (SEALING-FIX §3.9 floor (b)). One
    /// pass over the book, off the request path (the notary, once per cut trigger).
    pub fn oldest_unit_audit_seq(&self) -> Option<u64> {
        self.unit_checkpoints.pending.lock().oldest_audit_seq()
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
        snapshot.revision = match previous {
            Some(entry) => match entry.snapshot().revision.checked_add(1) {
                Some(next) => next,
                None => return true,
            },
            None => 0,
        };
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

    /// Called by the flusher's tick, boot restore and the upgrade candidate: never halted.
    pub async fn flush_unit_checkpoints(&self) -> RecordStoreResult<()> {
        self.flush_unit_checkpoints_until(&|| false).await
    }

    /// One pass in batches of `UNIT_FLUSH_BATCH` (SHUTDOWN-HANG F3.3/F4 [M]). `halt` is read before
    /// each batch and the pass returns at the first boundary where it is true; a batch already
    /// started runs to its end, so no write is dropped, and the items not reached stay in custody.
    /// Terminal entries go first, then running entries whose revision moved; the pass yields to
    /// the runtime after every batch.
    pub async fn flush_unit_checkpoints_until(
        &self,
        halt: &(impl Fn() -> bool + Sync),
    ) -> RecordStoreResult<()> {
        let _flush = self.unit_checkpoints.flushing.lock().await;
        let memory = self.unit_checkpoints.pending.lock().memory_order();
        let mut first_error = None;
        for batch in memory.chunks(UNIT_FLUSH_BATCH) {
            if halt() {
                break;
            }
            for id in batch {
                let mut pending = self.unit_checkpoints.pending.lock();
                let Some(mut entry) = pending.edit(id) else {
                    continue;
                };
                match entry.resolve_fee() {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(error) => {
                        first_error.get_or_insert(error);
                        continue;
                    }
                }
                if entry.awaiting_terminal_reader() {
                    continue;
                }
                let snapshot = entry.snapshot().clone();
                match self.apply_selected_checkpoint_memory(&snapshot) {
                    Ok(()) => {
                        pending.remove(id);
                    }
                    Err(failed) => {
                        first_error.get_or_insert_with(|| {
                            error(&crate::cold::governance::selected_policy::unit_checkpoint_selected_unresolved(&failed))
                        });
                    }
                }
            }
            tokio::task::yield_now().await;
        }
        let Some(sink) = self.unit_checkpoints.sink.get() else {
            return first_error.map_or(Ok(()), Err);
        };
        let ids = self.unit_checkpoints.pending.lock().flush_order();
        for batch in ids.chunks(UNIT_FLUSH_BATCH) {
            if halt() {
                break;
            }
            for (id, failed) in self.flush_unit_batch(sink.as_ref(), batch).await {
                tracing::warn!(checkpoint = %hex::encode(id), error = %failed,
                    "running money checkpoint remains unresolved and will retry");
                first_error.get_or_insert(failed);
            }
            tokio::task::yield_now().await;
        }
        first_error.map_or(Ok(()), Err)
    }

    /// One batch through the phases (SHUTDOWN-HANG F3.3): P for every item that moved, then T
    /// (every terminal operation selected before any is driven), then V-K2 (each operation driven
    /// to Settled), then R (one removal per settled unit, carrying its audit hint). Per-item order
    /// is unchanged, and every phase isolates its items: one that fails leaves the batch with its
    /// error and is retried next pass, while its siblings continue. Returns the failures.
    async fn flush_unit_batch(
        &self,
        sink: &dyn UnitCheckpointSink,
        ids: &[[u8; 16]],
    ) -> Vec<([u8; 16], RecordStoreError)> {
        let mut failed = Vec::new();
        let mut items = Vec::with_capacity(ids.len());
        for id in ids {
            match self.unit_flush_item(*id) {
                Ok(Some(item)) => items.push(item),
                Ok(None) => {}
                Err(why) => failed.push((*id, why)),
            }
        }

        // P: persist every item whose revision is not yet persisted.
        let moved: Vec<usize> = (0..items.len())
            .filter(|&at| items[at].persisted != Some(items[at].snapshot.revision))
            .collect();
        if !moved.is_empty() {
            let snapshots: Vec<UnitCheckpoint> =
                moved.iter().map(|&at| items[at].snapshot.clone()).collect();
            let mut results = sink.persist_batch(&snapshots).await.into_iter();
            for &at in &moved {
                let item = &mut items[at];
                match results.next() {
                    Some(Ok(())) => {
                        if let Some(mut entry) = self.unit_checkpoints.pending.lock().edit(&item.id)
                        {
                            entry.set_persisted(item.snapshot.revision);
                        }
                    }
                    Some(Err(why)) => item.failed = Some(why),
                    None => item.failed = Some(error("unit checkpoint batch result missing")),
                }
            }
        }
        // A running item is done once persisted; a failed one leaves the batch.
        items.retain_mut(|item| match item.failed.take() {
            Some(why) => {
                failed.push((item.id, why));
                false
            }
            None => item.snapshot.terminal.is_some() && !item.awaiting_terminal_reader,
        });

        // T: select every terminal operation of the batch before driving any, in one keep.
        let mut intents: Vec<(usize, RecoveryEvent)> = Vec::new();
        for (at, item) in items.iter_mut().enumerate() {
            let start = intents.len();
            match self
                .unselected_unit_terminal(&item.snapshot, at, &mut intents)
                .await
            {
                Ok(()) => {}
                Err(why) => {
                    intents.truncate(start);
                    item.failed = Some(why);
                }
            }
        }
        intents.retain(|(at, _)| items[*at].failed.is_none());
        if !intents.is_empty() {
            let events: Vec<RecoveryEvent> =
                intents.iter().map(|(_, event)| event.clone()).collect();
            let results = self.keep_recovery_events(&events).await;
            for ((at, _), result) in intents.iter().zip(results) {
                if let Err(why) = result {
                    items[*at].failed.get_or_insert(why);
                }
            }
        }
        // V-K2: drive every selected operation of the batch to Settled, in lockstep.
        let mut operations: Vec<(usize, [u8; 16])> = Vec::new();
        for (at, item) in items.iter().enumerate() {
            if item.failed.is_none() {
                operations.extend(
                    item.snapshot
                        .terminal
                        .iter()
                        .flatten()
                        .map(|initial| (at, initial.operation_id)),
                );
            }
        }
        if !operations.is_empty() {
            let ids: Vec<[u8; 16]> = operations.iter().map(|(_, id)| *id).collect();
            let results = self.drive_raw_recoveries(&ids).await;
            // One ambiguous operation does not strand its siblings; a unit is settled only when
            // all of its operations are.
            for ((at, id), result) in operations.iter().zip(results) {
                let item = &mut items[*at];
                if let Err(failed) = result {
                    item.failed.get_or_insert(failed);
                } else if !self
                    .recovery_event(*id)
                    .is_some_and(|e| e.state == RecoveryState::Settled)
                {
                    item.failed.get_or_insert_with(|| {
                        error("terminal unit awaits durable recovery acknowledgement")
                    });
                }
            }
        }
        // R: recovered targets refreshed, then one removal per settled unit.
        for item in &mut items {
            if item.failed.is_none() && item.recovered {
                if let Err(why) = self.refresh_recovered_unit_targets(&item.snapshot).await {
                    item.failed = Some(why);
                }
            }
        }
        items.retain_mut(|item| match item.failed.take() {
            Some(why) => {
                failed.push((item.id, why));
                false
            }
            None => true,
        });
        if items.is_empty() {
            return failed;
        }
        let results = {
            let removals: Vec<UnitRemoval<'_>> = items
                .iter()
                .map(|item| UnitRemoval {
                    snapshot: &item.snapshot,
                    audit: self.unit_checkpoint_audit_hint(&item.id),
                })
                .collect();
            sink.remove_batch(&removals).await
        };
        let mut results = results.into_iter();
        for item in &items {
            match results.next() {
                Some(Ok(())) => {
                    let mut pending = self.unit_checkpoints.pending.lock();
                    let Some(mut entry) = pending.edit(&item.id) else {
                        failed.push((
                            item.id,
                            error("original checkpoint disappeared before R acknowledgement"),
                        ));
                        continue;
                    };
                    if let Err(why) =
                        entry.confirm_ordinary(&item.snapshot, item.ordinary_signal.as_ref())
                    {
                        failed.push((item.id, why));
                        continue;
                    }
                    pending.remove(&item.id);
                    drop(pending);
                    for event in item.snapshot.terminal.iter().flatten() {
                        self.forget_confirmed_recovery(event.operation_id);
                    }
                }
                Some(Err(why)) => failed.push((item.id, why)),
                None => failed.push((item.id, error("unit checkpoint batch result missing"))),
            }
        }
        failed
    }

    /// An entry's flush snapshot, with its terminal events sealed when it has just ended.
    fn unit_flush_item(&self, id: [u8; 16]) -> RecordStoreResult<Option<UnitFlushItem>> {
        let mut pending = self.unit_checkpoints.pending.lock();
        let Some(mut entry) = pending.edit(&id) else {
            return Ok(None);
        };
        entry.snapshot().validate()?;
        let fee_ready = !entry.snapshot().ended || entry.resolve_fee()?;
        if fee_ready
            && !entry.is_memory_selected()
            && entry.snapshot().ended
            && entry.snapshot().terminal.is_none()
        {
            let events = self.unit_terminal_events(entry.snapshot())?;
            let revision = entry
                .snapshot()
                .revision
                .checked_add(1)
                .ok_or_else(|| error("unit checkpoint revision exhausted"))?;
            let mut sealed = entry.snapshot().clone();
            sealed.terminal = Some(events.clone());
            sealed.revision = revision;
            sealed.validate()?;
            if let Some(signal) = entry.ordinary_signal() {
                signal.fund_events(&events)?;
            }
            entry.set_terminal(events, revision);
        }
        Ok(Some(UnitFlushItem {
            id,
            snapshot: entry.snapshot().clone(),
            persisted: entry.persisted(),
            recovered: entry.is_recovered(),
            awaiting_terminal_reader: entry.awaiting_terminal_reader(),
            ordinary_signal: entry.ordinary_signal().cloned(),
            failed: None,
        }))
    }

    /// Transfer the exact final immutable revision to the root terminal/audit reader. Pending
    /// fee completion returns None; the caller uses its existing terminal retry owner. In RAM
    /// mode the book cannot retire before this handoff. No live money is reread or reconstructed.
    pub fn take_selected_terminal_snapshot(
        &self,
        id: [u8; 16],
    ) -> RecordStoreResult<Option<Arc<UnitCheckpoint>>> {
        self.take_selected_terminal_snapshot_for(id, None)
    }

    fn take_selected_terminal_snapshot_for(
        &self,
        id: [u8; 16],
        signal: Option<&Arc<TerminalSignal>>,
    ) -> RecordStoreResult<Option<Arc<UnitCheckpoint>>> {
        let Some(item) = self.unit_flush_item(id)? else {
            return Ok(None);
        };
        if !item.snapshot.ended
            || item
                .snapshot
                .partitions
                .as_ref()
                .is_none_or(|parts| parts.fee.pending())
        {
            return Ok(None);
        }
        let snapshot = Arc::new(item.snapshot);
        let mut pending = self.unit_checkpoints.pending.lock();
        let Some(mut entry) = pending.edit(&id) else {
            return Ok(None);
        };
        if !entry.matches_terminal_signal(signal) {
            return Err(error(
                "selected terminal reader belongs to a different completion lease",
            ));
        }
        if entry.snapshot() != snapshot.as_ref() {
            return Err(error(
                "selected terminal revision changed before reader handoff",
            ));
        }
        entry.terminal_reader_accepted();
        Ok(Some(snapshot))
    }

    /// Phase T for one unit: restore its terminal receipts, check each selected terminal
    /// operation is this exact identity, and push the Intents not yet selected onto `intents`,
    /// tagged with `at` (the pass keeps them in one batch).
    async fn unselected_unit_terminal(
        &self,
        snapshot: &UnitCheckpoint,
        at: usize,
        intents: &mut Vec<(usize, RecoveryEvent)>,
    ) -> RecordStoreResult<()> {
        self.validate_selected_terminal(snapshot)?;
        for initial in snapshot.terminal.iter().flatten() {
            self.restore_unit_terminal_receipt(initial).await?;
            if self.recovery_event(initial.operation_id).is_none() {
                intents.push((at, initial.clone()));
            } else if self.recovery_initial_event(initial.operation_id).as_ref() != Some(initial) {
                return Err(error(
                    "terminal unit operation identity differs from recovery custody",
                ));
            }
        }
        Ok(())
    }
}

/// One entry in a flush batch.
struct UnitFlushItem {
    id: [u8; 16],
    snapshot: UnitCheckpoint,
    persisted: Option<u64>,
    recovered: bool,
    awaiting_terminal_reader: bool,
    ordinary_signal: Option<Arc<ordinary_completion::OrdinarySignal>>,
    failed: Option<RecordStoreError>,
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
