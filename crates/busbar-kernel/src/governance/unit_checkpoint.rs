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
    pub fn unit_checkpoint_audit_hint(&self, id: &[u8; 16]) -> Option<Carried> {
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
        let Some(sink) = self.unit_checkpoints.sink.get() else {
            return Ok(());
        };
        let _flush = self.unit_checkpoints.flushing.lock().await;
        let ids = self.unit_checkpoints.pending.lock().flush_order();
        let mut first_error = None;
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
            None => item.snapshot.terminal.is_some(),
        });

        // T: select every terminal operation of the batch before driving any.
        for item in &mut items {
            if let Err(why) = self.select_unit_terminal(&item.snapshot).await {
                item.failed = Some(why);
            }
        }
        // V-K2: drive each selected operation to Settled.
        for item in &mut items {
            if item.failed.is_some() {
                continue;
            }
            if let Err(why) = self.settle_unit_terminal(&item.snapshot).await {
                item.failed = Some(why);
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
                    self.unit_checkpoints.pending.lock().remove(&item.id);
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
        if entry.snapshot().ended && entry.snapshot().terminal.is_none() {
            let events = self.unit_terminal_events(entry.snapshot())?;
            let revision = entry
                .snapshot()
                .revision
                .checked_add(1)
                .ok_or_else(|| error("unit checkpoint revision exhausted"))?;
            entry.set_terminal(events, revision);
        }
        Ok(Some(UnitFlushItem {
            id,
            snapshot: entry.snapshot().clone(),
            persisted: entry.persisted(),
            recovered: entry.is_recovered(),
            failed: None,
        }))
    }

    /// Phase T for one unit: restore its terminal receipts and select each terminal operation's
    /// Intent, or check the selected one is this exact identity.
    async fn select_unit_terminal(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        for initial in snapshot.terminal.iter().flatten() {
            self.restore_unit_terminal_receipt(initial).await?;
            if self.recovery_event(initial.operation_id).is_none() {
                self.keep_recovery_event(initial).await?;
            } else if self.recovery_initial_event(initial.operation_id).as_ref() != Some(initial) {
                return Err(error(
                    "terminal unit operation identity differs from recovery custody",
                ));
            }
        }
        Ok(())
    }

    /// Phases V-K2 for one unit: drive every terminal operation. One ambiguous operation does not
    /// strand its siblings; the unit is settled only when all of them are.
    async fn settle_unit_terminal(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        let mut first_error = None;
        for initial in snapshot.terminal.iter().flatten() {
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
        first_error.map_or(Ok(()), Err)
    }
}

/// One entry in a flush batch.
struct UnitFlushItem {
    id: [u8; 16],
    snapshot: UnitCheckpoint,
    persisted: Option<u64>,
    recovered: bool,
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
