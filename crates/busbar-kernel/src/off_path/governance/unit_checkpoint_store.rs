// SPDX-License-Identifier: Apache-2.0
//! Native custody for signed running-unit checkpoints. Journal framing, original
//! record identity and selected evidence are retained across every uncertain call.
//!
//! Off the request path: only the usage flush tick, boot restore and the upgrade candidate drive
//! this sink (`GovState::flush_unit_checkpoints`); a request only stages its snapshot in memory.
use crate::governance::unit_checkpoint::{UnitCheckpoint, UnitCheckpointSink, UnitRemoval};
use crate::persistence::{
    commit::SubmitResult,
    facade::CoreStore,
    journal::{
        runtime::{Carried, RuntimeError, RuntimeJournal, StagedRun},
        Pin, RowChange, VerifiedHead, WriteResult,
    },
    partition,
};
use async_trait::async_trait;
use busbar_contract::{
    caps::{DurableWrite, Grant},
    persistence::{Address, Decision, ExpectedValue, NamespaceId, Read, ReadResult},
    records::{RecordStoreError, RecordStoreResult},
    Secret,
};
use busbar_kernel_audit::{AuditKeySet, AuditRecord};
use busbar_kernel_wal::{BodyReader, BodyWriter, Entry, JournalRecord, Record, RecordClass};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};

const FAMILY: NamespaceId = NamespaceId(*b"busbar.unitcp.v1");
const TAG: &str = "unit.accrued";
const MEASUREMENT_TAG: &str = "measurement.accrued";
fn checkpoint_tag(snapshot: &UnitCheckpoint) -> &'static str {
    if snapshot.measurement.is_some() {
        MEASUREMENT_TAG
    } else {
        TAG
    }
}
fn error(e: impl std::fmt::Debug) -> RecordStoreError {
    crate::cold::governance::runtime::unit_checkpoint_store_error(&e)
}
fn refusal(message: &str) -> RecordStoreError {
    RecordStoreError(message.into())
}
/// A read against carried evidence: a different original at that place is named as such.
fn carried_error(e: RuntimeError) -> RecordStoreError {
    match e {
        RuntimeError::Corrupt => {
            refusal("journal original differs from carried evidence (Corrupt)")
        }
        other => error(other),
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    version: u8,
    node: u64,
    sequence: u64,
    revision: u64,
}

/// Root supplies its existing deployment signer and audit composition. Persistence
/// stays in this owner; callbacks may not select a checkpoint or invent a fee.
#[async_trait]
pub trait UnitCheckpointAudit: Send + Sync {
    fn keys(&self) -> AuditKeySet;
    /// SIGN A BATCH OF CHECKPOINT BODIES under the deployment key, one signature per body, in
    /// order (SEALING-FIX §3.3 "Checkpoint signing"): one job on the root's Bootstrap signer
    /// thread per persist call, never on the calling runtime. All or nothing: any failure fails
    /// every body, and nothing is staged.
    async fn sign_checkpoints(&self, bodies: &[&[u8]]) -> RecordStoreResult<Vec<Vec<u8>>>;
    /// Confirm a terminal unit's sealed audit line. `hint` is the line's carried evidence when
    /// this process sealed it (SHUTDOWN-HANG F1a): one read; `None` keeps the cold scan.
    async fn confirm(
        &self,
        snapshot: &UnitCheckpoint,
        hint: Option<Carried>,
    ) -> RecordStoreResult<()>;
    async fn recover(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()>;
}

#[derive(Clone)]
struct AuditPending {
    audit: AuditRecord,
    run: Arc<StagedRun>,
}
/// Scoped native evidence access for the root's unchanged audit composition.
pub struct UnitCheckpointEvidence {
    store: Arc<CoreStore>,
    node: u64,
    journal: Arc<RuntimeJournal>,
    _token: Grant<DurableWrite>,
    audit_pending: Mutex<Option<AuditPending>>,
    audit_driving: tokio::sync::Mutex<()>,
}
impl UnitCheckpointEvidence {
    pub fn new(journal: Arc<RuntimeJournal>, token: Grant<DurableWrite>) -> Self {
        Self {
            store: journal.store().clone(),
            node: journal.node(),
            journal,
            _token: token,
            audit_pending: Mutex::new(None),
            audit_driving: tokio::sync::Mutex::new(()),
        }
    }
    /// The runtime's live verified head, confirmed against native custody and
    /// admission while its publication driver is held. No history is replayed.
    async fn proof(&self) -> RecordStoreResult<Arc<VerifiedHead>> {
        self.journal.live_proof().await.map_err(error)
    }
    pub fn pending_audit(&self, unit: u64, incarnation: u64) -> Option<AuditRecord> {
        self.audit_pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .filter(|p| {
                p.audit.what.unit_key.get() == unit && p.audit.what.incarnation == incarnation
            })
            .map(|p| p.audit.clone())
    }
    /// Complete the native chain before returning any reconstructed audit facts.
    pub async fn find_audit(
        &self,
        unit: u64,
        incarnation: u64,
    ) -> RecordStoreResult<Option<AuditRecord>> {
        crate::off_path::governance::runtime::unit_checkpoint_store_find_audit(
            &self.journal,
            unit,
            incarnation,
        )
        .await
    }
    /// A terminal unit's live audit line, read by the evidence this process carried from its
    /// append (SHUTDOWN-HANG F1a).
    /// One original read at the line's computed ordinal, checked against the carried chain hash
    /// (`RuntimeJournal::record`), then decoded as a Transaction audit line. A line staged but not
    /// yet applied is published first (the journal flush), never searched for.
    pub async fn find_audit_at(&self, line: Carried) -> RecordStoreResult<AuditRecord> {
        let original = match self.journal.record(line).await {
            Err(RuntimeError::Pending) => {
                self.journal.flush().await.map_err(error)?;
                self.journal.record(line).await
            }
            read => read,
        }
        .map_err(carried_error)?;
        let record = JournalRecord::decode(&original.body).map_err(error)?;
        if record.class != RecordClass::Transaction {
            return Err(refusal("terminal unit's audit hint names no audit line"));
        }
        busbar_kernel_audit::from_journal_body(&record.body, &crate::Registration::meter_class)
            .map_err(error)?
            .ok_or_else(|| refusal("terminal unit's audit hint names no audit line"))
    }
    /// Retain the exact signed audit and original sealed frame before native IO.
    /// Callers reuse pending_audit after uncertainty rather than sealing a new line.
    /// Append a recovered running unit's audit line and confirm it. Returns the WAL `node_seq` of
    /// the record that carries it (SEALING-FIX §3.5 r16), or 0 when the identical line was already
    /// in the journal (found by scan, whose position this path does not keep).
    pub async fn append_audit(&self, audit: AuditRecord) -> RecordStoreResult<u64> {
        let _driving = self.audit_driving.lock().await;
        let existing = self
            .audit_pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let pending = if let Some(pending) = existing {
            if pending.audit != audit {
                return Err(refusal("another exact running audit awaits native custody"));
            }
            pending
        } else {
            if let Some(selected) = self
                .find_audit(audit.what.unit_key.get(), audit.what.incarnation)
                .await?
            {
                return if selected == audit {
                    Ok(0)
                } else {
                    Err(refusal("running audit identity already differs"))
                };
            }
            let entry = Entry::new(
                RecordClass::Transaction,
                busbar_kernel_audit::journal_body(&audit).map_err(error)?,
            )
            .at(audit.wall, audit.mono)
            .under(audit.controls.lease_epoch, audit.controls.policy_epoch);
            let run = self.journal.stage_run(&[entry]).map_err(error)?;
            let pending = AuditPending { audit, run };
            *self.audit_pending.lock().unwrap_or_else(|p| p.into_inner()) = Some(pending.clone());
            pending
        };
        self.journal.confirm(&pending.run).await.map_err(error)?;
        let node_seq = pending.run.records().first().map_or(0, |r| r.node_seq);
        self.audit_pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        Ok(node_seq)
    }
}

/// One checkpoint row of an attempt: its snapshot, the original the row names and the row's CAS.
#[derive(Clone)]
struct Row {
    snapshot: UnitCheckpoint,
    /// The staged checkpoint original (persist) or the selected one (removal).
    record: Record,
    /// The head row a persist puts; `None` deletes the row.
    value: Option<Secret<Vec<u8>>>,
    expected: Arc<ExpectedValue>,
    /// A removal's ordinal for its selected original, located lane-free.
    ordinal: Option<u64>,
    /// A persist's evidence for its staged original: carried once the append is confirmed.
    carried: Option<Carried>,
}

/// The one retained attempt (single-slot custody, SHUTDOWN-HANG F3.3): a persist or a removal of
/// one or more rows under one operation id, with one staged run for a persist. A single
/// `persist`/`remove` is an attempt of one row, so there is one code path.
#[derive(Clone)]
struct Pending {
    rows: Arc<[Row]>,
    /// A persist's staged originals; `None` for a removal.
    run: Option<Arc<StagedRun>>,
    appended: bool,
    /// The proof the retained attempt CASes against; `None` until the first crossing (live head)
    /// and after a definite no-effect re-arm.
    proof: Option<Arc<VerifiedHead>>,
    /// The last crossing definitely applied nothing and our authority was lost or could not be
    /// read: the next crossing first repeats the authority read, and nothing crosses until it
    /// passes (owner ruling 2026-11-16).
    authority_first: bool,
    operation: [u8; 16],
}
impl Pending {
    fn persist(&self) -> bool {
        self.run.is_some()
    }
    fn ids(&self) -> Vec<[u8; 16]> {
        self.rows.iter().map(|row| row.snapshot.id).collect()
    }
    /// The first `at` rows and the rest, each a fresh attempt under its own operation id. Only
    /// split an attempt that has definitely not applied, or has never crossed.
    fn split(self, at: usize) -> (Self, Self) {
        let (first, rest) = self.rows.split_at(at.min(self.rows.len()));
        let half = |rows: &[Row]| Self {
            rows: rows.into(),
            run: self.run.clone(),
            appended: self.appended,
            proof: None,
            authority_first: false,
            operation: crate::door::op_id().0,
        };
        (half(first), half(rest))
    }
}

/// What one crossing of the retained attempt decided.
enum Attempt {
    Applied,
    /// A definite no-effect on the attempt's first crossing: `conflict` for a failed condition,
    /// otherwise a refusal of the whole candidate. The slot still holds the attempt.
    Definite {
        pending: Pending,
        used: Arc<VerifiedHead>,
        conflict: bool,
        why: RecordStoreError,
    },
    /// A re-driven in-doubt attempt met a definite no-effect with our authority intact (owner
    /// ruling 2026-11-16): the same rows, re-armed under a new operation id and saved in the
    /// slot, to re-select against the live head.
    Reselect(Pending),
}

const UNRESOLVED: &str = "running money native custody remains unresolved";

fn copied(why: &RecordStoreError) -> RecordStoreError {
    RecordStoreError(why.0.clone())
}

pub struct StoreUnitCheckpoints {
    evidence: Arc<UnitCheckpointEvidence>,
    audit: Arc<dyn UnitCheckpointAudit>,
    pending: Mutex<Option<Pending>>,
    driving: tokio::sync::Mutex<()>,
    /// The selected original of each checkpoint in custody: inserted when P's append is
    /// confirmed (or by the boot replay), replaced by a later revision, popped when R's delete
    /// applies (SHUTDOWN-HANG F1). About 56 B per checkpoint; RAM only. On an Ephemeral journal
    /// each entry also pins its original, so no cut deletes it before R's
    /// `record(seq, carried)` reads it (SEALING-FIX §3.9 floor (d)).
    carried: Mutex<HashMap<[u8; 16], (Carried, Option<Pin>)>>,
}
impl StoreUnitCheckpoints {
    pub fn new(evidence: Arc<UnitCheckpointEvidence>, audit: Arc<dyn UnitCheckpointAudit>) -> Self {
        Self {
            evidence,
            audit,
            pending: Mutex::new(None),
            driving: tokio::sync::Mutex::new(()),
            carried: Mutex::new(HashMap::new()),
        }
    }
    /// Test probe: the evidence carried for checkpoint `id`'s selected original.
    #[cfg(test)]
    pub(crate) fn carried(&self, id: &[u8; 16]) -> Option<Carried> {
        self.carried_of(id)
    }
    fn namespace(&self) -> NamespaceId {
        partition::namespace(FAMILY, &[&self.evidence.node.to_be_bytes()])
    }
    fn prefix(&self) -> Vec<u8> {
        crate::off_path::governance::runtime::unit_checkpoint_store_prefix(
            &FAMILY.0,
            self.evidence.node,
        )
    }
    fn address(&self, id: &[u8; 16]) -> Address {
        let mut key = self.prefix();
        key.extend_from_slice(id);
        Address {
            namespace: self.namespace().0,
            key,
        }
    }
    async fn head(&self, id: &[u8; 16]) -> RecordStoreResult<Option<Secret<Vec<u8>>>> {
        match self
            .evidence
            .store
            .backend()
            .read(Arc::new(Read {
                dataset: self.evidence.store.info().dataset,
                addresses: vec![self.address(id)],
                time: None,
            }))
            .await
            .map_err(error)?
        {
            ReadResult::Values {
                observed_at,
                mut values,
            } if values.len() == 1
                && observed_at.authority == self.evidence.store.info().clock_authority =>
            {
                Ok(values.pop().flatten())
            }
            _ => Err(refusal("invalid running money head read")),
        }
    }
    async fn selected(
        &self,
        id: &[u8; 16],
        raw: &Secret<Vec<u8>>,
        proof: &VerifiedHead,
    ) -> RecordStoreResult<(Head, UnitCheckpoint, Record, Option<u64>, Carried)> {
        let head: Head = serde_json::from_slice(raw.expose(&crate::seal::lend())).map_err(error)?;
        if head.version != 1 || head.node != self.evidence.node || head.sequence == 0 {
            return Err(refusal("invalid running money head"));
        }
        let journal = self.evidence.journal.history().map_err(error)?;
        // Every record is located in O(1) from the runtime's segment map (W1); no replay.
        let ordinal = self
            .evidence
            .journal
            .locate(proof, head.sequence)
            .map_err(error)?;
        // An original this process appended (or the boot replay verified) is read against the
        // hash it carries, so a rewritten own original is refused, not trusted (SHUTDOWN-HANG F1).
        let original = match self.carried_of(id).filter(|c| c.seq == head.sequence) {
            Some(carried) => self
                .evidence
                .journal
                .record(carried)
                .await
                .map_err(carried_error)?,
            None => journal
                .record_at(proof, head.sequence, ordinal)
                .await
                .map_err(error)?,
        };
        let record = JournalRecord::decode(&original.body).map_err(error)?;
        let mut reader = BodyReader::new(&record.body);
        let tag = reader.text();
        if record.class != RecordClass::Checkpoint || !matches!(tag, Some(TAG | MEASUREMENT_TAG)) {
            return Err(refusal(
                "running money head does not name unit.accrued evidence",
            ));
        }
        let encoded = reader
            .bytes()
            .ok_or_else(|| refusal("truncated unit.accrued evidence"))?;
        let signature = reader
            .bytes()
            .ok_or_else(|| refusal("unsigned unit.accrued evidence"))?;
        let mut signed = BodyWriter::new();
        signed
            .text(tag.expect("validated checkpoint tag"))
            .bytes(encoded);
        self.audit
            .keys()
            .verify_checkpoint_body(&signed.finish(), signature)
            .map_err(error)?;
        if !reader.is_done() {
            return Err(refusal("trailing unit.accrued evidence"));
        }
        if tag == Some(MEASUREMENT_TAG)
            && encoded.len() > crate::host_measurement::MAX_EVIDENCE_BYTES
        {
            return Err(refusal("host measurement evidence exceeds bound"));
        }
        let snapshot: UnitCheckpoint = serde_json::from_slice(encoded).map_err(error)?;
        snapshot.validate()?;
        if tag != Some(checkpoint_tag(&snapshot)) {
            return Err(refusal(
                "checkpoint origin differs from signed evidence domain",
            ));
        }
        if snapshot.id != *id || snapshot.revision != head.revision {
            return Err(refusal("running money head differs from journal evidence"));
        }
        let carried = Carried {
            seq: head.sequence,
            hash: record.hash,
        };
        Ok((head, snapshot, original, Some(ordinal), carried))
    }
    fn carried_of(&self, id: &[u8; 16]) -> Option<Carried> {
        self.carried
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(id)
            .map(|(carried, _)| *carried)
    }
    /// Carry (or drop) checkpoint `id`'s original. Called while the original's staged run, or
    /// the boot replay before any cut, still covers it, so its pin is taken in time.
    fn carry(&self, id: [u8; 16], carried: Option<Carried>) {
        let mut map = self.carried.lock().unwrap_or_else(|p| p.into_inner());
        match carried {
            Some(carried) => {
                let pin = self.evidence.journal.pin(carried.seq);
                map.insert(id, (carried, pin));
            }
            None => {
                map.remove(&id);
            }
        }
    }
    fn no_foreign_pending(&self) -> RecordStoreResult<()> {
        if self
            .evidence
            .store
            .has_pending_namespace(self.namespace())
            .map_err(error)?
        {
            return Err(refusal(
                "running money selected-head custody remains unresolved",
            ));
        }
        Ok(())
    }
    fn save(&self, pending: Pending) {
        *self.pending.lock().unwrap_or_else(|p| p.into_inner()) = Some(pending);
    }
    fn clear(&self) {
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
    }
    fn retained(&self) -> Option<Pending> {
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
    fn held(&self) -> bool {
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some()
    }
    /// A definite no-effect re-arms the attempt: the same rows (and staged originals) under a
    /// new operation id, against the live head on the next crossing. It is saved in the slot and
    /// returned. With `authority_first` the next crossing first repeats the authority read, and
    /// nothing crosses until it passes.
    fn rearm(&self, mut pending: Pending, authority_first: bool) -> Pending {
        pending.proof = None;
        pending.authority_first = authority_first;
        pending.operation = crate::door::op_id().0;
        self.save(pending.clone());
        pending
    }
    /// Write the proof `change_rows_live` will CAS against into the retained slot,
    /// synchronously under its driver and before any native claim. Only the
    /// attempt with this exact operation id is touched.
    fn retain_proof(&self, operation: [u8; 16], proof: &Arc<VerifiedHead>) {
        let mut slot = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(pending) = slot.as_mut().filter(|p| p.operation == operation) {
            pending.proof = Some(proof.clone());
        }
    }

    /// One crossing of `pending`, which is retained before anything else: the append of its
    /// staged originals if not yet confirmed, then one CAS of all its rows built under the
    /// journal's publication driver against its live head (or the exact retained proof), so no
    /// append can move the head between the proof and the CAS. `Err` while it stays retained.
    async fn attempt(&self, mut pending: Pending) -> RecordStoreResult<Attempt> {
        self.save(pending.clone());
        if let Some(run) = pending.run.clone() {
            if !pending.appended {
                self.evidence.journal.confirm(&run).await.map_err(error)?;
                pending.appended = true;
                self.save(pending.clone());
            }
        }
        // A retained proof means an earlier crossing of this exact attempt has an unknown outcome
        // (cancelled or reply lost).
        if pending.authority_first {
            // (owner ruling 2026-11-16) Our authority was lost or unread after a crossing that
            // applied nothing: only the authority read repeats until it passes.
            self.evidence
                .journal
                .confirm_with(&[])
                .await
                .map_err(error)?;
            pending.authority_first = false;
            self.save(pending.clone());
        }
        let redrive = pending.proof.is_some();
        let operation = pending.operation;
        let mut changes = Vec::new();
        changes
            .try_reserve_exact(pending.rows.len())
            .map_err(error)?;
        for row in pending.rows.iter() {
            changes.push(RowChange {
                records: std::slice::from_ref(&row.record),
                address: self.address(&row.snapshot.id),
                expected: duplicate_expected(&row.expected),
                value: row.value.clone(),
            });
        }
        let (used, result) = self
            .evidence
            .journal
            .change_rows_live(
                operation,
                &changes,
                pending.proof.clone(),
                &|proof: &Arc<VerifiedHead>| self.retain_proof(operation, proof),
            )
            .await
            .map_err(error)?;
        drop(changes);
        pending.proof = Some(used.clone());
        match outcome(result) {
            Ok(()) => {
                self.clear();
                // A persisted original is this process's own sealing: carry it until the
                // checkpoint's delete applies (SHUTDOWN-HANG F1). A removal pops it.
                for row in pending.rows.iter() {
                    self.carry(row.snapshot.id, row.carried);
                }
                Ok(Attempt::Applied)
            }
            Err(Failed::Unresolved(why)) => Err(why),
            Err(Failed::Definite { .. }) if redrive => {
                // (F2.2, owner ruling 2026-11-16 "Re-select, after authority check") The re-drive
                // resubmitted the retained attempt under its own commit key, and the store answers
                // an attempt that already applied as Applied: this no-effect is definitive. Our
                // authority first: lost, nothing crosses again until it passes; otherwise the same
                // rows and staged originals are re-selected once under a new operation id.
                if let Err(lost) = self.evidence.journal.confirm_with(&[]).await {
                    self.rearm(pending, true);
                    return Err(error(lost));
                }
                Ok(Attempt::Reselect(self.rearm(pending, false)))
            }
            Err(Failed::Definite { conflict, why }) => Ok(Attempt::Definite {
                pending,
                used,
                conflict,
                why,
            }),
        }
    }

    /// Drives `first` to an answer per row (SHUTDOWN-HANG F3.2, F3.3).
    /// - Applied: every row of the attempt is Ok.
    /// - In doubt: the attempt stays retained with the same membership; its rows and every row
    ///   not yet tried answer unresolved, and the next call resolves it first.
    /// - A definite condition conflict bisects: each half under a new operation id (after a
    ///   definite no-effect that is safe), down to single rows, classified alone (F2).
    /// - A definite refusal of the whole attempt is first checked against our authority (one
    ///   read; a fenced writer is never retried as benign). Otherwise the batch limit is halved
    ///   for the rest of the call, each half is retried, and `UNIT_FLUSH_BATCH_REDUCED` is raised
    ///   once.
    ///
    /// For one bad row of B, at most 2·log2 B extra crossings.
    async fn drive(&self, first: Pending) -> Vec<([u8; 16], RecordStoreResult<()>)> {
        let mut out = Vec::with_capacity(first.rows.len());
        let mut limit = first.rows.len().max(1);
        let mut reduced = false;
        let mut blocked: Option<String> = None;
        let mut work = vec![first];
        while let Some(next) = work.pop() {
            if let Some(why) = &blocked {
                out.extend(
                    next.rows
                        .iter()
                        .map(|row| (row.snapshot.id, Err(RecordStoreError(why.clone())))),
                );
                continue;
            }
            if next.rows.len() > limit {
                let (head, rest) = next.split(limit);
                work.push(rest);
                work.push(head);
                continue;
            }
            let ids = next.ids();
            match self.attempt(next).await {
                Ok(Attempt::Applied) => out.extend(ids.into_iter().map(|id| (id, Ok(())))),
                Ok(Attempt::Reselect(pending)) => work.push(pending),
                Err(why) => {
                    out.extend(ids.iter().map(|id| (*id, Err(copied(&why)))));
                    blocked = Some(why.0);
                }
                Ok(Attempt::Definite {
                    pending,
                    used,
                    conflict,
                    why,
                }) => {
                    let width = pending.rows.len();
                    if width == 1 {
                        let (why, held) = self.alone(pending, used, why).await;
                        if held {
                            blocked = Some(why.0.clone());
                        }
                        out.push((ids[0], Err(why)));
                    } else if conflict {
                        self.clear();
                        let (head, rest) = pending.split(width / 2);
                        work.push(rest);
                        work.push(head);
                    } else if let Err(lost) = self.evidence.journal.confirm_with(&[]).await {
                        // Authority first (F3.2 step 4, r13): fenced, or not read. Nothing is
                        // split and the limit is not halved; the attempt is re-armed whole and
                        // the next call repeats only this check; nothing crosses until it passes.
                        let why = error(lost);
                        self.rearm(pending, true);
                        out.extend(ids.iter().map(|id| (*id, Err(copied(&why)))));
                        blocked = Some(why.0);
                    } else {
                        self.clear();
                        limit = limit.min(width / 2).max(1);
                        reduced = true;
                        let (head, rest) = pending.split(width / 2);
                        work.push(rest);
                        work.push(head);
                    }
                }
            }
        }
        if reduced {
            crate::diag_warn!(
                crate::diagnostics::UNIT_FLUSH_BATCH_REDUCED,
                b = limit,
                "the store refused a whole unit checkpoint batch; the rest of this batch used smaller ones"
            );
        }
        out
    }

    /// A definite no-effect for one row on its first crossing (SHUTDOWN-HANG F2).
    /// Returns the row's error, and whether its attempt stays retained in the slot.
    async fn alone(
        &self,
        pending: Pending,
        used: Arc<VerifiedHead>,
        why: RecordStoreError,
    ) -> (RecordStoreError, bool) {
        let Some(row) = pending.rows.first().cloned() else {
            self.clear();
            return (why, false);
        };
        // A different service may append to this same journal between verification and
        // selection. A known no-effect reply releases only the native attempt, never the exact
        // signed checkpoint and already sealed original frames.
        let current = match self.head(&row.snapshot.id).await {
            Ok(current) => current,
            Err(failed) => {
                self.rearm(pending, false);
                return (failed, true);
            }
        };
        let unchanged = match (row.expected.as_ref(), current.as_ref()) {
            (ExpectedValue::Absent, None) => true,
            (ExpectedValue::Exact(expected), Some(current)) => expected == current,
            _ => false,
        };
        if !unchanged {
            // (F2, 8.4(b)) Another candidate holds the row, so this attempt can never apply: it
            // is discarded, and the next pass reads the row afresh.
            self.clear();
            return (
                refusal("another candidate won the running money checkpoint selection"),
                false,
            );
        }
        // (F2.2) With the head row unchanged, a definite no-effect is our authority (a fence, a
        // moved root epoch, an execution epoch no longer admitted; a size refusal and a fenced
        // send answer alike) or a changed original. Authority first, in one read: then the
        // attempt is kept, never retried as benign, and nothing crosses until the read passes.
        if let Err(lost) = self.evidence.journal.confirm_with(&[]).await {
            self.rearm(pending, true);
            return (error(lost), true);
        }
        // Under the driver a no-effect is a real fence, epoch or foreign change, or changed
        // original bytes: name a changed original as such instead of a moved head.
        let mut diagnosis = None;
        match self.evidence.journal.history() {
            Ok(journal) => {
                let ordinal = self
                    .evidence
                    .journal
                    .locate(&used, row.record.node_seq)
                    .ok()
                    .or(row.ordinal);
                if let Some(ordinal) = ordinal {
                    if let Err(failed) = journal.confirm_original(&used, ordinal, &row.record).await
                    {
                        diagnosis = Some(error(failed));
                    }
                }
            }
            Err(failed) => diagnosis = Some(error(failed)),
        }
        // Re-arm with the live head on the next call.
        self.rearm(pending, false);
        (diagnosis.unwrap_or(why), true)
    }

    /// The retained attempt is resolved first, with exactly its membership (F3.2 step 1). Each
    /// of `snapshots` it covered and applied answers Ok in `out`; `Err` while it stays retained.
    async fn resolve_retained(
        &self,
        persist: bool,
        snapshots: &[&UnitCheckpoint],
        out: &mut [Option<RecordStoreResult<()>>],
    ) -> RecordStoreResult<()> {
        let Some(retained) = self.retained() else {
            return Ok(());
        };
        let covered: Vec<bool> = snapshots
            .iter()
            .map(|snapshot| {
                retained.persist() == persist
                    && retained.rows.iter().any(|row| row.snapshot == **snapshot)
            })
            .collect();
        let answers = self.drive(retained).await;
        if self.held() {
            return Err(answers
                .iter()
                .find_map(|(_, answer)| answer.as_ref().err().map(copied))
                .unwrap_or_else(|| refusal(UNRESOLVED)));
        }
        for (at, snapshot) in snapshots.iter().enumerate() {
            if covered[at]
                && answers
                    .iter()
                    .any(|(id, answer)| *id == snapshot.id && answer.is_ok())
            {
                out[at] = Some(Ok(()));
            }
        }
        Ok(())
    }

    /// Phase P (SHUTDOWN-HANG F3.1): every checkpoint that needs a new original is signed, all
    /// are staged as one run and appended once, and all rows are selected in one CAS. A
    /// checkpoint already selected is confirmed in place.
    async fn persist_rows(&self, snapshots: &[UnitCheckpoint]) -> Vec<RecordStoreResult<()>> {
        let _driving = self.driving.lock().await;
        let mut out: Vec<Option<RecordStoreResult<()>>> = Vec::with_capacity(snapshots.len());
        out.resize_with(snapshots.len(), || None);
        let refs: Vec<&UnitCheckpoint> = snapshots.iter().collect();
        if let Err(why) = self.resolve_retained(true, &refs, &mut out).await {
            return answered(out, &why);
        }
        if let Err(why) = self.no_foreign_pending() {
            return answered(out, &why);
        }
        let mut unsigned: Vec<(Vec<u8>, u64)> = Vec::new();
        let mut staged: Vec<(usize, Option<Secret<Vec<u8>>>)> = Vec::new();
        for (at, snapshot) in snapshots.iter().enumerate() {
            if out[at].is_some() {
                continue;
            }
            if snapshots[..at]
                .iter()
                .any(|earlier| earlier.id == snapshot.id)
            {
                out[at] = Some(Err(refusal(
                    "a running money checkpoint repeats in one batch",
                )));
                continue;
            }
            match self.prepare_persist(snapshot).await {
                Ok(None) => out[at] = Some(Ok(())),
                Ok(Some((body, arrived, previous))) => {
                    unsigned.push((body, arrived));
                    staged.push((at, previous));
                }
                Err(why) => out[at] = Some(Err(why)),
            }
        }
        if staged.is_empty() {
            return answered(out, &refusal("unit checkpoint batch result missing"));
        }
        // One signing job for the whole batch (SEALING-FIX §3.3): all or nothing, before staging.
        let bodies: Vec<&[u8]> = unsigned.iter().map(|(body, _)| body.as_slice()).collect();
        let signed = match self.audit.sign_checkpoints(&bodies).await {
            Ok(signatures) if signatures.len() == unsigned.len() => Ok(signatures),
            Ok(_) => Err(refusal("unit checkpoint signer answered a different count")),
            Err(why) => Err(why),
        };
        let signatures = match signed {
            Ok(signatures) => signatures,
            Err(why) => {
                for (at, _) in &staged {
                    out[*at] = Some(Err(copied(&why)));
                }
                return answered(out, &why);
            }
        };
        let entries: Vec<Entry> = unsigned
            .into_iter()
            .zip(signatures)
            .map(|((mut signed, arrived), signature)| {
                let mut field = BodyWriter::new();
                field.bytes(&signature);
                signed.extend_from_slice(&field.finish());
                Entry::new(RecordClass::Checkpoint, signed).at(arrived, 0)
            })
            .collect();
        let run = match self.evidence.journal.stage_run(&entries).map_err(error) {
            Ok(run) => run,
            Err(why) => {
                for (at, _) in &staged {
                    out[*at] = Some(Err(copied(&why)));
                }
                return answered(out, &why);
            }
        };
        let carried: Vec<Carried> = run.carried().collect();
        let mut rows = Vec::with_capacity(staged.len());
        for (index, (at, previous)) in staged.into_iter().enumerate() {
            let snapshot = &snapshots[at];
            let Some(record) = run.records().get(index).cloned() else {
                out[at] = Some(Err(refusal("unit.accrued staging produced no original")));
                continue;
            };
            let head = Head {
                version: 1,
                node: self.evidence.node,
                sequence: record.node_seq,
                revision: snapshot.revision,
            };
            match crate::off_path::governance::runtime::unit_checkpoint_store_encode(&head) {
                Ok(value) => rows.push(Row {
                    snapshot: snapshot.clone(),
                    record,
                    value: Some(Secret::new(value)),
                    expected: Arc::new(
                        previous.map_or(ExpectedValue::Absent, ExpectedValue::Exact),
                    ),
                    ordinal: None,
                    carried: carried.get(index).copied(),
                }),
                Err(failed) => out[at] = Some(Err(error(failed))),
            }
        }
        if !rows.is_empty() {
            let pending = Pending {
                rows: rows.into(),
                run: Some(run),
                appended: false,
                proof: None,
                authority_first: false,
                operation: crate::door::op_id().0,
            };
            place(&mut out, snapshots.iter(), self.drive(pending).await);
        }
        answered(out, &refusal("unit checkpoint batch result missing"))
    }

    /// One checkpoint's pre-checks before staging: `None` when its exact revision is already
    /// selected (confirmed in place), else its unsigned original body, its arrival, and the head
    /// row it replaces. The caller signs every body of the batch in one job.
    async fn prepare_persist(
        &self,
        snapshot: &UnitCheckpoint,
    ) -> RecordStoreResult<Option<(Vec<u8>, u64, Option<Secret<Vec<u8>>>)>> {
        snapshot.validate()?;
        if snapshot.measurement.is_none() && snapshot.audit.is_none() {
            return Err(refusal("unit.accrued lacks captured admission audit facts"));
        }
        let previous = self.head(&snapshot.id).await?;
        // A lane-free snapshot: the selected original is located in it and read against its
        // carried hash; every write below is a CAS on H and O (SHUTDOWN-HANG F1).
        let proof = self.evidence.journal.verified().map_err(error)?;
        if let Some(raw) = &previous {
            let (head, selected, _, _, _) = self.selected(&snapshot.id, raw, &proof).await?;
            if selected == *snapshot {
                self.evidence
                    .journal
                    .confirm_with(&[busbar_contract::persistence::Predicate {
                        address: self.address(&snapshot.id),
                        expected: ExpectedValue::Exact(raw.clone()),
                    }])
                    .await
                    .map_err(error)?;
                return Ok(None);
            }
            if head.revision >= snapshot.revision || selected.terminal.is_some() {
                return Err(refusal(
                    "running money checkpoint would overwrite selected custody",
                ));
            }
        }
        let encoded = crate::off_path::governance::runtime::unit_checkpoint_store_encode(snapshot)
            .map_err(error)?;
        if snapshot.measurement.is_some()
            && encoded.len() > crate::host_measurement::MAX_EVIDENCE_BYTES
        {
            return Err(refusal("host measurement evidence exceeds bound"));
        }
        let mut body = BodyWriter::new();
        body.text(checkpoint_tag(snapshot)).bytes(&encoded);
        Ok(Some((body.finish(), snapshot.arrived, previous)))
    }

    /// Phase R (SHUTDOWN-HANG F3.1): each terminal checkpoint's audit is confirmed (by its carried
    /// hint, F1a), its selected original verified, and all rows are deleted in one CAS.
    async fn remove_rows(&self, items: &[UnitRemoval<'_>]) -> Vec<RecordStoreResult<()>> {
        let _driving = self.driving.lock().await;
        let mut out: Vec<Option<RecordStoreResult<()>>> = Vec::with_capacity(items.len());
        out.resize_with(items.len(), || None);
        let refs: Vec<&UnitCheckpoint> = items.iter().map(|item| item.snapshot).collect();
        if let Err(why) = self.resolve_retained(false, &refs, &mut out).await {
            return answered(out, &why);
        }
        if let Err(why) = self.no_foreign_pending() {
            return answered(out, &why);
        }
        let mut rows = Vec::new();
        for (at, item) in items.iter().enumerate() {
            if out[at].is_some() {
                continue;
            }
            if refs[..at]
                .iter()
                .any(|earlier| earlier.id == item.snapshot.id)
            {
                out[at] = Some(Err(refusal(
                    "a running money checkpoint repeats in one batch",
                )));
                continue;
            }
            match self.prepare_remove(item).await {
                Ok(None) => out[at] = Some(Ok(())),
                Ok(Some(row)) => rows.push(row),
                Err(why) => out[at] = Some(Err(why)),
            }
        }
        if !rows.is_empty() {
            let pending = Pending {
                rows: rows.into(),
                run: None,
                appended: true,
                proof: None,
                authority_first: false,
                operation: crate::door::op_id().0,
            };
            place(&mut out, refs.iter().copied(), self.drive(pending).await);
        }
        answered(out, &refusal("unit checkpoint batch result missing"))
    }

    /// One removal's pre-checks: `None` when the row is already gone (confirmed absent), else
    /// the row to delete.
    async fn prepare_remove(&self, item: &UnitRemoval<'_>) -> RecordStoreResult<Option<Row>> {
        let snapshot = item.snapshot;
        if snapshot.terminal.is_none() {
            return Err(refusal(
                "cannot remove running money before terminal custody",
            ));
        }
        if snapshot.measurement.is_none() {
            self.audit.confirm(snapshot, item.audit).await?;
        }
        let Some(raw) = self.head(&snapshot.id).await? else {
            self.evidence
                .journal
                .confirm_with(&[busbar_contract::persistence::Predicate {
                    address: self.address(&snapshot.id),
                    expected: ExpectedValue::Absent,
                }])
                .await
                .map_err(error)?;
            return Ok(None);
        };
        let proof = self.evidence.journal.verified().map_err(error)?;
        let (_, selected, record, ordinal, _) = self.selected(&snapshot.id, &raw, &proof).await?;
        if selected != *snapshot {
            return Err(refusal("terminal running money custody changed"));
        }
        Ok(Some(Row {
            snapshot: snapshot.clone(),
            record,
            value: None,
            expected: Arc::new(ExpectedValue::Exact(raw)),
            ordinal,
            carried: None,
        }))
    }
}

/// Every answer of `drive`, placed at its checkpoint's position (ids are unique in a batch).
fn place<'a>(
    out: &mut [Option<RecordStoreResult<()>>],
    snapshots: impl Iterator<Item = &'a UnitCheckpoint>,
    answers: Vec<([u8; 16], RecordStoreResult<()>)>,
) {
    let mut by_id: HashMap<[u8; 16], RecordStoreResult<()>> = answers.into_iter().collect();
    for (at, snapshot) in snapshots.enumerate() {
        if out[at].is_none() {
            if let Some(answer) = by_id.remove(&snapshot.id) {
                out[at] = Some(answer);
            }
        }
    }
}

/// The batch's answers in order; a position with no answer gets `missing`.
fn answered(
    out: Vec<Option<RecordStoreResult<()>>>,
    missing: &RecordStoreError,
) -> Vec<RecordStoreResult<()>> {
    out.into_iter()
        .map(|answer| answer.unwrap_or_else(|| Err(copied(missing))))
        .collect()
}

fn duplicate_expected(expected: &ExpectedValue) -> ExpectedValue {
    match expected {
        ExpectedValue::Absent => ExpectedValue::Absent,
        ExpectedValue::Exact(value) => ExpectedValue::Exact(value.clone()),
    }
}

enum Failed {
    /// A definite no-effect: `conflict` for a failed condition, otherwise a refusal.
    Definite {
        conflict: bool,
        why: RecordStoreError,
    },
    /// The attempt may still apply, or needs reconciliation: it stays retained.
    Unresolved(RecordStoreError),
}

fn outcome(result: WriteResult) -> Result<(), Failed> {
    match result {
        WriteResult::Submitted(submission) => match submission.result {
            SubmitResult::Decided(decision) => match decision.as_ref() {
                Decision::Applied(_) => Ok(()),
                Decision::ConditionConflict => Err(Failed::Definite {
                    conflict: true,
                    why: refusal("running money head or node fence changed"),
                }),
                Decision::TimeGuardFailed { .. } => Err(Failed::Definite {
                    conflict: false,
                    why: refusal("running money temporal guard refused"),
                }),
                Decision::OpIdConflict | Decision::Fenced | Decision::Stale => {
                    Err(Failed::Unresolved(refusal(
                        "running money native identity requires reconciliation",
                    )))
                }
            },
            SubmitResult::NoEffect(failure) => Err(Failed::Definite {
                conflict: false,
                why: error(failure),
            }),
            _ => Err(Failed::Unresolved(refusal(UNRESOLVED))),
        },
        WriteResult::Busy => Err(Failed::Unresolved(refusal(
            "running money native custody has an active driver",
        ))),
    }
}

#[async_trait]
impl UnitCheckpointSink for StoreUnitCheckpoints {
    async fn persist(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        self.persist_rows(std::slice::from_ref(snapshot))
            .await
            .pop()
            .unwrap_or_else(|| Err(refusal("unit checkpoint batch result missing")))
    }
    async fn remove(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        self.remove_rows(&[UnitRemoval {
            snapshot,
            audit: None,
        }])
        .await
        .pop()
        .unwrap_or_else(|| Err(refusal("unit checkpoint batch result missing")))
    }
    /// One staged run, one append and one selection CAS for the whole batch (SHUTDOWN-HANG F3.1).
    async fn persist_batch(&self, snapshots: &[UnitCheckpoint]) -> Vec<RecordStoreResult<()>> {
        self.persist_rows(snapshots).await
    }
    /// One delete CAS for the whole batch; each removal carries its unit's audit hint into the
    /// audit confirmation (SHUTDOWN-HANG F1a, F3.1).
    async fn remove_batch(&self, items: &[UnitRemoval<'_>]) -> Vec<RecordStoreResult<()>> {
        self.remove_rows(items).await
    }
    async fn replay(&self) -> RecordStoreResult<Vec<UnitCheckpoint>> {
        self.no_foreign_pending()?;
        let collection = self
            .evidence
            .store
            .scan(self.namespace(), self.prefix(), None)
            .await
            .map_err(error)?;
        let proof = self.evidence.proof().await?;
        let mut out = BTreeMap::new();
        for (address, raw) in collection.rows {
            let id: [u8; 16] = address
                .key
                .get(24..)
                .ok_or_else(|| refusal("invalid running money key"))?
                .try_into()
                .map_err(error)?;
            let (_, snapshot, _, _, carried) = self.selected(&id, &raw, &proof).await?;
            // Boot evidence: this chain was just verified, so later reads check against it.
            self.carry(id, Some(carried));
            if out.insert(id, snapshot).is_some() {
                return Err(refusal("duplicate running money checkpoint"));
            }
        }
        let guard = crate::persistence::fences::scan_guard(self.namespace(), collection.generation);
        self.evidence
            .journal
            .confirm_with(&[guard])
            .await
            .map_err(error)?;
        self.no_foreign_pending()?;
        Ok(crate::off_path::governance::runtime::unit_checkpoint_store_replayed(out))
    }
    async fn recover_audit(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        if snapshot.measurement.is_some() {
            snapshot.validate()
        } else {
            self.audit.recover(snapshot).await
        }
    }
}
