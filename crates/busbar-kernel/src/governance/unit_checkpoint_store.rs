// SPDX-License-Identifier: Apache-2.0
//! Native custody for signed running-unit checkpoints. Journal framing, original
//! record identity and selected evidence are retained across every uncertain call.
use super::unit_checkpoint::{UnitCheckpoint, UnitCheckpointSink};
use crate::persistence::{
    commit::SubmitResult,
    facade::CoreStore,
    journal::{
        runtime::{RuntimeJournal, StagedRun},
        Selection, StoreJournal, VerifiedHead, WriteResult,
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
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

const FAMILY: NamespaceId = NamespaceId(*b"busbar.unitcp.v1");
const TAG: &str = "unit.accrued";
fn error(e: impl std::fmt::Debug) -> RecordStoreError {
    RecordStoreError(format!("unit checkpoint: {e:?}"))
}
fn refusal(message: &str) -> RecordStoreError {
    RecordStoreError(message.into())
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
    fn sign_checkpoint(&self, body: &[u8]) -> RecordStoreResult<Vec<u8>>;
    async fn confirm(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()>;
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
    async fn proof(&self) -> RecordStoreResult<Arc<VerifiedHead>> {
        self.journal.flush().await.map_err(error)?;
        let journal = StoreJournal::new(&self.store, self.node).map_err(error)?;
        let mut replay = journal.historical_replay().await.map_err(error)?;
        while replay.next().await.map_err(error)?.is_some() {}
        let proof = Arc::new(replay.finish().map_err(error)?);
        journal.confirm_owned(&proof).await.map_err(error)?;
        Ok(proof)
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
        self.journal.flush().await.map_err(error)?;
        let journal = StoreJournal::new(&self.store, self.node).map_err(error)?;
        let mut replay = journal.historical_replay().await.map_err(error)?;
        let mut found = None;
        while let Some(original) = replay.next().await.map_err(error)? {
            let record = JournalRecord::decode(&original.body).map_err(error)?;
            if record.class != RecordClass::Transaction {
                continue;
            }
            if let Some(audit) = busbar_kernel_audit::from_journal_body(
                &record.body,
                &crate::Registration::meter_class,
            )
            .map_err(error)?
            {
                if audit.what.unit_key.get() == unit && audit.what.incarnation == incarnation {
                    if found.is_some() {
                        return Err(refusal("duplicate original audit for recovered unit"));
                    }
                    found = Some(audit);
                }
            }
        }
        let proof = replay.finish().map_err(error)?;
        journal.confirm_owned(&proof).await.map_err(error)?;
        Ok(found)
    }
    /// Retain the exact signed audit and original sealed frame before native IO.
    /// Callers reuse pending_audit after uncertainty rather than sealing a new line.
    pub async fn append_audit(&self, audit: AuditRecord) -> RecordStoreResult<()> {
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
                    Ok(())
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
        self.audit_pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        Ok(())
    }
}

#[derive(Clone)]
struct PersistPending {
    snapshot: UnitCheckpoint,
    run: Arc<StagedRun>,
    head: Head,
    expected: Arc<ExpectedValue>,
    appended: bool,
    selection_proof: Option<Arc<VerifiedHead>>,
    operation: [u8; 16],
}
#[derive(Clone)]
struct RemovePending {
    snapshot: UnitCheckpoint,
    record: Record,
    expected: Arc<ExpectedValue>,
    proof: Arc<VerifiedHead>,
    operation: [u8; 16],
}
#[derive(Clone)]
enum Pending {
    Persist(PersistPending),
    Remove(RemovePending),
}
impl Pending {
    fn snapshot(&self) -> &UnitCheckpoint {
        match self {
            Self::Persist(p) => &p.snapshot,
            Self::Remove(p) => &p.snapshot,
        }
    }
}

pub struct StoreUnitCheckpoints {
    evidence: Arc<UnitCheckpointEvidence>,
    audit: Arc<dyn UnitCheckpointAudit>,
    pending: Mutex<Option<Pending>>,
    driving: tokio::sync::Mutex<()>,
}
impl StoreUnitCheckpoints {
    pub fn new(evidence: Arc<UnitCheckpointEvidence>, audit: Arc<dyn UnitCheckpointAudit>) -> Self {
        Self {
            evidence,
            audit,
            pending: Mutex::new(None),
            driving: tokio::sync::Mutex::new(()),
        }
    }
    fn namespace(&self) -> NamespaceId {
        partition::namespace(FAMILY, &[&self.evidence.node.to_be_bytes()])
    }
    fn prefix(&self) -> Vec<u8> {
        let mut key = FAMILY.0.to_vec();
        key.extend_from_slice(&self.evidence.node.to_be_bytes());
        key
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
    ) -> RecordStoreResult<(Head, UnitCheckpoint, Record)> {
        let head: Head = serde_json::from_slice(raw.expose(&crate::seal::lend())).map_err(error)?;
        if head.version != 1 || head.node != self.evidence.node || head.sequence == 0 {
            return Err(refusal("invalid running money head"));
        }
        let original = StoreJournal::new(&self.evidence.store, head.node)
            .map_err(error)?
            .read_verified_record(proof, head.sequence)
            .await
            .map_err(error)?;
        let record = JournalRecord::decode(&original.body).map_err(error)?;
        let mut reader = BodyReader::new(&record.body);
        if record.class != RecordClass::Checkpoint || reader.text() != Some(TAG) {
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
        signed.text(TAG).bytes(encoded);
        self.audit
            .keys()
            .verify_checkpoint_body(&signed.finish(), signature)
            .map_err(error)?;
        if !reader.is_done() {
            return Err(refusal("trailing unit.accrued evidence"));
        }
        let snapshot: UnitCheckpoint = serde_json::from_slice(encoded).map_err(error)?;
        snapshot.validate()?;
        if snapshot.id != *id || snapshot.revision != head.revision {
            return Err(refusal("running money head differs from journal evidence"));
        }
        Ok((head, snapshot, original))
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
    async fn complete(&self) -> RecordStoreResult<Option<Pending>> {
        let pending = self
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let Some(mut pending) = pending else {
            return Ok(None);
        };
        let journal = StoreJournal::new(&self.evidence.store, self.evidence.node).map_err(error)?;
        let result = match &mut pending {
            Pending::Persist(p) => {
                if !p.appended {
                    self.evidence.journal.confirm(&p.run).await.map_err(error)?;
                    p.appended = true;
                    self.save(Pending::Persist(p.clone()));
                }
                if p.selection_proof.is_none() {
                    p.selection_proof = Some(self.evidence.proof().await?);
                    self.save(Pending::Persist(p.clone()));
                }
                journal
                    .select_verified(
                        p.selection_proof
                            .as_ref()
                            .expect("retained selection proof"),
                        p.run.records(),
                        Selection {
                            operation_id: p.operation,
                            address: self.address(&p.snapshot.id),
                            expected: duplicate_expected(&p.expected),
                            value: Secret::new(serde_json::to_vec(&p.head).map_err(error)?),
                        },
                    )
                    .await
                    .map_err(error)?
            }
            Pending::Remove(p) => journal
                .delete_verified(
                    &p.proof,
                    std::slice::from_ref(&p.record),
                    p.operation,
                    self.address(&p.snapshot.id),
                    duplicate_expected(&p.expected),
                )
                .await
                .map_err(error)?,
        };
        match outcome(result) {
            Ok(()) => {
                self.clear();
                Ok(Some(pending))
            }
            Err((definite, why)) => {
                if definite {
                    // A different service may append to this same journal
                    // between verification and selection. A known no-effect
                    // reply releases only the native attempt, never the exact
                    // signed checkpoint and already sealed original frames.
                    let (snapshot, expected) = match &pending {
                        Pending::Persist(p) => (&p.snapshot, p.expected.as_ref()),
                        Pending::Remove(p) => (&p.snapshot, p.expected.as_ref()),
                    };
                    let current = self.head(&snapshot.id).await?;
                    let unchanged = match (expected, current.as_ref()) {
                        (ExpectedValue::Absent, None) => true,
                        (ExpectedValue::Exact(expected), Some(current)) => expected == current,
                        _ => false,
                    };
                    if !unchanged {
                        return Err(why);
                    }
                    let proof = self.evidence.proof().await?;
                    match &mut pending {
                        Pending::Persist(p) => {
                            p.selection_proof = Some(proof);
                            p.operation = crate::door::op_id().0;
                        }
                        Pending::Remove(p) => {
                            p.proof = proof;
                            p.operation = crate::door::op_id().0;
                        }
                    }
                    self.save(pending);
                }
                Err(why)
            }
        }
    }
}

fn duplicate_expected(expected: &ExpectedValue) -> ExpectedValue {
    match expected {
        ExpectedValue::Absent => ExpectedValue::Absent,
        ExpectedValue::Exact(value) => ExpectedValue::Exact(value.clone()),
    }
}

fn outcome(result: WriteResult) -> Result<(), (bool, RecordStoreError)> {
    match result {
        WriteResult::Submitted(submission) => match submission.result {
            SubmitResult::Decided(decision) => match decision.as_ref() {
                Decision::Applied(_) => Ok(()),
                Decision::ConditionConflict => {
                    Err((true, refusal("running money head or node fence changed")))
                }
                Decision::TimeGuardFailed { .. } => {
                    Err((true, refusal("running money temporal guard refused")))
                }
                Decision::OpIdConflict | Decision::ExpiredUnknown => Err((
                    false,
                    refusal("running money native identity requires reconciliation"),
                )),
            },
            SubmitResult::NoEffect(failure) => Err((true, error(failure))),
            _ => Err((
                false,
                refusal("running money native custody remains unresolved"),
            )),
        },
        WriteResult::Busy => Err((
            false,
            refusal("running money native custody has an active driver"),
        )),
    }
}

#[async_trait]
impl UnitCheckpointSink for StoreUnitCheckpoints {
    async fn persist(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        let _driving = self.driving.lock().await;
        if self
            .complete()
            .await?
            .as_ref()
            .is_some_and(|p| matches!(p, Pending::Persist(_)) && p.snapshot() == snapshot)
        {
            return Ok(());
        }
        self.no_foreign_pending()?;
        snapshot.validate()?;
        if snapshot.audit.is_none() {
            return Err(refusal("unit.accrued lacks captured admission audit facts"));
        }
        let previous = self.head(&snapshot.id).await?;
        let proof = self.evidence.proof().await?;
        if let Some(raw) = &previous {
            let (head, selected, _) = self.selected(&snapshot.id, raw, &proof).await?;
            if selected == *snapshot {
                StoreJournal::new(&self.evidence.store, self.evidence.node)
                    .map_err(error)?
                    .confirm_owned_with(
                        &proof,
                        &[busbar_contract::persistence::Predicate {
                            address: self.address(&snapshot.id),
                            expected: ExpectedValue::Exact(raw.clone()),
                        }],
                    )
                    .await
                    .map_err(error)?;
                return Ok(());
            }
            if head.revision >= snapshot.revision || selected.terminal.is_some() {
                return Err(refusal(
                    "running money checkpoint would overwrite selected custody",
                ));
            }
        }
        let encoded = serde_json::to_vec(snapshot).map_err(error)?;
        let mut body = BodyWriter::new();
        body.text(TAG).bytes(&encoded);
        let mut signed = body.finish();
        let signature = self.audit.sign_checkpoint(&signed)?;
        let mut field = BodyWriter::new();
        field.bytes(&signature);
        signed.extend_from_slice(&field.finish());
        let run = self
            .evidence
            .journal
            .stage_run(&[Entry::new(RecordClass::Checkpoint, signed).at(snapshot.arrived, 0)])
            .map_err(error)?;
        let head = Head {
            version: 1,
            node: self.evidence.node,
            sequence: run
                .records()
                .last()
                .ok_or_else(|| refusal("unit.accrued staging produced no original"))?
                .node_seq,
            revision: snapshot.revision,
        };
        self.save(Pending::Persist(PersistPending {
            snapshot: snapshot.clone(),
            run,
            head,
            expected: Arc::new(previous.map_or(ExpectedValue::Absent, ExpectedValue::Exact)),
            appended: false,
            selection_proof: None,
            operation: crate::door::op_id().0,
        }));
        self.complete().await.map(|_| ())
    }
    async fn remove(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        let _driving = self.driving.lock().await;
        if self
            .complete()
            .await?
            .as_ref()
            .is_some_and(|p| matches!(p, Pending::Remove(_)) && p.snapshot() == snapshot)
        {
            return Ok(());
        }
        self.no_foreign_pending()?;
        if snapshot.terminal.is_none() {
            return Err(refusal(
                "cannot remove running money before terminal custody",
            ));
        }
        self.audit.confirm(snapshot).await?;
        let Some(raw) = self.head(&snapshot.id).await? else {
            let proof = self.evidence.proof().await?;
            StoreJournal::new(&self.evidence.store, self.evidence.node)
                .map_err(error)?
                .confirm_owned_with(
                    &proof,
                    &[busbar_contract::persistence::Predicate {
                        address: self.address(&snapshot.id),
                        expected: ExpectedValue::Absent,
                    }],
                )
                .await
                .map_err(error)?;
            return Ok(());
        };
        let proof = self.evidence.proof().await?;
        let (_, selected, record) = self.selected(&snapshot.id, &raw, &proof).await?;
        if selected != *snapshot {
            return Err(refusal("terminal running money custody changed"));
        }
        self.save(Pending::Remove(RemovePending {
            snapshot: snapshot.clone(),
            record,
            expected: Arc::new(ExpectedValue::Exact(raw)),
            proof,
            operation: crate::door::op_id().0,
        }));
        self.complete().await.map(|_| ())
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
            let (_, snapshot, _) = self.selected(&id, &raw, &proof).await?;
            if out.insert(id, snapshot).is_some() {
                return Err(refusal("duplicate running money checkpoint"));
            }
        }
        let guard = crate::persistence::fences::scan_guard(self.namespace(), collection.generation);
        StoreJournal::new(&self.evidence.store, self.evidence.node)
            .map_err(error)?
            .confirm_owned_with(&proof, &[guard])
            .await
            .map_err(error)?;
        self.no_foreign_pending()?;
        Ok(out.into_values().collect())
    }
    async fn recover_audit(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        self.audit.recover(snapshot).await
    }
}
