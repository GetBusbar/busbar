// SPDX-License-Identifier: Apache-2.0
//! Root signer/audit composition for kernel-owned native unit checkpoint custody.
use super::Durability;
use busbar_contract::records::{RecordStoreError, RecordStoreResult};
use busbar_kernel::{
    governance::{
        unit_checkpoint::{UnitCheckpoint, UnitCheckpointSink},
        unit_checkpoint_store::{
            StoreUnitCheckpoints, UnitCheckpointAudit, UnitCheckpointEvidence,
        },
    },
    persistence::journal::runtime::RuntimeJournal,
};
use busbar_kernel_audit::AuditKeySet;
use busbar_kernel_wal::{BodyReader, JournalRecord, Record, RecordClass};
use std::sync::{Arc, Mutex};

pub(super) fn is_checkpoint_record(record: &Record) -> bool {
    JournalRecord::decode(&record.body).is_ok_and(|record| {
        record.class == RecordClass::Checkpoint
            && matches!(
                BodyReader::new(&record.body).text(),
                Some("unit.accrued" | "measurement.accrued")
            )
    })
}
struct AuditAdapter {
    book: Arc<Mutex<Durability>>,
    evidence: Arc<UnitCheckpointEvidence>,
}

/// Persistence of measurement custody is housekeeping, not another billable Store operation.
/// Scope each actual future so direct recovery calls and the periodic flusher agree.
struct CheckpointCustody(StoreUnitCheckpoints);
#[async_trait::async_trait]
impl UnitCheckpointSink for CheckpointCustody {
    async fn persist(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        crate::root::measurements::maintenance(self.0.persist(snapshot)).await
    }
    async fn remove(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        crate::root::measurements::maintenance(self.0.remove(snapshot)).await
    }
    async fn replay(&self) -> RecordStoreResult<Vec<UnitCheckpoint>> {
        crate::root::measurements::maintenance(self.0.replay()).await
    }
    async fn recover_audit(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        crate::root::measurements::maintenance(self.0.recover_audit(snapshot)).await
    }
}
#[async_trait::async_trait]
impl UnitCheckpointAudit for AuditAdapter {
    fn keys(&self) -> AuditKeySet {
        super::keyset_of(&self.book.lock().unwrap_or_else(|p| p.into_inner()).record)
    }
    fn sign_checkpoint(&self, body: &[u8]) -> RecordStoreResult<Vec<u8>> {
        self.book
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .record
            .sign_checkpoint_body(body)
            .ok_or_else(|| {
                RecordStoreError("unit.accrued requires the deployment signing key".into())
            })
    }
    async fn confirm(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        super::unit_checkpoint_audit::confirm(&self.book, &self.evidence, snapshot).await
    }
    async fn recover(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        super::unit_checkpoint_audit::recover(&self.book, &self.evidence, snapshot).await
    }
}
pub(crate) fn unit_checkpoint_sink(
    book: &Arc<Mutex<Durability>>,
    journal: Arc<RuntimeJournal>,
) -> RecordStoreResult<Arc<dyn UnitCheckpointSink>> {
    let evidence = Arc::new(UnitCheckpointEvidence::new(
        journal,
        busbar_kernel::teller::Kernel::new().durability_token(),
    ));
    let audit = Arc::new(AuditAdapter {
        book: book.clone(),
        evidence: evidence.clone(),
    });
    Ok(Arc::new(CheckpointCustody(StoreUnitCheckpoints::new(
        evidence, audit,
    ))))
}
#[cfg(test)]
#[path = "unit_checkpoint_tests.rs"]
mod tests;
