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
    persistence::journal::runtime::{Carried, RuntimeJournal},
};
use busbar_kernel_audit::AuditKeySet;
use std::sync::{Arc, Mutex};

/// Who signs this book's checkpoint bodies.
enum CheckpointSigner {
    /// The Bootstrap signer thread (production; SEALING-FIX §3.3 "Checkpoint signing").
    Thread(super::signer::SignerHandle<super::signer::Checkpoint>),
    /// No deployment key is bound: every persist is refused, as before the key existed.
    Unbound,
}

struct AuditAdapter {
    book: Arc<Mutex<Durability>>,
    evidence: Arc<UnitCheckpointEvidence>,
    signer: CheckpointSigner,
}

#[async_trait::async_trait]
impl UnitCheckpointAudit for AuditAdapter {
    fn keys(&self) -> AuditKeySet {
        super::keyset_of(&self.book.lock().unwrap_or_else(|p| p.into_inner()).record)
    }
    async fn sign_checkpoints(&self, bodies: &[&[u8]]) -> RecordStoreResult<Vec<Vec<u8>>> {
        match &self.signer {
            CheckpointSigner::Thread(handle) => {
                handle.sign_checkpoints(bodies).await.map_err(|why| {
                    RecordStoreError::from(format!("unit checkpoint signature unavailable: {why}"))
                })
            }
            // Test builds: a legacy-signing book signs in place (its fixtures predate the signer
            // threads). Production never holds a legacy chain.
            #[cfg(test)]
            CheckpointSigner::Unbound
                if self
                    .book
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .record
                    .signs_lines() =>
            {
                let book = self.book.lock().unwrap_or_else(|p| p.into_inner());
                bodies
                    .iter()
                    .map(|body| {
                        book.record.sign_checkpoint_body(body).ok_or_else(|| {
                            RecordStoreError(
                                "unit.accrued requires the deployment signing key".into(),
                            )
                        })
                    })
                    .collect()
            }
            CheckpointSigner::Unbound => Err(RecordStoreError(
                "unit.accrued requires the deployment signing key".into(),
            )),
        }
    }
    async fn confirm(
        &self,
        snapshot: &UnitCheckpoint,
        hint: Option<Carried>,
    ) -> RecordStoreResult<()> {
        super::unit_checkpoint_audit::confirm(&self.book, &self.evidence, snapshot, hint).await
    }
    async fn recover(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        super::unit_checkpoint_audit::recover(&self.book, &self.evidence, snapshot).await
    }
}
/// The book's checkpoint custody. `checkpoint` is the Bootstrap signer thread's handle; `None` on a
/// keyless book, which refuses every persist.
pub(crate) fn unit_checkpoint_sink(
    book: &Arc<Mutex<Durability>>,
    journal: Arc<RuntimeJournal>,
    checkpoint: Option<super::signer::SignerHandle<super::signer::Checkpoint>>,
) -> RecordStoreResult<Arc<dyn UnitCheckpointSink>> {
    let evidence = Arc::new(UnitCheckpointEvidence::new(
        journal,
        busbar_kernel::teller::Kernel::new().durability_token(),
    ));
    let audit = Arc::new(AuditAdapter {
        book: book.clone(),
        evidence: evidence.clone(),
        signer: checkpoint.map_or(CheckpointSigner::Unbound, CheckpointSigner::Thread),
    });
    Ok(Arc::new(StoreUnitCheckpoints::new(evidence, audit)))
}
#[cfg(test)]
#[path = "unit_checkpoint_tests.rs"]
mod tests;
