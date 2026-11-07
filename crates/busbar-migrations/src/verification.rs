// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Bounded native readback over complete, frozen source groups. Partial-family
//! counts and digests live in the authoritative checkpoint, so restart resumes
//! verification without treating a highest sequence as source coverage.

use std::sync::Arc;

use async_trait::async_trait;
use busbar_contract::{persistence::*, Secret};
use sha2::{Digest, Sha256};

use super::{
    coordinator::{check_rows, reserved, rolling_digest, rolling_target_digest},
    *,
};
use busbar_kernel::persistence::facade::WriterAuthority;

/// Compiled domain visitor; it verifies decoded semantics, parent relationships,
/// original audit material and historical receipt/debt evidence against actual
/// native values. There is no count-only or always-success implementation.
pub trait NativeReadback: Send + Sync {
    fn edge(&self) -> &Edge;
    fn verify(
        &self,
        source: &Identity,
        family: &Family,
        records: &[Record],
        bounds: Bounds,
        native_values: &[(Address, Secret<Vec<u8>>)],
    ) -> Result<Digest32, Error>;
}

#[async_trait]
pub trait TargetRecoveryProbe: Send + Sync {
    async fn verify_reopened_hydrated(&self, target: &Identity) -> Result<Digest32, Error>;
}

pub struct ArchiveVerifier {
    backend: Arc<dyn PersistenceBackend>,
    source: Arc<dyn SourceReader>,
    transform: Arc<dyn Transform>,
    readback: Arc<dyn NativeReadback>,
    fence: Arc<NativeSourceFence>,
    snapshot: SnapshotEvidence,
    recovery: Arc<dyn TargetRecoveryProbe>,
}

impl ArchiveVerifier {
    pub fn new(
        backend: Arc<dyn PersistenceBackend>,
        source: Arc<dyn SourceReader>,
        transform: Arc<dyn Transform>,
        readback: Arc<dyn NativeReadback>,
        fence: Arc<NativeSourceFence>,
        snapshot: SnapshotEvidence,
        recovery: Arc<dyn TargetRecoveryProbe>,
    ) -> Result<Self, Error> {
        if transform.edge() != readback.edge()
            || snapshot.content_digest == [0; 32]
            || snapshot.coverage_digest == [0; 32]
        {
            return Err(Error::MissingCapability);
        }
        Ok(Self {
            backend,
            source,
            transform,
            readback,
            fence,
            snapshot,
            recovery,
        })
    }
}

#[async_trait]
impl Verifier for ArchiveVerifier {
    async fn target_offline(
        &self,
        target: &Identity,
        authority: WriterAuthority,
    ) -> Result<(), Error> {
        if target.dataset != self.backend.info().dataset.0
            || target.format != CORE_FORMAT
            || target.format.physical != self.backend.info().physical_version
        {
            return Err(Error::IdentityMismatch);
        }
        super::activation::require_offline(self.backend.as_ref(), authority).await
    }
    async fn fence(&self, source: &Identity) -> Result<FenceEvidence, Error> {
        self.fence.verify(source).await
    }
    async fn snapshot(
        &self,
        source: &Identity,
        fence: &FenceEvidence,
    ) -> Result<SnapshotEvidence, Error> {
        if self.source.identify().await? != *source
            || self.snapshot.source != source.dataset
            || self.snapshot.content_digest != source.artifact_digest
            || self.fence.verify(source).await? != *fence
        {
            return Err(Error::SnapshotRequired);
        }
        Ok(self.snapshot.clone())
    }
    async fn target_step(
        &self,
        manifest: &Manifest,
        bounds: Bounds,
    ) -> Result<Verification, Error> {
        if self.source.identify().await? != manifest.source
            || self.transform.edge() != &manifest.edges[0]
            || manifest.snapshot.as_ref() != Some(&self.snapshot)
        {
            return Err(Error::IdentityMismatch);
        }
        let mut verification = manifest.verification.clone().unwrap_or(Verification {
            cursor: 0,
            families: Vec::new(),
            complete: false,
            debt_write_blocks_digest: [0; 32],
            partial: None,
        });
        let index = verification.families.len();
        verification.cursor = verification.cursor.checked_add(1).ok_or(Error::Bounds)?;
        if index == manifest.checkpoints.len() {
            verification.complete = true;
            verification.debt_write_blocks_digest =
                completion_digest(&verification, &self.snapshot);
            return Ok(verification);
        }
        let family = manifest.edges[0]
            .families
            .get(index)
            .ok_or(Error::Verification)?;
        let checkpoint = &manifest.checkpoints[index];
        let mut partial = verification
            .partial
            .take()
            .unwrap_or(VerificationCheckpoint {
                family: family.id,
                after: 0,
                source_count: 0,
                target_count: 0,
                source_digest: [0; 32],
                target_digest: [0; 32],
                decoded_invariants_digest: [0; 32],
            });
        if partial.family != family.id {
            return Err(Error::Verification);
        }
        let page = self
            .source
            .page(&self.snapshot, family, partial.after, bounds)
            .await?;
        if page.snapshot != self.snapshot.snapshot
            || page.family != family.id
            || page.after != partial.after
            || page.next < page.after
            || (!page.complete && (page.next == page.after || page.records.is_empty()))
        {
            return Err(Error::Verification);
        }
        let seal = crate::seal::lend();
        check_rows(
            page.records
                .iter()
                .map(|r| (r.key.as_slice(), r.value.expose(&seal).as_slice())),
            bounds,
        )?;
        let rows = self.transform.transform(family, &page.records, bounds)?;
        check_rows(
            rows.iter()
                .map(|r| (r.address.key.as_slice(), r.value.expose(&seal).as_slice())),
            bounds,
        )?;
        if rows.iter().any(|row| {
            reserved(row.address.namespace) || !self.transform.authorize(family, &row.address)
        }) {
            return Err(Error::Verification);
        }
        let response = self
            .backend
            .read(Arc::new(Read {
                dataset: self.backend.info().dataset,
                addresses: rows.iter().map(|r| r.address.clone()).collect(),
                time: None,
            }))
            .await
            .map_err(Error::Backend)?;
        let ReadResult::Values {
            observed_at,
            values,
        } = response
        else {
            return Err(Error::Verification);
        };
        if observed_at.authority != self.backend.info().clock_authority
            || values.len() != rows.len()
        {
            return Err(Error::Verification);
        }
        let mut native = Vec::new();
        native
            .try_reserve_exact(rows.len())
            .map_err(|_| Error::Bounds)?;
        for (row, value) in rows.iter().zip(values) {
            native.push((row.address.clone(), value.ok_or(Error::Verification)?));
        }
        let semantics =
            self.readback
                .verify(&manifest.source, family, &page.records, bounds, &native)?;
        if semantics == [0; 32] {
            return Err(Error::Verification);
        }
        partial.source_count = partial
            .source_count
            .checked_add(page.records.len() as u64)
            .ok_or(Error::Bounds)?;
        partial.target_count = partial
            .target_count
            .checked_add(rows.len() as u64)
            .ok_or(Error::Bounds)?;
        partial.source_digest = rolling_digest(
            partial.source_digest,
            page.records
                .iter()
                .map(|r| (r.key.as_slice(), r.value.expose(&seal).as_slice())),
        );
        partial.target_digest = rolling_target_digest(partial.target_digest, &rows);
        let mut invariants = Sha256::new();
        invariants.update(b"busbar.migration.invariants.v1\0");
        invariants.update(partial.decoded_invariants_digest);
        invariants.update(semantics);
        invariants.update(page.next.to_le_bytes());
        partial.decoded_invariants_digest = invariants.finalize().into();
        partial.after = page.next;
        if page.complete {
            if partial.after != checkpoint.cursor
                || partial.source_count != checkpoint.source_count
                || partial.target_count != checkpoint.target_count
                || partial.source_digest != checkpoint.source_digest
                || partial.target_digest != checkpoint.target_digest
            {
                return Err(Error::Verification);
            }
            let mut coverage = Sha256::new();
            coverage.update(b"busbar.migration.family.coverage.v1\0");
            coverage.update(self.snapshot.coverage_digest);
            coverage.update(family.id);
            coverage.update(partial.source_count.to_le_bytes());
            coverage.update(partial.source_digest);
            verification.families.push(VerifiedFamily {
                family: family.id,
                source_count: partial.source_count,
                target_count: partial.target_count,
                source_digest: partial.source_digest,
                target_digest: partial.target_digest,
                decoded_invariants_digest: partial.decoded_invariants_digest,
                source_coverage_digest: coverage.finalize().into(),
            });
        } else {
            verification.partial = Some(partial);
        }
        verification.complete = verification.families.len() == manifest.checkpoints.len();
        if verification.complete {
            verification.debt_write_blocks_digest =
                completion_digest(&verification, &self.snapshot);
        }
        Ok(verification)
    }
    async fn retirement_permitted(&self, manifest: &Manifest) -> Result<Digest32, Error> {
        let digest = self
            .recovery
            .verify_reopened_hydrated(&manifest.target)
            .await?;
        if digest == [0; 32] {
            return Err(Error::Verification);
        }
        Ok(digest)
    }
}

fn completion_digest(verification: &Verification, snapshot: &SnapshotEvidence) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(b"busbar.migration.verified.debt.v1\0");
    hash.update(snapshot.coverage_digest);
    for family in &verification.families {
        hash.update(family.family);
        hash.update(family.decoded_invariants_digest);
        hash.update(family.source_coverage_digest);
    }
    hash.finalize().into()
}
