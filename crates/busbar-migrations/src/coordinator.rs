// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use async_trait::async_trait;
use busbar_contract::persistence::{
    Address, AttemptId, Candidate, DatasetId, Decision, ExpectedValue, Failure, Mutation,
    PersistenceBackend, Predicate, Read, ReadResult, CANDIDATE_VERSION,
};
use busbar_contract::Secret;
use sha2::{Digest, Sha256};

use super::*;
use busbar_kernel::persistence::{
    commit::{Attempt, SubmitResult},
    facade::WriterAuthority,
    import_target::candidate_codec,
};

pub(super) const NAMESPACE: Id = *b"busbar.migrate1\0";

pub(super) fn reserved(namespace: Id) -> bool {
    namespace == NAMESPACE
        || namespace == super::intent::NAMESPACE
        || namespace == busbar_contract::persistence::control::NAMESPACE.0
        || namespace == busbar_contract::persistence::control::GENERATION_NAMESPACE.0
        || namespace
            == busbar_kernel::persistence::import_target::target::manifest_address().namespace
}

/// Content-free diagnostics: native messages and record values are never echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Bounds,
    UnsupportedVersion,
    InvalidManifest,
    InvalidState,
    IdentityMismatch,
    EdgeMismatch,
    UnsupportedPath,
    FenceRequired,
    SnapshotRequired,
    Verification,
    MissingCapability,
    /// An exact cold-journal attempt remains owned; retry this bounded step.
    IntentPending,
    ReconciliationRequired,
    Conflict,
    Entropy,
    Corrupt,
    Backend(Failure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    Advanced,
    Pending,
    Reconcile,
    Complete,
}

/// Reader output retains protected original bytes. Signed audit preimages,
/// ciphertext, generic plugin payloads and old uncertain candidates MUST carry
/// `preserve_exact`; their decoder/codec semantics must not be rewritten.
pub struct Record {
    pub key: zeroize::Zeroizing<Vec<u8>>,
    pub value: Secret<Vec<u8>>,
    pub preserve_exact: bool,
}
impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MigrationRecord")
            .field("key", &"[REDACTED]")
            .field("value", &self.value)
            .field("preserve_exact", &self.preserve_exact)
            .finish()
    }
}

pub struct SourcePage {
    pub snapshot: Id,
    pub family: Id,
    pub after: u64,
    pub next: u64,
    pub complete: bool,
    pub records: Vec<Record>,
}

pub struct TargetRow {
    pub address: Address,
    pub value: Secret<Vec<u8>>,
    /// Page-local source index for preserved signed/ciphertext/opaque bytes.
    /// Physical keys may change; this explicit binding preserves the payload.
    pub preserved_source: Option<u32>,
}

/// Compiled native historical reader; opening it must NEVER invoke legacy schema
/// upgrades, scrubbers or old write-behind. Unsupported input is an error.
#[async_trait]
pub trait SourceReader: Send + Sync {
    async fn identify(&self) -> Result<Identity, Error>;
    async fn read_group(
        &self,
        family: Id,
        key: &Secret<Vec<u8>>,
        bounds: Bounds,
    ) -> Result<Vec<Record>, Error> {
        let _ = (family, key, bounds);
        Err(Error::MissingCapability)
    }
    async fn page(
        &self,
        snapshot: &SnapshotEvidence,
        family: &Family,
        after: u64,
        bounds: Bounds,
    ) -> Result<SourcePage, Error>;
}

/// Native enforcement is a live capability, separate from operator attestations
/// and archive validation. Implementations are pinned trusted helpers; arbitrary
/// report-selected executables or saved successful replies cannot implement it.
#[async_trait]
pub trait SourceFenceProbe: Send + Sync {
    fn implementation_digest(&self) -> Digest32;
    async fn verify(
        &self,
        request: &busbar_contract::persistence::source_fence::ProbeRequest,
    ) -> Result<busbar_contract::persistence::source_fence::ProbeReply, Error>;
}

/// Trusted, statically registered transform, never code selected by report paths.
/// Overflow, unknown scales or unknown semantics MUST be returned as errors.
/// Output is restricted to the selected family's namespace by the coordinator.
pub trait Transform: Send + Sync {
    fn edge(&self) -> &Edge;
    /// Validate both the derived namespace and canonical key framing using the
    /// owning domain's address-class function. Partition sets are not finite.
    fn authorize(&self, family: &Family, address: &Address) -> bool;
    fn transform(
        &self,
        family: &Family,
        records: &[Record],
        bounds: Bounds,
    ) -> Result<Vec<TargetRow>, Error>;
}

/// Domain checks are native core capabilities. Implementations must perform
/// bounded work, preserve audit/ciphertext evidence and verify every source
/// sequence, count, exact scale, identity/tombstone, credential/index and receipt.
/// A digest match alone or an operator attestation alone cannot implement this.
#[async_trait]
pub trait Verifier: Send + Sync {
    /// Prove target identity/physical format and exclusive, non-serving migration
    /// authority. Startup's normal fresh-dataset admission is NOT this capability.
    async fn target_offline(
        &self,
        target: &Identity,
        authority: WriterAuthority,
    ) -> Result<(), Error>;
    /// Check real external enforcement plus BOTH cold quiescence receipts.
    async fn fence(&self, source: &Identity) -> Result<FenceEvidence, Error>;
    async fn snapshot(
        &self,
        source: &Identity,
        fence: &FenceEvidence,
    ) -> Result<SnapshotEvidence, Error>;
    /// Return cumulative progress; one call is bounded by the registered edge.
    async fn target_step(&self, manifest: &Manifest, bounds: Bounds)
        -> Result<Verification, Error>;
    /// Verify retention policy and reopened/hydrated target. Does not delete data.
    async fn retirement_permitted(&self, manifest: &Manifest) -> Result<Digest32, Error>;
}

/// Activation is deliberately separate from Startup. A production implementation
/// must conditionally publish the core format manifest AND advance writer epoch
/// in this same transaction, rejecting a concurrently changed active generation.
/// It must leave serving closed until reopen/hydration and domain debt checks.
/// CoreActivation implements the current native format; missing support blocks
/// TargetVerified.
#[async_trait]
pub trait Activation: Send + Sync {
    async fn prepare(
        &self,
        manifest: &Manifest,
        authority: WriterAuthority,
    ) -> Result<ActivationChange, Error>;
}

pub struct ActivationChange {
    pub predicates: Vec<Predicate>,
    pub mutations: Vec<Mutation>,
}

/// Protected durable custody, NOT the exported manifest. `persist` must durably
/// insert-if-absent or compare identical bytes for this migration, never replace
/// another operation or candidate. A failed/cancelled persist is retried with exact bytes.
/// `pending` must detect outstanding intent after a crash; `clear` is conditional
/// on the operation. Implementations must not log or expose the snapshot payload.
#[async_trait]
pub trait IntentStore: Send + Sync {
    async fn pending(&self, migration: Id) -> Result<bool, Error>;
    async fn persist(
        &self,
        migration: Id,
        operation: Id,
        snapshot: &Secret<Vec<u8>>,
    ) -> Result<(), Error>;
    async fn clear(
        &self,
        migration: Id,
        operation: Id,
        resolution: &IntentResolution,
    ) -> Result<(), Error>;
    /// Receipt lookup is allowed only after native retirement proves that the
    /// retained candidate cannot execute for the first time.
    async fn reconcile(&self, migration: Id) -> Result<ReconciliationProgress, Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconciliationProgress {
    Advanced,
    Pending,
    Unresolved,
    Resolved,
}

/// Created only from this coordinator's observed native terminal decision. It
/// cannot be manufactured by a caller supplying a boolean acknowledgement.
pub struct IntentResolution {
    pub(super) fingerprint: Digest32,
    pub(super) kind: ResolutionKind,
    pub(super) applied_result: Option<Secret<Vec<u8>>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ResolutionKind {
    Applied,
    Conflict,
    ProvenNoEffect,
}

/// All capabilities are explicit. None is implemented by calling an old Door's
/// config migration or treating an unreadable source as empty.
#[derive(Clone)]
pub struct Services {
    pub source: Arc<dyn SourceReader>,
    pub transform: Arc<dyn Transform>,
    pub verifier: Arc<dyn Verifier>,
    pub activation: Option<Arc<dyn Activation>>,
    pub intent: Arc<dyn IntentStore>,
}

struct Pending {
    next: Manifest,
    attempt: Attempt,
    snapshot: Secret<Vec<u8>>,
    durable: bool,
    decided: Option<Arc<Decision>>,
}

/// One bounded step at a time, with exact candidate custody across cancellation.
/// The backend must be a distinct offline target with established migration-only
/// writer authority; this type never initializes or exposes a serving CoreStore.
pub struct Coordinator {
    registry: Arc<Registry>,
    backend: Arc<dyn PersistenceBackend>,
    authority: WriterAuthority,
    services: Services,
    manifest: Manifest,
    stored: Option<Vec<u8>>,
    pending: Option<Pending>,
    activation_receipt: Option<Arc<busbar_contract::persistence::lifecycle::ActivationReceipt>>,
    complete_receipt: Option<Arc<busbar_contract::persistence::lifecycle::ActivationReceipt>>,
}

impl Coordinator {
    /// Planning was read-only. The first advance persists Identified, then
    /// Planned; neither a report's claimed state nor its proofs can skip stages.
    pub async fn start(
        plan: Manifest,
        registry: Arc<Registry>,
        backend: Arc<dyn PersistenceBackend>,
        authority: WriterAuthority,
        services: Services,
    ) -> Result<Self, Error> {
        plan.validate(&registry)?;
        if plan.state != State::Planned || plan.verification.is_some() {
            return Err(Error::InvalidState);
        }
        let authority =
            super::activation::offline_authority(backend.as_ref(), authority.writer).await?;
        Self::admit(&plan, &backend, authority, &services).await?;
        if status(backend.as_ref(), plan.migration, &registry)
            .await?
            .is_some()
        {
            return Err(Error::Conflict);
        }
        let mut manifest = plan;
        manifest.state = State::Identified;
        Ok(Self {
            registry,
            backend,
            authority,
            services,
            manifest,
            stored: None,
            pending: None,
            activation_receipt: None,
            complete_receipt: None,
        })
    }

    /// Always reads Store authority, never imports report progress. A crash with
    /// protected intent refuses until its original semantics/horizon are resolved
    /// by the custody owner. It does not mint a replacement operation identity.
    pub async fn resume(
        plan: &Manifest,
        registry: Arc<Registry>,
        backend: Arc<dyn PersistenceBackend>,
        authority: WriterAuthority,
        services: Services,
    ) -> Result<Self, Error> {
        plan.validate(&registry)?;
        let (manifest, bytes) = read_status(backend.as_ref(), plan.migration, &registry)
            .await?
            .ok_or(Error::InvalidState)?;
        if manifest.plan_digest() != plan.plan_digest() {
            return Err(Error::IdentityMismatch);
        }
        let authority = if matches!(manifest.state, State::Activated | State::Retired) {
            super::activation::activated_authority(backend.as_ref()).await?
        } else {
            super::activation::offline_authority(backend.as_ref(), authority.writer).await?
        };
        Self::admit(&manifest, &backend, authority, &services).await?;
        Ok(Self {
            registry,
            backend,
            authority,
            services,
            manifest,
            stored: Some(bytes),
            pending: None,
            activation_receipt: None,
            complete_receipt: None,
        })
    }

    async fn admit(
        manifest: &Manifest,
        backend: &Arc<dyn PersistenceBackend>,
        authority: WriterAuthority,
        services: &Services,
    ) -> Result<(), Error> {
        if manifest.edges.len() != 1 {
            return Err(Error::UnsupportedPath);
        }
        if backend.info().dataset.0 != manifest.target.dataset
            || backend.info().physical_version != manifest.target.format.physical
            || authority.writer == [0; 16]
            || authority.writer_epoch == 0
            || authority.execution_epoch == 0
        {
            return Err(Error::IdentityMismatch);
        }
        if services.transform.edge() != &manifest.edges[0] {
            return Err(Error::EdgeMismatch);
        }
        if services.source.identify().await? != manifest.source {
            return Err(Error::IdentityMismatch);
        }
        if services.intent.pending(manifest.migration).await? {
            return Err(Error::ReconciliationRequired);
        }
        if !matches!(manifest.state, State::Activated | State::Retired) {
            super::activation::require_offline(backend.as_ref(), authority).await?;
            services
                .verifier
                .target_offline(&manifest.target, authority)
                .await?;
        }
        Ok(())
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Exact original native Applied receipt retained by this coordinator.
    /// A checkpoint read alone cannot manufacture this receipt after restart.
    pub fn checkpoint_receipt(
        &self,
        phase: busbar_contract::persistence::lifecycle::CompletionPhase,
    ) -> Option<Arc<busbar_contract::persistence::lifecycle::ActivationReceipt>> {
        use busbar_contract::persistence::lifecycle::CompletionPhase;
        match phase {
            CompletionPhase::Activation => self.activation_receipt.clone(),
            CompletionPhase::Complete => self.complete_receipt.clone(),
        }
    }

    pub fn pending_operation(&self) -> Option<AttemptId> {
        self.pending
            .as_ref()
            .map(|p| p.attempt.candidate().candidate().id)
    }

    pub async fn advance(&mut self) -> Result<Progress, Error> {
        if self.pending.is_some() {
            return self.submit().await;
        }
        if self.manifest.state == State::Retired {
            return Ok(Progress::Complete);
        }
        if self.services.source.identify().await? != self.manifest.source {
            return Err(Error::IdentityMismatch);
        }
        if let Some(expected) = &self.manifest.fence {
            if self.services.verifier.fence(&self.manifest.source).await? != *expected {
                return Err(Error::FenceRequired);
            }
        }
        let mut next = self.manifest.clone();
        let mut predicates = Vec::new();
        let mut mutations = Vec::new();
        if self.stored.is_none() {
            // Durable identification precedes durable planning.
        } else {
            match next.state {
                State::Identified => next.state = State::Planned,
                State::Planned => {
                    next.fence = Some(self.services.verifier.fence(&next.source).await?);
                    next.state = State::SourceFenced;
                }
                State::SourceFenced => {
                    next.snapshot = Some(
                        self.services
                            .verifier
                            .snapshot(
                                &next.source,
                                next.fence.as_ref().ok_or(Error::FenceRequired)?,
                            )
                            .await?,
                    );
                    next.checkpoints = next.edges[0]
                        .families
                        .iter()
                        .map(|family| Checkpoint {
                            family: family.id,
                            cursor: 0,
                            source_count: 0,
                            target_count: 0,
                            source_bytes: 0,
                            target_bytes: 0,
                            source_digest: [0; 32],
                            target_digest: [0; 32],
                            complete: false,
                        })
                        .collect();
                    next.state = State::SnapshotVerified;
                }
                State::SnapshotVerified => next.state = State::Copying,
                State::Copying => {
                    if let Some(index) = next.checkpoints.iter().position(|cp| !cp.complete) {
                        let result = self.copy_page(&mut next, index).await?;
                        predicates = result.0;
                        mutations = result.1;
                    } else {
                        let verification = self
                            .services
                            .verifier
                            .target_step(&next, next.edges[0].bounds)
                            .await?;
                        if let Some(previous) = &next.verification {
                            if verification.cursor <= previous.cursor
                                || !verification.families.starts_with(&previous.families)
                            {
                                return Err(Error::Verification);
                            }
                        }
                        if verification.complete {
                            next.state = State::TargetVerified;
                        }
                        next.verification = Some(verification);
                    }
                }
                State::TargetVerified => {
                    let activation = self
                        .services
                        .activation
                        .as_ref()
                        .ok_or(Error::MissingCapability)?;
                    let change = activation.prepare(&next, self.authority).await?;
                    validate_activation(&change, &next, self.authority)?;
                    predicates = change.predicates;
                    mutations = change.mutations;
                    next.state = State::Activated;
                }
                State::Activated => {
                    let readiness = self.services.verifier.retirement_permitted(&next).await?;
                    if readiness == [0; 32] {
                        return Err(Error::Verification);
                    }
                    next.readiness_digest = Some(readiness);
                    next.state = State::Retired;
                }
                State::Retired => return Ok(Progress::Complete),
            }
        }
        predicates.push(self.checkpoint_guard().await?);
        self.prepare(next, predicates, mutations)?;
        self.submit().await
    }

    async fn copy_page(
        &self,
        next: &mut Manifest,
        index: usize,
    ) -> Result<(Vec<Predicate>, Vec<Mutation>), Error> {
        let edge = &next.edges[0];
        let family = &edge.families[index];
        let checkpoint = &mut next.checkpoints[index];
        let snapshot = next.snapshot.as_ref().ok_or(Error::SnapshotRequired)?;
        let page = self
            .services
            .source
            .page(snapshot, family, checkpoint.cursor, edge.bounds)
            .await?;
        if page.snapshot != snapshot.snapshot
            || page.family != family.id
            || page.after != checkpoint.cursor
            || page.next < page.after
            || (!page.complete && (page.next == page.after || page.records.is_empty()))
        {
            return Err(Error::IdentityMismatch);
        }
        let seal = crate::seal::lend();
        let source_bytes = check_rows(
            page.records
                .iter()
                .map(|r| (r.key.as_slice(), r.value.expose(&seal).as_slice())),
            edge.bounds,
        )?;
        let rows = self
            .services
            .transform
            .transform(family, &page.records, edge.bounds)?;
        let target_bytes = check_rows(
            rows.iter()
                .map(|r| (r.address.key.as_slice(), r.value.expose(&seal).as_slice())),
            edge.bounds,
        )?;
        let mut preserved = std::collections::BTreeSet::new();
        let mut addresses = std::collections::BTreeSet::new();
        for row in &rows {
            if !self.services.transform.authorize(family, &row.address)
                || reserved(row.address.namespace)
                || !addresses.insert(row.address.clone())
            {
                return Err(Error::Verification);
            }
            if let Some(index) = row.preserved_source {
                let record = page
                    .records
                    .get(index as usize)
                    .ok_or(Error::Verification)?;
                if !preserved.insert(index as usize)
                    || row.value.expose(&seal) != record.value.expose(&seal)
                {
                    return Err(Error::Verification);
                }
            }
        }
        for (index, record) in page.records.iter().enumerate() {
            if record.preserve_exact && !preserved.contains(&index) {
                return Err(Error::Verification);
            }
        }
        checkpoint.source_count = checkpoint
            .source_count
            .checked_add(page.records.len() as u64)
            .ok_or(Error::Bounds)?;
        checkpoint.target_count = checkpoint
            .target_count
            .checked_add(rows.len() as u64)
            .ok_or(Error::Bounds)?;
        checkpoint.source_bytes = checkpoint
            .source_bytes
            .checked_add(source_bytes)
            .ok_or(Error::Bounds)?;
        checkpoint.target_bytes = checkpoint
            .target_bytes
            .checked_add(target_bytes)
            .ok_or(Error::Bounds)?;
        checkpoint.source_digest = rolling_digest(
            checkpoint.source_digest,
            page.records
                .iter()
                .map(|r| (r.key.as_slice(), r.value.expose(&seal).as_slice())),
        );
        checkpoint.target_digest = rolling_target_digest(checkpoint.target_digest, &rows);
        checkpoint.cursor = page.next;
        checkpoint.complete = page.complete;
        let mut predicates = Vec::with_capacity(rows.len());
        let mut mutations = Vec::with_capacity(rows.len());
        let response = self
            .backend
            .read(Arc::new(Read {
                dataset: self.backend.info().dataset,
                addresses: rows.iter().map(|row| row.address.clone()).collect(),
                time: None,
            }))
            .await
            .map_err(Error::Backend)?;
        let ReadResult::Values {
            observed_at,
            values,
        } = response
        else {
            return Err(Error::Corrupt);
        };
        if observed_at.authority != self.backend.info().clock_authority
            || values.len() != rows.len()
        {
            return Err(Error::Corrupt);
        }
        for (row, actual) in rows.into_iter().zip(values) {
            let address = row.address;
            if actual.as_ref().is_some_and(|value| *value != row.value) {
                return Err(Error::Verification);
            }
            // Shared canonical indices may recur in later complete groups.
            // Reuse requires exact bytes and never repairs a different value.
            let absent = actual.is_none();
            predicates.push(Predicate {
                address: address.clone(),
                expected: actual.map_or(ExpectedValue::Absent, ExpectedValue::Exact),
            });
            if absent {
                mutations.push(Mutation::Put {
                    address,
                    value: row.value,
                });
            }
        }
        Ok((predicates, mutations))
    }

    async fn checkpoint_guard(&self) -> Result<Predicate, Error> {
        let address = Address {
            namespace: busbar_contract::persistence::control::GENERATION_NAMESPACE.0,
            key: NAMESPACE.to_vec(),
        };
        let response = self
            .backend
            .read(Arc::new(Read {
                dataset: self.backend.info().dataset,
                addresses: vec![address.clone()],
                time: None,
            }))
            .await
            .map_err(Error::Backend)?;
        let ReadResult::Values {
            observed_at,
            mut values,
        } = response
        else {
            return Err(Error::Corrupt);
        };
        if observed_at.authority != self.backend.info().clock_authority || values.len() != 1 {
            return Err(Error::Corrupt);
        }
        let expected = match values.pop().flatten() {
            None => ExpectedValue::Absent,
            Some(value) => {
                let seal = crate::seal::lend();
                let bytes: [u8; 8] = value
                    .expose(&seal)
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Corrupt)?;
                if u64::from_le_bytes(bytes) == 0 {
                    return Err(Error::Corrupt);
                }
                ExpectedValue::Exact(value)
            }
        };
        Ok(Predicate { address, expected })
    }

    fn prepare(
        &mut self,
        next: Manifest,
        mut predicates: Vec<Predicate>,
        mut mutations: Vec<Mutation>,
    ) -> Result<(), Error> {
        let bytes = next.encode(&self.registry)?;
        if matches!(next.state, State::Activated | State::Retired)
            && next.state != self.manifest.state
        {
            use busbar_contract::persistence::lifecycle::{self as native, CompletionPhase};
            let phase = if next.state == State::Activated {
                CompletionPhase::Activation
            } else {
                CompletionPhase::Complete
            };
            let marker = completion_marker(&next, &bytes, phase)?;
            let marker_address = native::completion_marker_address(next.migration);
            let expected = if phase == CompletionPhase::Activation {
                ExpectedValue::Absent
            } else {
                let prior = self.manifest.encode(&self.registry)?;
                ExpectedValue::Exact(completion_marker(
                    &self.manifest,
                    &prior,
                    CompletionPhase::Activation,
                )?)
            };
            predicates.push(Predicate {
                address: marker_address.clone(),
                expected,
            });
            mutations.push(Mutation::Put {
                address: marker_address,
                value: marker,
            });
        }
        if !matches!(next.state, State::Activated | State::Retired) {
            predicates.push(Predicate {
                address: busbar_kernel::persistence::import_target::target::manifest_address(),
                expected: ExpectedValue::Absent,
            });
            predicates.push(Predicate {
                address: busbar_kernel::persistence::import_target::target::root_address(),
                expected: ExpectedValue::Exact(Secret::new(
                    busbar_contract::persistence::control::Dataset {
                        id: self.backend.info().dataset,
                        writer_epoch: self.authority.writer_epoch,
                    }
                    .encode()
                    .ok_or(Error::Corrupt)?
                    .to_vec(),
                )),
            });
        }
        predicates.push(Predicate {
            address: address(next.migration),
            expected: self.stored.as_ref().map_or(ExpectedValue::Absent, |value| {
                ExpectedValue::Exact(Secret::new(value.clone()))
            }),
        });
        mutations.push(Mutation::Put {
            address: address(next.migration),
            value: Secret::new(bytes),
        });
        let mut operation = [0; 16];
        getrandom::fill(&mut operation).map_err(|_| Error::Entropy)?;
        predicates.push(Predicate {
            address: super::intent::guard_address(next.migration),
            expected: ExpectedValue::Exact(Secret::new(super::intent::open_guard(
                next.migration,
                operation,
            ))),
        });
        let id = AttemptId {
            dataset: self.backend.info().dataset,
            writer_epoch: self.authority.writer_epoch,
            writer: self.authority.writer,
            execution_epoch: self.authority.execution_epoch,
            operation,
        };
        let candidate = super::witness::attach(
            Candidate {
                id,
                codec: CANDIDATE_VERSION,
                predicates,
                mutations,
                time: None,
                result: Secret::new(Vec::new()),
            },
            next.migration,
        )?;
        let budget = (next.edges[0].bounds.bytes as usize)
            .checked_mul(4)
            .and_then(|v| v.checked_add(4 * MAX_MANIFEST_BYTES))
            .ok_or(Error::Bounds)?;
        let snapshot = candidate_codec::encode(&candidate, budget, &crate::seal::lend())
            .map_err(|_| Error::Bounds)?;
        let attempt =
            Attempt::new(candidate, self.backend.clone()).map_err(|_| Error::IdentityMismatch)?;
        self.pending = Some(Pending {
            next,
            attempt,
            snapshot,
            durable: false,
            decided: None,
        });
        Ok(())
    }

    async fn submit(&mut self) -> Result<Progress, Error> {
        let pending = self.pending.as_mut().ok_or(Error::InvalidState)?;
        let operation = pending.attempt.candidate().candidate().id.operation;
        if !pending.durable {
            match self
                .services
                .intent
                .persist(self.manifest.migration, operation, &pending.snapshot)
                .await
            {
                Ok(()) => {}
                Err(Error::IntentPending) => return Ok(Progress::Pending),
                Err(error) => return Err(error),
            }
            pending.durable = true;
        }
        if let Some(expected) = &pending.next.fence {
            if self.services.verifier.fence(&self.manifest.source).await? != *expected {
                return Err(Error::FenceRequired);
            }
        }
        if pending.decided.is_none() {
            let result = pending.attempt.submit().await;
            pending.decided = Some(match result {
                SubmitResult::Uncertain | SubmitResult::Busy => return Ok(Progress::Pending),
                SubmitResult::Reconcile => return Ok(Progress::Reconcile),
                SubmitResult::NoEffect(error) => return Err(Error::Backend(error)),
                SubmitResult::Decided(decision) => decision,
            });
        }
        let (outcome, kind) = match pending.decided.as_deref().ok_or(Error::InvalidState)? {
            Decision::Applied(value)
                if value == &pending.attempt.candidate().candidate().result =>
            {
                (Ok(()), ResolutionKind::Applied)
            }
            Decision::ConditionConflict => (Err(Error::Conflict), ResolutionKind::Conflict),
            _ => return Err(Error::ReconciliationRequired),
        };
        let resolution = IntentResolution {
            fingerprint: pending.attempt.candidate().fingerprint(),
            kind,
            applied_result: match pending.decided.as_deref() {
                Some(Decision::Applied(value)) => Some(value.clone()),
                _ => None,
            },
        };
        match self
            .services
            .intent
            .clear(self.manifest.migration, operation, &resolution)
            .await
        {
            Ok(()) => {}
            Err(Error::IntentPending) => return Ok(Progress::Pending),
            Err(error) => return Err(error),
        }
        let pending = self.pending.take().ok_or(Error::InvalidState)?;
        outcome?;
        if matches!(pending.next.state, State::Activated | State::Retired)
            && pending.next.state != self.manifest.state
        {
            use busbar_contract::persistence::lifecycle::{ActivationReceipt, CompletionPhase};
            let Decision::Applied(original_result) =
                pending.decided.as_deref().ok_or(Error::InvalidState)?
            else {
                return Err(Error::InvalidState);
            };
            let phase = if pending.next.state == State::Activated {
                CompletionPhase::Activation
            } else {
                CompletionPhase::Complete
            };
            let checkpoint = pending.next.encode(&self.registry)?;
            let proof = Arc::new(ActivationReceipt {
                attempt: pending.attempt.candidate().candidate().id,
                candidate_fingerprint: pending.attempt.candidate().fingerprint(),
                original_result: original_result.clone(),
                checkpoint_address: address(pending.next.migration),
                checkpoint_value_digest: Sha256::digest(&checkpoint).into(),
                phase,
            });
            match phase {
                CompletionPhase::Activation => self.activation_receipt = Some(proof),
                CompletionPhase::Complete => self.complete_receipt = Some(proof),
            }
        }
        if self.manifest.state == State::TargetVerified && pending.next.state == State::Activated {
            self.authority.writer_epoch = self
                .authority
                .writer_epoch
                .checked_add(1)
                .ok_or(Error::Bounds)?;
        }
        self.stored = Some(pending.next.encode(&self.registry)?);
        self.manifest = pending.next;
        Ok(Progress::Advanced)
    }
}

fn completion_marker(
    manifest: &Manifest,
    checkpoint: &[u8],
    phase: busbar_contract::persistence::lifecycle::CompletionPhase,
) -> Result<Secret<Vec<u8>>, Error> {
    use busbar_contract::persistence::lifecycle::{self as native, CompletionMarker};
    native::codec::encode_completion_marker(
        &CompletionMarker {
            version: native::VERSION,
            phase,
            upgrade: manifest.migration,
            source: DatasetId(manifest.source.dataset),
            target: DatasetId(manifest.target.dataset),
            checkpoint_address: address(manifest.migration),
            checkpoint_value_digest: Sha256::digest(checkpoint).into(),
        },
        native::Bounds {
            items: 16,
            bytes: 4096,
        },
    )
    .map_err(super::startup::native_error)
}

/// Read-only Store-authoritative status, with strict schema and registry matching.
pub async fn status(
    backend: &dyn PersistenceBackend,
    migration: Id,
    registry: &Registry,
) -> Result<Option<Manifest>, Error> {
    Ok(read_status(backend, migration, registry)
        .await?
        .map(|(manifest, _)| manifest))
}

async fn read_status(
    backend: &dyn PersistenceBackend,
    migration: Id,
    registry: &Registry,
) -> Result<Option<(Manifest, Vec<u8>)>, Error> {
    let response = backend
        .read(Arc::new(Read {
            dataset: backend.info().dataset,
            addresses: vec![address(migration)],
            time: None,
        }))
        .await
        .map_err(Error::Backend)?;
    let ReadResult::Values {
        observed_at,
        mut values,
    } = response
    else {
        return Err(Error::Corrupt);
    };
    if values.len() != 1 || observed_at.authority != backend.info().clock_authority {
        return Err(Error::Corrupt);
    }
    let Some(value) = values.pop().flatten() else {
        return Ok(None);
    };
    let bytes = value.expose(&crate::seal::lend());
    let manifest = Manifest::decode(bytes, registry)?;
    if manifest.migration != migration || manifest.target.dataset != backend.info().dataset.0 {
        return Err(Error::IdentityMismatch);
    }
    Ok(Some((manifest, bytes.clone())))
}

pub(super) fn address(migration: Id) -> Address {
    Address {
        namespace: NAMESPACE,
        key: migration.to_vec(),
    }
}

pub(super) fn check_rows<'a>(
    rows: impl Iterator<Item = (&'a [u8], &'a [u8])>,
    bounds: Bounds,
) -> Result<u64, Error> {
    let mut bytes = 0u64;
    let mut items = 0u32;
    for (key, value) in rows {
        items = items.checked_add(1).ok_or(Error::Bounds)?;
        bytes = bytes
            .checked_add(key.len() as u64)
            .and_then(|n| n.checked_add(value.len() as u64))
            .ok_or(Error::Bounds)?;
        if items > bounds.items || bytes > u64::from(bounds.bytes) {
            return Err(Error::Bounds);
        }
    }
    Ok(bytes)
}

pub(super) fn rolling_digest<'a>(
    previous: Digest32,
    rows: impl Iterator<Item = (&'a [u8], &'a [u8])>,
) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(b"busbar.migration.page.v1\0");
    hash.update(previous);
    for (key, value) in rows {
        hash.update((key.len() as u64).to_le_bytes());
        hash.update(key);
        hash.update((value.len() as u64).to_le_bytes());
        hash.update(value);
    }
    hash.finalize().into()
}

pub(super) fn rolling_target_digest(previous: Digest32, rows: &[TargetRow]) -> Digest32 {
    let seal = crate::seal::lend();
    let mut hash = Sha256::new();
    hash.update(b"busbar.migration.target.page.v1\0");
    hash.update(previous);
    for row in rows {
        hash.update(row.address.namespace);
        hash.update((row.address.key.len() as u64).to_le_bytes());
        hash.update(&row.address.key);
        hash.update((row.value.expose(&seal).len() as u64).to_le_bytes());
        hash.update(row.value.expose(&seal));
    }
    hash.finalize().into()
}

fn validate_activation(
    change: &ActivationChange,
    manifest: &Manifest,
    authority: WriterAuthority,
) -> Result<(), Error> {
    use busbar_contract::persistence::control;
    let seal = crate::seal::lend();
    let bounds = manifest.edges[0].bounds;
    // Control metadata has a fixed shape independent of a family's page limit.
    if change.predicates.len() != 3 || change.mutations.len() != 2 {
        return Err(Error::Bounds);
    }
    let mut bytes = 0usize;
    for predicate in &change.predicates {
        let value_len = match &predicate.expected {
            ExpectedValue::Absent => 0,
            ExpectedValue::Exact(value) => value.expose(&seal).len(),
        };
        bytes = bytes
            .checked_add(predicate.address.key.len())
            .and_then(|n| n.checked_add(value_len))
            .ok_or(Error::Bounds)?;
    }
    for mutation in &change.mutations {
        let Mutation::Put { address, value } = mutation else {
            return Err(Error::Verification);
        };
        if manifest.edges[0]
            .families
            .iter()
            .any(|family| family.target_namespace == address.namespace)
        {
            return Err(Error::Verification);
        }
        bytes = bytes
            .checked_add(address.key.len())
            .and_then(|n| n.checked_add(value.expose(&seal).len()))
            .ok_or(Error::Bounds)?;
    }
    if bytes > bounds.bytes as usize {
        return Err(Error::Bounds);
    }
    let root = Address {
        namespace: control::NAMESPACE.0,
        key: control::DATASET_KEY.to_vec(),
    };
    let prior = change
        .predicates
        .iter()
        .find_map(|p| match &p.expected {
            ExpectedValue::Exact(value) if p.address == root => {
                control::Dataset::decode(value.expose(&seal))
            }
            _ => None,
        })
        .ok_or(Error::Verification)?;
    let next = change
        .mutations
        .iter()
        .find_map(|m| match m {
            Mutation::Put { address, value } if *address == root => {
                control::Dataset::decode(value.expose(&seal))
            }
            _ => None,
        })
        .ok_or(Error::Verification)?;
    if prior.id != DatasetId(manifest.target.dataset)
        || prior.writer_epoch != authority.writer_epoch
        || next.id != prior.id
        || prior.writer_epoch.checked_add(1) != Some(next.writer_epoch)
    {
        return Err(Error::Verification);
    }
    let format_address = busbar_kernel::persistence::import_target::target::manifest_address();
    let format = change
        .mutations
        .iter()
        .find_map(|mutation| match mutation {
            Mutation::Put { address, value } if *address == format_address => {
                busbar_kernel::persistence::import_target::target::FormatRecord::decode(
                    value.expose(&seal),
                )
                .ok()
            }
            _ => None,
        })
        .ok_or(Error::Verification)?;
    if format.dataset != prior.id
        || format.registrar
            != (WriterAuthority {
                writer_epoch: next.writer_epoch,
                ..authority
            })
        || manifest.target.format != super::CORE_FORMAT
        || !change
            .predicates
            .iter()
            .any(|p| p.address == format_address && matches!(p.expected, ExpectedValue::Absent))
    {
        return Err(Error::Verification);
    }
    let writer_address =
        busbar_kernel::persistence::import_target::target::writer_address(authority.writer);
    if !change.predicates.iter().any(|p| {
        p.address == writer_address
            && match &p.expected {
                ExpectedValue::Exact(value) => control::Writer::decode(value.expose(&seal))
                    .is_some_and(|writer| writer.admits(authority.execution_epoch)),
                _ => false,
            }
    }) {
        return Err(Error::Verification);
    }
    Ok(())
}
