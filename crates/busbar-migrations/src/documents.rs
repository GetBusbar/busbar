// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native custody for opaque authored-document inventories. Paths, document
//! phases, filesystem policy, and secret resolution belong to the root caller.

use std::sync::Arc;

use busbar_contract::{persistence::*, Secret};
use busbar_kernel::persistence::{
    commit::{Attempt, SubmitResult},
    facade::WriterAuthority,
    import_target::{candidate_codec, target},
};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::{
    coordinator::ResolutionKind, Error, Id, IntentResolution, IntentStore, ReconciliationProgress,
};

const MARKER_MAGIC: &[u8; 8] = b"BSDOCM01";
const LOCATOR_MAGIC: &[u8; 8] = b"BSDOCL01";
const MARKER_BYTES: usize = 88;
const LOCATOR_BYTES: usize = 112;
const INTENT_HEADER_BYTES: usize = 160;

pub struct LocatedCheckpoint {
    pub migration: Id,
    pub protected: Secret<Vec<u8>>,
}

#[derive(Clone)]
struct Stored {
    protected: Secret<Vec<u8>>,
    marker: Secret<Vec<u8>>,
    revision: u64,
    complete: bool,
}
struct Observation {
    stored: Option<Stored>,
    locator: Option<Secret<Vec<u8>>>,
    locator_id: Option<Id>,
    guards: Vec<Predicate>,
}
struct Pending {
    migration: Id,
    protected: Secret<Vec<u8>>,
    marker: Secret<Vec<u8>>,
    revision: u64,
    complete: bool,
    attempt: Attempt,
    snapshot: Secret<Vec<u8>>,
    durable: bool,
    cleared: bool,
    resolution: Option<IntentResolution>,
    refusal: Option<Error>,
}
#[derive(Default)]
struct State {
    pending: Option<Pending>,
    known: Option<(Id, Option<Stored>)>,
    retryable: bool,
}

/// Supply a real registered writer and separately registered document intent
/// owner. This constructor never derives authority from an observed epoch.
pub struct StoreCheckpoints {
    backend: Arc<dyn PersistenceBackend>,
    info: BackendInfo,
    authority: WriterAuthority,
    intent: Arc<dyn IntentStore>,
    scope: [u8; 32],
    budget: usize,
    state: Mutex<State>,
}
impl StoreCheckpoints {
    pub fn new(
        backend: Arc<dyn PersistenceBackend>,
        authority: WriterAuthority,
        intent: Arc<dyn IntentStore>,
        scope: [u8; 32],
        budget: usize,
    ) -> Result<Self, Error> {
        let info = backend.info();
        valid_info(info)?;
        if info.durability == Durability::Ephemeral {
            return Err(Error::MissingCapability);
        }
        if authority.writer == [0; 16]
            || authority.writer_epoch == 0
            || authority.execution_epoch == 0
            || scope == [0; 32]
        {
            return Err(Error::IdentityMismatch);
        }
        if budget <= INTENT_HEADER_BYTES + LOCATOR_BYTES {
            return Err(Error::Bounds);
        }
        Ok(Self {
            backend,
            info,
            authority,
            intent,
            scope,
            budget,
            state: Mutex::new(State::default()),
        })
    }
    pub fn durability(&self) -> Durability {
        self.info.durability
    }

    /// Progress only, never a successful checkpoint acknowledgement. A busy
    /// waiter or explicit retryable outcome leaves the original operation owned.
    pub fn has_pending(&self) -> bool {
        self.state.try_lock().map_or(true, |state| state.retryable)
    }

    /// Find an unfinished inventory independently of this process's new upgrade
    /// id. Root supplies a stable opaque location scope, not document contents.
    pub async fn discover(
        backend: Arc<dyn PersistenceBackend>,
        scope: [u8; 32],
        budget: usize,
    ) -> Result<Option<LocatedCheckpoint>, Error> {
        let info = backend.info();
        valid_info(info)?;
        if scope == [0; 32] {
            return Err(Error::IdentityMismatch);
        }
        let first = values(
            backend.as_ref(),
            info,
            vec![
                target::root_address(),
                target::manifest_address(),
                locator_address(scope),
            ],
        )
        .await?;
        validate_root(info, &first[0], &first[1], None)?;
        let Some(locator) = first[2].as_ref() else {
            return Ok(None);
        };
        let DecodedLocator {
            migration,
            revision,
            digest,
        } = decode_locator(locator, info.dataset, scope)?;
        let current = values(
            backend.as_ref(),
            info,
            vec![
                target::root_address(),
                target::manifest_address(),
                locator_address(scope),
                data_address(migration),
                crate::coordinator::address(migration),
            ],
        )
        .await?;
        validate_root(info, &current[0], &current[1], None)?;
        if current[2].as_ref() != Some(locator) {
            return Err(Error::Conflict);
        }
        let stored = decode_stored(
            info.dataset,
            migration,
            current[3].clone(),
            current[4].clone(),
            budget,
        )?
        .ok_or(Error::Corrupt)?;
        if stored.complete
            || stored.revision != revision
            || Sha256::digest(stored.protected.expose(&crate::seal::lend())).as_slice() != digest
        {
            return Err(Error::Corrupt);
        }
        Ok(Some(LocatedCheckpoint {
            migration,
            protected: stored.protected,
        }))
    }

    pub async fn load(&self, migration: Id) -> Result<Option<Secret<Vec<u8>>>, Error> {
        let mut state = self.state.lock().await;
        let result = self.load_inner(&mut state, migration).await;
        state.retryable = result.as_ref().err().is_some_and(|error| retryable(*error));
        result
    }
    pub async fn confirm(
        &self,
        migration: Id,
        protected: &Secret<Vec<u8>>,
    ) -> Result<Secret<Vec<u8>>, Error> {
        self.write(migration, protected, false).await
    }
    /// Root calls only after its typed filesystem publication is complete. The
    /// final value and removal of this inventory's locator commit atomically.
    pub async fn complete(
        &self,
        migration: Id,
        protected: &Secret<Vec<u8>>,
    ) -> Result<Secret<Vec<u8>>, Error> {
        self.write(migration, protected, true).await
    }
    async fn write(
        &self,
        migration: Id,
        protected: &Secret<Vec<u8>>,
        complete: bool,
    ) -> Result<Secret<Vec<u8>>, Error> {
        let mut state = self.state.lock().await;
        let result = self
            .write_inner(&mut state, migration, protected, complete)
            .await;
        state.retryable = result.as_ref().err().is_some_and(|error| retryable(*error));
        result
    }
    async fn load_inner(
        &self,
        state: &mut State,
        migration: Id,
    ) -> Result<Option<Secret<Vec<u8>>>, Error> {
        validate_id(migration)?;
        if let Some(pending) = &state.pending {
            if pending.migration != migration {
                return Err(Error::IdentityMismatch);
            }
            self.drive(state).await?;
        }
        self.reconcile_prior(migration).await?;
        let observed = self.observe(migration).await?;
        let result = observed
            .stored
            .as_ref()
            .map(|stored| stored.protected.clone());
        state.known = Some((migration, observed.stored));
        Ok(result)
    }
    async fn write_inner(
        &self,
        state: &mut State,
        migration: Id,
        protected: &Secret<Vec<u8>>,
        complete: bool,
    ) -> Result<Secret<Vec<u8>>, Error> {
        validate_id(migration)?;
        if protected.expose(&crate::seal::lend()).len() > self.budget {
            return Err(Error::Bounds);
        }
        if let Some(pending) = &state.pending {
            if pending.migration != migration
                || pending.protected != *protected
                || pending.complete != complete
            {
                return Err(Error::Conflict);
            }
            return self.drive(state).await;
        }
        self.reconcile_prior(migration).await?;
        let observed = self.observe(migration).await?;
        if observed.locator_id.is_some_and(|id| id != migration) {
            return Err(Error::Conflict);
        }
        if let Some((known_id, known)) = &state.known {
            if *known_id != migration || !same_stored(known, &observed.stored) {
                return Err(Error::Conflict);
            }
        }
        if observed.stored.as_ref().is_some_and(|held| held.complete) && !complete {
            return Err(Error::InvalidState);
        }
        let revision = observed
            .stored
            .as_ref()
            .map_or(0, |held| held.revision)
            .checked_add(1)
            .ok_or(Error::Bounds)?;
        let marker = marker(self.info.dataset, migration, revision, protected, complete);
        let mut operation = [0; 16];
        getrandom::fill(&mut operation).map_err(|_| Error::Entropy)?;
        if operation == [0; 16] {
            return Err(Error::Entropy);
        }
        let mut predicates = observed.guards;
        predicates.push(exact(
            data_address(migration),
            observed.stored.as_ref().map(|s| s.protected.clone()),
        ));
        predicates.push(exact(
            crate::coordinator::address(migration),
            observed.stored.as_ref().map(|s| s.marker.clone()),
        ));
        predicates.push(exact(locator_address(self.scope), observed.locator));
        predicates.push(Predicate {
            address: crate::intent::guard_address(migration),
            expected: ExpectedValue::Exact(Secret::new(crate::intent::open_guard(
                migration, operation,
            ))),
        });
        let mut mutations = vec![
            Mutation::Put {
                address: data_address(migration),
                value: protected.clone(),
            },
            Mutation::Put {
                address: crate::coordinator::address(migration),
                value: marker.clone(),
            },
        ];
        if complete {
            mutations.push(Mutation::Delete(locator_address(self.scope)));
        } else {
            mutations.push(Mutation::Put {
                address: locator_address(self.scope),
                value: locator(
                    self.info.dataset,
                    self.scope,
                    migration,
                    revision,
                    protected,
                ),
            });
        }
        let candidate = crate::witness::attach(
            Candidate {
                id: AttemptId {
                    dataset: self.info.dataset,
                    writer_epoch: self.authority.writer_epoch,
                    writer: self.authority.writer,
                    execution_epoch: self.authority.execution_epoch,
                    operation,
                },
                codec: CANDIDATE_VERSION,
                predicates,
                mutations,
                time: None,
                result: marker.clone(),
            },
            migration,
        )?;
        let snapshot = candidate_codec::encode(
            &candidate,
            self.budget
                .checked_sub(INTENT_HEADER_BYTES)
                .ok_or(Error::Bounds)?,
            &crate::seal::lend(),
        )
        .map_err(|_| Error::Bounds)?;
        let attempt =
            Attempt::new(candidate, self.backend.clone()).map_err(|_| Error::IdentityMismatch)?;
        state.pending = Some(Pending {
            migration,
            protected: protected.clone(),
            marker,
            revision,
            complete,
            attempt,
            snapshot,
            durable: false,
            cleared: false,
            resolution: None,
            refusal: None,
        });
        self.drive(state).await
    }
    async fn reconcile_prior(&self, migration: Id) -> Result<(), Error> {
        if !self.intent.pending(migration).await? {
            return Ok(());
        }
        match self.intent.reconcile(migration).await? {
            ReconciliationProgress::Resolved => {
                if self.intent.pending(migration).await? {
                    return Err(Error::IntentPending);
                }
                Ok(())
            }
            ReconciliationProgress::Advanced | ReconciliationProgress::Pending => {
                Err(Error::IntentPending)
            }
            ReconciliationProgress::Unresolved => Err(Error::ReconciliationRequired),
        }
    }
    async fn drive(&self, state: &mut State) -> Result<Secret<Vec<u8>>, Error> {
        let pending = state.pending.as_mut().ok_or(Error::InvalidState)?;
        let operation = pending.attempt.candidate().candidate().id.operation;
        if !pending.durable {
            self.intent
                .persist(pending.migration, operation, &pending.snapshot)
                .await?;
            pending.durable = true;
        }
        if pending.resolution.is_none() {
            let (kind, result, refusal) = match pending.attempt.submit().await {
                SubmitResult::Uncertain | SubmitResult::Busy => return Err(Error::IntentPending),
                SubmitResult::Reconcile => return Err(Error::ReconciliationRequired),
                SubmitResult::NoEffect(failure) => (
                    ResolutionKind::ProvenNoEffect,
                    None,
                    Some(Error::Backend(failure)),
                ),
                SubmitResult::Decided(decision) => match decision.as_ref() {
                    Decision::Applied(value)
                        if value == &pending.attempt.candidate().candidate().result =>
                    {
                        (ResolutionKind::Applied, Some(value.clone()), None)
                    }
                    Decision::ConditionConflict => {
                        (ResolutionKind::Conflict, None, Some(Error::Conflict))
                    }
                    Decision::Applied(_) => return Err(Error::Corrupt),
                    _ => return Err(Error::ReconciliationRequired),
                },
            };
            pending.refusal = refusal;
            pending.resolution = Some(IntentResolution {
                fingerprint: pending.attempt.candidate().fingerprint(),
                kind,
                applied_result: result,
            });
        }
        if pending.refusal.is_none() {
            self.readback(pending).await?;
        }
        if !pending.cleared {
            self.intent
                .clear(
                    pending.migration,
                    operation,
                    pending.resolution.as_ref().ok_or(Error::InvalidState)?,
                )
                .await?;
            pending.cleared = true;
        }
        if let Some(error) = pending.refusal {
            state.pending = None;
            return Err(error);
        }
        let protected = self.readback(pending).await?;
        state.known = Some((
            pending.migration,
            Some(Stored {
                protected: protected.clone(),
                marker: pending.marker.clone(),
                revision: pending.revision,
                complete: pending.complete,
            }),
        ));
        state.pending = None;
        Ok(protected)
    }
    async fn readback(&self, pending: &Pending) -> Result<Secret<Vec<u8>>, Error> {
        let readback = values(
            self.backend.as_ref(),
            self.info,
            vec![
                data_address(pending.migration),
                crate::coordinator::address(pending.migration),
            ],
        )
        .await?;
        if readback[0].as_ref() != Some(&pending.protected)
            || readback[1].as_ref() != Some(&pending.marker)
        {
            return Err(Error::Verification);
        }
        Ok(readback[0].as_ref().ok_or(Error::Corrupt)?.clone())
    }
    async fn observe(&self, migration: Id) -> Result<Observation, Error> {
        let root = target::root_address();
        let format = target::manifest_address();
        let writer = target::writer_address(self.authority.writer);
        let generation = generation_address();
        let observed = values(
            self.backend.as_ref(),
            self.info,
            vec![
                root.clone(),
                format.clone(),
                writer.clone(),
                generation.clone(),
                data_address(migration),
                crate::coordinator::address(migration),
                locator_address(self.scope),
            ],
        )
        .await?;
        validate_root(self.info, &observed[0], &observed[1], Some(self.authority))?;
        let writer_state = observed[2]
            .as_ref()
            .and_then(|bytes| control::Writer::decode(bytes.expose(&crate::seal::lend())))
            .ok_or(Error::FenceRequired)?;
        if !writer_state.admits(self.authority.execution_epoch) {
            return Err(Error::FenceRequired);
        }
        if let Some(bytes) = &observed[3] {
            let generation: [u8; 8] = bytes
                .expose(&crate::seal::lend())
                .as_slice()
                .try_into()
                .map_err(|_| Error::Corrupt)?;
            if u64::from_le_bytes(generation) == 0 {
                return Err(Error::Corrupt);
            }
        }
        let stored = decode_stored(
            self.info.dataset,
            migration,
            observed[4].clone(),
            observed[5].clone(),
            self.budget,
        )?;
        let locator_id = if let Some(locator) = &observed[6] {
            let DecodedLocator {
                migration: id,
                revision,
                digest,
            } = decode_locator(locator, self.info.dataset, self.scope)?;
            if id == migration {
                let held = stored.as_ref().ok_or(Error::Corrupt)?;
                if held.complete
                    || held.revision != revision
                    || Sha256::digest(held.protected.expose(&crate::seal::lend())).as_slice()
                        != digest
                {
                    return Err(Error::Corrupt);
                }
            }
            Some(id)
        } else {
            None
        };
        if stored.as_ref().is_some_and(|held| !held.complete) && locator_id != Some(migration) {
            return Err(Error::Corrupt);
        }
        Ok(Observation {
            stored,
            locator: observed[6].clone(),
            locator_id,
            guards: vec![
                exact(root, observed[0].clone()),
                exact(format, observed[1].clone()),
                exact(writer, observed[2].clone()),
                exact(generation, observed[3].clone()),
            ],
        })
    }
}

fn retryable(error: Error) -> bool {
    matches!(
        error,
        Error::IntentPending
            | Error::Backend(
                Failure::Unknown | Failure::Unavailable | Failure::Overloaded | Failure::StaleScan
            )
    )
}
fn valid_info(info: BackendInfo) -> Result<(), Error> {
    if info.dataset.0 == [0; 16] || info.atomic_domain == [0; 16] || info.clock_authority == [0; 16]
    {
        Err(Error::IdentityMismatch)
    } else {
        Ok(())
    }
}
fn validate_id(id: Id) -> Result<(), Error> {
    if id == [0; 16] {
        Err(Error::IdentityMismatch)
    } else {
        Ok(())
    }
}
fn data_address(migration: Id) -> Address {
    let mut key = vec![b'd'];
    key.extend_from_slice(&migration);
    Address {
        namespace: crate::coordinator::NAMESPACE,
        key,
    }
}
fn locator_address(scope: [u8; 32]) -> Address {
    let mut key = vec![b'L'];
    key.extend_from_slice(&scope);
    Address {
        namespace: crate::coordinator::NAMESPACE,
        key,
    }
}
fn generation_address() -> Address {
    Address {
        namespace: control::GENERATION_NAMESPACE.0,
        key: crate::coordinator::NAMESPACE.to_vec(),
    }
}
fn exact(address: Address, value: Option<Secret<Vec<u8>>>) -> Predicate {
    Predicate {
        address,
        expected: value.map_or(ExpectedValue::Absent, ExpectedValue::Exact),
    }
}
async fn values(
    backend: &dyn PersistenceBackend,
    info: BackendInfo,
    addresses: Vec<Address>,
) -> Result<Vec<Option<Secret<Vec<u8>>>>, Error> {
    if backend.info() != info {
        return Err(Error::IdentityMismatch);
    }
    let count = addresses.len();
    let ReadResult::Values {
        observed_at,
        values,
    } = backend
        .read(Arc::new(Read {
            dataset: info.dataset,
            addresses,
            time: None,
        }))
        .await
        .map_err(Error::Backend)?
    else {
        return Err(Error::Corrupt);
    };
    if values.len() != count
        || observed_at.authority != info.clock_authority
        || backend.info() != info
    {
        return Err(Error::IdentityMismatch);
    }
    Ok(values)
}
fn validate_root(
    info: BackendInfo,
    root: &Option<Secret<Vec<u8>>>,
    format: &Option<Secret<Vec<u8>>>,
    authority: Option<WriterAuthority>,
) -> Result<(), Error> {
    let root = root
        .as_ref()
        .and_then(|bytes| control::Dataset::decode(bytes.expose(&crate::seal::lend())))
        .ok_or(Error::FenceRequired)?;
    let format = format.as_ref().ok_or(Error::FenceRequired)?;
    let format = target::FormatRecord::decode(format.expose(&crate::seal::lend()))
        .map_err(|_| Error::UnsupportedVersion)?;
    if root.id != info.dataset
        || format.dataset != info.dataset
        || format.registrar.writer_epoch != root.writer_epoch
        || authority.is_some_and(|authority| root.writer_epoch != authority.writer_epoch)
    {
        return Err(Error::IdentityMismatch);
    }
    Ok(())
}
fn marker(
    dataset: DatasetId,
    migration: Id,
    revision: u64,
    protected: &Secret<Vec<u8>>,
    complete: bool,
) -> Secret<Vec<u8>> {
    let mut bytes = Vec::with_capacity(MARKER_BYTES);
    bytes.extend_from_slice(MARKER_MAGIC);
    bytes.push(if complete { 2 } else { 1 });
    bytes.extend_from_slice(&[0; 7]);
    bytes.extend_from_slice(&dataset.0);
    bytes.extend_from_slice(&migration);
    bytes.extend_from_slice(&revision.to_le_bytes());
    bytes.extend_from_slice(&Sha256::digest(protected.expose(&crate::seal::lend())));
    Secret::new(bytes)
}
fn locator(
    dataset: DatasetId,
    scope: [u8; 32],
    migration: Id,
    revision: u64,
    protected: &Secret<Vec<u8>>,
) -> Secret<Vec<u8>> {
    let mut bytes = Vec::with_capacity(LOCATOR_BYTES);
    bytes.extend_from_slice(LOCATOR_MAGIC);
    bytes.extend_from_slice(&dataset.0);
    bytes.extend_from_slice(&scope);
    bytes.extend_from_slice(&migration);
    bytes.extend_from_slice(&revision.to_le_bytes());
    bytes.extend_from_slice(&Sha256::digest(protected.expose(&crate::seal::lend())));
    Secret::new(bytes)
}
fn decode_stored(
    dataset: DatasetId,
    migration: Id,
    protected: Option<Secret<Vec<u8>>>,
    marker: Option<Secret<Vec<u8>>>,
    budget: usize,
) -> Result<Option<Stored>, Error> {
    let (protected, marker) = match (protected, marker) {
        (None, None) => return Ok(None),
        (Some(protected), Some(marker)) => (protected, marker),
        _ => return Err(Error::Corrupt),
    };
    let bytes = marker.expose(&crate::seal::lend());
    if bytes.len() != MARKER_BYTES
        || &bytes[..8] != MARKER_MAGIC
        || !matches!(bytes[8], 1 | 2)
        || bytes[9..16] != [0; 7]
        || bytes[16..32] != dataset.0
        || bytes[32..48] != migration
        || protected.expose(&crate::seal::lend()).len() > budget
        || Sha256::digest(protected.expose(&crate::seal::lend())).as_slice() != &bytes[56..88]
    {
        return Err(Error::Corrupt);
    }
    let revision = u64::from_le_bytes(bytes[48..56].try_into().map_err(|_| Error::Corrupt)?);
    if revision == 0 {
        return Err(Error::Corrupt);
    }
    let complete = bytes[8] == 2;
    Ok(Some(Stored {
        protected,
        marker,
        revision,
        complete,
    }))
}
/// Public locator metadata authenticated by the protected original envelope.
struct DecodedLocator {
    migration: Id,
    revision: u64,
    digest: [u8; 32],
}
fn decode_locator(
    locator: &Secret<Vec<u8>>,
    dataset: DatasetId,
    scope: [u8; 32],
) -> Result<DecodedLocator, Error> {
    let bytes = locator.expose(&crate::seal::lend());
    if bytes.len() != LOCATOR_BYTES
        || &bytes[..8] != LOCATOR_MAGIC
        || bytes[8..24] != dataset.0
        || bytes[24..56] != scope
    {
        return Err(Error::Corrupt);
    }
    let migration: Id = bytes[56..72].try_into().map_err(|_| Error::Corrupt)?;
    validate_id(migration)?;
    let revision = u64::from_le_bytes(bytes[72..80].try_into().map_err(|_| Error::Corrupt)?);
    if revision == 0 {
        return Err(Error::Corrupt);
    }
    Ok(DecodedLocator {
        migration,
        revision,
        digest: bytes[80..112].try_into().map_err(|_| Error::Corrupt)?,
    })
}
fn same_stored(left: &Option<Stored>, right: &Option<Stored>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.marker == right.marker && left.protected == right.protected
        }
        _ => false,
    }
}
