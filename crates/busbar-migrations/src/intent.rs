// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Protected, live Store-backed intent under a distinct registered cold writer.
//! Journal writes are idempotent exact-key CAS operations, resolved by coherent
//! readback. They do not recursively journal themselves. Persistent closed guards
//! prevent delayed journal or business commands from resurrecting cleared work.

use std::sync::Arc;

use async_trait::async_trait;
use busbar_contract::{persistence::*, Secret};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use super::ReconciliationProgress;
use super::{coordinator::ResolutionKind, Digest32, Error, Id, IntentResolution, IntentStore};
use busbar_kernel::persistence::{
    commit::{Attempt, SubmitResult},
    facade::WriterAuthority,
    import_target::candidate_codec,
    import_target::target as startup,
};

pub(super) const NAMESPACE: Id = *b"busbar.migint1\0\0";
const HEADER: usize = 160;
const GUARD: usize = 48;
const HORIZON: u64 = 24 * 60 * 60;

fn checkpoint_phase(
    candidate: &PreparedCandidate,
    migration: Id,
) -> Result<Option<busbar_contract::persistence::lifecycle::CompletionMarker>, Error> {
    use busbar_contract::persistence::lifecycle as native;
    use sha2::{Digest, Sha256};
    let marker_address = native::completion_marker_address(migration);
    let mut markers =
        candidate
            .candidate()
            .mutations
            .iter()
            .filter_map(|mutation| match mutation {
                Mutation::Put { address, value } if *address == marker_address => Some(value),
                _ => None,
            });
    let Some(value) = markers.next() else {
        return Ok(None);
    };
    if markers.next().is_some() {
        return Err(Error::Corrupt);
    }
    let marker = native::codec::decode_completion_marker(
        value.expose(&crate::seal::lend()),
        native::Bounds {
            items: 16,
            bytes: 4096,
        },
    )
    .map_err(super::startup::native_error)?;
    if marker.upgrade != migration
        || marker.target != candidate.candidate().id.dataset
        || marker.checkpoint_address != super::coordinator::address(migration)
    {
        return Err(Error::Corrupt);
    }
    let checkpoint = candidate
        .candidate()
        .mutations
        .iter()
        .find_map(|mutation| match mutation {
            Mutation::Put { address, value } if *address == marker.checkpoint_address => {
                Some(value)
            }
            _ => None,
        })
        .ok_or(Error::Corrupt)?;
    let digest: [u8; 32] = Sha256::digest(checkpoint.expose(&crate::seal::lend())).into();
    if digest != marker.checkpoint_value_digest {
        return Err(Error::Corrupt);
    }
    Ok(Some(marker))
}

pub(super) fn guard_address(migration: Id) -> Address {
    address(b'g', migration)
}
fn payload_address(migration: Id) -> Address {
    address(b'p', migration)
}
fn proof_address(
    migration: Id,
    phase: busbar_contract::persistence::lifecycle::CompletionPhase,
) -> Address {
    use busbar_contract::persistence::lifecycle::CompletionPhase;
    address(
        match phase {
            CompletionPhase::Activation => b'a',
            CompletionPhase::Complete => b'c',
        },
        migration,
    )
}
fn owner_address(migration: Id) -> Address {
    address(b'w', migration)
}

fn owner_binding(dataset: DatasetId, migration: Id, writer: Id) -> Vec<u8> {
    let mut bytes = vec![0; 64];
    bytes[..8].copy_from_slice(b"BSMOWN1\0");
    bytes[8..24].copy_from_slice(&dataset.0);
    bytes[24..40].copy_from_slice(&migration);
    bytes[40..56].copy_from_slice(&writer);
    bytes[56..64].copy_from_slice(&1u64.to_le_bytes());
    bytes
}

/// Register one never-reused cold identity and its immutable migration binding.
/// This operation contains only public authority metadata; exact-key readback
/// resolves lost replies without a recursive confidential intent requirement.
pub struct ColdWriterRegistration {
    backend: Arc<dyn PersistenceBackend>,
    migration: Id,
    bootstrap: WriterAuthority,
    cold: Id,
    operation: Id,
    pending: Option<Attempt>,
    current: bool,
}

impl ColdWriterRegistration {
    pub fn new(
        backend: Arc<dyn PersistenceBackend>,
        migration: Id,
        bootstrap: WriterAuthority,
        cold: Id,
        operation: Id,
    ) -> Result<Self, Error> {
        if migration == [0; 16]
            || cold == [0; 16]
            || cold == bootstrap.writer
            || operation == [0; 16]
            || bootstrap.writer == [0; 16]
            || bootstrap.writer_epoch != 1
            || bootstrap.execution_epoch != 1
        {
            return Err(Error::IdentityMismatch);
        }
        Ok(Self {
            backend,
            migration,
            bootstrap,
            cold,
            operation,
            pending: None,
            current: false,
        })
    }

    /// Register confidential startup-document custody under an already admitted
    /// current writer. Current root and format bytes are checked atomically;
    /// observing an epoch alone never grants this writer authority.
    pub fn for_current(
        backend: Arc<dyn PersistenceBackend>,
        migration: Id,
        authority: WriterAuthority,
        cold: Id,
        operation: Id,
    ) -> Result<Self, Error> {
        if migration == [0; 16]
            || cold == [0; 16]
            || cold == authority.writer
            || operation == [0; 16]
            || authority.writer == [0; 16]
            || authority.writer_epoch == 0
            || authority.execution_epoch == 0
        {
            return Err(Error::IdentityMismatch);
        }
        Ok(Self {
            backend,
            migration,
            bootstrap: authority,
            cold,
            operation,
            pending: None,
            current: true,
        })
    }

    pub async fn advance(&mut self) -> Result<super::BootstrapProgress, Error> {
        let info = self.backend.info();
        let response = self
            .backend
            .read(Arc::new(Read {
                dataset: info.dataset,
                addresses: vec![
                    startup::root_address(),
                    startup::manifest_address(),
                    startup::writer_address(self.bootstrap.writer),
                    startup::writer_address(self.cold),
                    owner_address(self.migration),
                ],
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
        if observed_at.authority != info.clock_authority || values.len() != 5 {
            return Err(Error::Corrupt);
        }
        let seal = crate::seal::lend();
        let observed_root = values[0]
            .as_ref()
            .and_then(|value| control::Dataset::decode(value.expose(&seal)))
            .ok_or(Error::FenceRequired)?;
        if observed_root.id != info.dataset {
            return Err(Error::IdentityMismatch);
        }
        let binding = owner_binding(info.dataset, self.migration, self.cold);
        let open = control::Writer {
            retired_through: 0,
            admitted_through: 1,
        }
        .encode()
        .ok_or(Error::Corrupt)?
        .to_vec();
        if let Some(owner) = &values[4] {
            if owner.expose(&seal) == &binding
                && values[3]
                    .as_ref()
                    .is_some_and(|writer| writer.expose(&seal) == &open)
            {
                self.pending = None;
                return Ok(super::BootstrapProgress::Ready);
            }
            return Err(Error::Conflict);
        }
        if self.pending.is_none() {
            let root = values[0].as_ref().ok_or(Error::FenceRequired)?;
            let caller = values[2].as_ref().ok_or(Error::FenceRequired)?;
            let caller_state =
                control::Writer::decode(caller.expose(&seal)).ok_or(Error::Corrupt)?;
            let format_expected = if self.current {
                let bytes = values[1].as_ref().ok_or(Error::FenceRequired)?;
                let format = startup::FormatRecord::decode(bytes.expose(&seal))
                    .map_err(super::activation::import_error)?;
                if format.dataset != info.dataset
                    || format.registrar.writer_epoch != self.bootstrap.writer_epoch
                {
                    return Err(Error::FenceRequired);
                }
                ExpectedValue::Exact(bytes.clone())
            } else {
                if values[1].is_some() {
                    return Err(Error::FenceRequired);
                }
                ExpectedValue::Absent
            };
            if control::Dataset::decode(root.expose(&seal))
                != Some(control::Dataset {
                    id: info.dataset,
                    writer_epoch: self.bootstrap.writer_epoch,
                })
                || !caller_state.admits(self.bootstrap.execution_epoch)
                || values[3].is_some()
            {
                return Err(Error::FenceRequired);
            }
            let candidate = PreparedCandidate::new(Candidate {
                id: AttemptId {
                    dataset: info.dataset,
                    writer_epoch: self.bootstrap.writer_epoch,
                    writer: self.bootstrap.writer,
                    execution_epoch: self.bootstrap.execution_epoch,
                    operation: self.operation,
                },
                codec: CANDIDATE_VERSION,
                predicates: vec![
                    Predicate {
                        address: startup::root_address(),
                        expected: ExpectedValue::Exact(root.clone()),
                    },
                    Predicate {
                        address: startup::manifest_address(),
                        expected: format_expected,
                    },
                    Predicate {
                        address: startup::writer_address(self.bootstrap.writer),
                        expected: ExpectedValue::Exact(caller.clone()),
                    },
                    Predicate {
                        address: startup::writer_address(self.cold),
                        expected: ExpectedValue::Absent,
                    },
                    Predicate {
                        address: owner_address(self.migration),
                        expected: ExpectedValue::Absent,
                    },
                ],
                mutations: vec![
                    Mutation::Put {
                        address: startup::writer_address(self.cold),
                        value: Secret::new(open),
                    },
                    Mutation::Put {
                        address: owner_address(self.migration),
                        value: Secret::new(binding),
                    },
                ],
                time: None,
                result: Secret::new(Vec::new()),
            })
            .map_err(|_| Error::Corrupt)?;
            self.pending = Some(
                Attempt::new(candidate, self.backend.clone())
                    .map_err(|_| Error::IdentityMismatch)?,
            );
        }
        match self
            .pending
            .as_ref()
            .ok_or(Error::InvalidState)?
            .submit()
            .await
        {
            SubmitResult::Uncertain | SubmitResult::Busy => Ok(super::BootstrapProgress::Pending),
            SubmitResult::Reconcile => Err(Error::ReconciliationRequired),
            SubmitResult::NoEffect(failure) => Err(Error::Backend(failure)),
            SubmitResult::Decided(value) => match value.as_ref() {
                Decision::Applied(_) => {
                    self.pending = None;
                    Ok(super::BootstrapProgress::Advanced)
                }
                Decision::ConditionConflict => Err(Error::Conflict),
                _ => Err(Error::ReconciliationRequired),
            },
        }
    }
}
fn address(kind: u8, migration: Id) -> Address {
    let mut key = Vec::with_capacity(17);
    key.push(kind);
    key.extend_from_slice(&migration);
    Address {
        namespace: NAMESPACE,
        key,
    }
}

pub(super) fn open_guard(migration: Id, operation: Id) -> Vec<u8> {
    guard(migration, operation, 1)
}
fn guard(migration: Id, operation: Id, state: u8) -> Vec<u8> {
    let mut bytes = vec![0; GUARD];
    bytes[..8].copy_from_slice(b"BSMIGD1\0");
    bytes[8..24].copy_from_slice(&migration);
    bytes[24..40].copy_from_slice(&operation);
    bytes[40] = state;
    bytes
}

#[derive(Clone, Copy)]
struct Header {
    migration: Id,
    operation: Id,
    fingerprint: Digest32,
    prepared_at: ClockObservation,
    deadline: u64,
    length: usize,
    original: WriterAuthority,
}

/// Recovery custody only. The native timestamp is preparation evidence, never
/// a replacement for the original monotonic first-send clock. An outstanding
/// record cannot authorize automatic replay, even within its recorded horizon.
pub struct OutstandingIntent {
    pub candidate: Secret<Vec<u8>>,
    pub fingerprint: Digest32,
    pub prepared_at: ClockObservation,
    pub replay_deadline: u64,
    pub original: WriterAuthority,
}

struct Observation {
    root: Secret<Vec<u8>>,
    epoch: u64,
    writer: Secret<Vec<u8>>,
    writer_state: control::Writer,
    guard: Option<Secret<Vec<u8>>>,
    payload: Option<Secret<Vec<u8>>>,
    header: Option<Header>,
    state: u8,
    at: ClockObservation,
}

struct Pending {
    migration: Id,
    operation: Id,
    state: u8,
    desired_guard: Secret<Vec<u8>>,
    desired_payload: Secret<Vec<u8>>,
    attempt: Attempt,
}

struct RecoveryPending {
    operation: Id,
    writer: Id,
    next: control::Writer,
    attempt: Attempt,
}

/// The cold writer is admitted explicitly before attaching this owner; this
/// constructor cannot create or grant one. Its identity and execution epoch stay
/// fixed across activation. New journal writes validate its existing admission
/// and exact root/writer values, including after the dataset epoch advances.
pub struct StoreIntent {
    backend: Arc<dyn PersistenceBackend>,
    info: BackendInfo,
    cold: WriterAuthority,
    migration: Id,
    binding: Vec<u8>,
    budget: usize,
    pending: Mutex<Option<Pending>>,
    recovery: Mutex<Option<RecoveryPending>>,
}

impl StoreIntent {
    pub async fn open(
        backend: Arc<dyn PersistenceBackend>,
        migration: Id,
        budget: usize,
    ) -> Result<Self, Error> {
        let info = backend.info();
        if info.durability == Durability::Ephemeral || migration == [0; 16] || budget < HEADER {
            return Err(Error::MissingCapability);
        }
        let response = backend
            .read(Arc::new(Read {
                dataset: info.dataset,
                addresses: vec![startup::root_address(), owner_address(migration)],
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
        if observed_at.authority != info.clock_authority || values.len() != 2 {
            return Err(Error::Corrupt);
        }
        let seal = crate::seal::lend();
        let root = values[0]
            .as_ref()
            .and_then(|value| control::Dataset::decode(value.expose(&seal)))
            .ok_or(Error::FenceRequired)?;
        let binding = values[1]
            .as_ref()
            .ok_or(Error::FenceRequired)?
            .expose(&seal);
        if binding.len() != 64
            || &binding[..8] != b"BSMOWN1\0"
            || binding[8..24] != info.dataset.0
            || binding[24..40] != migration
            || binding[56..64] != 1u64.to_le_bytes()
            || root.id != info.dataset
        {
            return Err(Error::Corrupt);
        }
        let writer: Id = binding[40..56].try_into().map_err(|_| Error::Corrupt)?;
        if writer == [0; 16] {
            return Err(Error::Corrupt);
        }
        let cold = WriterAuthority {
            writer_epoch: root.writer_epoch,
            writer,
            execution_epoch: 1,
        };
        let owner = Self {
            backend,
            info,
            cold,
            migration,
            binding: binding.clone(),
            budget,
            pending: Mutex::new(None),
            recovery: Mutex::new(None),
        };
        let observed = owner.observe(migration).await?;
        if observed.epoch != cold.writer_epoch
            || !observed.writer_state.admits(cold.execution_epoch)
        {
            return Err(Error::FenceRequired);
        }
        Ok(owner)
    }

    pub async fn outstanding(&self, migration: Id) -> Result<Option<OutstandingIntent>, Error> {
        let observed = self.observe(migration).await?;
        if observed.state != 1 {
            return Ok(None);
        }
        let header = observed.header.ok_or(Error::Corrupt)?;
        let seal = crate::seal::lend();
        let bytes = observed
            .payload
            .as_ref()
            .ok_or(Error::Corrupt)?
            .expose(&seal);
        Ok(Some(OutstandingIntent {
            candidate: Secret::new(bytes[HEADER..].to_vec()),
            fingerprint: header.fingerprint,
            prepared_at: header.prepared_at,
            replay_deadline: header.deadline,
            original: header.original,
        }))
    }

    /// Recover the exact observed Applied checkpoint receipt after process loss.
    /// The closed guard prevents this retained candidate from first execution.
    pub async fn confirmed_checkpoint(
        &self,
        migration: Id,
    ) -> Result<Option<Arc<busbar_contract::persistence::lifecycle::ActivationReceipt>>, Error>
    {
        let observed = self.observe(migration).await?;
        if observed.state != 5 {
            return Ok(None);
        }
        let header = observed.header.ok_or(Error::Corrupt)?;
        self.decode_checkpoint_capsule(observed.payload.as_ref().ok_or(Error::Corrupt)?, header)
    }

    /// Phase-specific immutable custody survives the later Complete candidate.
    pub async fn confirmed_checkpoint_phase(
        &self,
        migration: Id,
        phase: busbar_contract::persistence::lifecycle::CompletionPhase,
    ) -> Result<Option<Arc<busbar_contract::persistence::lifecycle::ActivationReceipt>>, Error>
    {
        if migration != self.migration {
            return Err(Error::IdentityMismatch);
        }
        let values = self.values(vec![proof_address(migration, phase)]).await?;
        let Some(payload) = values.into_iter().next().flatten() else {
            return Ok(None);
        };
        let header = self.header(&payload)?;
        if header.migration != migration {
            return Err(Error::IdentityMismatch);
        }
        let proof = self.decode_checkpoint_capsule(&payload, header)?;
        if proof.as_ref().is_none_or(|proof| proof.phase != phase) {
            return Err(Error::Corrupt);
        }
        Ok(proof)
    }

    fn decode_checkpoint_capsule(
        &self,
        payload: &Secret<Vec<u8>>,
        header: Header,
    ) -> Result<Option<Arc<busbar_contract::persistence::lifecycle::ActivationReceipt>>, Error>
    {
        let seal = crate::seal::lend();
        let payload = payload.expose(&seal);
        let capsule = &payload[HEADER..];
        if capsule.len() < 24 || &capsule[..8] != b"BSMPRF01" {
            return Err(Error::Corrupt);
        }
        let length = usize::try_from(u64::from_le_bytes(
            capsule[8..16].try_into().map_err(|_| Error::Corrupt)?,
        ))
        .map_err(|_| Error::Bounds)?;
        let result_length = usize::try_from(u64::from_le_bytes(
            capsule[16..24].try_into().map_err(|_| Error::Corrupt)?,
        ))
        .map_err(|_| Error::Bounds)?;
        let end = 24usize.checked_add(length).ok_or(Error::Bounds)?;
        if end.checked_add(result_length) != Some(capsule.len()) {
            return Err(Error::Corrupt);
        }
        let snapshot = Secret::new(capsule[24..end].to_vec());
        let candidate = self.decode(header.migration, header.operation, &snapshot)?;
        if candidate.fingerprint() != header.fingerprint {
            return Err(Error::Corrupt);
        }
        if candidate.candidate().result.expose(&seal).as_slice() != &capsule[end..] {
            return Err(Error::Corrupt);
        }
        let marker = checkpoint_phase(&candidate, header.migration)?.ok_or(Error::Corrupt)?;
        Ok(Some(Arc::new(
            busbar_contract::persistence::lifecycle::ActivationReceipt {
                attempt: candidate.candidate().id,
                candidate_fingerprint: header.fingerprint,
                original_result: Secret::new(capsule[end..].to_vec()),
                checkpoint_address: marker.checkpoint_address,
                checkpoint_value_digest: marker.checkpoint_value_digest,
                phase: marker.phase,
            },
        )))
    }

    async fn observe(&self, migration: Id) -> Result<Observation, Error> {
        if migration != self.migration {
            return Err(Error::IdentityMismatch);
        }
        if self.backend.info() != self.info {
            return Err(Error::IdentityMismatch);
        }
        let response = self
            .backend
            .read(Arc::new(Read {
                dataset: self.info.dataset,
                addresses: vec![
                    startup::root_address(),
                    startup::writer_address(self.cold.writer),
                    guard_address(migration),
                    payload_address(migration),
                    owner_address(migration),
                ],
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
        if values.len() != 5 || observed_at.authority != self.info.clock_authority {
            return Err(Error::Corrupt);
        }
        let mut values = values.into_iter();
        let root = values.next().flatten().ok_or(Error::FenceRequired)?;
        let writer = values.next().flatten().ok_or(Error::FenceRequired)?;
        let stored_guard = values.next().flatten();
        let payload = values.next().flatten();
        let seal = crate::seal::lend();
        if !values
            .next()
            .flatten()
            .is_some_and(|value| value.expose(&seal) == &self.binding)
        {
            return Err(Error::FenceRequired);
        }
        let dataset = control::Dataset::decode(root.expose(&seal)).ok_or(Error::Corrupt)?;
        let writer_state = control::Writer::decode(writer.expose(&seal)).ok_or(Error::Corrupt)?;
        if dataset.id != self.info.dataset {
            return Err(Error::IdentityMismatch);
        }
        let (header, state) = match (&stored_guard, &payload) {
            (None, None) => (None, 0),
            (Some(guard), Some(payload)) => {
                let bytes = guard.expose(&seal);
                if bytes.len() != GUARD
                    || &bytes[..8] != b"BSMIGD1\0"
                    || bytes[8..24] != migration
                    || !(1..=5).contains(&bytes[40])
                    || bytes[41..].iter().any(|b| *b != 0)
                {
                    return Err(Error::Corrupt);
                }
                let header = self.header(payload)?;
                if header.migration != migration
                    || bytes[24..40] != header.operation
                    || matches!(bytes[40], 1 | 5) != (header.length != 0)
                {
                    return Err(Error::Corrupt);
                }
                if bytes[40] == 1 {
                    let snapshot = Secret::new(payload.expose(&seal)[HEADER..].to_vec());
                    let candidate = self.decode(migration, header.operation, &snapshot)?;
                    if candidate.fingerprint() != header.fingerprint {
                        return Err(Error::Corrupt);
                    }
                    let id = candidate.candidate().id;
                    if header.original
                        != (WriterAuthority {
                            writer_epoch: id.writer_epoch,
                            writer: id.writer,
                            execution_epoch: id.execution_epoch,
                        })
                    {
                        return Err(Error::Corrupt);
                    }
                }
                (Some(header), bytes[40])
            }
            _ => return Err(Error::Corrupt),
        };
        Ok(Observation {
            root,
            epoch: dataset.writer_epoch,
            writer,
            writer_state,
            guard: stored_guard,
            payload,
            header,
            state,
            at: observed_at,
        })
    }

    fn header(&self, payload: &Secret<Vec<u8>>) -> Result<Header, Error> {
        let seal = crate::seal::lend();
        let bytes = payload.expose(&seal);
        if bytes.len() < HEADER
            || bytes.len() > self.budget
            || &bytes[..8] != b"BSMINT1\0"
            || bytes[8..24] != self.info.dataset.0
        {
            return Err(Error::Corrupt);
        }
        let length = usize::try_from(u64::from_le_bytes(
            bytes[120..128].try_into().map_err(|_| Error::Corrupt)?,
        ))
        .map_err(|_| Error::Bounds)?;
        if HEADER.checked_add(length) != Some(bytes.len()) {
            return Err(Error::Corrupt);
        }
        let header = Header {
            migration: bytes[24..40].try_into().map_err(|_| Error::Corrupt)?,
            operation: bytes[40..56].try_into().map_err(|_| Error::Corrupt)?,
            fingerprint: bytes[56..88].try_into().map_err(|_| Error::Corrupt)?,
            prepared_at: ClockObservation {
                authority: bytes[88..104].try_into().map_err(|_| Error::Corrupt)?,
                unix_seconds: u64::from_le_bytes(
                    bytes[104..112].try_into().map_err(|_| Error::Corrupt)?,
                ),
            },
            deadline: u64::from_le_bytes(bytes[112..120].try_into().map_err(|_| Error::Corrupt)?),
            length,
            original: WriterAuthority {
                writer: bytes[128..144].try_into().map_err(|_| Error::Corrupt)?,
                writer_epoch: u64::from_le_bytes(
                    bytes[144..152].try_into().map_err(|_| Error::Corrupt)?,
                ),
                execution_epoch: u64::from_le_bytes(
                    bytes[152..160].try_into().map_err(|_| Error::Corrupt)?,
                ),
            },
        };
        if header.migration == [0; 16]
            || header.operation == [0; 16]
            || header.prepared_at.authority != self.info.clock_authority
            || header.prepared_at.unix_seconds.checked_add(HORIZON) != Some(header.deadline)
            || header.original.writer == [0; 16]
            || header.original.writer == self.cold.writer
            || header.original.writer_epoch == 0
            || header.original.execution_epoch == 0
        {
            return Err(Error::Corrupt);
        }
        Ok(header)
    }

    fn encode(&self, header: Header, snapshot: &[u8]) -> Result<Secret<Vec<u8>>, Error> {
        let length = HEADER.checked_add(snapshot.len()).ok_or(Error::Bounds)?;
        if length > self.budget {
            return Err(Error::Bounds);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.try_reserve_exact(length).map_err(|_| Error::Bounds)?;
        bytes.resize(HEADER, 0);
        bytes[..8].copy_from_slice(b"BSMINT1\0");
        bytes[8..24].copy_from_slice(&self.info.dataset.0);
        bytes[24..40].copy_from_slice(&header.migration);
        bytes[40..56].copy_from_slice(&header.operation);
        bytes[56..88].copy_from_slice(&header.fingerprint);
        bytes[88..104].copy_from_slice(&header.prepared_at.authority);
        bytes[104..112].copy_from_slice(&header.prepared_at.unix_seconds.to_le_bytes());
        bytes[112..120].copy_from_slice(&header.deadline.to_le_bytes());
        bytes[120..128].copy_from_slice(&(snapshot.len() as u64).to_le_bytes());
        bytes[128..144].copy_from_slice(&header.original.writer);
        bytes[144..152].copy_from_slice(&header.original.writer_epoch.to_le_bytes());
        bytes[152..160].copy_from_slice(&header.original.execution_epoch.to_le_bytes());
        bytes.extend_from_slice(snapshot);
        Ok(Secret::new(std::mem::take(&mut *bytes)))
    }

    fn decode(
        &self,
        migration: Id,
        operation: Id,
        snapshot: &Secret<Vec<u8>>,
    ) -> Result<PreparedCandidate, Error> {
        let seal = crate::seal::lend();
        let candidate =
            candidate_codec::decode(snapshot, self.budget, &seal).map_err(|_| Error::Corrupt)?;
        let body = candidate.candidate();
        super::witness::expected(&candidate, migration)?;
        if body.id.dataset != self.info.dataset
            || body.id.operation != operation
            || body.id.writer == self.cold.writer
            || !body.predicates.iter().any(|p| {
                p.address == guard_address(migration)
                    && match &p.expected {
                        ExpectedValue::Exact(value) => {
                            value.expose(&seal).as_slice() == open_guard(migration, operation)
                        }
                        _ => false,
                    }
            })
            || body.mutations.iter().any(|m| match m {
                Mutation::Put { address, .. } | Mutation::Delete(address) => {
                    address.namespace == NAMESPACE
                }
                Mutation::DeleteRange { namespace, .. } => namespace.0 == NAMESPACE,
            })
        {
            return Err(Error::IdentityMismatch);
        }
        Ok(candidate)
    }

    fn prepare(
        &self,
        observed: Observation,
        migration: Id,
        operation: Id,
        state: u8,
        desired_payload: Secret<Vec<u8>>,
        main_authority: Option<Predicate>,
    ) -> Result<Pending, Error> {
        if !observed.writer_state.admits(self.cold.execution_epoch) {
            return Err(Error::FenceRequired);
        }
        let desired_guard = Secret::new(guard(migration, operation, state));
        let exact = |address, value: Option<Secret<Vec<u8>>>| Predicate {
            address,
            expected: value.map_or(ExpectedValue::Absent, ExpectedValue::Exact),
        };
        let mut journal_operation = [0; 16];
        getrandom::fill(&mut journal_operation).map_err(|_| Error::Entropy)?;
        let mut predicates = vec![
            exact(startup::root_address(), Some(observed.root)),
            exact(
                startup::writer_address(self.cold.writer),
                Some(observed.writer),
            ),
            exact(guard_address(migration), observed.guard),
            exact(payload_address(migration), observed.payload),
            exact(
                owner_address(migration),
                Some(Secret::new(self.binding.clone())),
            ),
        ];
        if let Some(authority) = main_authority {
            predicates.push(authority);
        }
        let mut mutations = vec![
            Mutation::Put {
                address: guard_address(migration),
                value: desired_guard.clone(),
            },
            Mutation::Put {
                address: payload_address(migration),
                value: desired_payload.clone(),
            },
        ];
        if state == 5 {
            let proof = self
                .decode_checkpoint_capsule(&desired_payload, self.header(&desired_payload)?)?
                .ok_or(Error::Corrupt)?;
            let address = proof_address(migration, proof.phase);
            predicates.push(Predicate {
                address: address.clone(),
                expected: ExpectedValue::Absent,
            });
            mutations.push(Mutation::Put {
                address,
                value: desired_payload.clone(),
            });
        }
        let candidate = PreparedCandidate::new(Candidate {
            id: AttemptId {
                dataset: self.info.dataset,
                writer_epoch: observed.epoch,
                writer: self.cold.writer,
                execution_epoch: self.cold.execution_epoch,
                operation: journal_operation,
            },
            codec: CANDIDATE_VERSION,
            predicates,
            mutations,
            time: None,
            result: Secret::new(Vec::new()),
        })
        .map_err(|_| Error::Corrupt)?;
        Ok(Pending {
            migration,
            operation,
            state,
            desired_guard,
            desired_payload,
            attempt: Attempt::new(candidate, self.backend.clone())
                .map_err(|_| Error::IdentityMismatch)?,
        })
    }

    async fn drive(&self, pending: &mut Option<Pending>) -> Result<(), Error> {
        let work = pending.as_ref().ok_or(Error::InvalidState)?;
        let observed = self.observe(work.migration).await?;
        if observed.guard.as_ref() == Some(&work.desired_guard)
            && observed.payload.as_ref() == Some(&work.desired_payload)
        {
            *pending = None;
            return Ok(());
        }
        let result = work.attempt.submit().await;
        let observed = self.observe(work.migration).await?;
        if observed.guard.as_ref() == Some(&work.desired_guard)
            && observed.payload.as_ref() == Some(&work.desired_payload)
        {
            *pending = None;
            return Ok(());
        }
        match result {
            SubmitResult::Uncertain | SubmitResult::Busy => Err(Error::IntentPending),
            SubmitResult::Reconcile => Err(Error::ReconciliationRequired),
            SubmitResult::NoEffect(failure) => Err(Error::Backend(failure)),
            SubmitResult::Decided(value) => match value.as_ref() {
                Decision::ConditionConflict => {
                    *pending = None;
                    Err(Error::Conflict)
                }
                _ => Err(Error::ReconciliationRequired),
            },
        }
    }

    async fn values(&self, addresses: Vec<Address>) -> Result<Vec<Option<Secret<Vec<u8>>>>, Error> {
        let count = addresses.len();
        match self
            .backend
            .read(Arc::new(Read {
                dataset: self.info.dataset,
                addresses,
                time: None,
            }))
            .await
            .map_err(Error::Backend)?
        {
            ReadResult::Values {
                observed_at,
                values,
            } if observed_at.authority == self.info.clock_authority && values.len() == count => {
                Ok(values)
            }
            _ => Err(Error::Corrupt),
        }
    }

    async fn main_authority(&self, id: AttemptId) -> Result<Predicate, Error> {
        let address = startup::writer_address(id.writer);
        let values = self.values(vec![address.clone()]).await?;
        let value = values[0].as_ref().ok_or(Error::FenceRequired)?;
        if !control::Writer::decode(value.expose(&crate::seal::lend()))
            .is_some_and(|writer| writer.admits(id.execution_epoch))
        {
            return Err(Error::ReconciliationRequired);
        }
        Ok(Predicate {
            address,
            expected: ExpectedValue::Exact(value.clone()),
        })
    }

    async fn writer_state(&self, writer: Id) -> Result<(control::Writer, Secret<Vec<u8>>), Error> {
        let mut values = self.values(vec![startup::writer_address(writer)]).await?;
        let value = values.pop().flatten().ok_or(Error::FenceRequired)?;
        let state =
            control::Writer::decode(value.expose(&crate::seal::lend())).ok_or(Error::Corrupt)?;
        Ok((state, value))
    }

    async fn transition(
        &self,
        observed: Observation,
        header: Header,
        current: Secret<Vec<u8>>,
        next: control::Writer,
        pending: &mut Option<RecoveryPending>,
    ) -> Result<ReconciliationProgress, Error> {
        if !observed.writer_state.admits(self.cold.execution_epoch) {
            return Err(Error::FenceRequired);
        }
        if let Some(work) = pending.as_ref() {
            if work.operation != header.operation
                || work.writer != header.original.writer
                || work.next != next
            {
                return Err(Error::Conflict);
            }
        } else {
            let mut operation = [0; 16];
            getrandom::fill(&mut operation).map_err(|_| Error::Entropy)?;
            let exact = |address, value| Predicate {
                address,
                expected: ExpectedValue::Exact(value),
            };
            let next_bytes = next.encode().ok_or(Error::Corrupt)?;
            let candidate = PreparedCandidate::new(Candidate {
                id: AttemptId {
                    dataset: self.info.dataset,
                    writer_epoch: observed.epoch,
                    writer: self.cold.writer,
                    execution_epoch: self.cold.execution_epoch,
                    operation,
                },
                codec: CANDIDATE_VERSION,
                predicates: vec![
                    exact(startup::root_address(), observed.root),
                    exact(startup::writer_address(self.cold.writer), observed.writer),
                    exact(
                        owner_address(self.migration),
                        Secret::new(self.binding.clone()),
                    ),
                    exact(
                        guard_address(self.migration),
                        observed.guard.ok_or(Error::Corrupt)?,
                    ),
                    exact(
                        payload_address(self.migration),
                        observed.payload.ok_or(Error::Corrupt)?,
                    ),
                    exact(startup::writer_address(header.original.writer), current),
                ],
                mutations: vec![Mutation::Put {
                    address: startup::writer_address(header.original.writer),
                    value: Secret::new(next_bytes.to_vec()),
                }],
                time: None,
                result: Secret::new(Vec::new()),
            })
            .map_err(|_| Error::Corrupt)?;
            *pending = Some(RecoveryPending {
                operation: header.operation,
                writer: header.original.writer,
                next,
                attempt: Attempt::new(candidate, self.backend.clone())
                    .map_err(|_| Error::IdentityMismatch)?,
            });
        }
        match pending
            .as_ref()
            .ok_or(Error::InvalidState)?
            .attempt
            .submit()
            .await
        {
            SubmitResult::Uncertain | SubmitResult::Busy => Ok(ReconciliationProgress::Pending),
            SubmitResult::Reconcile => Err(Error::ReconciliationRequired),
            SubmitResult::NoEffect(failure) => Err(Error::Backend(failure)),
            SubmitResult::Decided(value) => match value.as_ref() {
                Decision::Applied(_) | Decision::ConditionConflict => {
                    *pending = None;
                    Ok(ReconciliationProgress::Advanced)
                }
                _ => Err(Error::ReconciliationRequired),
            },
        }
    }
}

#[async_trait]
impl IntentStore for StoreIntent {
    async fn reconcile(&self, migration: Id) -> Result<ReconciliationProgress, Error> {
        {
            let mut journal = self.pending.lock().await;
            if journal.is_some() {
                match self.drive(&mut journal).await {
                    Ok(()) => {}
                    Err(Error::IntentPending) => return Ok(ReconciliationProgress::Pending),
                    Err(error) => return Err(error),
                }
            }
        }
        let mut recovery = self.recovery.lock().await;
        let observed = self.observe(migration).await?;
        let Some(header) = observed.header else {
            return Ok(ReconciliationProgress::Resolved);
        };
        let (writer, writer_bytes) = self.writer_state(header.original.writer).await?;
        if observed.epoch < header.original.writer_epoch {
            return Err(Error::Corrupt);
        }
        if observed.state != 1 {
            // The closed record retains the original authority so a crash after
            // closing but before this grant cannot strand the migration.
            if observed.epoch == header.original.writer_epoch
                && !writer.admits(writer.admitted_through)
            {
                let next = control::Writer {
                    admitted_through: writer
                        .admitted_through
                        .checked_add(1)
                        .ok_or(Error::Bounds)?,
                    ..writer
                };
                return self
                    .transition(observed, header, writer_bytes, next, &mut recovery)
                    .await;
            }
            *recovery = None;
            return Ok(ReconciliationProgress::Resolved);
        }
        if observed.epoch == header.original.writer_epoch
            && writer.retired_through < header.original.execution_epoch
        {
            if !writer.admits(header.original.execution_epoch) {
                return Err(Error::Corrupt);
            }
            let next = control::Writer {
                retired_through: header.original.execution_epoch,
                ..writer
            };
            return self
                .transition(observed, header, writer_bytes, next, &mut recovery)
                .await;
        }
        // Root generations and retired execution floors never move backwards.
        // The original candidate now cannot execute for the first time. This
        // direct crossing is solely a receipt lookup; no Attempt/Instant is reset.
        *recovery = None;
        let snapshot = Secret::new(
            observed
                .payload
                .as_ref()
                .ok_or(Error::Corrupt)?
                .expose(&crate::seal::lend())[HEADER..]
                .to_vec(),
        );
        let candidate = self.decode(migration, header.operation, &snapshot)?;
        let marker = super::witness::expected(&candidate, migration)?;
        let decision = self
            .backend
            .commit(candidate.clone())
            .await
            .map_err(Error::Backend)?;
        let mut applied_result = None;
        let kind = match decision {
            Decision::Applied(value) if value == candidate.candidate().result => {
                applied_result = Some(value);
                ResolutionKind::Applied
            }
            Decision::ExpiredUnknown => {
                let generation_address = Address {
                    namespace: control::GENERATION_NAMESPACE.0,
                    key: super::coordinator::NAMESPACE.to_vec(),
                };
                let checkpoint_address = super::coordinator::address(migration);
                let values = self
                    .values(vec![
                        super::witness::address(migration, header.operation),
                        generation_address.clone(),
                        checkpoint_address.clone(),
                    ])
                    .await?;
                match &values[0] {
                    Some(actual) if actual == &marker => ResolutionKind::Applied,
                    Some(_) => return Err(Error::Corrupt),
                    None => {
                        let body = candidate.candidate();
                        let generation = body
                            .predicates
                            .iter()
                            .find(|p| p.address == generation_address);
                        let checkpoint = body
                            .predicates
                            .iter()
                            .find(|p| p.address == checkpoint_address);
                        let matches =
                            |expected: &ExpectedValue, actual: &Option<Secret<Vec<u8>>>| {
                                match expected {
                                    ExpectedValue::Absent => actual.is_none(),
                                    ExpectedValue::Exact(value) => actual.as_ref() == Some(value),
                                }
                            };
                        if !generation.is_some_and(|p| matches(&p.expected, &values[1]))
                            || !checkpoint.is_some_and(|p| matches(&p.expected, &values[2]))
                            || !body.mutations.iter().any(|m| matches!(m, Mutation::Put { address, .. } if *address == checkpoint_address))
                        { return Ok(ReconciliationProgress::Unresolved); }
                        // The original checkpoint bytes AND its native monotonic
                        // namespace generation are unchanged after irreversible
                        // retirement. Any application would atomically advance
                        // that generation, so absence here has ABA protection.
                        ResolutionKind::ProvenNoEffect
                    }
                }
            }
            _ => return Err(Error::ReconciliationRequired),
        };
        let resolution = IntentResolution {
            fingerprint: header.fingerprint,
            kind,
            applied_result,
        };
        match self.clear(migration, header.operation, &resolution).await {
            Ok(()) => Ok(ReconciliationProgress::Advanced),
            Err(Error::IntentPending) => Ok(ReconciliationProgress::Pending),
            Err(error) => Err(error),
        }
    }

    async fn pending(&self, migration: Id) -> Result<bool, Error> {
        if self.pending.lock().await.is_some() {
            return Ok(true);
        }
        Ok(self.observe(migration).await?.state == 1)
    }

    async fn persist(
        &self,
        migration: Id,
        operation: Id,
        snapshot: &Secret<Vec<u8>>,
    ) -> Result<(), Error> {
        let candidate = self.decode(migration, operation, snapshot)?;
        let mut pending = self.pending.lock().await;
        if let Some(work) = pending.as_ref() {
            if work.migration != migration || work.operation != operation || work.state != 1 {
                return Err(Error::Conflict);
            }
            let header = self.header(&work.desired_payload)?;
            if header.fingerprint != candidate.fingerprint() {
                return Err(Error::Conflict);
            }
            return self.drive(&mut pending).await;
        }
        let observed = self.observe(migration).await?;
        if let Some(header) = observed.header {
            if observed.state == 1 {
                let seal = crate::seal::lend();
                return if header.operation == operation
                    && header.fingerprint == candidate.fingerprint()
                    && observed
                        .payload
                        .as_ref()
                        .is_some_and(|p| p.expose(&seal)[HEADER..] == *snapshot.expose(&seal))
                {
                    Ok(())
                } else {
                    Err(Error::Conflict)
                };
            }
            if header.operation == operation {
                return Err(Error::ReconciliationRequired);
            }
        }
        let header = Header {
            migration,
            operation,
            fingerprint: candidate.fingerprint(),
            prepared_at: observed.at,
            deadline: observed
                .at
                .unix_seconds
                .checked_add(HORIZON)
                .ok_or(Error::Bounds)?,
            length: snapshot.expose(&crate::seal::lend()).len(),
            original: WriterAuthority {
                writer_epoch: candidate.candidate().id.writer_epoch,
                writer: candidate.candidate().id.writer,
                execution_epoch: candidate.candidate().id.execution_epoch,
            },
        };
        let payload = self.encode(header, snapshot.expose(&crate::seal::lend()))?;
        if observed.epoch != candidate.candidate().id.writer_epoch {
            return Err(Error::ReconciliationRequired);
        }
        let main_authority = self.main_authority(candidate.candidate().id).await?;
        *pending = Some(self.prepare(
            observed,
            migration,
            operation,
            1,
            payload,
            Some(main_authority),
        )?);
        self.drive(&mut pending).await
    }

    async fn clear(
        &self,
        migration: Id,
        operation: Id,
        resolution: &IntentResolution,
    ) -> Result<(), Error> {
        let state = match resolution.kind {
            ResolutionKind::Applied => 2,
            ResolutionKind::Conflict => 3,
            ResolutionKind::ProvenNoEffect => 4,
        };
        let mut pending = self.pending.lock().await;
        if let Some(work) = pending.as_ref() {
            if work.migration != migration
                || work.operation != operation
                || (work.state != state && !(state == 2 && work.state == 5))
                || self.header(&work.desired_payload)?.fingerprint != resolution.fingerprint
            {
                return Err(Error::Conflict);
            }
            return self.drive(&mut pending).await;
        }
        let observed = self.observe(migration).await?;
        let header = observed.header.ok_or(Error::InvalidState)?;
        if header.operation != operation || header.fingerprint != resolution.fingerprint {
            return Err(Error::Conflict);
        }
        if observed.state == state || (state == 2 && observed.state == 5) {
            return Ok(());
        }
        if observed.state != 1 {
            return Err(Error::Conflict);
        }
        let (state, payload) = if state == 2 {
            let snapshot = Secret::new(
                observed
                    .payload
                    .as_ref()
                    .ok_or(Error::Corrupt)?
                    .expose(&crate::seal::lend())[HEADER..]
                    .to_vec(),
            );
            let candidate = self.decode(migration, operation, &snapshot)?;
            if checkpoint_phase(&candidate, migration)?.is_some() {
                let actual = resolution
                    .applied_result
                    .as_ref()
                    .ok_or(Error::ReconciliationRequired)?;
                let seal = crate::seal::lend();
                let source = snapshot.expose(&seal);
                let result = actual.expose(&seal);
                let length = 24usize
                    .checked_add(source.len())
                    .and_then(|v| v.checked_add(result.len()))
                    .ok_or(Error::Bounds)?;
                if HEADER.checked_add(length).ok_or(Error::Bounds)? > self.budget {
                    return Err(Error::Bounds);
                }
                let mut out = Zeroizing::new(Vec::new());
                out.try_reserve_exact(length).map_err(|_| Error::Bounds)?;
                out.extend_from_slice(b"BSMPRF01");
                out.extend_from_slice(&(source.len() as u64).to_le_bytes());
                out.extend_from_slice(&(result.len() as u64).to_le_bytes());
                out.extend_from_slice(source);
                out.extend_from_slice(result);
                (5, self.encode(header, &out)?)
            } else {
                (state, self.encode(header, &[])?)
            }
        } else {
            (state, self.encode(header, &[])?)
        };
        *pending = Some(self.prepare(observed, migration, operation, state, payload, None)?);
        self.drive(&mut pending).await
    }
}
