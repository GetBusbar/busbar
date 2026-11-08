// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Storage admission, separate from hydration and runtime publication. The owner
//! survives a cancelled waiter; each authority change retains one exact attempt.
//! An incomplete initialization is recovery work, never an empty database.

use std::sync::Arc;

use busbar_contract::persistence::{
    control, Address, AttemptId, Candidate, DatasetId, Decision, ExpectedValue, Failure, Mutation,
    NamespaceId, PersistenceBackend, Predicate, PreparedCandidate, Read, ReadResult,
    CANDIDATE_VERSION,
};
use busbar_contract::Secret;

use super::{
    commit::{Attempt, SubmitResult},
    facade::{AccessError, CoreStore, Limits, WriterAuthority},
    fences,
    first_start::{self, Birth, FirstStart},
};

const NAMESPACE: NamespaceId = NamespaceId(*b"busbar.format1\0\0");
const KEY: &[u8] = b"active";
const FORMAT: u32 = 1;

/// A core format, not a product release or the backend's physical schema.
/// The initial crossing admits exactly one reader/writer format, no guessed range.
#[derive(Clone, Copy)]
pub(crate) struct Manifest {
    pub(crate) dataset: DatasetId,
    pub(crate) registrar: WriterAuthority,
}

impl Manifest {
    pub(crate) fn encode(self) -> [u8; 80] {
        let mut bytes = [0; 80];
        bytes[..8].copy_from_slice(b"BSCFMT1\0");
        for at in [8, 12, 16, 20] {
            bytes[at..at + 4].copy_from_slice(&FORMAT.to_le_bytes());
        }
        bytes[24..40].copy_from_slice(&self.dataset.0);
        bytes[40..48].copy_from_slice(&self.registrar.writer_epoch.to_le_bytes());
        bytes[48..64].copy_from_slice(&self.registrar.writer);
        bytes[64..72].copy_from_slice(&self.registrar.execution_epoch.to_le_bytes());
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 80 || &bytes[..8] != b"BSCFMT1\0" {
            return Err(Error::UnsupportedFormat);
        }
        for at in [8, 12, 16, 20] {
            if bytes[at..at + 4] != FORMAT.to_le_bytes() {
                return Err(Error::UnsupportedFormat);
            }
        }
        if bytes[72..].iter().any(|byte| *byte != 0) {
            return Err(Error::UnsupportedFormat);
        }
        let value = Self {
            dataset: DatasetId(bytes[24..40].try_into().map_err(|_| Error::Corrupt)?),
            registrar: WriterAuthority {
                writer_epoch: u64::from_le_bytes(
                    bytes[40..48].try_into().map_err(|_| Error::Corrupt)?,
                ),
                writer: bytes[48..64].try_into().map_err(|_| Error::Corrupt)?,
                execution_epoch: u64::from_le_bytes(
                    bytes[64..72].try_into().map_err(|_| Error::Corrupt)?,
                ),
            },
        };
        if value.dataset.0 == [0; 16]
            || value.registrar.writer == [0; 16]
            || value.registrar.writer_epoch == 0
            || value.registrar.execution_epoch == 0
        {
            return Err(Error::Corrupt);
        }
        Ok(value)
    }
}

/// Content-free startup failure; unknown outcomes remain held by this owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    UnsupportedFormat,
    IncompleteInitialization,
    InitializationNotAllowed,
    Corrupt,
    Authority,
    Entropy,
    Conflict,
    PendingWork,
    EpochExhausted,
    NotAdmitted,
    Backend(Failure),
    Access(AccessError),
}

/// One bounded step. `Admitted` means storage only: recovery/hydration must still
/// succeed before the composition root can publish a serving runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    Advanced,
    /// A retained native attempt is still uncertain or busy.
    Pending,
    /// Old business attempts must be resolved by their semantic owners.
    Draining,
    Reconcile,
    Admitted,
    Retired,
}

#[derive(Clone)]
enum Phase {
    Inspect,
    Initialize(Arc<Attempt>),
    Register(Manifest, WriterAuthority, Option<Birth>, Arc<Attempt>),
    Attach(Manifest, WriterAuthority, Option<Birth>),
    Admitted(Session),
    Grant(Session, WriterAuthority, control::Writer, Arc<Attempt>),
    Drain(Session),
    RetireEpoch(Session, control::Writer, Arc<Attempt>),
    Retiring(Arc<Attempt>),
    Retired,
}

/// The last confirmed writer control value stays with this process session.
#[derive(Clone)]
struct Session {
    manifest: Manifest,
    store: Arc<CoreStore>,
    writer: control::Writer,
}

/// Retain this owner across retries and reload. No backend handle is exposed to
/// business callers. The persistent registrar is for admission/retirement only;
/// every admitted process receives an independent never-reused writer identity.
pub struct Startup {
    backend: Arc<dyn PersistenceBackend>,
    limits: Limits,
    initialize_empty: bool,
    phase: Phase,
}

impl Startup {
    pub fn new(
        backend: Arc<dyn PersistenceBackend>,
        limits: Limits,
        initialize_empty: bool,
    ) -> Result<Self, Error> {
        let info = backend.info();
        if info.dataset.0 == [0; 16]
            || info.atomic_domain == [0; 16]
            || info.clock_authority == [0; 16]
        {
            return Err(Error::Authority);
        }
        if limits.pending_operations == 0 || limits.scan_items == 0 || limits.scan_bytes == 0 {
            return Err(Error::Access(AccessError::InvalidLimits));
        }
        Ok(Self {
            backend,
            limits,
            initialize_empty,
            phase: Phase::Inspect,
        })
    }

    /// No hidden retry loop. Install custody before crossing; dropping this
    /// future never drops an initialized, published or registered attempt.
    pub async fn advance(&mut self) -> Result<Progress, Error> {
        match self.phase.clone() {
            Phase::Inspect => self.inspect().await?,
            Phase::Initialize(attempt) => {
                if let Some(progress) = decided(&attempt).await? {
                    return Ok(progress);
                }
                self.phase = Phase::Inspect;
            }
            Phase::Register(manifest, authority, birth, attempt) => {
                if let Some(progress) = decided(&attempt).await? {
                    return Ok(progress);
                }
                self.phase = Phase::Attach(manifest, authority, birth);
            }
            Phase::Attach(manifest, authority, birth) => {
                let store = CoreStore::attach(self.backend.clone(), authority, self.limits)
                    .await
                    .map_err(Error::Access)?;
                if let Some(birth) = birth {
                    store
                        .first_start
                        .set(Arc::new(FirstStart::new(
                            self.backend.clone(),
                            authority,
                            birth,
                        )))
                        .map_err(|_| Error::Authority)?;
                }
                self.phase = Phase::Admitted(Session {
                    manifest,
                    store: Arc::new(store),
                    writer: open_writer(),
                });
                return Ok(Progress::Admitted);
            }
            Phase::Admitted(..) => return Ok(Progress::Admitted),
            Phase::Grant(mut session, authority, writer, attempt) => {
                if let Some(progress) = decided(&attempt).await? {
                    return Ok(progress);
                }
                session
                    .store
                    .promote_authority(authority)
                    .map_err(Error::Access)?;
                session.writer = writer;
                self.phase = Phase::Drain(session);
            }
            Phase::Drain(session) => {
                let through = session.writer.admitted_through - 1;
                if !session
                    .store
                    .epoch_drained(through)
                    .map_err(Error::Access)?
                {
                    return Ok(Progress::Draining);
                }
                let writer = control::Writer {
                    retired_through: through,
                    ..session.writer
                };
                let candidate = writer_transition(&session, writer)?;
                self.phase = Phase::RetireEpoch(session, writer, self.attempt(candidate)?);
            }
            Phase::RetireEpoch(mut session, writer, attempt) => {
                if let Some(progress) = decided(&attempt).await? {
                    return Ok(progress);
                }
                session.writer = writer;
                self.phase = Phase::Admitted(session);
                return Ok(Progress::Admitted);
            }
            Phase::Retiring(attempt) => {
                if let Some(progress) = decided(&attempt).await? {
                    return Ok(progress);
                }
                self.phase = Phase::Retired;
                return Ok(Progress::Retired);
            }
            Phase::Retired => return Ok(Progress::Retired),
        }
        Ok(Progress::Advanced)
    }

    /// Available only after confirmed registration and validated attachment.
    pub fn store(&self) -> Option<Arc<CoreStore>> {
        match &self.phase {
            Phase::Admitted(session)
            | Phase::Grant(session, ..)
            | Phase::Drain(session)
            | Phase::RetireEpoch(session, ..) => Some(session.store.clone()),
            _ => None,
        }
    }

    /// Admit one new execution epoch on the existing writer and backend. The
    /// exact registrar attempt is retained before crossing; advance performs each
    /// grant, promotion, drain observation and retirement as a bounded step.
    pub fn begin_epoch_roll(&mut self) -> Result<(), Error> {
        let Phase::Admitted(session) = &self.phase else {
            return Err(Error::NotAdmitted);
        };
        let current = session.store.authority().map_err(Error::Access)?;
        let epoch = current
            .execution_epoch
            .checked_add(1)
            .ok_or(Error::EpochExhausted)?;
        let authority = WriterAuthority {
            execution_epoch: epoch,
            ..current
        };
        let writer = control::Writer {
            admitted_through: epoch,
            ..session.writer
        };
        let candidate = writer_transition(session, writer)?;
        self.phase = Phase::Grant(session.clone(), authority, writer, self.attempt(candidate)?);
        Ok(())
    }

    /// Stop local admissions before preparing durable retirement. Unresolved
    /// work remains recoverable through the existing CoreStore handle; it is not
    /// evicted to force shutdown. Finish any active roll before retiring.
    pub fn begin_retirement(&mut self) -> Result<(), Error> {
        let Phase::Admitted(session) = &self.phase else {
            return Err(Error::NotAdmitted);
        };
        if !session
            .store
            .stop_admission()
            .map_err(Error::Access)?
            .is_empty()
        {
            return Err(Error::PendingWork);
        }
        let writer = control::Writer {
            retired_through: session.writer.admitted_through,
            ..session.writer
        };
        let candidate = writer_transition(session, writer)?;
        self.phase = Phase::Retiring(self.attempt(candidate)?);
        Ok(())
    }

    async fn inspect(&mut self) -> Result<(), Error> {
        let info = self.backend.info();
        let values = self
            .read(vec![
                root_address(),
                manifest_address(),
                first_start::address(),
            ])
            .await?;
        let seal = crate::seal::lend();
        match (&values[0], &values[1]) {
            (None, None) => {
                if values[2].is_some() {
                    return Err(Error::Corrupt);
                }
                if !self.initialize_empty {
                    return Err(Error::InitializationNotAllowed);
                }
                let manifest = Manifest {
                    dataset: info.dataset,
                    registrar: WriterAuthority {
                        writer_epoch: 1,
                        writer: random_id()?,
                        execution_epoch: 1,
                    },
                };
                let candidate = fences::initialize_with_records(
                    info.dataset,
                    manifest.registrar.writer,
                    random_id()?,
                    vec![
                        (manifest_address(), Secret::new(manifest.encode().to_vec())),
                        (
                            first_start::address(),
                            Secret::new(Birth::new(info.dataset).encode()?),
                        ),
                    ],
                )
                .map_err(|_| Error::Corrupt)?;
                // The adapter proves the whole dataset empty at COMMIT. Authority
                // and its current-format manifest become visible in that same commit.
                self.phase = Phase::Initialize(self.attempt(candidate)?);
            }
            (Some(_), None) => return Err(Error::IncompleteInitialization),
            (None, Some(_)) => return Err(Error::Corrupt),
            (Some(root_bytes), Some(bytes)) => {
                let manifest = Manifest::decode(bytes.expose(&seal))?;
                if manifest.dataset != info.dataset
                    || control::Dataset::decode(root_bytes.expose(&seal)) != Some(root(manifest))
                {
                    return Err(Error::Authority);
                }
                let observed = self
                    .read(vec![writer_address(manifest.registrar.writer)])
                    .await?;
                let registrar = observed[0]
                    .as_ref()
                    .and_then(|value| control::Writer::decode(value.expose(&seal)))
                    .ok_or(Error::Corrupt)?;
                if !registrar.admits(manifest.registrar.execution_epoch) {
                    return Err(Error::Authority);
                }
                let authority = WriterAuthority {
                    writer: random_id()?,
                    execution_epoch: 1,
                    writer_epoch: manifest.registrar.writer_epoch,
                };
                let mut birth = values[2]
                    .as_ref()
                    .map(|bytes| Birth::decode(bytes.expose(&seal), info.dataset))
                    .transpose()?;
                let mut predicates = vec![
                    exact(root_address(), root_bytes.expose(&seal).clone()),
                    exact(manifest_address(), bytes.expose(&seal).clone()),
                    exact(
                        writer_address(manifest.registrar.writer),
                        registrar.encode().ok_or(Error::Corrupt)?.to_vec(),
                    ),
                    Predicate {
                        address: writer_address(authority.writer),
                        expected: ExpectedValue::Absent,
                    },
                ];
                let mut mutations = vec![Mutation::Put {
                    address: writer_address(authority.writer),
                    value: Secret::new(open_writer().encode().ok_or(Error::Corrupt)?.to_vec()),
                }];
                if let Some(pending) = birth.as_mut().filter(|birth| !birth.published) {
                    predicates.push(exact(first_start::address(), pending.encode()?));
                    if let Some(previous) = pending.owner {
                        if previous == manifest.registrar.writer {
                            return Err(Error::Corrupt);
                        }
                        let observed = self.read(vec![writer_address(previous)]).await?;
                        let bytes = observed[0].as_ref().ok_or(Error::Corrupt)?.expose(&seal);
                        let prior = control::Writer::decode(bytes).ok_or(Error::Corrupt)?;
                        let retired = control::Writer {
                            retired_through: prior.admitted_through,
                            ..prior
                        };
                        control::replacement(
                            control::Key::Writer(previous),
                            info.dataset,
                            Some(bytes),
                            &retired.encode().ok_or(Error::Corrupt)?,
                        )
                        .map_err(|_| Error::Authority)?;
                        predicates.push(exact(writer_address(previous), bytes.clone()));
                        mutations.push(Mutation::Put {
                            address: writer_address(previous),
                            value: Secret::new(retired.encode().ok_or(Error::Corrupt)?.to_vec()),
                        });
                    }
                    pending.owner = Some(authority.writer);
                    mutations.push(Mutation::Put {
                        address: first_start::address(),
                        value: Secret::new(pending.encode()?),
                    });
                } else {
                    // Publication already completed, or this retained format predates the
                    // native birth proof. Neither can mint initial-record authority.
                    birth = None;
                }
                let candidate = prepare(manifest, predicates, mutations)?;
                self.phase = Phase::Register(manifest, authority, birth, self.attempt(candidate)?);
            }
        }
        Ok(())
    }

    async fn read(&self, addresses: Vec<Address>) -> Result<Vec<Option<Secret<Vec<u8>>>>, Error> {
        let count = addresses.len();
        let observed = self
            .backend
            .read(Arc::new(Read {
                dataset: self.backend.info().dataset,
                addresses,
                time: None,
            }))
            .await
            .map_err(Error::Backend)?;
        match observed {
            ReadResult::Values {
                observed_at,
                values,
            } if observed_at.authority == self.backend.info().clock_authority
                && values.len() == count =>
            {
                Ok(values)
            }
            _ => Err(Error::Corrupt),
        }
    }

    fn attempt(&self, candidate: PreparedCandidate) -> Result<Arc<Attempt>, Error> {
        Attempt::new(candidate, self.backend.clone())
            .map(Arc::new)
            .map_err(|_| Error::Authority)
    }
}

fn writer_transition(session: &Session, next: control::Writer) -> Result<PreparedCandidate, Error> {
    let authority = session.store.authority().map_err(Error::Access)?;
    prepare(
        session.manifest,
        vec![
            exact(manifest_address(), session.manifest.encode().to_vec()),
            exact(
                writer_address(authority.writer),
                session.writer.encode().ok_or(Error::Corrupt)?.to_vec(),
            ),
        ],
        vec![Mutation::Put {
            address: writer_address(authority.writer),
            value: Secret::new(next.encode().ok_or(Error::Corrupt)?.to_vec()),
        }],
    )
}

pub(super) async fn decided(attempt: &Attempt) -> Result<Option<Progress>, Error> {
    match attempt.submit().await {
        SubmitResult::Decided(value) => match value.as_ref() {
            Decision::Applied(_) => Ok(None),
            Decision::ConditionConflict => Err(Error::Conflict),
            _ => Err(Error::Authority),
        },
        SubmitResult::NoEffect(failure) => Err(Error::Backend(failure)),
        SubmitResult::Uncertain | SubmitResult::Busy => Ok(Some(Progress::Pending)),
        SubmitResult::Reconcile => Ok(Some(Progress::Reconcile)),
    }
}

fn prepare(
    manifest: Manifest,
    predicates: Vec<Predicate>,
    mutations: Vec<Mutation>,
) -> Result<PreparedCandidate, Error> {
    PreparedCandidate::new(Candidate {
        id: AttemptId {
            dataset: manifest.dataset,
            writer_epoch: manifest.registrar.writer_epoch,
            writer: manifest.registrar.writer,
            execution_epoch: manifest.registrar.execution_epoch,
            operation: random_id()?,
        },
        codec: CANDIDATE_VERSION,
        predicates,
        mutations,
        time: None,
        result: Secret::new(Vec::new()),
    })
    .map_err(|_| Error::Corrupt)
}
pub(super) fn random_id() -> Result<[u8; 16], Error> {
    let mut value = [0; 16];
    getrandom::fill(&mut value).map_err(|_| Error::Entropy)?;
    if value == [0; 16] {
        return Err(Error::Entropy);
    }
    Ok(value)
}
pub(crate) fn manifest_address() -> Address {
    Address {
        namespace: NAMESPACE.0,
        key: KEY.to_vec(),
    }
}
pub(crate) fn root_address() -> Address {
    Address {
        namespace: control::NAMESPACE.0,
        key: control::DATASET_KEY.to_vec(),
    }
}
pub(crate) fn writer_address(writer: [u8; 16]) -> Address {
    Address {
        namespace: control::NAMESPACE.0,
        key: control::writer_key(writer).to_vec(),
    }
}
fn exact(address: Address, value: Vec<u8>) -> Predicate {
    Predicate {
        address,
        expected: ExpectedValue::Exact(Secret::new(value)),
    }
}
fn root(manifest: Manifest) -> control::Dataset {
    control::Dataset {
        id: manifest.dataset,
        writer_epoch: manifest.registrar.writer_epoch,
    }
}
fn open_writer() -> control::Writer {
    control::Writer {
        retired_through: 0,
        admitted_through: 1,
    }
}

#[cfg(test)]
#[path = "startup_tests.rs"]
mod tests;
