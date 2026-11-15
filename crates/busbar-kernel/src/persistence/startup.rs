// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Storage admission, separate from hydration and runtime publication. The owner
//! survives a cancelled waiter; each authority change retains one exact attempt.
//! An incomplete initialization is recovery work, never an empty database.

use std::sync::Arc;
use std::time::Duration;

use crate::hashing::Sha256;
use busbar_contract::persistence::{
    control, witness, Address, AttemptId, Candidate, DatasetId, Decision, ExpectedValue, Failure,
    Mutation, NamespaceId, PersistenceBackend, Predicate, PreparedCandidate, Read, ReadResult,
    CANDIDATE_VERSION, MAX_SLOTS,
};
use busbar_contract::Secret;
use tokio::time::Instant;

use super::{
    commit::{Attempt, SubmitResult},
    facade::{AccessError, CoreStore, Limits, WriterAuthority},
    fences,
    first_start::{self, Birth, FirstStart},
};
use crate::diagnostics::{diag_error, FIRST_START_TAKEOVER, FIRST_START_TAKEOVER_UNCONFIRMED};

const NAMESPACE: NamespaceId = witness::FORMAT_NAMESPACE;
const KEY: &[u8] = b"active";
const FORMAT: u32 = 1;

/// Base stall window: longer than the longest legitimate gap between two progress writes of an
/// owner that resumes nothing: one READY plus margin for opens, driver builds and the
/// admission-to-freeze gap (FIRST-START-TAKEOVER §2.3).
pub const FIRST_START_STALL: Duration = Duration::from_secs(90);
/// One READY as the host bounds it: READY_DEADLINE 30 s + CANCEL_GRACE 5 s (plugin-loader
/// `dispatch/ready.rs`). The binary pins `READY_STEP >= READY_DEADLINE + CANCEL_GRACE`.
pub const READY_STEP: Duration = Duration::from_secs(35);
/// G, the assumed bound on Register -> `freeze` (no code bound; `FIRST_START_SLOW_STEP` sees it).
const REGISTER_TO_FREEZE: Duration = Duration::from_secs(55);

/// The window for the observed birth record. A resumed owner runs READY, writing nothing, for
/// every plane already done before its first real write, so each adds one READY_STEP.
pub(super) fn stall_window(birth: &Birth) -> Duration {
    let done = u32::try_from(birth.done_len()).unwrap_or(u32::MAX);
    FIRST_START_STALL.saturating_add(READY_STEP.saturating_mul(done))
}

/// The longest one process can legitimately spend before binding its listener while it waits on
/// a first start over `planes` conditional-records planes: the owner progresses for G + P READYs,
/// stalls for one window, then this process runs its own resumed first start (200 + 105P s).
/// It excludes M, the one-time migration time of a 1.5.5 upgrade boot (§2.6).
pub fn first_start_probe_floor(planes: u32) -> Duration {
    let readies = READY_STEP.saturating_mul(planes);
    let owner = REGISTER_TO_FREEZE.saturating_add(readies);
    owner
        .saturating_add(FIRST_START_STALL.saturating_add(readies))
        .saturating_add(owner)
}

/// The progress rows of a first-start owner as last observed, and when they last changed.
#[derive(Clone, Copy)]
struct Stall {
    observed: [u8; 32],
    since: Instant,
    owner: [u8; 16],
    window: Duration,
}

/// What a waiting `Startup` waits on, for the boot wait line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Waiting {
    pub owner: [u8; 16],
    pub since_change: Duration,
    pub window: Duration,
}

/// Facts of a takeover candidate, carried beside its attempt. Copied, never re-read.
#[derive(Clone)]
struct Takeover {
    dataset: DatasetId,
    previous: [u8; 16],
    observed: [u8; 32],
    stall: Duration,
    window: Duration,
    done_len: usize,
}

/// SHA-256 over the progress rows: birth record, the owner's writer row, core's R0 progress row.
fn progress_digest(birth: &[u8], writer: &[u8], r0: Option<&[u8]>) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update((birth.len() as u64).to_le_bytes());
    hash.update(birth);
    hash.update((writer.len() as u64).to_le_bytes());
    hash.update(writer);
    match r0 {
        None => hash.update([0]),
        Some(bytes) => {
            hash.update([1]);
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        }
    }
    hash.finalize()
}

/// Lower-case hex of a writer id, as the boot wait line prints it (32 hex digits).
pub fn writer_hex(id: &[u8; 16]) -> String {
    hex(id)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn takeover_applied(t: &Takeover, writer: [u8; 16]) {
    diag_error!(
        FIRST_START_TAKEOVER,
        dataset = %hex(&t.dataset.0),
        previous = %writer_hex(&t.previous),
        new_writer = %writer_hex(&writer),
        stall_ms = u64::try_from(t.stall.as_millis()).unwrap_or(u64::MAX),
        window_s = t.window.as_secs(),
        done = t.done_len,
        observed = %hex(&t.observed),
        "took over this dataset's first start from writer {}: no progress for {} s (window {} s)",
        writer_hex(&t.previous),
        t.stall.as_secs(),
        t.window.as_secs(),
    );
}

enum Outcome<'a> {
    Unknown,
    Refused(&'a Error),
}

fn takeover_unconfirmed(t: &Takeover, writer: [u8; 16], outcome: Outcome<'_>) {
    let outcome = match outcome {
        Outcome::Unknown => format!(
            "outcome unknown; writer {} may have been retired",
            writer_hex(&t.previous)
        ),
        Outcome::Refused(error) => format!("refused: {error:?}"),
    };
    diag_error!(
        FIRST_START_TAKEOVER_UNCONFIRMED,
        dataset = %hex(&t.dataset.0),
        previous = %writer_hex(&t.previous),
        new_writer = %writer_hex(&writer),
        stall_ms = u64::try_from(t.stall.as_millis()).unwrap_or(u64::MAX),
        window_s = t.window.as_secs(),
        done = t.done_len,
        observed = %hex(&t.observed),
        outcome = %outcome,
        "first start takeover of writer {} not confirmed: {outcome}",
        writer_hex(&t.previous),
    );
}

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

    /// Once per open; pinned so the migrate-size job finds it (MIGRATE-ON-BOOT §7 †).
    #[cold]
    #[inline(never)]
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
    Register(
        Manifest,
        WriterAuthority,
        Option<Birth>,
        Arc<Attempt>,
        Option<Takeover>,
    ),
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
    /// The first-start owner's progress rows as last observed (FIRST-START-TAKEOVER §2.1).
    stall: Option<Stall>,
    /// Definitive CAS losses of Initialize or Register, bounded by `limits.conflict_retries`
    /// (STORE-TRANSACTIONS §2.3, FIRST-START-TAKEOVER §2.5).
    lost: usize,
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
        if limits.pending_operations == 0
            || limits.pending_operations > MAX_SLOTS as usize
            || limits.scan_items == 0
            || limits.scan_bytes == 0
        {
            return Err(Error::Access(AccessError::InvalidLimits));
        }
        Ok(Self {
            backend,
            limits,
            initialize_empty,
            phase: Phase::Inspect,
            stall: None,
            lost: 0,
        })
    }

    /// No hidden retry loop. Install custody before crossing; dropping this
    /// future never drops an initialized, published or registered attempt.
    pub async fn advance(&mut self) -> Result<Progress, Error> {
        match self.phase.clone() {
            Phase::Inspect => {
                if let Some(progress) = self.inspect().await? {
                    return Ok(progress);
                }
            }
            Phase::Initialize(attempt) => {
                // A definitive loss (a peer initialized first) re-inspects; the lost
                // candidate can never apply (readback rows d/e are final).
                let result = attempt.submit().await;
                if is_loss(&result, true) {
                    return self.lose();
                }
                if let Some(progress) = settle(result)? {
                    return Ok(progress);
                }
                self.phase = Phase::Inspect;
            }
            Phase::Register(manifest, authority, birth, attempt, takeover) => {
                let result = attempt.submit().await;
                // A decided CONDITION_CONFLICT applied nothing: re-inspect (§2.5), bounded by
                // `conflict_retries` (STORE-TRANSACTIONS §2.3).
                if is_loss(&result, false) {
                    if let Some(t) = &takeover {
                        tracing::debug!(
                            previous = %writer_hex(&t.previous),
                            "first start takeover lost to a concurrent write; re-inspecting"
                        );
                    }
                    return self.lose();
                }
                match settle(result) {
                    Err(error) => {
                        if let Some(t) = &takeover {
                            takeover_unconfirmed(t, authority.writer, Outcome::Refused(&error));
                        }
                        return Err(error);
                    }
                    Ok(Some(Progress::Reconcile)) => {
                        if let Some(t) = &takeover {
                            takeover_unconfirmed(t, authority.writer, Outcome::Unknown);
                        }
                        return Ok(Progress::Reconcile);
                    }
                    // Pending: the same attempt and its facts are resubmitted next advance.
                    Ok(Some(progress)) => return Ok(progress),
                    Ok(None) => {
                        if let Some(t) = &takeover {
                            takeover_applied(t, authority.writer);
                        }
                        self.stall = None;
                        self.phase = Phase::Attach(manifest, authority, birth);
                    }
                }
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

    /// The first-start owner this `Startup` is waiting on, while its last advance answered
    /// `Pending` for an owner whose progress rows have not stalled for the window yet.
    pub fn waiting_on(&self) -> Option<Waiting> {
        if !matches!(self.phase, Phase::Inspect) {
            return None;
        }
        self.stall.map(|stall| Waiting {
            owner: stall.owner,
            since_change: stall.since.elapsed(),
            window: stall.window,
        })
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

    /// One read of the dataset's authority rows. `Some(Pending)` while a live first-start owner
    /// is making progress (FIRST-START-TAKEOVER §2.1); otherwise the next phase is set.
    async fn inspect(&mut self) -> Result<Option<Progress>, Error> {
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
                // A FENCED Initialize that left no dataset root was not a peer's win: the
                // dataset holds foreign rows, which the store refuses to initialize.
                if self.lost > 0 {
                    return Err(Error::Backend(Failure::Refused));
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
                let mut takeover = None;
                let mut waiting = false;
                if let Some(pending) = birth.as_mut().filter(|birth| !birth.published) {
                    let birth_bytes = pending.encode()?;
                    predicates.push(exact(first_start::address(), birth_bytes.clone()));
                    if let Some(previous) = pending.owner {
                        if previous == manifest.registrar.writer {
                            return Err(Error::Corrupt);
                        }
                        let observed = self
                            .read(vec![
                                writer_address(previous),
                                first_start::r0_progress_address(),
                            ])
                            .await?;
                        let bytes = observed[0].as_ref().ok_or(Error::Corrupt)?.expose(&seal);
                        let prior = control::Writer::decode(bytes).ok_or(Error::Corrupt)?;
                        let r0 = observed[1].as_ref().map(|value| value.expose(&seal));
                        if prior.retired_through == prior.admitted_through {
                            // The owner can no longer write: it handed over on exit (§2.7) or
                            // was retired. Take ownership now; nothing is left to retire.
                            self.stall = None;
                            predicates.push(exact(writer_address(previous), bytes.clone()));
                        } else {
                            let digest =
                                progress_digest(&birth_bytes, bytes, r0.map(Vec::as_slice));
                            let now = Instant::now();
                            let window = stall_window(pending);
                            let seen = self.stall.filter(|stall| stall.observed == digest);
                            let since = match seen {
                                Some(stall) => stall.since,
                                None => {
                                    self.stall = Some(Stall {
                                        observed: digest,
                                        since: now,
                                        owner: previous,
                                        window,
                                    });
                                    now
                                }
                            };
                            let stalled = now.duration_since(since);
                            if stalled < window {
                                waiting = true;
                            } else {
                                // Unchanged for the whole window: retire the owner under exact
                                // predicates on every progress row, so a late write makes this
                                // Register lose. Audited only when it applies (§2.5).
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
                                predicates.push(match r0 {
                                    Some(value) => {
                                        exact(first_start::r0_progress_address(), value.clone())
                                    }
                                    None => Predicate {
                                        address: first_start::r0_progress_address(),
                                        expected: ExpectedValue::Absent,
                                    },
                                });
                                mutations.push(Mutation::Put {
                                    address: writer_address(previous),
                                    value: Secret::new(
                                        retired.encode().ok_or(Error::Corrupt)?.to_vec(),
                                    ),
                                });
                                takeover = Some(Takeover {
                                    dataset: info.dataset,
                                    previous,
                                    observed: digest,
                                    stall: stalled,
                                    window,
                                    done_len: pending.done_len(),
                                });
                            }
                        }
                    } else {
                        self.stall = None;
                    }
                    pending.owner = Some(authority.writer);
                    mutations.push(Mutation::Put {
                        address: first_start::address(),
                        value: Secret::new(pending.encode()?),
                    });
                } else {
                    // Publication already completed, or this retained format predates the
                    // native birth proof. Neither can mint initial-record authority.
                    self.stall = None;
                    birth = None;
                }
                if waiting {
                    return Ok(Some(Progress::Pending));
                }
                let candidate = prepare(manifest, predicates, mutations)?;
                self.phase = Phase::Register(
                    manifest,
                    authority,
                    birth,
                    self.attempt(candidate)?,
                    takeover,
                );
            }
        }
        Ok(None)
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

    /// Every Startup commit is self-fenced: Initialize and Register by their fresh
    /// writer row (A), writer transitions by the writer row (E).
    fn attempt(&self, candidate: PreparedCandidate) -> Result<Arc<Attempt>, Error> {
        Attempt::proven(candidate, self.backend.clone())
            .map(Arc::new)
            .map_err(|_| Error::Authority)
    }

    fn lose(&mut self) -> Result<Progress, Error> {
        self.lost += 1;
        if self.lost > self.limits.conflict_retries {
            return Err(Error::Conflict);
        }
        self.phase = Phase::Inspect;
        Ok(Progress::Advanced)
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
    settle(attempt.submit().await)
}

/// A definitive CAS loss: a peer's commit won, so this candidate never applies.
/// A FENCED Register means the registrar is retired, which stays `Err(Authority)`.
fn is_loss(result: &SubmitResult, initialize: bool) -> bool {
    matches!(result, SubmitResult::Decided(decision) if matches!(
        decision.as_ref(),
        Decision::ConditionConflict
    ) || (initialize && matches!(decision.as_ref(), Decision::Fenced)))
}

fn settle(result: SubmitResult) -> Result<Option<Progress>, Error> {
    match result {
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

pub(super) fn prepare(
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
    busbar_contract::crypto::fill(&mut value).map_err(|_| Error::Entropy)?;
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
pub(super) fn exact(address: Address, value: Vec<u8>) -> Predicate {
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
