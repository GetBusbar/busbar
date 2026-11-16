// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Finite record initialization, rooted in the adapter's atomic empty-dataset admission.
//! Neither missing business rows nor a principal/durability label can create this authority.

use std::sync::Arc;
use std::time::Duration;

use busbar_contract::persistence::{
    control, Address, AttemptId, Candidate, DatasetId, ExpectedValue, Mutation, NamespaceId,
    PersistenceBackend, Predicate, PreparedCandidate, Read, ReadResult, CANDIDATE_VERSION,
};
use busbar_contract::Secret;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::Instant;

use super::{commit::Attempt, facade::WriterAuthority, startup};
use crate::diagnostics::{diag_warn, FIRST_START_SLOW_STEP};

const NAMESPACE: NamespaceId = busbar_contract::persistence::witness::BIRTH_NAMESPACE;

/// A gap between two progress writes, outside READY, longer than this is reported (§2.3).
const SLOW_STEP: Duration = Duration::from_secs(45);

/// Core's R0 progress row (FIRST-START-TAKEOVER §2.9 (c)): present only while an R0 import runs,
/// Put by every R0 commit with `pages + 1` and deleted by the final one, so each R0 commit is a
/// progress write a waiter observes. A fixed binary layout like `control::Writer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct R0Progress {
    pub version: u32,
    pub pages: u64,
    /// MIGRATE-ON-BOOT's paged pre-check cursor; its inner layout is MIGRATE's.
    pub cursor: Vec<u8>,
}

const R0_MAGIC: &[u8; 8] = b"bbr0prg1";
const R0_VERSION: u32 = 1;
const R0_CURSOR_MAX: usize = 1 << 20;

impl R0Progress {
    /// Magic, `version` u32 LE, `pages` u64 LE, `cursor` length u32 LE and its bytes.
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        if self.version != R0_VERSION || self.cursor.len() > R0_CURSOR_MAX {
            return None;
        }
        let mut bytes = Vec::with_capacity(24 + self.cursor.len());
        bytes.extend_from_slice(R0_MAGIC);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.pages.to_le_bytes());
        bytes.extend_from_slice(&u32::try_from(self.cursor.len()).ok()?.to_le_bytes());
        bytes.extend_from_slice(&self.cursor);
        Some(bytes)
    }

    /// Refuses a wrong magic, an unknown version, and a short or over-long buffer.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 24 || &bytes[..8] != R0_MAGIC {
            return None;
        }
        let version = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
        if version != R0_VERSION {
            return None;
        }
        let pages = u64::from_le_bytes(bytes[12..20].try_into().ok()?);
        let len = usize::try_from(u32::from_le_bytes(bytes[20..24].try_into().ok()?)).ok()?;
        if len > R0_CURSOR_MAX || bytes.len() != 24 + len {
            return None;
        }
        Some(Self {
            version,
            pages,
            cursor: bytes[24..].to_vec(),
        })
    }
}

/// The address of core's R0 progress row, beside the birth record in the first-start namespace.
#[must_use]
pub fn r0_progress_address() -> Address {
    Address {
        namespace: NAMESPACE.0,
        key: b"r0-progress".to_vec(),
    }
}

/// The selected initial instance and its exact admitted plugin/configuration digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub instance: String,
    pub digest: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Birth {
    version: u32,
    dataset: [u8; 16],
    pub(super) owner: Option<[u8; 16]>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    initialized: Vec<Binding>,
    plan: Option<Vec<Binding>>,
    done: Vec<String>,
    pub(super) published: bool,
}

impl Birth {
    pub(super) fn new(dataset: DatasetId) -> Self {
        Self {
            version: 1,
            dataset: dataset.0,
            owner: None,
            initialized: Vec::new(),
            plan: None,
            done: Vec::new(),
            published: false,
        }
    }

    pub(super) fn decode(bytes: &[u8], dataset: DatasetId) -> Result<Self, startup::Error> {
        if bytes.len() > 1 << 20 {
            return Err(startup::Error::Corrupt);
        }
        let value: Self =
            busbar_contract::json::parse(bytes).map_err(|_| startup::Error::Corrupt)?;
        if value.version != 1
            || value.dataset != dataset.0
            || value.owner == Some([0; 16])
            || (value.owner.is_none()
                && (!value.initialized.is_empty()
                    || value.plan.is_some()
                    || !value.done.is_empty()
                    || value.published))
        {
            return Err(startup::Error::Corrupt);
        }
        validate_plan(&value.initialized)?;
        if let Some(plan) = &value.plan {
            validate_plan(plan)?;
            if value.done.windows(2).any(|w| w[0] >= w[1])
                || value
                    .done
                    .iter()
                    .any(|name| !plan.iter().any(|b| &b.instance == name))
                || (value.published && value.done.len() != plan.len())
            {
                return Err(startup::Error::Corrupt);
            }
        } else if !value.done.is_empty() || value.published {
            return Err(startup::Error::Corrupt);
        }
        if value.encode()?.as_slice() != bytes {
            return Err(startup::Error::Corrupt);
        }
        Ok(value)
    }

    /// Planes this record shows done; each adds one READY to a resumed owner's first write.
    pub(super) fn done_len(&self) -> usize {
        self.done.len()
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, startup::Error> {
        let bytes = busbar_contract::json::to_vec(self).map_err(|_| startup::Error::Corrupt)?;
        if bytes.len() > 1 << 20 {
            return Err(startup::Error::Corrupt);
        }
        Ok(bytes)
    }
}

fn validate_plan(plan: &[Binding]) -> Result<(), startup::Error> {
    if plan.len() > 4096
        || plan.windows(2).any(|w| w[0].instance >= w[1].instance)
        || plan.iter().any(|b| {
            b.instance.is_empty()
                || b.instance.len() > usize::from(u16::MAX)
                || b.instance.chars().any(char::is_control)
                || b.digest == [0; 32]
        })
    {
        return Err(startup::Error::Authority);
    }
    Ok(())
}

pub(super) fn address() -> Address {
    Address {
        namespace: NAMESPACE.0,
        key: busbar_contract::persistence::witness::BIRTH_KEY.to_vec(),
    }
}

/// What [`FirstStart::abandon`] did on the exit path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Abandoned {
    /// This writer's row is retired; the next inspect takes over at once.
    Retired,
    /// The first start is published; nothing to hand over, nothing written.
    Published,
    /// This writer was already retired (taken over); nothing written.
    NotAdmitted,
    /// The retire's outcome is unknown or it was refused; the next owner waits the window.
    Unconfirmed,
}

struct State {
    birth: Birth,
    pending: Option<(Birth, Arc<Attempt>)>,
    /// Set by `abandon`: every later first-start step is refused.
    abandoned: bool,
}

/// Only Startup can construct this proof, after its exact ownership/fence transaction
/// and writer attachment are confirmed. A replacement process cannot inherit its caller grant.
pub struct FirstStart {
    backend: Arc<dyn PersistenceBackend>,
    authority: WriterAuthority,
    state: Mutex<State>,
    /// The last confirmed progress write (or construction, for a resumed owner).
    last_write: std::sync::Mutex<Instant>,
}

impl FirstStart {
    pub(super) fn new(
        backend: Arc<dyn PersistenceBackend>,
        authority: WriterAuthority,
        birth: Birth,
    ) -> Self {
        Self {
            backend,
            authority,
            state: Mutex::new(State {
                birth,
                pending: None,
                abandoned: false,
            }),
            last_write: std::sync::Mutex::new(Instant::now()),
        }
    }

    pub async fn published(&self) -> bool {
        self.state.lock().await.birth.published
    }

    pub fn owner(&self) -> [u8; 16] {
        self.authority.writer
    }

    /// Exit path only (FIRST-START-TAKEOVER §2.7): retire this writer so the next inspect takes
    /// over at once. The birth record keeps this owner; after this call every first-start step
    /// is refused. Writes nothing after publication or once this writer was taken over.
    pub async fn abandon(&self) -> Result<Abandoned, startup::Error> {
        let mut state = self.state.lock().await;
        if state.birth.published {
            return Ok(Abandoned::Published);
        }
        state.abandoned = true;
        let me = self.authority.writer;
        // A decided conflict is a takeover between the read and the commit (the fence is on the
        // registrar's row, which a takeover leaves alone) or a moved manifest: re-read once.
        for _ in 0..2 {
            let attempt = {
                let values = self
                    .read(vec![
                        startup::manifest_address(),
                        startup::writer_address(me),
                    ])
                    .await?;
                let seal = crate::seal::lend();
                let manifest_bytes = values[0]
                    .as_ref()
                    .ok_or(startup::Error::Corrupt)?
                    .expose(&seal);
                let manifest = startup::Manifest::decode(manifest_bytes)?;
                let row_bytes = values[1]
                    .as_ref()
                    .ok_or(startup::Error::Corrupt)?
                    .expose(&seal);
                let row = control::Writer::decode(row_bytes).ok_or(startup::Error::Corrupt)?;
                if !row.admits(self.authority.execution_epoch) {
                    return Ok(Abandoned::NotAdmitted);
                }
                let retired = control::Writer {
                    retired_through: row.admitted_through,
                    ..row
                };
                let candidate = startup::prepare(
                    manifest,
                    vec![
                        startup::exact(startup::manifest_address(), manifest_bytes.clone()),
                        startup::exact(startup::writer_address(me), row_bytes.clone()),
                    ],
                    vec![Mutation::Put {
                        address: startup::writer_address(me),
                        value: Secret::new(
                            retired.encode().ok_or(startup::Error::Corrupt)?.to_vec(),
                        ),
                    }],
                )?;
                Attempt::proven(candidate, self.backend.clone())
                    .map_err(|_| startup::Error::Authority)?
            };
            match startup::decided(&attempt).await {
                Ok(None) => return Ok(Abandoned::Retired),
                Ok(Some(_)) => return Ok(Abandoned::Unconfirmed),
                Err(startup::Error::Conflict) => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(Abandoned::Unconfirmed)
    }

    /// Record a confirmed R0 commit as this owner's progress write (§2.9 (c) obligation 2), so
    /// `FIRST_START_SLOW_STEP` measures each gap, never the whole import.
    pub fn note_r0_commit(&self) {
        self.progressed("r0-commit");
    }

    /// Report the gap since the last progress write if it exceeds its budget, then restart it.
    /// Steps that run inside a plane's READY get one READY_STEP more.
    fn progressed(&self, step: &'static str) {
        let now = Instant::now();
        let mut last = self
            .last_write
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let gap = now.duration_since(*last);
        let budget = match step {
            "complete" | "initialize-host" => SLOW_STEP.saturating_add(startup::READY_STEP),
            _ => SLOW_STEP,
        };
        if gap > budget {
            diag_warn!(
                FIRST_START_SLOW_STEP,
                step,
                gap_ms = u64::try_from(gap.as_millis()).unwrap_or(u64::MAX),
                budget_s = budget.as_secs(),
                "first start step {step} came {} s after the previous progress write (budget {} s)",
                gap.as_secs(),
                budget.as_secs(),
            );
        }
        *last = now;
    }

    async fn read(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<Secret<Vec<u8>>>>, startup::Error> {
        let info = self.backend.info();
        let count = addresses.len();
        let observed = self
            .backend
            .read(Arc::new(Read {
                dataset: info.dataset,
                addresses,
                time: None,
            }))
            .await
            .map_err(startup::Error::Backend)?;
        match observed {
            ReadResult::Values {
                observed_at,
                values,
            } if observed_at.authority == info.clock_authority && values.len() == count => {
                Ok(values)
            }
            _ => Err(startup::Error::Corrupt),
        }
    }

    /// Atomically consume a finite host initialization binding with its native effects.
    pub(crate) async fn initialize_host(
        &self,
        binding: Binding,
        predicates: Vec<Predicate>,
        mutations: Vec<Mutation>,
    ) -> Result<startup::Progress, startup::Error> {
        validate_plan(std::slice::from_ref(&binding))?;
        let mut state = self.state.lock().await;
        if state.birth.published || state.abandoned {
            return Err(startup::Error::Authority);
        }
        if let Some(held) = state
            .birth
            .initialized
            .iter()
            .find(|held| held.instance == binding.instance)
        {
            if held != &binding || state.pending.is_some() {
                return Err(startup::Error::Authority);
            }
            return self
                .verify(&state.birth)
                .await
                .map(|()| startup::Progress::Advanced);
        }
        if state.birth.plan.is_some() {
            return Err(startup::Error::Authority);
        }
        let mut next = state.birth.clone();
        next.initialized.push(binding);
        next.initialized.sort_by(|a, b| a.instance.cmp(&b.instance));
        validate_plan(&next.initialized)?;
        let progress = self
            .change_with(&mut state, next, predicates, mutations, "initialize-host")
            .await?;
        if progress == startup::Progress::Advanced {
            self.verify(&state.birth).await?;
        }
        Ok(progress)
    }

    /// Whether a retained initialization still needs its exact native decision reconciled.
    pub(crate) async fn host_initialization_pending(&self, instance: &str) -> bool {
        let state = self.state.lock().await;
        !state
            .birth
            .initialized
            .iter()
            .any(|b| b.instance == instance)
            && state
                .pending
                .as_ref()
                .is_some_and(|(next, _)| next.initialized.iter().any(|b| b.instance == instance))
    }

    /// Verified, nonsecret receipt preimage. An uncertain initialization keeps its
    /// original preimage stable until initialize_host reconciles the exact candidate.
    pub(crate) async fn initialization_witness(&self) -> Result<Vec<u8>, startup::Error> {
        let state = self.state.lock().await;
        if state.birth.published || state.abandoned {
            return Err(startup::Error::Authority);
        }
        let pending = match &state.pending {
            Some((next, _)) if next.initialized != state.birth.initialized => Some(next),
            Some(_) => return Err(startup::Error::Authority),
            None => None,
        };
        self.verify_with(&state.birth, pending).await?;
        state.birth.encode()
    }

    /// Freeze before any instance initialization or public route publication. A changed
    /// selection, including a changed configuration on crash resume, grants nothing.
    pub async fn freeze(&self, plan: Vec<Binding>) -> Result<startup::Progress, startup::Error> {
        validate_plan(&plan)?;
        let mut state = self.state.lock().await;
        if state.birth.published || state.abandoned {
            return Err(startup::Error::Authority);
        }
        if let Some(held) = &state.birth.plan {
            if held != &plan {
                return Err(startup::Error::Authority);
            }
            return self
                .verify(&state.birth)
                .await
                .map(|()| startup::Progress::Advanced);
        }
        let mut next = state.birth.clone();
        next.plan = Some(plan);
        self.change(&mut state, next, "freeze").await
    }

    /// Exact proof of a still-current initial owner, not a runtime emptiness observation.
    pub(crate) async fn permits(&self, instance: &str) -> Result<bool, startup::Error> {
        let state = self.state.lock().await;
        if state.pending.is_some() || state.birth.published || state.abandoned {
            return Ok(false);
        }
        self.verify(&state.birth).await?;
        Ok(state
            .birth
            .plan
            .as_ref()
            .is_some_and(|plan| plan.iter().any(|b| b.instance == instance))
            && !state.birth.done.iter().any(|name| name == instance))
    }

    /// READY is not public admission. Its completion is fenced before revoking the
    /// finite in-process grant, so late Applied replays cannot let a stale owner serve.
    pub async fn complete(&self, instance: &str) -> Result<startup::Progress, startup::Error> {
        let mut state = self.state.lock().await;
        if state.birth.published
            || state.abandoned
            || !state
                .birth
                .plan
                .as_ref()
                .is_some_and(|plan| plan.iter().any(|b| b.instance == instance))
        {
            return Err(startup::Error::Authority);
        }
        if state.birth.done.iter().any(|name| name == instance) {
            return self
                .verify(&state.birth)
                .await
                .map(|()| startup::Progress::Advanced);
        }
        let mut next = state.birth.clone();
        next.done.push(instance.to_string());
        next.done.sort();
        self.change(&mut state, next, "complete").await
    }

    pub async fn publish(&self) -> Result<startup::Progress, startup::Error> {
        let mut state = self.state.lock().await;
        if state.abandoned {
            return Err(startup::Error::Authority);
        }
        if state.birth.published {
            return self
                .verify(&state.birth)
                .await
                .map(|()| startup::Progress::Advanced);
        }
        if state
            .birth
            .plan
            .as_ref()
            .is_none_or(|plan| plan.len() != state.birth.done.len())
        {
            return Err(startup::Error::Authority);
        }
        let mut next = state.birth.clone();
        next.published = true;
        self.change(&mut state, next, "publish").await
    }

    async fn verify(&self, birth: &Birth) -> Result<(), startup::Error> {
        self.verify_with(birth, None).await
    }

    async fn verify_with(
        &self,
        birth: &Birth,
        alternate: Option<&Birth>,
    ) -> Result<(), startup::Error> {
        let info = self.backend.info();
        let observed = self
            .backend
            .read(Arc::new(Read {
                dataset: info.dataset,
                addresses: vec![
                    address(),
                    startup::root_address(),
                    startup::writer_address(self.authority.writer),
                ],
                time: None,
            }))
            .await
            .map_err(startup::Error::Backend)?;
        let ReadResult::Values {
            observed_at,
            values,
        } = observed
        else {
            return Err(startup::Error::Corrupt);
        };
        if observed_at.authority != info.clock_authority || values.len() != 3 {
            return Err(startup::Error::Corrupt);
        }
        let seal = crate::seal::lend();
        let encoded = birth.encode()?;
        let alternate = alternate.map(Birth::encode).transpose()?;
        let observed_birth = values[0].as_ref().map(|v| v.expose(&seal).as_slice());
        if birth.owner != Some(self.authority.writer)
            || (observed_birth != Some(encoded.as_slice())
                && !alternate
                    .as_ref()
                    .is_some_and(|bytes| observed_birth == Some(bytes.as_slice())))
            || values[1]
                .as_ref()
                .and_then(|v| control::Dataset::decode(v.expose(&seal)))
                != Some(control::Dataset {
                    id: info.dataset,
                    writer_epoch: self.authority.writer_epoch,
                })
            || !values[2]
                .as_ref()
                .and_then(|v| control::Writer::decode(v.expose(&seal)))
                .is_some_and(|writer| writer.admits(self.authority.execution_epoch))
        {
            return Err(startup::Error::Authority);
        }
        Ok(())
    }

    async fn change(
        &self,
        state: &mut State,
        next: Birth,
        step: &'static str,
    ) -> Result<startup::Progress, startup::Error> {
        self.change_with(state, next, Vec::new(), Vec::new(), step)
            .await
    }

    async fn change_with(
        &self,
        state: &mut State,
        next: Birth,
        predicates: Vec<Predicate>,
        mutations: Vec<Mutation>,
        step: &'static str,
    ) -> Result<startup::Progress, startup::Error> {
        let operation = match &state.pending {
            Some((_, attempt)) => attempt.candidate().candidate().id.operation,
            None => startup::random_id()?,
        };
        let candidate = self.candidate(&state.birth, &next, operation, predicates, mutations)?;
        let attempt = if let Some((_, attempt)) = &state.pending {
            if attempt.candidate().fingerprint() != candidate.fingerprint() {
                return Err(startup::Error::Authority);
            }
            attempt.clone()
        } else {
            let attempt = Arc::new(
                Attempt::proven(candidate, self.backend.clone())
                    .map_err(|_| startup::Error::Authority)?,
            );
            state.pending = Some((next.clone(), attempt.clone()));
            attempt
        };
        if let Some(progress) = startup::decided(&attempt).await? {
            return Ok(progress);
        }
        state.birth = next;
        state.pending = None;
        self.progressed(step);
        Ok(startup::Progress::Advanced)
    }

    fn candidate(
        &self,
        before: &Birth,
        after: &Birth,
        operation: [u8; 16],
        mut predicates: Vec<Predicate>,
        mut mutations: Vec<Mutation>,
    ) -> Result<PreparedCandidate, startup::Error> {
        if before.owner != Some(self.authority.writer) || after.owner != before.owner {
            return Err(startup::Error::Authority);
        }
        predicates.push(Predicate {
            address: address(),
            expected: ExpectedValue::Exact(Secret::new(before.encode()?)),
        });
        mutations.push(Mutation::Put {
            address: address(),
            value: Secret::new(after.encode()?),
        });
        PreparedCandidate::new(Candidate {
            id: AttemptId {
                dataset: self.backend.info().dataset,
                writer_epoch: self.authority.writer_epoch,
                writer: self.authority.writer,
                execution_epoch: self.authority.execution_epoch,
                operation,
            },
            codec: CANDIDATE_VERSION,
            predicates,
            mutations,
            time: None,
            result: Secret::new(Vec::new()),
        })
        .map_err(|_| startup::Error::Corrupt)
    }
}
