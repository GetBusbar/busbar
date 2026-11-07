// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One immutable candidate and one fixed backend, retained across cancellation.
//!
//! Submission performs at most one native call. Callers choose when to retry;
//! uncertainty never authorizes replanning, and elapsed replay authority never
//! starts over on retry. This module does not acknowledge durable acceptance.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use busbar_contract::persistence::{
    BackendInfo, Decision, Failure, PersistenceBackend, PreparedCandidate,
};
use busbar_contract::plugin::KernelSeal;
use busbar_contract::Secret;

use super::candidate_codec::{self, CodecError};

const REPLAY_HORIZON: Duration = Duration::from_secs(24 * 60 * 60);

/// Content-free rejection of an attempt aimed at another dataset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatasetMismatch;

/// Content-free snapshot decoding or allocation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotError(CodecError);

/// A snapshot could not be admitted to this backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreError {
    /// The immutable candidate names another dataset.
    DatasetMismatch,
    /// The snapshot is invalid, unsupported, or exceeds its allocation budget.
    Snapshot(SnapshotError),
}

/// Public observation of custody, without exposing candidate or receipt contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// No send has an unresolved possible effect.
    Prepared,
    /// One caller currently owns the native crossing.
    InFlight,
    /// A send may have applied; only exact replay may resolve it.
    Uncertain,
    /// A definitive decision has been cached.
    Resolved,
    /// Automatic submission is prohibited; retained evidence needs reconciliation.
    Reconcile,
}

/// Result of one submission; no branch retries internally.
#[derive(Debug)]
pub enum SubmitResult {
    /// A definitive decision, shared by every subsequent caller.
    Decided(Arc<Decision>),
    /// This attempt has no earlier uncertainty and this call applied nothing.
    NoEffect(Failure),
    /// Execution may have occurred; retain this attempt for exact replay.
    Uncertain,
    /// Replay authority is unavailable or a later rejection cannot resolve history.
    Reconcile,
    /// Another caller currently owns the native crossing.
    Busy,
}

enum Phase {
    Prepared,
    InFlight,
    Uncertain,
    Resolved(Arc<Decision>),
    Reconcile,
}

struct Inner {
    phase: Phase,
    first_send: Option<Instant>,
}

/// Shared custody of immutable input and its original backend instance.
///
/// Retain this owner while unresolved. Dropping a submission future relinquishes
/// its waiter, marks the attempt uncertain, and does not drop its candidate.
/// Replacing the application's backend cannot retarget this owner.
pub struct Attempt {
    candidate: PreparedCandidate,
    backend: Arc<dyn PersistenceBackend>,
    info: BackendInfo,
    inner: Mutex<Inner>,
}

impl Attempt {
    /// Bind validated input to one opened backend before any native crossing.
    pub fn new(
        candidate: PreparedCandidate,
        backend: Arc<dyn PersistenceBackend>,
    ) -> Result<Self, DatasetMismatch> {
        let info = backend.info();
        if candidate.candidate().id.dataset != info.dataset {
            return Err(DatasetMismatch);
        }
        Ok(Self {
            candidate,
            backend,
            info,
            inner: Mutex::new(Inner {
                phase: Phase::Prepared,
                first_send: None,
            }),
        })
    }

    /// Restore immutable candidate custody only, with submission prohibited.
    ///
    /// A candidate snapshot has no trustworthy same-process first-send clock.
    /// It cannot establish complete durable intent or durable acceptance.
    pub fn restore_candidate<S: KernelSeal + ?Sized>(
        snapshot: &Secret<Vec<u8>>,
        allocation_budget: usize,
        seal: &S,
        backend: Arc<dyn PersistenceBackend>,
    ) -> Result<Self, RestoreError> {
        let candidate = candidate_codec::decode(snapshot, allocation_budget, seal)
            .map_err(|error| RestoreError::Snapshot(SnapshotError(error)))?;
        let attempt = Self::new(candidate, backend).map_err(|_| RestoreError::DatasetMismatch)?;
        attempt.lock().phase = Phase::Reconcile;
        Ok(attempt)
    }

    /// Encode immutable candidate custody ONLY, under the existing seal API.
    ///
    /// This is not a complete durable intent/first-send record, is not encrypted,
    /// and is not proof of durable acceptance. Its protected bytes require the
    /// existing protected recovery storage; this method performs no storage write.
    pub fn encode_candidate<S: KernelSeal + ?Sized>(
        &self,
        allocation_budget: usize,
        seal: &S,
    ) -> Result<Secret<Vec<u8>>, SnapshotError> {
        candidate_codec::encode(&self.candidate, allocation_budget, seal).map_err(SnapshotError)
    }

    /// Original immutable input, shared rather than reconstructed for retries.
    #[must_use]
    pub fn candidate(&self) -> &PreparedCandidate {
        &self.candidate
    }

    /// Authority facts captured from the original backend at construction.
    #[must_use]
    pub fn backend_info(&self) -> BackendInfo {
        self.info
    }

    /// Observe custody state without disclosing any protected bytes.
    #[must_use]
    pub fn state(&self) -> State {
        match self.lock().phase {
            Phase::Prepared => State::Prepared,
            Phase::InFlight => State::InFlight,
            Phase::Uncertain => State::Uncertain,
            Phase::Resolved(_) => State::Resolved,
            Phase::Reconcile => State::Reconcile,
        }
    }

    /// Make at most one native commit call with the exact original candidate.
    ///
    /// Cancellation after the crossing begins preserves uncertainty. The first
    /// send starts one monotonic 24-hour horizon, including refused sends; retries
    /// never extend it. No lock is held while awaiting the backend.
    pub async fn submit(&self) -> SubmitResult {
        let uncertain = {
            let mut inner = self.lock();
            let uncertain = match &inner.phase {
                Phase::InFlight => return SubmitResult::Busy,
                Phase::Resolved(decision) => return SubmitResult::Decided(decision.clone()),
                Phase::Reconcile => return SubmitResult::Reconcile,
                Phase::Prepared => false,
                Phase::Uncertain => true,
            };
            let now = Instant::now();
            if inner
                .first_send
                .is_some_and(|first| now.saturating_duration_since(first) >= REPLAY_HORIZON)
            {
                inner.phase = Phase::Reconcile;
                return SubmitResult::Reconcile;
            }
            inner.first_send.get_or_insert(now);
            inner.phase = Phase::InFlight;
            uncertain
        };
        // Install before invoking the backend: even a panic constructing its
        // future cannot turn a possible crossing into a no-effect outcome.
        let mut crossing = Crossing {
            attempt: self,
            armed: true,
        };
        let reply = self.backend.commit(self.candidate.clone()).await;
        let (phase, result) = match reply {
            Ok(Decision::Applied(value)) if value == self.candidate.candidate().result => {
                let decision = Arc::new(Decision::Applied(value));
                (
                    Phase::Resolved(decision.clone()),
                    SubmitResult::Decided(decision),
                )
            }
            Ok(Decision::Applied(_)) => (Phase::Uncertain, SubmitResult::Uncertain),
            Ok(Decision::ExpiredUnknown) => (Phase::Reconcile, SubmitResult::Reconcile),
            Ok(Decision::TimeGuardFailed { observed_at })
                if observed_at.authority != self.info.clock_authority
                    || self
                        .candidate
                        .candidate()
                        .time
                        .is_none_or(|guard| guard.permits(observed_at.unix_seconds)) =>
            {
                (Phase::Uncertain, SubmitResult::Uncertain)
            }
            Ok(_) if uncertain => (Phase::Reconcile, SubmitResult::Reconcile),
            Ok(decision) => {
                let decision = Arc::new(decision);
                (
                    Phase::Resolved(decision.clone()),
                    SubmitResult::Decided(decision),
                )
            }
            Err(failure @ (Failure::Refused | Failure::Overloaded)) if !uncertain => {
                (Phase::Prepared, SubmitResult::NoEffect(failure))
            }
            Err(_) => (Phase::Uncertain, SubmitResult::Uncertain),
        };
        self.lock().phase = phase;
        crossing.armed = false;
        result
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|poisoned| {
            let mut inner = poisoned.into_inner();
            inner.phase = Phase::Reconcile;
            inner
        })
    }
}

struct Crossing<'a> {
    attempt: &'a Attempt,
    armed: bool,
}
impl Drop for Crossing<'_> {
    fn drop(&mut self) {
        if self.armed {
            let mut inner = self.attempt.lock();
            if matches!(inner.phase, Phase::InFlight) {
                inner.phase = Phase::Uncertain;
            }
        }
    }
}

#[cfg(test)]
#[path = "commit_tests.rs"]
mod tests;
