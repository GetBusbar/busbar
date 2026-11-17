// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One immutable candidate, its dedupe key and one fixed backend, retained across
//! cancellation (STORE-TRANSACTIONS §2.2-§2.3).
//!
//! Submission performs at most one native commit call. A slotted attempt is deduped by
//! its (writer, slot, seq) row, which never expires, so a retry is always safe. A
//! self-fenced attempt can apply at most once by its own witness; when a retry after a
//! possible earlier effect is answered "did not apply", one readback of the witness
//! and every predicate decides it. Uncertainty never authorizes replanning.

use std::sync::{Arc, Mutex, MutexGuard};

use busbar_contract::persistence::{
    Address, BackendInfo, CommitKey, Decision, ExpectedValue, Failure, Mutation,
    PersistenceBackend, PreparedCandidate, Read, ReadResult, SelfFenced, WitnessKind,
};
use busbar_contract::plugin::KernelSeal;
use busbar_contract::Secret;

use super::candidate_codec::{self, CodecError};
use crate::diagnostics::Diagnostic;

/// Content-free rejection of an attempt aimed at another dataset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatasetMismatch;

/// An attempt could not be bound to its backend and key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindError {
    /// The immutable candidate names another dataset.
    DatasetMismatch,
    /// The candidate is not provably single-shot, or the proof is for another candidate.
    NotSelfFenced,
    /// A slotted attempt was given a self-fenced key.
    Key,
}

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

/// Public observation of custody, without exposing candidate contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// No send has an unresolved possible effect.
    Prepared,
    /// One caller currently owns the native crossing.
    InFlight,
    /// A send may have applied; only exact replay or readback may resolve it.
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
    /// The outcome cannot be decided automatically; reconcile the retained evidence.
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
    audited: Option<&'static Diagnostic>,
    /// Why the last send answered [`SubmitResult::NoEffect`].
    no_effect: Option<NoEffectCause>,
}

/// Why a send with no earlier uncertainty applied nothing (#319 r4 §7.1). [`SubmitResult::NoEffect`]
/// carries `Failure::Refused` for a slotted send the store fenced or found stale as well as for a
/// backend refusal; the native decision is kept here so a fence or a slot invariant is never taken
/// for a refusal a smaller candidate could pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoEffectCause {
    /// The backend answered this failure.
    Backend(Failure),
    /// The store fenced the stamping writer (its dataset epoch or execution epoch moved).
    Fenced,
    /// The slot row is newer than this send: a slot invariant, not a refusal.
    Stale,
}

#[derive(Clone, Copy)]
enum Kind {
    Slotted,
    SelfFenced(SelfFenced),
    /// Restored custody: never submitted.
    Restored,
}

/// Shared custody of immutable input, its dedupe key and its original backend.
///
/// Retain this owner while unresolved. Dropping a submission future relinquishes
/// its waiter, marks the attempt uncertain, and does not drop its candidate.
/// Replacing the application's backend cannot retarget this owner.
///
/// Only the kernel and the migration library build one (LINT-RULES R9); anyone else is refused:
///
/// ```compile_fail,E0624
/// use busbar_kernel::persistence::commit::Attempt;
/// let _ = Attempt::new(todo!(), todo!());
/// ```
pub struct Attempt {
    candidate: PreparedCandidate,
    key: Option<CommitKey>,
    kind: Kind,
    backend: Arc<dyn PersistenceBackend>,
    info: BackendInfo,
    inner: Mutex<Inner>,
}

/// The answer a self-fenced readback starts from: all three mean "this send did not apply".
#[derive(Clone, Copy, PartialEq, Eq)]
enum NotApplied {
    Conflict,
    Fenced,
    Refused,
}

impl Attempt {
    fn bind(
        candidate: PreparedCandidate,
        key: Option<CommitKey>,
        kind: Kind,
        backend: Arc<dyn PersistenceBackend>,
    ) -> Result<Self, BindError> {
        let info = backend.info();
        if candidate.candidate().id.dataset != info.dataset {
            return Err(BindError::DatasetMismatch);
        }
        Ok(Self {
            candidate,
            key,
            kind,
            backend,
            info,
            inner: Mutex::new(Inner {
                phase: Phase::Prepared,
                audited: None,
                no_effect: None,
            }),
        })
    }

    /// Bind a candidate to the queue slot the facade leased for it.
    pub(crate) fn slotted(
        candidate: PreparedCandidate,
        key: CommitKey,
        backend: Arc<dyn PersistenceBackend>,
    ) -> Result<Self, BindError> {
        if key.is_self_fenced() {
            return Err(BindError::Key);
        }
        Self::bind(candidate, Some(key), Kind::Slotted, backend)
    }

    /// Bind a candidate that can apply at most once by its own witness. The proof
    /// must be [`SelfFenced::check`] of this exact candidate.
    pub fn self_fenced(
        candidate: PreparedCandidate,
        proof: SelfFenced,
        backend: Arc<dyn PersistenceBackend>,
    ) -> Result<Self, BindError> {
        if SelfFenced::check(&candidate) != Ok(proof) {
            return Err(BindError::NotSelfFenced);
        }
        let key = CommitKey::self_fenced(&proof);
        Self::bind(candidate, Some(key), Kind::SelfFenced(proof), backend)
    }

    /// Check and bind a self-fenced candidate in one step.
    pub fn proven(
        candidate: PreparedCandidate,
        backend: Arc<dyn PersistenceBackend>,
    ) -> Result<Self, BindError> {
        let proof = SelfFenced::check(&candidate).map_err(|_| BindError::NotSelfFenced)?;
        Self::self_fenced(candidate, proof, backend)
    }

    /// The dedupe key this attempt travels with; `None` for restored custody.
    #[cfg(test)]
    pub(crate) fn key(&self) -> Option<CommitKey> {
        self.key
    }

    /// Restore immutable candidate custody only, with submission prohibited.
    ///
    /// A restored candidate has no leased slot. It cannot establish complete durable
    /// intent or durable acceptance.
    pub fn restore_candidate<S: KernelSeal + ?Sized>(
        snapshot: &Secret<Vec<u8>>,
        allocation_budget: usize,
        seal: &S,
        backend: Arc<dyn PersistenceBackend>,
    ) -> Result<Self, RestoreError> {
        let candidate = candidate_codec::decode(snapshot, allocation_budget, seal)
            .map_err(|error| RestoreError::Snapshot(SnapshotError(error)))?;
        let attempt = Self::bind(candidate, None, Kind::Restored, backend)
            .map_err(|_| RestoreError::DatasetMismatch)?;
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

    /// Why the last send answered [`SubmitResult::NoEffect`], if one did (#319 r4 §7.1).
    #[must_use]
    pub fn no_effect_cause(&self) -> Option<NoEffectCause> {
        self.lock().no_effect
    }

    /// The last audited diagnostic this attempt emitted, if any.
    #[must_use]
    pub fn audited(&self) -> Option<&'static Diagnostic> {
        self.lock().audited
    }

    /// Make at most one native commit call with the exact original candidate and key,
    /// plus at most one readback for a self-fenced attempt.
    ///
    /// Cancellation after the crossing begins preserves uncertainty. No lock is held
    /// while awaiting the backend.
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
            let Some(_) = self.key else {
                inner.phase = Phase::Reconcile;
                return SubmitResult::Reconcile;
            };
            inner.phase = Phase::InFlight;
            uncertain
        };
        // Install before invoking the backend: even a panic constructing its
        // future cannot turn a possible crossing into a no-effect outcome.
        let mut crossing = Crossing {
            attempt: self,
            armed: true,
        };
        let key = self.key.expect("checked above");
        let reply = self.backend.commit(self.candidate.clone(), key).await;
        let fence = match self.kind {
            Kind::SelfFenced(proof) => Some(proof),
            _ => None,
        };
        let step = match reply {
            Ok(Decision::Applied(_)) => Step::Resolved(self.applied()),
            Ok(Decision::TimeGuardFailed { observed_at })
                if observed_at.authority != self.info.clock_authority
                    || self
                        .candidate
                        .candidate()
                        .time
                        .is_none_or(|guard| guard.permits(observed_at.unix_seconds)) =>
            {
                self.audit(&crate::diagnostics::STORE_TIME_GUARD_INCONSISTENT, || {
                    format!(
                        "observed authority {:02x?} at {}, guard {:?}",
                        observed_at.authority,
                        observed_at.unix_seconds,
                        self.candidate.candidate().time
                    )
                });
                Step::Reconcile
            }
            Ok(Decision::ConditionConflict) => match fence {
                Some(proof) if uncertain => Step::Readback(proof, NotApplied::Conflict),
                _ => Step::Resolved(Decision::ConditionConflict),
            },
            Ok(decision @ Decision::TimeGuardFailed { .. }) => Step::Resolved(decision),
            Ok(Decision::Fenced) => match (fence, uncertain) {
                (Some(proof), true) => Step::Readback(proof, NotApplied::Fenced),
                (Some(_), false) => Step::Resolved(Decision::Fenced),
                (None, false) => Step::NoEffect(Failure::Refused, NoEffectCause::Fenced),
                (None, true) => {
                    self.audit(
                        &crate::diagnostics::STORE_COMMIT_FENCED_IN_DOUBT,
                        String::new,
                    );
                    Step::Reconcile
                }
            },
            Ok(Decision::Stale) => {
                self.audit(&crate::diagnostics::STORE_SLOT_INVARIANT, String::new);
                if uncertain || fence.is_some() {
                    Step::Reconcile
                } else {
                    Step::NoEffect(Failure::Refused, NoEffectCause::Stale)
                }
            }
            Ok(Decision::OpIdConflict) => Step::Resolved(Decision::OpIdConflict),
            Err(failure @ (Failure::Refused | Failure::Overloaded)) if !uncertain => {
                Step::NoEffect(failure, NoEffectCause::Backend(failure))
            }
            Err(Failure::Refused) => match fence {
                Some(proof) => Step::Readback(proof, NotApplied::Refused),
                None => Step::Uncertain,
            },
            Err(_) => Step::Uncertain,
        };
        let step = match step {
            Step::Readback(proof, answer) => self.readback(proof, answer).await,
            other => other,
        };
        let (phase, result) = match step {
            Step::Resolved(decision) => {
                let decision = Arc::new(decision);
                (
                    Phase::Resolved(decision.clone()),
                    SubmitResult::Decided(decision),
                )
            }
            Step::NoEffect(failure, cause) => {
                self.lock().no_effect = Some(cause);
                (Phase::Prepared, SubmitResult::NoEffect(failure))
            }
            Step::Uncertain | Step::Readback(..) => (Phase::Uncertain, SubmitResult::Uncertain),
            Step::Reconcile => (Phase::Reconcile, SubmitResult::Reconcile),
        };
        self.lock().phase = phase;
        crossing.armed = false;
        result
    }

    /// ResolveByReadback (§2.3): one read of the witness and every predicate address.
    async fn readback(&self, proof: SelfFenced, answer: NotApplied) -> Step {
        let body = self.candidate.candidate();
        let (first, pair) = proof.witness_puts();
        let witness: Vec<(&Address, &Secret<Vec<u8>>)> = [Some(first), pair]
            .into_iter()
            .flatten()
            .filter_map(|index| match body.mutations.get(index) {
                Some(Mutation::Put { address, value }) => Some((address, value)),
                _ => None,
            })
            .collect();
        if witness.len() != 1 + usize::from(pair.is_some()) {
            return Step::Uncertain;
        }
        let mut addresses: Vec<Address> = Vec::new();
        for address in witness
            .iter()
            .map(|(address, _)| *address)
            .chain(body.predicates.iter().map(|p| &p.address))
        {
            if !addresses.contains(address) {
                addresses.push(address.clone());
            }
        }
        let count = addresses.len();
        let observed = self
            .backend
            .read(Arc::new(Read {
                dataset: self.info.dataset,
                addresses: addresses.clone(),
                time: None,
            }))
            .await;
        // (a) nothing learned.
        let values = match observed {
            Ok(ReadResult::Values {
                observed_at,
                values,
            }) if observed_at.authority == self.info.clock_authority && values.len() == count => {
                values
            }
            _ => return Step::Uncertain,
        };
        let at = |address: &Address| {
            addresses
                .iter()
                .position(|a| a == address)
                .and_then(|i| values[i].as_ref())
        };
        // (b) the witness shows this attempt's effect.
        let applied = match proof.kind() {
            WitnessKind::Absent => at(witness[0].0).is_some(),
            WitnessKind::Value => witness
                .iter()
                .all(|(address, value)| at(address) == Some(*value)),
            WitnessKind::Exact => at(witness[0].0) == Some(witness[0].1),
        };
        if applied {
            return Step::Resolved(self.applied());
        }
        // (c) an Exact witness moved past both its expected and its successor value.
        if proof.kind() == WitnessKind::Exact {
            let before = body
                .predicates
                .iter()
                .find(|p| p.address == *witness[0].0)
                .map(|p| &p.expected);
            if let Some(ExpectedValue::Exact(x)) = before {
                if at(witness[0].0) != Some(x) {
                    self.audit(&crate::diagnostics::STORE_SELF_FENCED_AMBIGUOUS, || {
                        "exact witness superseded".to_owned()
                    });
                    return Step::Reconcile;
                }
            }
        }
        // (d) a fence is final.
        if answer == NotApplied::Fenced {
            return Step::Resolved(Decision::Fenced);
        }
        let fails = body.predicates.iter().any(|p| {
            let value = at(&p.address);
            match &p.expected {
                ExpectedValue::Absent => value.is_some(),
                ExpectedValue::Exact(expected) => value != Some(expected),
            }
        });
        match (fails, proof.no_aba(), answer) {
            // (e) did not apply and never will.
            (true, true, _) => Step::Resolved(Decision::ConditionConflict),
            // (g) the only case a retry can still change.
            (false, _, NotApplied::Refused) => Step::Uncertain,
            // (f) a domain predicate could return; (h) an evaluated conflict that holds again.
            _ => {
                self.audit(&crate::diagnostics::STORE_SELF_FENCED_AMBIGUOUS, || {
                    if fails {
                        "failed predicate may return".to_owned()
                    } else {
                        "conflict on predicates that hold".to_owned()
                    }
                });
                Step::Reconcile
            }
        }
    }

    /// Stores never echo result bytes; an applied decision carries this candidate's own.
    fn applied(&self) -> Decision {
        Decision::Applied(self.candidate.candidate().result.clone())
    }

    fn audit(&self, diagnostic: &'static Diagnostic, detail: impl FnOnce() -> String) {
        let id = self.candidate.candidate().id;
        let (slot, seq) = self.key.map_or((0, 0), CommitKey::wire);
        crate::diag_warn!(
            diagnostic,
            dataset = ?id.dataset.0,
            writer = ?id.writer,
            slot,
            seq,
            detail = %detail(),
            "store commit needs attention"
        );
        self.lock().audited = Some(diagnostic);
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|poisoned| {
            let mut inner = poisoned.into_inner();
            inner.phase = Phase::Reconcile;
            inner
        })
    }
}

enum Step {
    Resolved(Decision),
    NoEffect(Failure, NoEffectCause),
    Uncertain,
    Reconcile,
    Readback(SelfFenced, NotApplied),
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
