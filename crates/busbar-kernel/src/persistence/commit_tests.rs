// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! STORE-TRANSACTIONS §2.3: the decision table, ResolveByReadback and test 8.15.

use super::*;
use busbar_contract::persistence::{
    control, AttemptId, Call, Candidate, ClockObservation, DatasetId, Durability, Page, Predicate,
    Scan, TimeGuard, CANDIDATE_VERSION,
};
use busbar_contract::plugin::TestKernelSeal;
use futures::FutureExt;
use std::collections::VecDeque;

type Reply = Option<Result<Decision, Failure>>;

#[derive(Default)]
struct Backend {
    replies: Mutex<VecDeque<Reply>>,
    reads: Mutex<VecDeque<Result<ReadResult, Failure>>>,
    sent: Mutex<Vec<([u8; 32], CommitKey)>>,
    read_calls: Mutex<usize>,
}
impl Backend {
    fn new(replies: Vec<Reply>) -> Arc<Self> {
        Arc::new(Self {
            replies: Mutex::new(replies.into()),
            ..Self::default()
        })
    }
    fn reading(self: Arc<Self>, reads: Vec<Result<ReadResult, Failure>>) -> Arc<Self> {
        *self.reads.lock().unwrap() = reads.into();
        self
    }
    fn calls(&self) -> usize {
        self.sent.lock().unwrap().len()
    }
}
impl PersistenceBackend for Backend {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            dataset: DatasetId([1; 16]),
            atomic_domain: [2; 16],
            clock_authority: [3; 16],
            physical_version: 2,
            durability: Durability::Local,
        }
    }
    fn read(&self, _: Arc<Read>) -> Call<'_, ReadResult> {
        *self.read_calls.lock().unwrap() += 1;
        let reply = self
            .reads
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(Failure::Unavailable));
        Box::pin(async move { reply })
    }
    fn scan(&self, _: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async { Err(Failure::Unavailable) })
    }
    fn clock(&self, _: DatasetId) -> Call<'_, ClockObservation> {
        Box::pin(async { Err(Failure::Unavailable) })
    }
    fn commit(&self, candidate: PreparedCandidate, key: CommitKey) -> Call<'_, Decision> {
        self.sent
            .lock()
            .unwrap()
            .push((candidate.fingerprint(), key));
        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("scripted call");
        Box::pin(async move {
            match reply {
                Some(reply) => reply,
                None => std::future::pending().await,
            }
        })
    }
}

fn key() -> CommitKey {
    super::super::slot_seal::slotted(5, 9).unwrap()
}

fn candidate() -> PreparedCandidate {
    PreparedCandidate::new(Candidate {
        id: AttemptId {
            dataset: DatasetId([1; 16]),
            writer_epoch: 2,
            writer: [4; 16],
            execution_epoch: 3,
            operation: [5; 16],
        },
        codec: CANDIDATE_VERSION,
        predicates: vec![],
        mutations: vec![Mutation::Delete(Address {
            namespace: [6; 16],
            key: vec![7],
        })],
        time: Some(TimeGuard {
            not_before: None,
            before: Some(10),
        }),
        result: Secret::new(vec![8, 9]),
    })
    .unwrap()
}

fn slotted(backend: &Arc<Backend>) -> Attempt {
    Attempt::slotted(candidate(), key(), backend.clone()).unwrap()
}

fn applied() -> Reply {
    // Stores never echo result bytes.
    Some(Ok(Decision::Applied(Secret::new(Vec::new()))))
}

fn observed(values: Vec<Option<Vec<u8>>>) -> Result<ReadResult, Failure> {
    Ok(ReadResult::Values {
        observed_at: ClockObservation {
            authority: [3; 16],
            unix_seconds: 5,
        },
        values: values.into_iter().map(|v| v.map(Secret::new)).collect(),
    })
}

fn open() -> Vec<u8> {
    control::Writer {
        retired_through: 0,
        admitted_through: 1,
    }
    .encode()
    .unwrap()
    .to_vec()
}

fn closed(through: u64) -> Vec<u8> {
    control::Writer {
        retired_through: through,
        admitted_through: through,
    }
    .encode()
    .unwrap()
    .to_vec()
}

fn writer_address(w: u8) -> Address {
    Address {
        namespace: control::NAMESPACE.0,
        key: control::writer_key([w; 16]).to_vec(),
    }
}

/// A Register-shaped (A) candidate: W absent → open, birth record Exact → owned.
fn register() -> PreparedCandidate {
    let birth = busbar_contract::persistence::witness::birth();
    PreparedCandidate::new(Candidate {
        id: AttemptId {
            dataset: DatasetId([1; 16]),
            writer_epoch: 1,
            writer: [2; 16],
            execution_epoch: 1,
            operation: [5; 16],
        },
        codec: CANDIDATE_VERSION,
        predicates: vec![
            Predicate {
                address: writer_address(7),
                expected: ExpectedValue::Absent,
            },
            Predicate {
                address: birth.clone(),
                expected: ExpectedValue::Exact(Secret::new(b"pending".to_vec())),
            },
        ],
        mutations: vec![
            Mutation::Put {
                address: writer_address(7),
                value: Secret::new(open()),
            },
            Mutation::Put {
                address: birth,
                value: Secret::new(b"owned".to_vec()),
            },
        ],
        time: None,
        result: Secret::new(Vec::new()),
    })
    .unwrap()
}

/// A writer-transition-shaped (E) candidate: W open → closed.
fn transition(domain_predicate: bool) -> PreparedCandidate {
    let mut predicates = vec![Predicate {
        address: writer_address(7),
        expected: ExpectedValue::Exact(Secret::new(open())),
    }];
    if domain_predicate {
        predicates.push(Predicate {
            address: Address {
                namespace: [6; 16],
                key: b"domain".to_vec(),
            },
            expected: ExpectedValue::Exact(Secret::new(b"x".to_vec())),
        });
    }
    PreparedCandidate::new(Candidate {
        id: AttemptId {
            dataset: DatasetId([1; 16]),
            writer_epoch: 1,
            writer: [2; 16],
            execution_epoch: 1,
            operation: [6; 16],
        },
        codec: CANDIDATE_VERSION,
        predicates,
        mutations: vec![Mutation::Put {
            address: writer_address(7),
            value: Secret::new(closed(1)),
        }],
        time: None,
        result: Secret::new(Vec::new()),
    })
    .unwrap()
}

fn fenced(candidate: PreparedCandidate, backend: &Arc<Backend>) -> Attempt {
    Attempt::proven(candidate, backend.clone()).unwrap()
}

fn decided(result: SubmitResult) -> Decision {
    match result {
        SubmitResult::Decided(decision) => match decision.as_ref() {
            Decision::Applied(value) => Decision::Applied(value.clone()),
            Decision::ConditionConflict => Decision::ConditionConflict,
            Decision::Fenced => Decision::Fenced,
            Decision::OpIdConflict => Decision::OpIdConflict,
            Decision::Stale => Decision::Stale,
            Decision::TimeGuardFailed { observed_at } => Decision::TimeGuardFailed {
                observed_at: *observed_at,
            },
        },
        other => panic!("expected a decision, got {other:?}"),
    }
}

#[tokio::test]
async fn cancellation_and_concurrent_submission_preserve_exact_custody() {
    let backend = Backend::new(vec![None, applied()]);
    let attempt = slotted(&backend);
    let fingerprint = attempt.candidate().fingerprint();
    let mut submission = Box::pin(attempt.submit());
    assert!(submission.as_mut().now_or_never().is_none());
    assert_eq!(attempt.state(), State::InFlight);
    assert!(matches!(attempt.submit().await, SubmitResult::Busy));
    drop(submission);
    assert_eq!(attempt.state(), State::Uncertain);
    assert!(matches!(attempt.submit().await, SubmitResult::Decided(_)));
    assert_eq!(
        *backend.sent.lock().unwrap(),
        vec![(fingerprint, key()), (fingerprint, key())],
        "every send carries the same candidate and the same (slot, seq)"
    );
}

#[tokio::test]
async fn applied_carries_the_candidates_own_result_never_store_bytes() {
    let backend = Backend::new(vec![Some(Err(Failure::Unknown)), applied()]);
    let attempt = slotted(&backend);
    assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
    let Decision::Applied(result) = decided(attempt.submit().await) else {
        panic!("applied")
    };
    assert_eq!(result, Secret::new(vec![8, 9]));
    assert!(matches!(attempt.submit().await, SubmitResult::Decided(_)));
    assert_eq!(backend.calls(), 2);
}

#[tokio::test]
async fn slotted_conflicts_after_uncertainty_are_the_slots_single_evaluation() {
    for decision in [
        Decision::ConditionConflict,
        Decision::TimeGuardFailed {
            observed_at: ClockObservation {
                authority: [3; 16],
                unix_seconds: 10,
            },
        },
        Decision::OpIdConflict,
    ] {
        let backend = Backend::new(vec![Some(Err(Failure::Unknown)), Some(Ok(decision))]);
        let attempt = slotted(&backend);
        assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
        assert!(matches!(attempt.submit().await, SubmitResult::Decided(_)));
        assert!(matches!(attempt.submit().await, SubmitResult::Decided(_)));
        assert_eq!(backend.calls(), 2);
    }
}

#[tokio::test]
async fn refusals_cannot_erase_prior_uncertainty() {
    for failure in [Failure::Refused, Failure::Overloaded] {
        let backend = Backend::new(vec![Some(Err(Failure::Unknown)), Some(Err(failure))]);
        let attempt = slotted(&backend);
        assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
        assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
        assert_eq!(backend.calls(), 2);
    }
}

#[tokio::test]
async fn first_refusal_is_no_effect_and_keeps_the_key() {
    for failure in [Failure::Refused, Failure::Overloaded] {
        let backend = Backend::new(vec![Some(Err(failure)), applied()]);
        let attempt = slotted(&backend);
        assert!(
            matches!(attempt.submit().await, SubmitResult::NoEffect(value) if value == failure)
        );
        assert_eq!(attempt.state(), State::Prepared);
        assert!(matches!(attempt.submit().await, SubmitResult::Decided(_)));
        let sent = backend.sent.lock().unwrap();
        assert_eq!(sent[0].1, sent[1].1);
    }
}

#[tokio::test]
async fn slotted_fenced_is_no_effect_first_and_audited_reconcile_in_doubt() {
    let backend = Backend::new(vec![Some(Ok(Decision::Fenced))]);
    let attempt = slotted(&backend);
    assert!(matches!(
        attempt.submit().await,
        SubmitResult::NoEffect(Failure::Refused)
    ));
    // 8.4: W applied X, the reply was lost, then W was closed (rows deleted).
    let backend = Backend::new(vec![
        Some(Err(Failure::Unknown)),
        Some(Ok(Decision::Fenced)),
    ]);
    let attempt = slotted(&backend);
    assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
    assert!(matches!(attempt.submit().await, SubmitResult::Reconcile));
    assert!(matches!(attempt.submit().await, SubmitResult::Reconcile));
    assert_eq!(
        attempt.audited().map(|d| d.code),
        Some(crate::diagnostics::STORE_COMMIT_FENCED_IN_DOUBT.code)
    );
    assert_eq!(backend.calls(), 2);
}

#[tokio::test]
async fn stale_on_a_live_attempt_is_an_audited_slot_invariant() {
    let backend = Backend::new(vec![Some(Ok(Decision::Stale))]);
    let attempt = slotted(&backend);
    assert!(matches!(attempt.submit().await, SubmitResult::NoEffect(_)));
    assert_eq!(
        attempt.audited().map(|d| d.code),
        Some(crate::diagnostics::STORE_SLOT_INVARIANT.code)
    );
    let backend = Backend::new(vec![Some(Err(Failure::Unknown)), Some(Ok(Decision::Stale))]);
    let attempt = slotted(&backend);
    assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
    assert!(matches!(attempt.submit().await, SubmitResult::Reconcile));
    assert_eq!(
        attempt.audited().map(|d| d.code),
        Some(crate::diagnostics::STORE_SLOT_INVARIANT.code)
    );
}

/// 8.15: an inconsistent TIME_GUARD_FAILED is a store fault: Reconcile on the first
/// such answer, one audit, and never resubmitted (red: Uncertain on every resubmit).
#[tokio::test]
async fn inconsistent_time_guard_is_audited_reconcile_never_uncertain() {
    let other_authority = Decision::TimeGuardFailed {
        observed_at: ClockObservation {
            authority: [99; 16],
            unix_seconds: 10,
        },
    };
    let permitted = Decision::TimeGuardFailed {
        observed_at: ClockObservation {
            authority: [3; 16],
            unix_seconds: 9,
        },
    };
    for decision in [other_authority, permitted] {
        let backend = Backend::new(vec![Some(Err(Failure::Unknown)), Some(Ok(decision))]);
        let attempt = slotted(&backend);
        assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
        assert!(matches!(attempt.submit().await, SubmitResult::Reconcile));
        for _ in 0..1_000 {
            assert!(matches!(attempt.submit().await, SubmitResult::Reconcile));
        }
        assert_eq!(backend.calls(), 2);
        assert_eq!(
            attempt.audited().map(|d| d.code),
            Some(crate::diagnostics::STORE_TIME_GUARD_INCONSISTENT.code)
        );
    }
    // A self-fenced candidate has no guard, so any TIME_GUARD_FAILED is inconsistent.
    let backend = Backend::new(vec![Some(Ok(Decision::TimeGuardFailed {
        observed_at: ClockObservation {
            authority: [3; 16],
            unix_seconds: 9,
        },
    }))]);
    let attempt = fenced(register(), &backend);
    assert!(matches!(attempt.submit().await, SubmitResult::Reconcile));
    assert_eq!(
        attempt.audited().map(|d| d.code),
        Some(crate::diagnostics::STORE_TIME_GUARD_INCONSISTENT.code)
    );
}

#[tokio::test]
async fn unexpected_failures_stay_uncertain_and_retry_the_same_key() {
    for reply in [
        Err(Failure::Unknown),
        Err(Failure::Unavailable),
        Err(Failure::Corrupt),
        Err(Failure::StaleScan),
    ] {
        let backend = Backend::new(vec![Some(reply), applied()]);
        let attempt = slotted(&backend);
        assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
        assert!(matches!(attempt.submit().await, SubmitResult::Decided(_)));
        assert_eq!(backend.calls(), 2);
    }
}

#[tokio::test]
async fn restored_candidate_never_sends() {
    let backend = Backend::new(vec![]);
    let attempt = slotted(&backend);
    let wire = attempt
        .encode_candidate(usize::MAX, &TestKernelSeal)
        .unwrap();
    let restored =
        Attempt::restore_candidate(&wire, usize::MAX, &TestKernelSeal, backend.clone()).unwrap();
    assert_eq!(restored.state(), State::Reconcile);
    assert!(matches!(restored.submit().await, SubmitResult::Reconcile));
    assert_eq!(restored.key(), None);
    assert_eq!(backend.calls(), 0);
}

#[test]
fn binding_checks_dataset_key_kind_and_proof() {
    let backend = Backend::new(vec![]);
    let mut other = Candidate {
        id: candidate().candidate().id,
        codec: CANDIDATE_VERSION,
        predicates: vec![],
        mutations: vec![Mutation::Delete(Address {
            namespace: [6; 16],
            key: vec![],
        })],
        time: None,
        result: Secret::default(),
    };
    other.id.dataset = DatasetId([99; 16]);
    assert!(matches!(
        Attempt::slotted(
            PreparedCandidate::new(other).unwrap(),
            key(),
            backend.clone()
        ),
        Err(BindError::DatasetMismatch)
    ));
    // A plain domain candidate is not self-fenced.
    assert!(matches!(
        Attempt::proven(candidate(), backend.clone()),
        Err(BindError::NotSelfFenced)
    ));
    // A proof for another candidate is refused.
    let proof = SelfFenced::check(&register()).unwrap();
    assert!(matches!(
        Attempt::self_fenced(transition(false), proof, backend.clone()),
        Err(BindError::NotSelfFenced)
    ));
    let self_key = CommitKey::self_fenced(&proof);
    assert!(matches!(
        Attempt::slotted(candidate(), self_key, backend.clone()),
        Err(BindError::Key)
    ));
    assert_eq!(backend.calls(), 0);
}

#[tokio::test]
async fn self_fenced_first_answers_are_final() {
    let backend = Backend::new(vec![Some(Ok(Decision::Fenced))]);
    let attempt = fenced(register(), &backend);
    assert!(matches!(decided(attempt.submit().await), Decision::Fenced));
    let backend = Backend::new(vec![Some(Ok(Decision::ConditionConflict))]);
    let attempt = fenced(register(), &backend);
    assert!(matches!(
        decided(attempt.submit().await),
        Decision::ConditionConflict
    ));
    assert_eq!(
        *backend.read_calls.lock().unwrap(),
        0,
        "no readback without doubt"
    );
    let sent = backend.sent.lock().unwrap();
    assert!(sent[0].1.is_self_fenced());
}

/// Readback (b): the lost-reply retry of an applied (A) candidate answers
/// CONDITION_CONFLICT; the witness is present, so it applied.
#[tokio::test]
async fn readback_absent_witness_present_is_applied() {
    let backend = Backend::new(vec![
        Some(Err(Failure::Unknown)),
        Some(Ok(Decision::ConditionConflict)),
    ])
    .reading(vec![observed(vec![Some(open()), Some(b"owned".to_vec())])]);
    let attempt = fenced(register(), &backend);
    assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
    assert!(matches!(
        decided(attempt.submit().await),
        Decision::Applied(_)
    ));
    assert_eq!(*backend.read_calls.lock().unwrap(), 1);
}

/// Readback (d) and (e): a peer won. FENCED is final; a failed no-ABA predicate
/// with the witness absent is "did not apply and never will".
#[tokio::test]
async fn readback_definitive_losses_resolve() {
    let backend = Backend::new(vec![
        Some(Err(Failure::Unknown)),
        Some(Ok(Decision::Fenced)),
    ])
    .reading(vec![observed(vec![None, Some(b"peer".to_vec())])]);
    let attempt = fenced(register(), &backend);
    assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
    assert!(matches!(decided(attempt.submit().await), Decision::Fenced));
    let backend = Backend::new(vec![
        Some(Err(Failure::Unknown)),
        Some(Ok(Decision::ConditionConflict)),
    ])
    .reading(vec![observed(vec![None, Some(b"peer".to_vec())])]);
    let attempt = fenced(register(), &backend);
    assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
    assert!(matches!(
        decided(attempt.submit().await),
        Decision::ConditionConflict
    ));
}

/// Readback (a) and (g): nothing learned, or Refused with every predicate holding,
/// stay Uncertain.
#[tokio::test]
async fn readback_without_evidence_stays_uncertain() {
    let backend = Backend::new(vec![
        Some(Err(Failure::Unknown)),
        Some(Err(Failure::Refused)),
    ])
    .reading(vec![Err(Failure::Unavailable)]);
    let attempt = fenced(register(), &backend);
    assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
    assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
    let backend = Backend::new(vec![
        Some(Err(Failure::Unknown)),
        Some(Err(Failure::Refused)),
    ])
    .reading(vec![observed(vec![None, Some(b"pending".to_vec())])]);
    let attempt = fenced(register(), &backend);
    assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
    assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
    assert_eq!(attempt.state(), State::Uncertain);
}

/// Readback (b) and (c) for an (E) witness: `== v` applied; neither `x` nor `v`
/// (W closed externally while in doubt) is audited Reconcile.
#[tokio::test]
async fn readback_exact_witness_applied_or_superseded() {
    let backend = Backend::new(vec![
        Some(Err(Failure::Unknown)),
        Some(Ok(Decision::ConditionConflict)),
    ])
    .reading(vec![observed(vec![Some(closed(1))])]);
    let attempt = fenced(transition(false), &backend);
    assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
    assert!(matches!(
        decided(attempt.submit().await),
        Decision::Applied(_)
    ));
    let backend = Backend::new(vec![
        Some(Err(Failure::Unknown)),
        Some(Ok(Decision::ConditionConflict)),
    ])
    .reading(vec![observed(vec![Some(closed(u64::MAX))])]);
    let attempt = fenced(transition(false), &backend);
    assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
    assert!(matches!(attempt.submit().await, SubmitResult::Reconcile));
    assert_eq!(
        attempt.audited().map(|d| d.code),
        Some(crate::diagnostics::STORE_SELF_FENCED_AMBIGUOUS.code)
    );
}

/// Readback (f) and (h): a failed domain predicate may return (not no-ABA), and a
/// conflict on predicates that all hold again, are audited Reconcile.
#[tokio::test]
async fn readback_ambiguity_is_audited_reconcile() {
    let backend = Backend::new(vec![
        Some(Err(Failure::Unknown)),
        Some(Ok(Decision::ConditionConflict)),
    ])
    .reading(vec![observed(vec![Some(open()), Some(b"moved".to_vec())])]);
    let attempt = fenced(transition(true), &backend);
    assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
    assert!(matches!(attempt.submit().await, SubmitResult::Reconcile));
    let backend = Backend::new(vec![
        Some(Err(Failure::Unknown)),
        Some(Ok(Decision::ConditionConflict)),
    ])
    .reading(vec![observed(vec![None, Some(b"pending".to_vec())])]);
    let attempt = fenced(register(), &backend);
    assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
    assert!(matches!(attempt.submit().await, SubmitResult::Reconcile));
    assert_eq!(
        attempt.audited().map(|d| d.code),
        Some(crate::diagnostics::STORE_SELF_FENCED_AMBIGUOUS.code)
    );
}
