// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::persistence::{
    Address, AttemptId, Call, Candidate, ClockObservation, DatasetId, Durability, Mutation, Page,
    Read, ReadResult, Scan, TimeGuard, CANDIDATE_VERSION,
};
use busbar_contract::plugin::TestKernelSeal;
use futures::FutureExt;
use std::collections::VecDeque;

struct Backend {
    replies: Mutex<VecDeque<Option<Result<Decision, Failure>>>>,
    sent: Mutex<Vec<[u8; 32]>>,
}
impl Backend {
    fn new(replies: Vec<Option<Result<Decision, Failure>>>) -> Arc<Self> {
        Arc::new(Self {
            replies: Mutex::new(replies.into()),
            sent: Mutex::new(Vec::new()),
        })
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
            physical_version: 1,
            durability: Durability::Local,
        }
    }
    fn read(&self, _: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async { Err(Failure::Unavailable) })
    }
    fn scan(&self, _: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async { Err(Failure::Unavailable) })
    }
    fn clock(&self, _: DatasetId) -> Call<'_, ClockObservation> {
        Box::pin(async { Err(Failure::Unavailable) })
    }
    fn commit(&self, candidate: PreparedCandidate) -> Call<'_, Decision> {
        self.sent.lock().unwrap().push(candidate.fingerprint());
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
fn applied() -> Option<Result<Decision, Failure>> {
    Some(Ok(Decision::Applied(Secret::new(vec![8, 9]))))
}

#[tokio::test]
async fn cancellation_and_concurrent_submission_preserve_exact_custody() {
    let backend = Backend::new(vec![None, applied()]);
    let attempt = Attempt::new(candidate(), backend.clone()).unwrap();
    let fingerprint = attempt.candidate().fingerprint();
    let snapshot = attempt
        .encode_candidate(usize::MAX, &TestKernelSeal)
        .unwrap();
    let mut submission = Box::pin(attempt.submit());
    assert!(submission.as_mut().now_or_never().is_none());
    let first_send = attempt.lock().first_send;
    assert_eq!(attempt.state(), State::InFlight);
    assert!(matches!(attempt.submit().await, SubmitResult::Busy));
    assert_eq!(backend.calls(), 1);
    drop(submission);
    assert_eq!(attempt.state(), State::Uncertain);
    assert_eq!(attempt.candidate().fingerprint(), fingerprint);
    assert_eq!(
        attempt
            .encode_candidate(usize::MAX, &TestKernelSeal)
            .unwrap(),
        snapshot
    );
    assert!(matches!(attempt.submit().await, SubmitResult::Decided(_)));
    assert_eq!(attempt.lock().first_send, first_send);
    assert_eq!(
        *backend.sent.lock().unwrap(),
        vec![fingerprint, fingerprint]
    );
}

#[tokio::test]
async fn lost_reply_retries_exactly_and_caches_the_matching_receipt() {
    let backend = Backend::new(vec![Some(Err(Failure::Unknown)), applied()]);
    let attempt = Attempt::new(candidate(), backend.clone()).unwrap();
    assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
    let first_send = attempt.lock().first_send;
    let SubmitResult::Decided(first) = attempt.submit().await else {
        panic!("receipt")
    };
    let SubmitResult::Decided(second) = attempt.submit().await else {
        panic!("cached receipt")
    };
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(attempt.state(), State::Resolved);
    assert_eq!(attempt.lock().first_send, first_send);
    assert_eq!(backend.calls(), 2);
    let sent = backend.sent.lock().unwrap();
    assert_eq!(sent[0], sent[1]);
}

#[tokio::test]
async fn refusals_cannot_erase_prior_uncertainty() {
    for failure in [Failure::Refused, Failure::Overloaded] {
        let backend = Backend::new(vec![Some(Err(Failure::Unknown)), Some(Err(failure))]);
        let attempt = Attempt::new(candidate(), backend.clone()).unwrap();
        assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
        assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
        assert_eq!(attempt.state(), State::Uncertain);
        assert_eq!(backend.calls(), 2);
    }
}

#[tokio::test]
async fn later_conflicts_require_reconciliation_and_never_resend() {
    for decision in [
        Decision::ConditionConflict,
        Decision::OpIdConflict,
        Decision::TimeGuardFailed {
            observed_at: ClockObservation {
                authority: [3; 16],
                unix_seconds: 10,
            },
        },
        Decision::ExpiredUnknown,
    ] {
        let backend = Backend::new(vec![Some(Err(Failure::Unknown)), Some(Ok(decision))]);
        let attempt = Attempt::new(candidate(), backend.clone()).unwrap();
        assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
        assert!(matches!(attempt.submit().await, SubmitResult::Reconcile));
        assert!(matches!(attempt.submit().await, SubmitResult::Reconcile));
        assert_eq!(backend.calls(), 2);
    }
}

#[tokio::test]
async fn first_refusal_retains_candidate_and_first_send() {
    for failure in [Failure::Refused, Failure::Overloaded] {
        let backend = Backend::new(vec![Some(Err(failure)), applied()]);
        let attempt = Attempt::new(candidate(), backend.clone()).unwrap();
        assert!(
            matches!(attempt.submit().await, SubmitResult::NoEffect(value) if value == failure)
        );
        assert_eq!(attempt.state(), State::Prepared);
        let first_send = attempt.lock().first_send;
        assert!(matches!(attempt.submit().await, SubmitResult::Decided(_)));
        assert_eq!(attempt.lock().first_send, first_send);
        assert_eq!(backend.calls(), 2);
    }
}

#[tokio::test]
async fn original_horizon_boundary_prohibits_another_crossing() {
    let backend = Backend::new(vec![Some(Err(Failure::Unknown))]);
    let attempt = Attempt::new(candidate(), backend.clone()).unwrap();
    assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
    attempt.lock().first_send = Some(Instant::now() - REPLAY_HORIZON);
    let first_send = attempt.lock().first_send;
    assert!(matches!(attempt.submit().await, SubmitResult::Reconcile));
    assert!(matches!(attempt.submit().await, SubmitResult::Reconcile));
    assert_eq!(attempt.lock().first_send, first_send);
    assert_eq!(backend.calls(), 1);
    assert!(attempt
        .encode_candidate(usize::MAX, &TestKernelSeal)
        .is_ok());
}

#[tokio::test]
async fn restored_candidate_cannot_send_without_a_trustworthy_clock() {
    let backend = Backend::new(vec![]);
    let attempt = Attempt::new(candidate(), backend.clone()).unwrap();
    let wire = attempt
        .encode_candidate(usize::MAX, &TestKernelSeal)
        .unwrap();
    let restored =
        Attempt::restore_candidate(&wire, usize::MAX, &TestKernelSeal, backend.clone()).unwrap();
    assert_eq!(restored.state(), State::Reconcile);
    assert!(matches!(restored.submit().await, SubmitResult::Reconcile));
    assert_eq!(
        restored.candidate().fingerprint(),
        attempt.candidate().fingerprint()
    );
    assert_eq!(backend.calls(), 0);
}

#[tokio::test]
async fn malformed_results_and_unexpected_failures_cannot_publish() {
    for reply in [
        Ok(Decision::Applied(Secret::new(vec![0]))),
        Ok(Decision::TimeGuardFailed {
            observed_at: ClockObservation {
                authority: [99; 16],
                unix_seconds: 10,
            },
        }),
        Ok(Decision::TimeGuardFailed {
            observed_at: ClockObservation {
                authority: [3; 16],
                unix_seconds: 9,
            },
        }),
        Err(Failure::Unavailable),
        Err(Failure::Corrupt),
        Err(Failure::StaleScan),
    ] {
        let backend = Backend::new(vec![Some(reply), applied()]);
        let attempt = Attempt::new(candidate(), backend.clone()).unwrap();
        assert!(matches!(attempt.submit().await, SubmitResult::Uncertain));
        assert_eq!(attempt.state(), State::Uncertain);
        assert!(matches!(attempt.submit().await, SubmitResult::Decided(_)));
        assert_eq!(backend.calls(), 2);
    }
}

#[tokio::test]
async fn first_conflicts_are_cached_but_expired_unknown_is_never_decided() {
    for decision in [
        Decision::ConditionConflict,
        Decision::OpIdConflict,
        Decision::TimeGuardFailed {
            observed_at: ClockObservation {
                authority: [3; 16],
                unix_seconds: 10,
            },
        },
    ] {
        let backend = Backend::new(vec![Some(Ok(decision))]);
        let attempt = Attempt::new(candidate(), backend.clone()).unwrap();
        assert!(matches!(attempt.submit().await, SubmitResult::Decided(_)));
        assert!(matches!(attempt.submit().await, SubmitResult::Decided(_)));
        assert_eq!(backend.calls(), 1);
    }
    let backend = Backend::new(vec![Some(Ok(Decision::ExpiredUnknown))]);
    let attempt = Attempt::new(candidate(), backend.clone()).unwrap();
    assert!(matches!(attempt.submit().await, SubmitResult::Reconcile));
    assert!(matches!(attempt.submit().await, SubmitResult::Reconcile));
    assert_eq!(backend.calls(), 1);
}

#[test]
fn dataset_mismatch_is_rejected_before_crossing() {
    let original = candidate();
    let mut candidate = Candidate {
        id: original.candidate().id,
        codec: CANDIDATE_VERSION,
        predicates: vec![],
        mutations: vec![Mutation::Delete(Address {
            namespace: [6; 16],
            key: vec![],
        })],
        time: None,
        result: Secret::default(),
    };
    candidate.id.dataset = DatasetId([99; 16]);
    let backend = Backend::new(vec![]);
    assert!(matches!(
        Attempt::new(PreparedCandidate::new(candidate).unwrap(), backend.clone()),
        Err(DatasetMismatch)
    ));
    assert_eq!(backend.calls(), 0);
}
