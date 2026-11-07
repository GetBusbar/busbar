// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::persistence::{
    Call, Candidate, ClockObservation, DatasetId, Decision, Durability, Mutation, Page, Scan,
    CANDIDATE_VERSION,
};
use busbar_contract::Secret;
use futures::FutureExt;
use std::collections::VecDeque;

type Reply = Option<Result<Decision, Failure>>;

struct Backend {
    root: control::Dataset,
    writer: control::Writer,
    replies: Mutex<VecDeque<Reply>>,
    sent: Mutex<Vec<[u8; 32]>>,
}

impl Backend {
    fn new(replies: Vec<Reply>) -> Self {
        Self {
            root: control::Dataset {
                id: DatasetId([1; 16]),
                writer_epoch: 2,
            },
            writer: control::Writer {
                retired_through: 2,
                admitted_through: 3,
            },
            replies: Mutex::new(replies.into()),
            sent: Mutex::new(Vec::new()),
        }
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
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        assert_eq!(request.dataset, self.info().dataset);
        assert_eq!(
            request.addresses,
            vec![
                Address {
                    namespace: control::NAMESPACE.0,
                    key: control::DATASET_KEY.to_vec()
                },
                Address {
                    namespace: control::NAMESPACE.0,
                    key: control::writer_key([4; 16]).to_vec()
                },
            ]
        );
        Box::pin(async move {
            Ok(ReadResult::Values {
                observed_at: ClockObservation {
                    authority: [3; 16],
                    unix_seconds: 10,
                },
                values: vec![
                    Some(Secret::new(self.root.encode().unwrap().to_vec())),
                    Some(Secret::new(self.writer.encode().unwrap().to_vec())),
                ],
            })
        })
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
            .expect("scripted native crossing");
        Box::pin(async move {
            match reply {
                Some(result) => result,
                None => std::future::pending().await,
            }
        })
    }
}

fn authority() -> WriterAuthority {
    WriterAuthority {
        writer_epoch: 2,
        writer: [4; 16],
        execution_epoch: 3,
    }
}
fn limits() -> Limits {
    Limits {
        pending_operations: 1,
        conflict_retries: 2,
        scan_items: 100,
        scan_bytes: 4096,
    }
}
fn candidate(store: &CoreStore, operation: u8, value: u8) -> PreparedCandidate {
    let mut id = store.next_id().unwrap();
    id.operation = [operation; 16];
    PreparedCandidate::new(Candidate {
        id,
        codec: CANDIDATE_VERSION,
        predicates: vec![],
        mutations: vec![Mutation::Put {
            address: Address {
                namespace: [8; 16],
                key: vec![9],
            },
            value: Secret::new(vec![value]),
        }],
        time: None,
        result: Secret::new(vec![]),
    })
    .unwrap()
}
fn applied() -> Reply {
    Some(Ok(Decision::Applied(Secret::new(vec![]))))
}

#[tokio::test]
async fn attachment_requires_the_registered_live_incarnation() {
    let backend = Arc::new(Backend::new(vec![]));
    let store = CoreStore::attach(backend.clone(), authority(), limits())
        .await
        .unwrap();
    assert_eq!(store.backend().info(), backend.info());
    assert_eq!(store.limits().conflict_retries, 2);
    for changed in [
        WriterAuthority {
            writer_epoch: 1,
            ..authority()
        },
        WriterAuthority {
            execution_epoch: 2,
            ..authority()
        },
        WriterAuthority {
            execution_epoch: 4,
            ..authority()
        },
    ] {
        assert!(matches!(
            CoreStore::attach(backend.clone(), changed, limits()).await,
            Err(AccessError::Authority)
        ));
    }
    let invalid = Limits {
        pending_operations: 0,
        ..limits()
    };
    assert!(matches!(
        CoreStore::attach(backend, authority(), invalid).await,
        Err(AccessError::InvalidLimits)
    ));
    let mut corrupt = Backend::new(vec![]);
    corrupt.root.id = DatasetId([9; 16]);
    assert!(matches!(
        CoreStore::attach(Arc::new(corrupt), authority(), limits()).await,
        Err(AccessError::Corrupt)
    ));
}

#[tokio::test]
async fn pressure_and_shutdown_preserve_unknown_work_for_exact_replay() {
    let backend = Arc::new(Backend::new(vec![Some(Err(Failure::Unknown)), applied()]));
    let store = CoreStore::attach(backend.clone(), authority(), limits())
        .await
        .unwrap();
    let first = candidate(&store, 1, 2);
    let another = candidate(&store, 2, 3);
    let changed = candidate(&store, 1, 4);
    let sent = store.submit(first.clone()).await.unwrap();
    assert!(matches!(sent.result, SubmitResult::Uncertain));
    assert!(matches!(
        store.submit(another).await,
        Err(AccessError::Overloaded)
    ));
    assert!(matches!(
        store.submit(changed).await,
        Err(AccessError::OperationConflict)
    ));
    assert_eq!(store.stop_admission().unwrap(), vec![sent.id]);
    assert!(matches!(
        store.submit(first).await,
        Err(AccessError::Closed)
    ));
    assert!(matches!(store.next_id(), Err(AccessError::Closed)));
    assert!(matches!(
        store.retry(sent.id).await.unwrap().result,
        SubmitResult::Decided(_)
    ));
    assert!(store.stop_admission().unwrap().is_empty());
    let sent = backend.sent.lock().unwrap();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0], sent[1]);
}

#[tokio::test]
async fn cancellation_keeps_candidate_and_concurrent_waiter_cannot_remove_it() {
    let backend = Arc::new(Backend::new(vec![None, applied()]));
    let store = CoreStore::attach(backend.clone(), authority(), limits())
        .await
        .unwrap();
    let candidate = candidate(&store, 1, 2);
    let id = PendingId(candidate.candidate().id.operation);
    let mut future = Box::pin(store.submit(candidate.clone()));
    assert!(future.as_mut().now_or_never().is_none());
    assert!(matches!(
        store.retry(id).await.unwrap().result,
        SubmitResult::Busy
    ));
    assert!(matches!(
        store.submit(candidate).await.unwrap().result,
        SubmitResult::Busy
    ));
    assert_eq!(backend.sent.lock().unwrap().len(), 1);
    drop(future);
    assert_eq!(store.stop_admission().unwrap(), vec![id]);
    assert!(matches!(
        store.retry(id).await.unwrap().result,
        SubmitResult::Decided(_)
    ));
    assert_eq!(backend.sent.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn definitive_refusal_releases_capacity_but_later_refusal_cannot_erase_unknown() {
    let backend = Arc::new(Backend::new(vec![
        Some(Err(Failure::Refused)),
        Some(Err(Failure::Unknown)),
        Some(Err(Failure::Refused)),
    ]));
    let store = CoreStore::attach(backend, authority(), limits())
        .await
        .unwrap();
    assert!(matches!(
        store.submit(candidate(&store, 1, 2)).await.unwrap().result,
        SubmitResult::NoEffect(Failure::Refused)
    ));
    let sent = store.submit(candidate(&store, 2, 3)).await.unwrap();
    assert!(matches!(sent.result, SubmitResult::Uncertain));
    assert!(matches!(
        store.retry(sent.id).await.unwrap().result,
        SubmitResult::Uncertain
    ));
    assert_eq!(store.stop_admission().unwrap(), vec![sent.id]);
}

fn logical_id() -> LogicalId {
    LogicalId {
        namespace: [10; 16],
        operation: [11; 16],
    }
}

#[tokio::test]
async fn logical_planning_is_exclusive_and_abandoned_plan_releases_its_claim() {
    let store = CoreStore::attach(Arc::new(Backend::new(vec![])), authority(), limits())
        .await
        .unwrap();
    let LogicalClaim::Prepare(permit) = store.claim_logical(logical_id(), [1; 32]).unwrap() else {
        panic!("fresh planner")
    };
    assert!(matches!(
        store.claim_logical(logical_id(), [1; 32]).unwrap(),
        LogicalClaim::Busy
    ));
    assert!(matches!(
        store.claim_logical(logical_id(), [2; 32]),
        Err(AccessError::OperationConflict)
    ));
    let another = LogicalId {
        operation: [12; 16],
        ..logical_id()
    };
    assert!(matches!(
        store.claim_logical(another, [1; 32]),
        Err(AccessError::Overloaded)
    ));
    drop(permit);
    assert!(matches!(
        store.claim_logical(logical_id(), [2; 32]).unwrap(),
        LogicalClaim::Prepare(_)
    ));
}

#[tokio::test]
async fn logical_unknown_and_cancel_bind_exact_attempt_before_crossing() {
    for first in [None, Some(Err(Failure::Unknown))] {
        let backend = Arc::new(Backend::new(vec![first, applied()]));
        let store = CoreStore::attach(backend.clone(), authority(), limits())
            .await
            .unwrap();
        let LogicalClaim::Prepare(permit) = store.claim_logical(logical_id(), [1; 32]).unwrap()
        else {
            panic!("fresh planner")
        };
        let prepared = candidate(&store, 1, 2);
        let mut future = Box::pin(permit.submit(prepared));
        if let Some(answer) = future.as_mut().now_or_never() {
            assert!(matches!(answer.unwrap().result, SubmitResult::Uncertain));
        }
        drop(future);
        let LogicalClaim::Retained(id) = store.claim_logical(logical_id(), [1; 32]).unwrap() else {
            panic!("must replay exact attempt")
        };
        assert!(matches!(
            store.claim_logical(logical_id(), [2; 32]),
            Err(AccessError::OperationConflict)
        ));
        assert!(matches!(
            store.retry(id).await.unwrap().result,
            SubmitResult::Decided(_)
        ));
        assert!(matches!(
            store.claim_logical(logical_id(), [1; 32]).unwrap(),
            LogicalClaim::Prepare(_)
        ));
        let sent = backend.sent.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0], sent[1]);
    }
}

#[tokio::test]
async fn promotion_only_changes_epoch_and_preserves_exact_old_custody() {
    let backend = Arc::new(Backend::new(vec![Some(Err(Failure::Unknown)), applied()]));
    let store = CoreStore::attach(backend.clone(), authority(), limits())
        .await
        .unwrap();
    let prepared = candidate(&store, 1, 2);
    let stale = candidate(&store, 2, 3);
    let pending = store.submit(prepared.clone()).await.unwrap();
    let next = WriterAuthority {
        execution_epoch: 4,
        ..authority()
    };
    for invalid in [
        authority(),
        WriterAuthority {
            execution_epoch: 5,
            ..next
        },
        WriterAuthority {
            writer: [5; 16],
            ..next
        },
        WriterAuthority {
            writer_epoch: 3,
            ..next
        },
    ] {
        assert_eq!(
            store.promote_authority(invalid),
            Err(AccessError::Authority)
        );
    }
    store.promote_authority(next).unwrap();
    assert_eq!(store.next_id().unwrap().execution_epoch, 4);
    assert!(!store.epoch_drained(3).unwrap());
    assert_eq!(store.epoch_drained(4), Err(AccessError::Authority));
    assert!(matches!(
        store.submit(stale).await,
        Err(AccessError::Authority)
    ));
    assert!(matches!(
        store.retry(pending.id).await.unwrap().result,
        SubmitResult::Decided(_)
    ));
    assert!(store.epoch_drained(3).unwrap());
    let sent = backend.sent.lock().unwrap();
    assert_eq!(&*sent, &[prepared.fingerprint(), prepared.fingerprint()]);
}

#[tokio::test]
async fn promotion_preserves_closed_admission_and_rejects_overflow() {
    let store = CoreStore::attach(Arc::new(Backend::new(vec![])), authority(), limits())
        .await
        .unwrap();
    store.stop_admission().unwrap();
    store
        .promote_authority(WriterAuthority {
            execution_epoch: 4,
            ..authority()
        })
        .unwrap();
    assert!(matches!(store.next_id(), Err(AccessError::Closed)));
    store.pending.lock().unwrap().authority.execution_epoch = u64::MAX;
    assert_eq!(
        store.promote_authority(WriterAuthority {
            execution_epoch: 0,
            ..authority()
        }),
        Err(AccessError::Authority)
    );
}
