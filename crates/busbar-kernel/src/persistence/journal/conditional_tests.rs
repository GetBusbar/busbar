// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::persistence::scoped::{self, ScopedStore};
use runtime::ConditionalOutcome;

async fn owner(store: Arc<CoreStore>, node: u64) -> Arc<RuntimeJournal> {
    RuntimeJournal::open(
        store,
        node,
        BufferBudget {
            records: 4,
            bytes: 4096,
        },
    )
    .await
    .unwrap()
}

fn entry(value: u8) -> busbar_kernel_wal::Entry {
    busbar_kernel_wal::Entry::new(RecordClass::Transaction, vec![value])
}

fn scope(store: Arc<CoreStore>) -> ScopedStore {
    ScopedStore::host_private(store, "receipt-test", ["receipts".to_string()]).unwrap()
}

fn participant(
    scope: &ScopedStore,
    record: &Record,
) -> std::result::Result<scoped::PreparedRows, scoped::Error> {
    scope.prepare_participant(
        &[scoped::Predicate {
            schema: "receipts".into(),
            key: b"publication".to_vec(),
            expected: scoped::Expected::Absent,
        }],
        &[scoped::Mutation::Put {
            schema: "receipts".into(),
            key: b"publication".to_vec(),
            value: Secret::new(record.node.to_be_bytes().to_vec()),
        }],
        4096,
    )
}

#[tokio::test]
async fn conditional_reservation_closes_successor_sealing_before_draining() {
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend.clone(), 4).await);
    let owner = owner(store.clone(), 7).await;
    let prior = owner.stage_run(&[entry(1)]).unwrap();
    let original = prior.records()[0].body.clone();
    let reserved = owner.reserve_conditional().unwrap();
    assert!(matches!(
        owner.stage_run(&[entry(2)]),
        Err(RuntimeError::Pending)
    ));
    backend.hold_first.store(true, Ordering::SeqCst);
    let preparing = tokio::spawn(async move {
        reserved
            .prepare(entry(3), |record| participant(&scope(store), record))
            .await
            .unwrap();
        reserved
    });
    for _ in 0..100 {
        if !backend.state.lock().unwrap().sent.is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(backend.state.lock().unwrap().sent.len(), 1);
    assert!(matches!(
        owner.stage_run(&[entry(2)]),
        Err(RuntimeError::Pending)
    ));
    backend.release_first.notify_one();
    let reserved = preparing.await.unwrap();
    owner.confirm(&prior).await.unwrap();
    assert_eq!(prior.records()[0].body, original);
    assert_eq!(
        owner.next_seq(),
        2,
        "private J must not reserve public ancestry"
    );
    assert_eq!(reserved.drive().await.unwrap(), ConditionalOutcome::Applied);
    assert!(matches!(
        owner.stage_run(&[entry(2)]),
        Err(RuntimeError::Pending)
    ));
    reserved.finish().await.unwrap();
    let successor = owner.stage_run(&[entry(4)]).unwrap();
    owner.confirm(&successor).await.unwrap();
    assert_eq!(successor.records()[0].node_seq, 3);
    assert_eq!(owner.failed(), None);
}

#[tokio::test]
async fn two_node_loser_keeps_ordinary_ancestry_and_does_not_poison_lane() {
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend.clone(), 4).await);
    let a = owner(store.clone(), 7).await;
    let b = owner(store.clone(), 8).await;
    let a_j = a.reserve_conditional().unwrap();
    let b_j = b.reserve_conditional().unwrap();
    let receipts = scope(store);
    a_j.prepare(entry(10), |r| participant(&receipts, r))
        .await
        .unwrap();
    b_j.prepare(entry(20), |r| participant(&receipts, r))
        .await
        .unwrap();
    assert_eq!(b_j.drive().await.unwrap(), ConditionalOutcome::Applied);
    b_j.finish().await.unwrap();
    assert_eq!(a_j.drive().await.unwrap(), ConditionalOutcome::Conflict);
    a_j.finish().await.unwrap();
    assert_eq!(a.next_seq(), 1);
    assert_eq!(a.failed(), None);
    let run = a.stage_run(&[entry(30)]).unwrap();
    a.confirm(&run).await.unwrap();
    assert_eq!(run.records()[0].node_seq, 1);
    assert_eq!(
        receipts
            .get("receipts", b"publication")
            .await
            .unwrap()
            .unwrap()
            .expose(&crate::seal::lend()),
        &8u64.to_be_bytes()
    );
    assert_eq!(
        a.read_records(BufferBudget {
            records: 4,
            bytes: 4096
        })
        .await
        .unwrap()
        .len(),
        1
    );
}

#[tokio::test]
async fn canceled_native_waiter_retains_exact_candidate_and_sealing_barrier() {
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend.clone(), 4).await);
    let owner = owner(store.clone(), 7).await;
    let reserved = owner.reserve_conditional().unwrap();
    reserved
        .prepare(entry(1), |r| participant(&scope(store), r))
        .await
        .unwrap();
    backend.hang.store(true, Ordering::SeqCst);
    let task = tokio::spawn(async move { reserved.drive().await });
    for _ in 0..100 {
        if !backend.state.lock().unwrap().sent.is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(backend.state.lock().unwrap().sent.len(), 1);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(matches!(
        owner.stage_run(&[entry(2)]),
        Err(RuntimeError::Pending)
    ));
    assert_eq!(owner.flush().await, Err(RuntimeError::Pending));
    backend.hang.store(false, Ordering::SeqCst);
    let retained = owner.retained_conditional().unwrap().unwrap();
    assert_eq!(retained.drive().await.unwrap(), ConditionalOutcome::Applied);
    retained.finish().await.unwrap();
    let sent = &backend.state.lock().unwrap().sent;
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].candidate().id, sent[1].candidate().id);
    assert_eq!(sent[0].fingerprint(), sent[1].fingerprint());
    assert!(owner.stage_run(&[entry(2)]).is_ok());
}

#[tokio::test]
async fn unknown_applied_j_keeps_barrier_until_owner_publication() {
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend.clone(), 4).await);
    let owner = owner(store.clone(), 7).await;
    let reserved = owner.reserve_conditional().unwrap();
    reserved
        .prepare(entry(1), |r| participant(&scope(store), r))
        .await
        .unwrap();
    backend.lose_reply.store(true, Ordering::SeqCst);
    assert_eq!(reserved.drive().await, Err(RuntimeError::Pending));
    assert_eq!(owner.next_seq(), 1);
    drop(reserved);
    let retained = owner.retained_conditional().unwrap().unwrap();
    assert_eq!(retained.drive().await.unwrap(), ConditionalOutcome::Applied);
    drop(retained);
    assert!(matches!(
        owner.stage_run(&[entry(2)]),
        Err(RuntimeError::Pending)
    ));
    let retained = owner.retained_conditional().unwrap().unwrap();
    assert_eq!(retained.original().unwrap().node_seq, 1);
    retained.finish().await.unwrap();
    assert_eq!(owner.next_seq(), 2);
    assert_eq!(owner.pending_records(), 0);
}

#[tokio::test]
async fn abandoned_unsubmitted_reservation_and_foreign_participant_have_no_effect() {
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend.clone(), 4).await);
    let other = Arc::new(attach(backend.clone(), 4).await);
    let owner = owner(store, 7).await;
    let reserved = owner.reserve_conditional().unwrap();
    assert!(matches!(
        reserved
            .prepare(entry(1), |r| participant(&scope(other), r))
            .await,
        Err(RuntimeError::Authority)
    ));
    drop(reserved);
    assert!(backend.state.lock().unwrap().sent.is_empty());
    assert!(owner.stage_run(&[entry(2)]).is_ok());
}

#[tokio::test]
async fn participant_budget_and_scope_refusals_submit_nothing() {
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend.clone(), 4).await);
    let mutations = vec![scoped::Mutation::Put {
        schema: "receipts".into(),
        key: b"p".to_vec(),
        value: Secret::new(vec![1]),
    }];
    assert!(matches!(
        scope(store.clone()).prepare_participant(&[], &mutations, 0),
        Err(scoped::Error::Access(
            crate::persistence::facade::AccessError::Overloaded
        ))
    ));
    let untrusted = ScopedStore::authorized(store, "receipt-test", ["receipts"]).unwrap();
    assert!(matches!(
        untrusted.prepare_participant(&[], &mutations, 4096),
        Err(scoped::Error::Unauthorized)
    ));
    assert!(backend.state.lock().unwrap().sent.is_empty());
}

#[tokio::test]
async fn conditional_reconciliation_does_not_release_or_replace_the_original() {
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend.clone(), 4).await);
    let owner = owner(store.clone(), 7).await;
    let reserved = owner.reserve_conditional().unwrap();
    reserved
        .prepare(entry(1), |r| participant(&scope(store), r))
        .await
        .unwrap();
    backend.lose_reply.store(true, Ordering::SeqCst);
    assert_eq!(reserved.drive().await, Err(RuntimeError::Pending));
    backend.state.lock().unwrap().receipts.clear();
    backend.expire_receipt.store(true, Ordering::SeqCst);
    assert_eq!(reserved.drive().await, Err(RuntimeError::Reconcile));
    assert_eq!(reserved.drive().await, Err(RuntimeError::Reconcile));
    assert_eq!(owner.pending_records(), 1);
    assert!(matches!(
        owner.stage_run(&[entry(2)]),
        Err(RuntimeError::Pending)
    ));
    assert_eq!(reserved.finish().await, Err(RuntimeError::Pending));
    assert!(owner.retained_conditional().unwrap().is_some());
    assert_eq!(backend.state.lock().unwrap().sent.len(), 2);
}
