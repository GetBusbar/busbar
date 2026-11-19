// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The request path's money flag (`admits_money`, one lock-free read) always equals the locked
//! answer (`refuses_money`) after every change to what the journal can record.

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

/// The flag and the locked answer agree; returns whether money is admitted.
#[track_caller]
fn agreed(owner: &RuntimeJournal) -> bool {
    let admits = owner.admits_money();
    assert_eq!(
        admits,
        owner.refuses_money().is_none(),
        "flag {admits} disagrees with the locked answer {:?}",
        owner.refuses_money()
    );
    admits
}

#[tokio::test]
async fn money_flag_follows_the_custody_buffer_filling_and_draining() {
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend, 4).await);
    let owner = owner(store, 7).await;
    assert!(agreed(&owner), "a fresh journal admits money");
    owner.stage_run(&[entry(1), entry(2), entry(3)]).unwrap();
    assert!(agreed(&owner), "below the record budget");
    owner.stage_run(&[entry(4)]).unwrap();
    assert!(!agreed(&owner), "a full custody buffer refuses money");
    owner.flush().await.unwrap();
    assert!(agreed(&owner), "draining the buffer re-admits at once");
}

#[tokio::test]
async fn money_flag_follows_a_conditional_publication_from_reserve_to_finish() {
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend, 4).await);
    let owner = owner(store.clone(), 7).await;
    let reserved = owner.reserve_conditional().unwrap();
    assert!(!agreed(&owner), "a reserved conditional slot refuses money");
    drop(reserved);
    assert!(agreed(&owner), "dropping an unprepared slot re-admits");
    let reserved = owner.reserve_conditional().unwrap();
    let scope = ScopedStore::host_private(store, "receipt-test", ["receipts".to_string()]).unwrap();
    reserved
        .prepare(entry(1), |record| {
            scope.prepare_participant(
                &[],
                &[scoped::Mutation::Put {
                    schema: "receipts".into(),
                    key: b"publication".to_vec(),
                    value: Secret::new(record.node.to_be_bytes().to_vec()),
                }],
                4096,
            )
        })
        .await
        .unwrap();
    assert!(!agreed(&owner), "a prepared slot refuses money");
    assert_eq!(reserved.drive().await.unwrap(), ConditionalOutcome::Applied);
    assert!(
        !agreed(&owner),
        "an applied but unfinished slot refuses money"
    );
    reserved.finish().await.unwrap();
    assert!(agreed(&owner), "finishing the publication re-admits");
}

#[tokio::test]
async fn money_flag_follows_a_custody_failure_and_closed_staging() {
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend.clone(), 4).await);
    let owner = owner(store.clone(), 7).await;
    let run = owner.stage_run(&[entry(1)]).unwrap();
    backend.lose_reply.store(true, Ordering::SeqCst);
    assert_eq!(owner.confirm(&run).await, Err(RuntimeError::Pending));
    backend.state.lock().unwrap().receipts.clear();
    backend.expire_receipt.store(true, Ordering::SeqCst);
    assert_eq!(owner.confirm(&run).await, Err(RuntimeError::Reconcile));
    assert_eq!(owner.failed(), Some(RuntimeError::Reconcile));
    assert!(!agreed(&owner), "a failed journal refuses money");

    let closing = self::owner(store, 8).await;
    assert!(agreed(&closing));
    closing.stop_staging().unwrap();
    assert!(!agreed(&closing), "closed staging refuses money");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn money_flag_matches_the_locked_answer_after_concurrent_transitions() {
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend, 4).await);
    let owner = owner(store, 7).await;
    for round in 0..64u8 {
        let stagers: Vec<_> = (0..3u8)
            .map(|i| {
                let owner = owner.clone();
                tokio::spawn(async move {
                    // A full buffer refuses the stage; that is one of the transitions under test.
                    let _ = owner.stage_run(&[entry(round), entry(i)]);
                })
            })
            .collect();
        let flusher = {
            let owner = owner.clone();
            tokio::spawn(async move { owner.flush().await })
        };
        for stager in stagers {
            stager.await.unwrap();
        }
        flusher.await.unwrap().unwrap();
        // Whether this round ended full depends on scheduling; either way the two agree.
        agreed(&owner);
    }
    owner.flush().await.unwrap();
    assert!(agreed(&owner), "a drained journal admits");
}

#[tokio::test]
async fn a_stalled_flusher_refuses_money_on_the_one_flag_but_never_its_own_staging() {
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend, 4).await);
    let owner = owner(store, 7).await;
    owner.set_flusher_stalled(true);
    assert!(!agreed(&owner), "a stalled flusher refuses money");
    assert!(
        owner.refuses_staging().is_none(),
        "the flusher's own report never stops its recovery"
    );
    owner.stage_run(&[entry(1)]).unwrap();
    owner.flush().await.unwrap();
    assert!(
        !agreed(&owner),
        "a commit by others does not clear the flusher's report"
    );
    owner.set_flusher_stalled(false);
    assert!(
        agreed(&owner),
        "the flusher's good commit re-admits at once"
    );
}
