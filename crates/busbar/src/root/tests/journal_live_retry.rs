// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::LeaseTick;
use crate::root::durability::node_book;
use crate::root::plane_node::Node;
use crate::root::store_double::NativeFaults;
use busbar_kernel::persistence::journal::{BufferBudget, RuntimeJournal};
use busbar_kernel_wal::{Entry, RecordClass};
use std::sync::atomic::Ordering;
use std::sync::Arc;

const BUDGET: BufferBudget = BufferBudget {
    records: 3,
    bytes: 1024 * 1024,
};
const HISTORY: BufferBudget = BufferBudget {
    records: 64,
    bytes: 1024 * 1024,
};

async fn fixture(
    node_id: u64,
) -> (
    Arc<NativeFaults>,
    Arc<busbar_kernel::persistence::facade::CoreStore>,
    Arc<RuntimeJournal>,
    LeaseTick,
) {
    let faults = NativeFaults::open().await;
    let core = crate::root::real_store::core_over(faults.clone()).await;
    let journal = RuntimeJournal::open(core.clone(), node_id, BUDGET)
        .await
        .unwrap();
    let book = node_book(journal.clone(), HISTORY)
        .await
        .unwrap()
        .durability;
    let node = Arc::new(Node::new());
    node.bind_book(book.clone());
    faults.clear_observations();
    (faults, core, journal, LeaseTick { node })
}

fn pressure(journal: &RuntimeJournal) {
    // All original frames live in the native owner's one bounded custody queue.
    for index in 0..3 {
        journal
            .stage_run(&[Entry::new(RecordClass::Load, vec![index])])
            .unwrap();
    }
    assert!(journal
        .stage_run(&[Entry::new(RecordClass::Load, vec![3])])
        .is_err());
    assert_eq!(journal.pending_records(), 3);
}

async fn assert_three_once(journal: &RuntimeJournal) {
    let records = journal.read_records(HISTORY).await.unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(
        records
            .iter()
            .map(|record| record.node_seq)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    busbar_kernel_wal::verify_journal(&records).unwrap();
    assert_eq!(
        records
            .iter()
            .map(|record| record.body.clone())
            .collect::<Vec<_>>(),
        vec![vec![0], vec![1], vec![2]]
    );
}

#[tokio::test]
async fn live_tick_reopens_admission_after_store_pressure_without_another_unit() {
    let (faults, core, journal, tick) = fixture(871).await;
    faults.pause(true);
    pressure(&journal);
    assert_eq!(faults.waiting(), 0, "staging performs no backend crossing");
    faults.pause(false);
    faults.refusing.store(true, Ordering::SeqCst);
    assert!(tick.node.journal_refusal().is_some());
    assert!(tick.tick().await.is_err());
    assert_eq!(
        journal.pending_records(),
        3,
        "refusal retains every original frame"
    );
    assert!(tick.node.journal_refusal().is_some());
    faults.refusing.store(false, Ordering::SeqCst);
    tick.tick().await.unwrap();
    assert!(
        tick.node.journal_refusal().is_none(),
        "the live node admits after recovery"
    );
    assert_eq!(journal.pending_records(), 0);
    for _ in 0..3 {
        tick.tick().await.unwrap();
    }
    assert_three_once(&journal).await;
    drop(tick);
    drop(journal);
    let restarted = RuntimeJournal::open(core, 871, BUDGET).await.unwrap();
    assert_eq!(restarted.next_seq(), 4);
    assert_three_once(&restarted).await;
}

#[tokio::test]
async fn live_tick_does_not_duplicate_a_batch_with_an_unknown_store_commit() {
    let (faults, _book, journal, tick) = fixture(872).await;
    faults.pause(true);
    pressure(&journal);
    assert_eq!(faults.waiting(), 0, "staging performs no backend crossing");
    faults.pause(false);
    faults.lose_acks.store(true, Ordering::SeqCst);
    assert!(tick.tick().await.is_err());
    assert_eq!(
        journal.pending_records(),
        3,
        "the exact unknown original stays owned"
    );
    assert!(tick.node.journal_refusal().is_some());
    assert_eq!(
        faults.applied(),
        1,
        "the actual Store applied before losing its reply"
    );
    for _ in 0..3 {
        assert!(tick.tick().await.is_err());
    }
    let sent = faults.requests.lock().unwrap().clone();
    assert!(sent.len() >= 4);
    assert!(sent
        .iter()
        .all(|candidate| candidate.fingerprint() == sent[0].fingerprint()
            && candidate.candidate().id == sent[0].candidate().id));
    faults.lose_acks.store(false, Ordering::SeqCst);
    tick.tick().await.unwrap();
    assert!(tick.node.journal_refusal().is_none());
    assert_three_once(&journal).await;
}
