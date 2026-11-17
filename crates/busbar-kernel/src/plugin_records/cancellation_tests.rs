// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::persistence::{
    BackendInfo, Call, ClockObservation, CommitKey, DatasetId, Decision, Failure, Page,
    PersistenceBackend, PreparedCandidate, Read, ReadResult, Scan,
};
use futures::FutureExt;
use std::{collections::VecDeque, sync::Mutex};

enum Crossing {
    Pending,
    LostReply,
    Unavailable,
}

struct Faults {
    backend: Arc<dyn PersistenceBackend>,
    script: Mutex<Option<VecDeque<Crossing>>>,
    sent: Mutex<Vec<(PreparedCandidate, CommitKey)>>,
}

impl Faults {
    fn arm(&self, crossings: impl IntoIterator<Item = Crossing>) {
        *self.script.lock().unwrap() = Some(crossings.into_iter().collect());
    }

    fn same_attempt(&self) {
        let sent = self.sent.lock().unwrap();
        assert!(sent.len() >= 2, "the original native crossing was retried");
        for (candidate, key) in &sent[1..] {
            assert_eq!(candidate.candidate().id, sent[0].0.candidate().id);
            assert_eq!(candidate.fingerprint(), sent[0].0.fingerprint());
            assert_eq!(*key, sent[0].1, "the original slot lease is retained");
        }
    }
}

impl PersistenceBackend for Faults {
    fn info(&self) -> BackendInfo {
        self.backend.info()
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        self.backend.read(request)
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        self.backend.scan(request)
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.backend.clock(dataset)
    }
    fn commit(&self, candidate: PreparedCandidate, key: CommitKey) -> Call<'_, Decision> {
        let step = {
            let mut script = self.script.lock().unwrap();
            script.as_mut().and_then(|steps| {
                self.sent.lock().unwrap().push((candidate.clone(), key));
                steps.pop_front()
            })
        };
        Box::pin(async move {
            match step {
                Some(Crossing::Pending) => std::future::pending().await,
                Some(Crossing::Unavailable) => Err(Failure::Unavailable),
                Some(Crossing::LostReply) => {
                    self.backend.commit(candidate, key).await?;
                    Err(Failure::Unavailable)
                }
                None => self.backend.commit(candidate, key).await,
            }
        })
    }
}

async fn rig() -> (Arc<Faults>, StoreRecords) {
    let backend = Arc::new(Faults {
        backend: crate::real_store::native_backend().await,
        script: Mutex::new(None),
        sent: Mutex::default(),
    });
    let mut startup = crate::persistence::startup::Startup::new(
        backend.clone(),
        crate::persistence::facade::Limits {
            pending_operations: 2,
            conflict_retries: 2,
            scan_items: 128,
            scan_bytes: 1024 * 1024,
        },
        true,
    )
    .unwrap();
    loop {
        match startup.advance().await.unwrap() {
            crate::persistence::startup::Progress::Advanced => {}
            crate::persistence::startup::Progress::Admitted => break,
            other => panic!("startup must admit: {other:?}"),
        }
    }
    let records = StoreRecords::with_clock(startup.store().unwrap(), clock);
    (backend, records)
}

#[tokio::test]
async fn cancelled_first_submit_is_collected_without_another_consumer() {
    let (backend, records) = rig().await;
    let who = caller("test-plane", "instance");
    for iteration in 0..6u8 {
        backend.sent.lock().unwrap().clear();
        backend.arm([Crossing::Pending]);
        assert!(records
            .put(&who, Scope::default(), b"key", &[iteration], 0)
            .now_or_never()
            .is_none());
        let store = records.store_for_tests();
        assert_eq!(store.pending_operations().unwrap(), 1);
        assert_eq!(store.slot_states().unwrap().free, 1);
        assert_eq!(records.settle().await, 0);
        assert_eq!(store.pending_operations().unwrap(), 0);
        assert_eq!(store.slot_states().unwrap().free, 2);
        backend.same_attempt();
        assert_eq!(
            get(&records, &who, Scope::default(), b"key").await,
            Some(vec![iteration])
        );
    }
}

#[tokio::test]
async fn cancelled_immediate_retry_keeps_one_applied_chain_entry() {
    let (backend, records) = rig().await;
    let who = caller("test-plane", "instance");
    backend.arm([Crossing::LostReply, Crossing::Pending]);
    assert!(records
        .append(&who, Scope::default(), b"chain", b"entry")
        .now_or_never()
        .is_none());
    assert_eq!(records.store_for_tests().pending_operations().unwrap(), 1);
    assert_eq!(records.settle().await, 0);
    assert_eq!(records.store_for_tests().pending_operations().unwrap(), 0);
    assert_eq!(records.store_for_tests().slot_states().unwrap().free, 2);
    backend.same_attempt();
    let (read, entries) = read_chain(&records, &who, Scope::default(), b"chain", 0, 10).await;
    assert_eq!(read.len, 1, "a lost reply cannot append twice");
    assert_eq!(entries, vec![(1, b"entry".to_vec())]);
}

#[tokio::test]
async fn cancelled_maintenance_retains_the_original_queue_slot() {
    let (backend, records) = rig().await;
    let who = caller("test-plane", "instance");
    backend.arm([
        Crossing::Unavailable,
        Crossing::Unavailable,
        Crossing::Unavailable,
    ]);
    assert_eq!(
        records
            .put(&who, Scope::default(), b"key", b"value", 0)
            .await,
        Err(RecordsDenied::Unavailable)
    );
    backend.arm([Crossing::Pending]);
    assert!(records.settle().now_or_never().is_none());
    let store = records.store_for_tests();
    assert_eq!(store.pending_operations().unwrap(), 1);
    store.stop_admission().unwrap();
    assert_eq!(
        records.settle().await,
        0,
        "retired consumer admits no new work"
    );
    assert_eq!(store.pending_operations().unwrap(), 0);
    assert_eq!(store.slot_states().unwrap().free, 2);
    backend.same_attempt();
}

#[tokio::test]
async fn resolved_uncollected_record_is_reclaimed_by_its_owner() {
    let (backend, records) = rig().await;
    let who = caller("test-plane", "instance");
    backend.arm([Crossing::Pending]);
    assert!(records
        .put(&who, Scope::default(), b"key", b"value", 0)
        .now_or_never()
        .is_none());
    let store = records.store_for_tests();
    assert_eq!(store.settle_in_doubt(1).await.unwrap(), 1);
    assert_eq!(store.slot_states().unwrap().resolved_uncollected, 1);
    assert_eq!(records.settle().await, 0);
    assert_eq!(store.pending_operations().unwrap(), 0);
    assert_eq!(store.slot_states().unwrap().free, 2);
    backend.same_attempt();
}
