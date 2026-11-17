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
    Conflict,
    Pending,
    LostReply,
    Unavailable,
    Fenced,
}

struct Faults {
    backend: Arc<dyn PersistenceBackend>,
    script: Mutex<Option<VecDeque<Crossing>>>,
    sent: Mutex<Vec<(PreparedCandidate, CommitKey)>>,
    read_clock: Mutex<VecDeque<u64>>,
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
        Box::pin(async move {
            let read = self.backend.read(request).await?;
            let next = self.read_clock.lock().unwrap().pop_front();
            if let Some(now) = next {
                tokio::task::yield_now().await;
                set_now(now);
            }
            Ok(read)
        })
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
                Some(Crossing::Conflict) => Ok(Decision::ConditionConflict),
                Some(Crossing::Pending) => std::future::pending().await,
                Some(Crossing::Unavailable) => Err(Failure::Unavailable),
                Some(Crossing::Fenced) => Ok(Decision::Fenced),
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
        read_clock: Mutex::default(),
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
async fn absolute_claim_keeps_original_cutoff_after_a_suspended_read() {
    set_now(START);
    let (backend, records) = rig().await;
    let who = caller("test-auth", "verifier");
    set_now(START + 4);
    backend.read_clock.lock().unwrap().push_back(START + 9);
    assert!(records
        .claim_until(&who, Scope::default(), b"claim", b"1", START + 10)
        .await
        .unwrap());
    let scope = records.scoped(&who).unwrap();
    let raw = scope
        .get(
            RECORDS,
            &super::super::store::scoped_key(Scope::default(), b"claim"),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        super::super::store::opened(raw.expose(&crate::seal::lend()))
            .unwrap()
            .0,
        START + 10
    );
}

#[tokio::test]
async fn absolute_claim_submits_nothing_after_read_or_conflict_passes_cutoff() {
    for conflict in [false, true] {
        set_now(START);
        let (backend, records) = rig().await;
        let who = caller("test-auth", "verifier");
        backend.arm(if conflict {
            vec![Crossing::Conflict]
        } else {
            vec![]
        });
        *backend.read_clock.lock().unwrap() = if conflict {
            VecDeque::from([START + 9, START + 10])
        } else {
            VecDeque::from([START + 10])
        };
        assert!(!records
            .claim_until(&who, Scope::default(), b"claim", b"1", START + 10)
            .await
            .unwrap());
        assert_eq!(backend.sent.lock().unwrap().len(), usize::from(conflict));
        assert_eq!(get(&records, &who, Scope::default(), b"claim").await, None);
    }
}

#[tokio::test]
async fn absolute_claim_settlement_keeps_the_submitted_cutoff() {
    set_now(START);
    let (backend, records) = rig().await;
    let who = caller("test-auth", "verifier");
    backend.arm([Crossing::LostReply, Crossing::Pending]);
    assert!(records
        .claim_until(&who, Scope::default(), b"claim", b"1", START + 10)
        .now_or_never()
        .is_none());
    set_now(START + 11);
    assert_eq!(records.settle().await, 0);
    backend.same_attempt();
    let scope = records.scoped(&who).unwrap();
    let raw = scope
        .get(
            RECORDS,
            &super::super::store::scoped_key(Scope::default(), b"claim"),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        super::super::store::opened(raw.expose(&crate::seal::lend()))
            .unwrap()
            .0,
        START + 10
    );
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

#[tokio::test]
async fn maintenance_does_not_collect_a_live_foreground_reservation() {
    let (backend, records) = rig().await;
    let who = caller("test-plane", "instance");
    let scoped = records.scoped(&who).unwrap();
    backend.arm([Crossing::Pending]);
    assert!(scoped
        .put(RECORDS, b"key", Secret::new(vec![1]))
        .now_or_never()
        .is_none());
    let store = records.store_for_tests();
    let ids = store.stop_admission().unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(
        records.settle().await,
        1,
        "the foreground still owns its answer"
    );
    assert_eq!(
        backend.sent.lock().unwrap().len(),
        1,
        "maintenance made no crossing"
    );
    assert_eq!(
        scoped.retry(ids[0]).await.unwrap(),
        crate::persistence::scoped::Outcome::Applied
    );
    assert_eq!(store.pending_operations().unwrap(), 0);
    assert_eq!(store.slot_states().unwrap().free, 2);
    backend.same_attempt();
}

#[tokio::test]
async fn reconcile_stays_owned_and_is_not_blindly_resubmitted() {
    let (backend, records) = rig().await;
    let who = caller("test-plane", "instance");
    backend.arm([Crossing::Pending]);
    assert!(records
        .put(&who, Scope::default(), b"key", b"value", 0)
        .now_or_never()
        .is_none());
    backend.arm([Crossing::Fenced]);
    assert_eq!(records.settle().await, 1);
    assert_eq!(
        records.store_for_tests().slot_states().unwrap().reconcile,
        1
    );
    assert_eq!(records.settle().await, 1);
    assert_eq!(
        backend.sent.lock().unwrap().len(),
        2,
        "reconciliation is not resubmission permission"
    );
    assert_eq!(records.store_for_tests().slot_states().unwrap().free, 1);
}
