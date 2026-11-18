// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W1-L3: the store lane (C-STORE-LANE's lane arms at unit level), the one-poll rule, the inline/lane choice by
//! `F_BLOCKING_FILE`, the pre-send checks (round 30 `control::admit` choke point), the `Failure` mapping, the
//! clock-authority check (C-STORE-INFO) and the durability rule (round 12).

use std::sync::atomic::{AtomicBool, Ordering};

use busbar_contract::persistence::control::SLOT_NS;
use busbar_contract::persistence::{
    Address, AttemptId, Candidate, ExpectedValue, Mutation, NamespaceId, Predicate, TimeGuard,
    CANDIDATE_VERSION,
};
use busbar_contract::Secret;

use super::*;

const DATASET: DatasetId = DatasetId([1; 16]);
const AUTHORITY: [u8; 16] = [9; 16];

fn runtime(workers: usize) -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_time()
        .build()
        .expect("runtime")
}

fn info(durability: Durability) -> BackendInfo {
    BackendInfo {
        dataset: DATASET,
        atomic_domain: [2; 16],
        clock_authority: AUTHORITY,
        physical_version: 1,
        durability,
    }
}

fn candidate(dataset: DatasetId, guard_slot_ns: bool) -> PreparedCandidate {
    let namespace = if guard_slot_ns { SLOT_NS.0 } else { [5; 16] };
    PreparedCandidate::new(Candidate {
        id: AttemptId {
            dataset,
            writer_epoch: 1,
            writer: [2; 16],
            execution_epoch: 1,
            operation: [3; 16],
        },
        codec: CANDIDATE_VERSION,
        predicates: vec![Predicate {
            address: Address {
                namespace,
                key: b"a".to_vec(),
            },
            expected: ExpectedValue::Absent,
        }],
        mutations: vec![Mutation::Put {
            address: Address {
                namespace: [5; 16],
                key: b"a".to_vec(),
            },
            value: Secret::new(b"v".to_vec()),
        }],
        time: None,
        result: Secret::new(b"r".to_vec()),
    })
    .expect("a valid candidate")
}

fn key() -> CommitKey {
    CommitKey::slotted(4, 9, &busbar_contract::caps::SlotSeal::acquire_for_tests())
        .expect("slot 4, seq 9")
}

fn scan(after: bool, generation: bool, allow_change: bool) -> Op {
    Op::Scan(Arc::new(Scan {
        dataset: DATASET,
        namespace: NamespaceId([5; 16]),
        prefix: Vec::new(),
        after: after.then(|| b"k".to_vec()),
        generation: generation.then_some(3),
        allow_change,
        max_items: 10,
        max_bytes: 1024,
    }))
}

#[test]
fn the_lane_never_blocks_a_worker() {
    let rt = runtime(2);
    let lane = StoreLane::new(rt.handle().clone());
    rt.block_on(async {
        let jobs: Vec<_> = (0..4)
            .map(|_| {
                lane.run(|| {
                    std::thread::sleep(Duration::from_millis(300));
                    Ok(std::thread::current().id())
                })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let asked = Instant::now();
        let waited = tokio::spawn(async move { asked.elapsed() })
            .await
            .expect("the no-op task");
        assert!(
            waited < Duration::from_millis(50),
            "a no-op task waited {waited:?} behind lane jobs"
        );
        for job in jobs {
            assert_ne!(job.await.expect("job"), std::thread::current().id());
        }
    });
}

#[test]
fn a_panic_that_escapes_a_lane_job_is_a_fault() {
    let rt = runtime(1);
    let lane = StoreLane::new(rt.handle().clone());
    let got =
        rt.block_on(lane.run(|| -> Result<(), CallError> { panic!("escaped the entry wrapper") }));
    assert_eq!(got, Err(CallError::Fault(FaultReason::Panic)));
}

#[test]
fn a_dropped_lane_future_still_runs_its_job_to_completion() {
    let rt = runtime(1);
    let lane = StoreLane::new(rt.handle().clone());
    let done = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&done);
    rt.block_on(async {
        drop(lane.run(move || {
            std::thread::sleep(Duration::from_millis(100));
            seen.store(true, Ordering::SeqCst);
            Ok(())
        }));
        let until = Instant::now() + Duration::from_secs(5);
        while !done.load(Ordering::SeqCst) && Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    assert!(done.load(Ordering::SeqCst), "the detached job never ran");
}

struct Parked(Arc<AtomicBool>);
impl Drop for Parked {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[test]
fn one_poll_answers_ready_and_faults_pending_after_dropping_the_chain() {
    assert_eq!(once(async { 7 }), Ok(7));
    let dropped = Arc::new(AtomicBool::new(false));
    let parked = Parked(Arc::clone(&dropped));
    let got = once(async move {
        let _guard = parked;
        core::future::pending::<()>().await;
    });
    assert!(matches!(
        got,
        Err(CallError::Fault(FaultReason::NeedNotAllowed(_)))
    ));
    assert!(
        dropped.load(Ordering::SeqCst),
        "the parked chain was not dropped"
    );
}

#[test]
fn only_a_blocking_file_store_takes_the_lane() {
    let rt = runtime(1);
    assert!(lane_for(wire::F_BLOCKING_FILE, rt.handle()).is_some());
    assert!(lane_for(wire::F_BLOCKING_FILE | wire::FB_EPHEMERAL, rt.handle()).is_some());
    assert!(lane_for(wire::FB_EPHEMERAL, rt.handle()).is_none());
    assert!(lane_for(0, rt.handle()).is_none());
}

#[test]
fn nothing_is_sent_for_another_dataset_a_bare_continuation_or_an_inadmissible_commit() {
    let info = info(Durability::Local);
    let other = DatasetId([7; 16]);
    let read = |dataset| {
        Op::Read(Arc::new(Read {
            dataset,
            addresses: Vec::new(),
            time: Some(TimeGuard {
                not_before: None,
                before: Some(5),
            }),
        }))
    };
    assert_eq!(admit(&info, &read(DATASET)), Ok(()));
    assert_eq!(admit(&info, &read(other)), Err(Failure::Refused));
    assert_eq!(admit(&info, &Op::Clock(DATASET)), Ok(()));
    assert_eq!(admit(&info, &Op::Clock(other)), Err(Failure::Refused));
    assert_eq!(admit(&info, &scan(false, false, false)), Ok(()));
    assert_eq!(admit(&info, &scan(true, true, false)), Ok(()));
    assert_eq!(admit(&info, &scan(true, false, true)), Ok(()));
    assert_eq!(
        admit(&info, &scan(true, false, false)),
        Err(Failure::Refused)
    );
    assert_eq!(
        admit(&info, &Op::Commit(candidate(DATASET, false), key())),
        Ok(())
    );
    assert_eq!(
        admit(&info, &Op::Commit(candidate(other, false), key())),
        Err(Failure::Refused)
    );
    assert_eq!(
        admit(&info, &Op::Commit(candidate(DATASET, true), key())),
        Err(Failure::Refused),
        "a SLOT_NS predicate is refused at the choke point"
    );
}

#[test]
fn a_commit_that_may_have_run_is_unknown_and_a_read_is_unavailable() {
    for e in [
        CallError::Fault(FaultReason::Panic),
        CallError::Deadline,
        CallError::Cancelled,
        CallError::Quarantined,
        CallError::Steps,
    ] {
        assert_eq!(call_failure(e.clone(), true), Failure::Unknown, "{e:?}");
        assert_eq!(
            call_failure(e.clone(), false),
            Failure::Unavailable,
            "{e:?}"
        );
    }
    assert_eq!(call_failure(CallError::NotDeclared, true), Failure::Refused);
    assert_eq!(
        call_failure(CallError::NotDeclared, false),
        Failure::Refused
    );
    assert_eq!(status_failure(Status::REFUSED, true), Failure::Refused);
    assert_eq!(status_failure(Status::REFUSED, false), Failure::Refused);
    assert_eq!(status_failure(Status::FAILED, true), Failure::Unknown);
    assert_eq!(status_failure(Status::FAILED, false), Failure::Unavailable);
}

#[test]
fn an_observation_must_name_the_info_clock_authority() {
    let info = info(Durability::Local);
    let at = |authority| ClockObservation {
        authority,
        unix_seconds: 100,
    };
    assert_eq!(authority(&info, &at(AUTHORITY), false), Ok(()));
    assert_eq!(authority(&info, &at(AUTHORITY), true), Ok(()));
    assert_eq!(authority(&info, &at([8; 16]), false), Err(Failure::Corrupt));
    assert_eq!(authority(&info, &at([8; 16]), true), Err(Failure::Unknown));
}

#[test]
fn info_durability_must_agree_with_the_ephemeral_fact() {
    assert!(durability(wire::FB_EPHEMERAL, &info(Durability::Ephemeral)).is_ok());
    assert!(durability(0, &info(Durability::Local)).is_ok());
    assert!(durability(wire::F_BLOCKING_FILE, &info(Durability::Quorum)).is_ok());
    for (facts, dur) in [
        (wire::FB_EPHEMERAL, Durability::Local),
        (wire::FB_EPHEMERAL, Durability::Quorum),
        (0, Durability::Ephemeral),
    ] {
        match durability(facts, &info(dur)) {
            Err(OpenError::Config { code, text, error }) => {
                assert_eq!(code, R_INVALID);
                assert_eq!(
                    text,
                    "the store's `info` durability disagrees with its describe facts"
                );
                assert!(error.is_none());
            }
            other => panic!("{facts:#x} {dur:?}: {other:?}"),
        }
    }
}

/// `request` writes the op's records into a pooled buffer (it was a `todo!()` panic on the first store call).
#[test]
fn request_clock_writes_one_clock_record() {
    let d = DatasetId([7; 16]);
    let req = request(
        4096,
        &Op::Clock(d),
        &busbar_contract::plugin::TestKernelSeal,
    )
    .expect("fits max_out");
    let bytes = req.bytes();
    assert!(!bytes.is_empty());
    assert!(bytes.windows(16).any(|w| w == d.0));
}

/// The `clock` argument is the dataset itself, 16 bytes (ABI-MIN3-INTERFACE §8.8: "Authoritative UTC for `dataset`
/// (16 bytes). Answer: CLOCK."; the SDK's `Store::clock` doc says the same). CLOCK is the answer's record, never the
/// request's: every MIN-3 store reads the argument as exactly 16 bytes (store-memory e59e035, store-sqlite,
/// store-postgres 03c5ff4, store-valkey) and refuses anything else ("a dataset is 16 bytes"), so a record-wrapped
/// argument refuses the default binary's boot persistence over the linked store-memory image.
#[test]
fn request_clock_is_exactly_the_sixteen_dataset_bytes() {
    let d = DatasetId([7; 16]);
    let req = request(
        4096,
        &Op::Clock(d),
        &busbar_contract::plugin::TestKernelSeal,
    )
    .expect("fits max_out");
    assert_eq!(req.bytes(), &d.0[..]);
}
