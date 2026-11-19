// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SHUTDOWN-HANG 8.15 `fence_settle_races_a_driving_retire`: the seal phase's fence settle beside
//! a driving `retire_after`, over the 8.14 store double. Two holds: the store double holds the
//! fence commit unanswered, and `WriterRetirements`' test hook holds the driver between the
//! CoreStore's decision and `take_decided`. Each test owns fresh random writer ids.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Barrier};
use std::time::Duration;

use busbar_contract::persistence::{
    AttemptId, Candidate, Mutation, PreparedCandidate, CANDIDATE_VERSION,
};
use busbar_contract::Secret;

use super::expired_writers_tests::{
    attach, control_address, durable_records, placement, reached, records_for, seen, until,
    writer_id, Store, CLOSED, DATASET, EPOCH, OWN,
};
use super::{
    undrained_records, ObservedBy, PredecessorFence, SettleAnswer, Target, TestHold,
    UndrainedWriter, WriterRetirement, WriterRetirements, LEASE_TTL_MS,
};
use crate::persistence::commit::SubmitResult;
use crate::persistence::facade::{AccessError, PendingId};
use crate::persistence::undrained::{
    fill_admin_queue, ledger_test_guard, retry_unrecorded_without_drain, Placement,
};

/// One `PredecessorFence` over a store double and one writer W whose lease expired long ago.
struct Rig {
    store: Arc<Store>,
    fence: Arc<PredecessorFence>,
    writer: [u8; 16],
    seen: UndrainedWriter,
}

async fn rig(retired: bool) -> Rig {
    let store = Store::new();
    store.now.store(1_000, Ordering::SeqCst);
    let fence = PredecessorFence::new(attach(&store, OWN).await, "f5-host").unwrap();
    let writer = writer_id();
    if retired {
        store.retired_writer(writer, 100_000, "dead-w", 77);
    } else {
        store.open_writer(writer, 100_000, "dead-w", 77);
    }
    Rig {
        seen: seen(writer, "dead-w", 77, ObservedBy::ExpiredLeasePass),
        store,
        fence,
        writer,
    }
}

fn answers(rig: &Rig) -> Vec<SettleAnswer> {
    rig.fence.retirements.settle_answers()
}

fn count(answers: &[SettleAnswer], answer: SettleAnswer) -> usize {
    answers.iter().filter(|seen| **seen == answer).count()
}

/// 8.15 (a) and (b), for any W: `settle()` beside a driving `retire_after`, first while its
/// submit is held, then while the driver is held after the CoreStore dropped the decided attempt
/// and before `take_decided`. `before_decision` runs, with no await, just before the driver is
/// released to `take_decided`. Returns once both have returned.
async fn settle_races_a_driving_retire(rig: &Rig, before_decision: impl FnOnce()) {
    let submit = Arc::new(TestHold::default());
    rig.store.hold_next_fence(submit.clone());
    let driver = {
        let (fence, writer, seen) = (rig.fence.clone(), rig.writer, rig.seen.clone());
        tokio::spawn(async move {
            fence
                .retirements
                .retire_after(&fence.core, EPOCH, writer, LEASE_TTL_MS, Some(seen))
                .await
                .map(|answer| matches!(answer, WriterRetirement::Pending))
        })
    };
    reached(&submit).await;
    assert!(
        rig.fence.retirements.gate.try_lock().is_err(),
        "the driver holds gate while its submit is unanswered"
    );
    assert_eq!(rig.fence.retained(), 1);
    let settle = {
        let fence = rig.fence.clone();
        tokio::spawn(async move { fence.settle().await })
    };

    // (a) settle never awaits gate: its retries run while the driver holds it, and answer Busy;
    // it waits and retries.
    until("settle to answer Busy twice", || {
        count(&answers(rig), SettleAnswer::Busy) >= 2
    })
    .await;
    let seen = answers(rig);
    assert_eq!(seen.first(), Some(&SettleAnswer::Busy), "{seen:?}");
    assert!(
        seen.iter().all(|answer| *answer == SettleAnswer::Busy),
        "{seen:?}"
    );
    assert!(rig.fence.retirements.gate.try_lock().is_err());
    assert!(!settle.is_finished());
    assert_eq!(rig.fence.retained(), 1);

    // (b) the store decides; the driver is held before take_decided, still holding gate.
    let decision = Arc::new(TestHold::default());
    rig.fence.retirements.hold_decision(decision.clone());
    submit.release.notify_one();
    reached(&decision).await;
    let before = answers(rig).len();
    until("settle to see UnknownOperation twice", || {
        count(&answers(rig)[before..], SettleAnswer::Unknown) >= 2
    })
    .await;
    let seen = answers(rig);
    assert_eq!(
        count(&seen, SettleAnswer::Lost),
        0,
        "a driver holds the decision: settle never removes it: {seen:?}"
    );
    assert_eq!(rig.fence.retained(), 1, "the entry is left to its driver");
    assert!(!settle.is_finished());
    assert!(rig.fence.retirements.gate.try_lock().is_err());
    before_decision();
    decision.release.notify_one();
    assert!(
        driver.await.unwrap().unwrap(),
        "an applied close answers Pending"
    );
    tokio::time::timeout(Duration::from_secs(10), settle)
        .await
        .expect("settle returns once nothing is retained")
        .unwrap();
    // A retry that read `pending` before `take_decided` may find `gate` free once the driver has
    // returned; its removal then finds nothing (the callers assert W is not `unconfirmed`).
    assert_eq!(rig.fence.retained(), 0);
    assert_eq!(rig.store.fence_applies(rig.writer), 1);
    assert_eq!(rig.store.control(rig.writer), Some(CLOSED));
}

/// 8.15 (a), (b): the driver's `take_decided` removes the entry and enqueues exactly one
/// `shutdown.drain_incomplete`; `settle()` then finds nothing and returns. `recorded` holds W.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settle_leaves_a_driven_decision_to_its_driver_which_records_it_once() {
    let _guard = ledger_test_guard().await;
    let rig = rig(false).await;
    settle_races_a_driving_retire(&rig, || {}).await;
    let offered = placement(rig.writer);
    assert!(
        offered.recorded.is_some()
            && !offered.retained
            && !offered.record_failed
            && !offered.unconfirmed,
        "{offered:?}"
    );
    assert!(rig.fence.retirements.take_closed_open(EPOCH, rig.writer));
    assert!(!rig.fence.retirements.take_closed_open(EPOCH, rig.writer));
    let records = durable_records().await;
    assert_eq!(records_for(&records, rig.writer), 1, "{records:?}");
}

/// 8.15 (b2): the decision is lost to this process. Another driver collects it, so the CoreStore
/// forgets the attempt while `pending` still holds W and no driver is in flight. `settle()`'s
/// `try_lock` succeeds; it removes the entry with no record, and W is listed `unconfirmed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settle_lists_a_decision_lost_with_no_driver_in_flight() {
    let _guard = ledger_test_guard().await;
    let rig = rig(false).await;
    rig.store.lose_fence_reply.store(true, Ordering::SeqCst);
    assert!(matches!(
        rig.fence
            .retirements
            .retire_after(
                &rig.fence.core,
                EPOCH,
                rig.writer,
                LEASE_TTL_MS,
                Some(rig.seen.clone())
            )
            .await,
        Ok(WriterRetirement::Pending)
    ));
    assert_eq!(rig.fence.retained(), 1, "an Unknown reply is retained");
    assert!(placement(rig.writer).retained);
    let operation = rig
        .fence
        .retirements
        .state()
        .pending
        .get(&(EPOCH, rig.writer))
        .map(|(candidate, _)| candidate.candidate().id.operation)
        .expect("W is retained");
    let elsewhere = rig.fence.core.retry(PendingId(operation)).await.unwrap();
    assert!(matches!(elsewhere.result, SubmitResult::Decided(_)));
    assert!(matches!(
        rig.fence.core.retry(PendingId(operation)).await,
        Err(AccessError::UnknownOperation)
    ));
    assert!(rig.fence.retirements.gate.try_lock().is_ok(), "no driver");
    tokio::time::timeout(Duration::from_secs(10), rig.fence.settle())
        .await
        .expect("settle returns");
    assert_eq!(answers(&rig), [SettleAnswer::Unknown, SettleAnswer::Lost]);
    assert_eq!(rig.fence.retained(), 0);
    assert_eq!(
        placement(rig.writer),
        Placement {
            unconfirmed: true,
            ..Placement::default()
        },
        "lost, never recorded"
    );
    let report = undrained_records().exit_report();
    assert!(report.unconfirmed.contains(&rig.seen));
    assert!(!report.unrecorded.contains(&rig.seen));
    assert!(!rig.fence.retirements.take_closed_open(EPOCH, rig.writer));
    assert_eq!(rig.store.fence_applies(rig.writer), 1);
}

fn candidate() -> PreparedCandidate {
    PreparedCandidate::new(Candidate {
        id: AttemptId {
            dataset: DATASET,
            writer_epoch: EPOCH,
            writer: OWN,
            execution_epoch: 1,
            operation: writer_id(),
        },
        codec: CANDIDATE_VERSION,
        predicates: Vec::new(),
        mutations: vec![Mutation::Put {
            address: control_address(writer_id()),
            value: Secret::new(vec![1]),
        }],
        time: None,
        result: Secret::default(),
    })
    .unwrap()
}

/// A retained attempt for `seen`, as `retire_after` leaves it: `Some(seen)` iff W is open.
fn retain(retirements: &WriterRetirements, seen: &UndrainedWriter, open: bool) {
    if open {
        undrained_records().retain(seen);
    }
    retirements
        .state()
        .pending
        .insert(seen.target(), (candidate(), open.then(|| seen.clone())));
}

/// After any number of `take_decided(W, applied)` calls: the entry was taken once.
fn assert_taken_once(retirements: &WriterRetirements, seen: &UndrainedWriter, open: bool) {
    let target = seen.target();
    assert!(!retirements.state().pending.contains_key(&target));
    assert_eq!(retirements.take_closed_open(target.0, target.1), open);
    assert!(!retirements.take_closed_open(target.0, target.1));
    let placement = placement(seen.writer);
    if open {
        assert!(
            placement.recorded.is_some()
                && !placement.retained
                && !placement.record_failed
                && !placement.unconfirmed,
            "{placement:?}"
        );
    } else {
        assert_eq!(placement, Placement::default());
    }
}

/// Two threads call `take_decided(target, true)` for each target, released together by a barrier.
fn race(retirements: &WriterRetirements, targets: &[Target]) {
    let start = Barrier::new(2);
    std::thread::scope(|scope| {
        for _ in 0..2 {
            scope.spawn(|| {
                for target in targets {
                    start.wait();
                    retirements.take_decided(*target, true);
                }
            });
        }
    });
}

const RACES: usize = 10_000;
/// Records drained per round, well inside the admin audit queue's 256 rows.
const ROUND: usize = 100;

/// 8.15 (c): `take_decided` called twice for one target, sequentially and then from two threads
/// racing on a barrier, 10,000 times. Exactly one call takes the entry; the other does not touch
/// `closed_open`, `recorded` or `record_failed`; exactly one admin audit row is made per target.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn take_decided_offers_one_record_whoever_reaches_it() {
    let _guard = ledger_test_guard().await;
    let retirements = WriterRetirements::default();
    let first = seen(writer_id(), "dead-c", 1, ObservedBy::Successor);
    retain(&retirements, &first, true);
    retirements.take_decided(first.target(), true);
    retirements.take_decided(first.target(), true);
    assert_taken_once(&retirements, &first, true);
    let records = durable_records().await;
    assert_eq!(records_for(&records, first.writer), 1);

    for _ in 0..RACES / ROUND {
        let round: Vec<UndrainedWriter> = (0..ROUND)
            .map(|node| seen(writer_id(), "dead-c", node as u64, ObservedBy::Adopter))
            .collect();
        for seen in &round {
            retain(&retirements, seen, true);
        }
        let targets: Vec<Target> = round.iter().map(UndrainedWriter::target).collect();
        race(&retirements, &targets);
        for seen in &round {
            assert_taken_once(&retirements, seen, true);
        }
        let records = durable_records().await;
        for seen in &round {
            assert_eq!(
                records_for(&records, seen.writer),
                1,
                "one row for {}",
                seen.resource()
            );
        }
    }
    assert_eq!(retirements.retained(), 0);
}

/// 8.15 (d): a gracefully retired W (`old.admits(epoch) == false`): the same races, no record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_gracefully_retired_writer_races_the_same_way_with_no_record() {
    let _guard = ledger_test_guard().await;
    let rig = rig(true).await;
    settle_races_a_driving_retire(&rig, || {}).await;
    assert_eq!(placement(rig.writer), Placement::default(), "no record");
    assert!(!rig.fence.retirements.take_closed_open(EPOCH, rig.writer));

    let retirements = WriterRetirements::default();
    let once = seen(writer_id(), "retired-d", 1, ObservedBy::Successor);
    retain(&retirements, &once, false);
    retirements.take_decided(once.target(), true);
    retirements.take_decided(once.target(), true);
    assert_taken_once(&retirements, &once, false);
    let round: Vec<UndrainedWriter> = (0..1_000)
        .map(|node| seen(writer_id(), "retired-d", node, ObservedBy::Successor))
        .collect();
    for seen in &round {
        retain(&retirements, seen, false);
    }
    let targets: Vec<Target> = round.iter().map(UndrainedWriter::target).collect();
    race(&retirements, &targets);
    for seen in &round {
        assert_taken_once(&retirements, seen, false);
    }
}

/// 8.15 (e) at kernel level: as (b), with the admin audit queue pre-filled to its 256 rows and no
/// native owner draining it. The driver's `take_decided` puts W in `record_failed`, not
/// `recorded`. The first retry is refused while the queue is full; once the native owner drains
/// it, the second retry accepts W, a mark taken after it confirms it, and exactly one record is
/// in the audit log. (The retry task is closed first, as `finish`'s [5] does, so only this test
/// retries.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_the_full_queue_refuses_is_recorded_once_the_queue_drains() {
    let _guard = ledger_test_guard().await;
    undrained_records().close_retry_task();
    let mut filled = 0;
    while crate::audit::auditlog::try_emit_admin_hostless_now("test.fill", "x", "ok", "system")
        .is_ok()
    {
        filled += 1;
        assert!(filled <= 4096, "the admin audit queue is bounded");
    }
    let rig = rig(false).await;
    settle_races_a_driving_retire(&rig, || {}).await;
    assert_eq!(
        placement(rig.writer),
        Placement {
            record_failed: true,
            ..Placement::default()
        },
        "refused, held and never counted as recorded"
    );
    let report = undrained_records().exit_report();
    assert!(report.unrecorded.contains(&rig.seen));
    assert!(!report.unconfirmed.contains(&rig.seen));
    assert_eq!(
        undrained_records().retry_unrecorded(),
        0,
        "still refused at 256 rows"
    );
    assert!(placement(rig.writer).record_failed);

    // The native owner drains the queue to empty.
    crate::audit::auditlog::ensure_global_audit_stream_registered().await;
    assert!(undrained_records().retry_unrecorded() >= 1);
    let recorded = placement(rig.writer);
    let generation = recorded.recorded.expect("accepted by the second round");
    assert!(!recorded.record_failed, "{recorded:?}");
    let mark = undrained_records().mark();
    assert!(mark > generation);
    let records = durable_records().await;
    undrained_records().confirm_before(mark);
    assert_eq!(placement(rig.writer), Placement::default(), "confirmed");
    let report = undrained_records().exit_report();
    assert!(!report.unrecorded.contains(&rig.seen));
    assert!(!report.unconfirmed.contains(&rig.seen));
    assert_eq!(records_for(&records, rig.writer), 1, "{records:?}");
}

/// 8.15 (f): an adopter's own `WriterRetirements` decides after [5]'s mark. Its `take_decided`
/// moves W from `retained` to `recorded` with a generation at or above the mark; a confirmation
/// before the mark leaves it; `exit_report()` names W whether the release comes before, during or
/// after the report (100 runs).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_adopter_deciding_after_the_mark_is_listed_at_exit() {
    let _guard = ledger_test_guard().await;
    let store = Store::new();
    store.now.store(1_000, Ordering::SeqCst);
    let core = attach(&store, OWN).await;
    let adopter = Arc::new(WriterRetirements::default());
    let ledger = undrained_records();
    for run in 0..100u64 {
        let writer = writer_id();
        let host = format!("adopted-{run}");
        store.open_writer(writer, 100_000, &host, 500 + run);
        let seen = seen(writer, &host, 500 + run, ObservedBy::Adopter);
        let hold = Arc::new(TestHold::default());
        store.hold_next_fence(hold.clone());
        let driver = {
            let (adopter, core, seen) = (adopter.clone(), core.clone(), seen.clone());
            tokio::spawn(async move {
                adopter
                    .retire_after(&core, EPOCH, writer, 0, Some(seen))
                    .await
                    .map(|answer| matches!(answer, WriterRetirement::Pending))
            })
        };
        reached(&hold).await;
        assert!(placement(writer).retained);
        // [5]: the mark, then a clean drain confirms every record made before it.
        let mark = ledger.mark();
        ledger.confirm_before(mark);
        let listed = |report: &crate::persistence::undrained::ExitReport| {
            report.unconfirmed.contains(&seen) && !report.unrecorded.contains(&seen)
        };
        match run % 3 {
            0 => {
                hold.release.notify_one();
                assert!(driver.await.unwrap().unwrap());
                assert!(listed(&ledger.exit_report()), "run {run}: recorded");
            }
            1 => {
                hold.release.notify_one();
                assert!(
                    listed(&ledger.exit_report()),
                    "run {run}: racing the decision"
                );
                assert!(driver.await.unwrap().unwrap());
            }
            _ => {
                assert!(listed(&ledger.exit_report()), "run {run}: retained");
                hold.release.notify_one();
                assert!(driver.await.unwrap().unwrap());
            }
        }
        let recorded = placement(writer);
        assert!(
            recorded
                .recorded
                .is_some_and(|generation| generation >= mark)
                && !recorded.retained,
            "run {run}: {recorded:?}"
        );
        ledger.confirm_before(mark);
        assert!(placement(writer).recorded.is_some(), "not confirmed by [5]");
        assert!(listed(&ledger.exit_report()), "run {run}: after");
        assert_eq!(store.control(writer), Some(CLOSED));
    }
    assert_eq!(adopter.retained(), 0);
}

/// #258 (1): two closers in one process (F5's and an adopter's `WriterRetirements`) race one
/// open W. Both read W's open row and retain their close. The winner's close applies but its
/// reply is lost, so it stays retained and in doubt. The loser's close, built from the same open
/// row, is then decided as a condition conflict. The loser's decision must not drop the
/// winner's retained entry from the ledger: W stays listed at exit until the winner's own attempt
/// is decided, and then it is recorded exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_losing_closer_never_drops_the_winners_retained_close() {
    let _guard = ledger_test_guard().await;
    let rig = rig(false).await;
    let other = writer_id();
    rig.store.admit(other);
    let other_core = attach(&rig.store, other).await;
    let loser = Arc::new(WriterRetirements::default());
    let held = Arc::new(TestHold::default());
    rig.store.hold_next_fence(held.clone());
    let losing = {
        let (loser, core, writer) = (loser.clone(), other_core.clone(), rig.writer);
        let seen = seen(writer, "dead-w", 77, ObservedBy::Adopter);
        tokio::spawn(async move {
            loser
                .retire_after(&core, EPOCH, writer, LEASE_TTL_MS, Some(seen))
                .await
                .map(|answer| matches!(answer, WriterRetirement::Pending))
        })
    };
    reached(&held).await;
    assert_eq!(
        loser.retained(),
        1,
        "the loser built its close from the open row"
    );

    rig.store.lose_fence_reply.store(true, Ordering::SeqCst);
    assert!(matches!(
        rig.fence
            .retirements
            .retire_after(
                &rig.fence.core,
                EPOCH,
                rig.writer,
                LEASE_TTL_MS,
                Some(rig.seen.clone())
            )
            .await,
        Ok(WriterRetirement::Pending)
    ));
    assert_eq!(
        rig.fence.retained(),
        1,
        "the winner's lost reply is retained"
    );
    assert_eq!(rig.store.control(rig.writer), Some(CLOSED));

    held.release.notify_one();
    assert!(
        losing.await.unwrap().unwrap(),
        "the loser's conflict answers Pending"
    );
    assert_eq!(
        loser.retained(),
        0,
        "the loser's decided conflict leaves pending"
    );
    assert!(!loser.take_closed_open(EPOCH, rig.writer));
    assert!(
        placement(rig.writer).retained,
        "the winner's close may still apply: {:?}",
        placement(rig.writer)
    );
    assert!(undrained_records()
        .exit_report()
        .unconfirmed
        .iter()
        .any(|listed| listed.target() == rig.seen.target()));

    tokio::time::timeout(Duration::from_secs(10), rig.fence.settle())
        .await
        .expect("settle decides the winner's attempt");
    let recorded = placement(rig.writer);
    assert!(
        recorded.recorded.is_some()
            && !recorded.retained
            && !recorded.record_failed
            && !recorded.unconfirmed,
        "{recorded:?}"
    );
    assert!(rig.fence.retirements.take_closed_open(EPOCH, rig.writer));
    let records = durable_records().await;
    assert_eq!(records_for(&records, rig.writer), 1, "{records:?}");
    assert_eq!(rig.store.fence_applies(rig.writer), 1);
}
