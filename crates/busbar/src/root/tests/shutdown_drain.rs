// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SHUTDOWN-HANG 8.6 `drain_deadline_never_cancels_and_recovers_exactly_once`, the variants
//! that reach `finish` without a live plane: a stall injected at a store write the drain owns
//! ends the drain within its budget, detaches the owner of the held write (it keeps running and
//! its write still lands: nothing is cancelled), and returns 75 or 70 by the custody rule, never
//! 1. `finish` returns the code instead of exiting; that is the test seam.
//!
//! (a) and (b) run here over the store-backed unit checkpoint and recovery sinks. Not here (they
//! need a running gateway, a live plane or a successor process): every successor/adoption
//! assertion, (c) (its removal first confirms a sealed audit line), (g), (h) and its variants
//! v2-v7, (i), the notary, the predecessor fence cases and the slow-store backlog.

use super::tests::{coordinate_test, money_driver, Fixture, FlushGate};
use super::*;

/// A budget whose cuts these tests wait out: C1 1.5 s, C2 1.75 s, C3 1.875 s.
const SHORT: Duration = Duration::from_secs(2);
/// The design's bound on every stalled case: the budget plus one second.
const SLACK: Duration = Duration::from_secs(1);

/// Runs `finish` and returns its code and how long it took.
async fn finished(post: PostServe<'static>, drain: &ShutdownDrain) -> (i32, Duration) {
    let started = std::time::Instant::now();
    let code = tokio::time::timeout(drain.clock().budget() + SLACK, finish(post, drain))
        .await
        .expect("the drain ends within its budget plus one second");
    (code, started.elapsed())
}

/// Waits until `done` holds; a detached owner's write lands after the drain returned.
async fn eventually<F, Fut>(what: &str, done: F)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    tokio::time::timeout(Duration::from_secs(5), async {
        while !done().await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}"));
}

/// (d) A budget flight the store never answers: the settle wait is cut at C2, the money driver
/// is detached at C3 (never aborted), and the exit is 70: completed spend is in doubt.
#[tokio::test(flavor = "current_thread")]
async fn a_held_budget_flight_detaches_the_money_driver_and_exits_70() {
    let fixture = Fixture::new(16).await;
    fixture.accrue();
    let gate = Arc::new(FlushGate::default());
    *fixture.seen.backend.budget.lock().unwrap() = Some(gate.clone());
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let clock = DrainClock::new(SHORT);
    let flusher = money_driver(&fixture.seen.gov, &clock, &shutdown_tx);
    let (post, seen) = fixture.post(true, Some(flusher), &shutdown_tx, None);
    let drain = ShutdownDrain::new(clock);
    coordinate_test(&drain, &shutdown_tx);
    let (code, _) = finished(post, &drain).await;
    assert_eq!(
        code, 70,
        "a flight not confirmed is in doubt: spend unsaved"
    );
    assert!(drain.detached() >= 1, "the money driver was detached at C3");
    let custody = seen.gov.spend_custody();
    assert!(custody.spend_unsaved(), "{custody:?}");
    assert_eq!(seen.requests().await, 0);
    gate.release();
    let seen = &seen;
    eventually(
        "the detached driver's write still lands",
        move || async move { seen.requests().await == 1 },
    )
    .await;
}

/// (e) A journal flush the store never answers: [5] detaches it at the deadline, the exit is
/// 75 (no completed spend is outside custody), and the held write still lands afterwards.
#[tokio::test(flavor = "current_thread")]
async fn a_held_journal_flush_is_detached_at_the_deadline_and_exits_75() {
    let fixture = Fixture::new(16).await;
    fixture.stage(2);
    let gate = Arc::new(FlushGate::default());
    *fixture.seen.backend.journal.lock().unwrap() = Some(gate.clone());
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let (post, seen) = fixture.post(false, None, &shutdown_tx, None);
    let drain = ShutdownDrain::new(DrainClock::new(SHORT));
    coordinate_test(&drain, &shutdown_tx);
    let (code, took) = finished(post, &drain).await;
    assert_eq!(code, 75);
    assert!(drain.detached() >= 1, "the journal flush was detached");
    assert!(took >= SHORT - Duration::from_millis(100), "{took:?}");
    assert_eq!(seen.journal.pending_records(), 2);
    gate.release();
    let journal = Arc::clone(&seen.journal);
    eventually("the detached journal flush still lands", move || {
        let journal = Arc::clone(&journal);
        async move { journal.pending_records() == 0 }
    })
    .await;
    assert_eq!(
        seen.journal.read_records(seen.budget).await.unwrap().len(),
        2
    );
}

/// (f) The retirement's first write held: [6] is detached at the deadline, the writer is not
/// retired (it stays open for the next closer), and the exit is 75, never 0.
#[tokio::test(flavor = "current_thread")]
async fn a_held_retirement_write_is_detached_and_the_writer_stays_open() {
    let fixture = Fixture::new(16).await;
    let gate = Arc::new(FlushGate::default());
    *fixture.seen.backend.other.lock().unwrap() = Some(gate.clone());
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let (post, seen) = fixture.post(false, None, &shutdown_tx, None);
    let drain = ShutdownDrain::new(DrainClock::new(SHORT));
    coordinate_test(&drain, &shutdown_tx);
    let (code, _) = finished(post, &drain).await;
    assert_eq!(code, 75, "an unconfirmed retirement is never a clean exit");
    assert!(drain.detached() >= 1, "the retirement was detached");
    // At exit the writer is open (the held write is the lease release, before retirement).
    seen.still_admitted().await;
    // The detached retirement is never cancelled: released, it goes on.
    gate.release();
}

/// (j) Completed metering no flush captured into a flight, at the deadline: the shard is
/// listed `unpersisted` and the exit is 70, not 75. Sibling: a dirty budget cell with no flight.
/// There is no money driver here, so nothing captures either into a flight.
#[tokio::test(flavor = "current_thread")]
async fn unflushed_metering_or_a_dirty_cell_at_the_deadline_exits_70() {
    for budget_cell in [false, true] {
        let fixture = Fixture::new(16).await;
        let seen = &fixture.seen;
        let cost = busbar_kernel::cost::CostModel::resolve_parts(
            None,
            0,
            &std::collections::BTreeMap::new(),
        );
        let now = busbar_kernel::store::now();
        let units: std::collections::BTreeMap<String, u64> =
            [(busbar_contract::records::UNIT_INPUT.to_owned(), 3)]
                .into_iter()
                .collect();
        if budget_cell {
            drop(seen.gov.try_admit(&cost, &seen.key, "", now).unwrap());
            seen.gov
                .record_usage(&cost, &seen.key, "", "shutdown-model", &units, now);
        } else {
            seen.gov.record_lane_metering(
                &seen.key.id,
                "shutdown-model",
                Some("shutdown-provider"),
                &units,
                now,
            );
        }
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        let (post, seen) = fixture.post(true, None, &shutdown_tx, None);
        let drain = ShutdownDrain::new(DrainClock::new(SHORT));
        coordinate_test(&drain, &shutdown_tx);
        let (code, _) = finished(post, &drain).await;
        assert_eq!(code, 70, "budget_cell={budget_cell}");
        let custody = seen.gov.spend_custody();
        let kind = if budget_cell {
            "budget_cell"
        } else {
            "metering"
        };
        assert!(
            custody.unpersisted.iter().any(|item| item.kind == kind),
            "{kind} listed unpersisted: {custody:?}"
        );
        assert!(
            !custody
                .in_doubt
                .iter()
                .any(|item| item.kind == "metering_flight" || item.kind == "budget_flight"),
            "nothing was captured into a flight: {custody:?}"
        );
    }
}

/// A second signal while [1] waits on a connection that never finishes, with 15 s of the
/// budget left: the drain takes the deadline branch at once (within 100 ms of the signal).
#[tokio::test(flavor = "current_thread")]
async fn a_second_signal_ends_the_drain_at_once() {
    let fixture = Fixture::new(16).await;
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let (mut post, _seen) = fixture.post(false, None, &shutdown_tx, None);
    // A graceful serve future that never ends: one connection is still in flight.
    post.admin = Some(Box::pin(std::future::pending::<()>()));
    let clock = DrainClock::new(Duration::from_secs(20));
    let drain = ShutdownDrain::new(Arc::clone(&clock));
    coordinate_test(&drain, &shutdown_tx);
    let signalled = Arc::new(std::sync::Mutex::new(None::<std::time::Instant>));
    let signals = {
        let clock = Arc::clone(&clock);
        let signalled = Arc::clone(&signalled);
        tokio::spawn(async move {
            // The first signal arms the drain, as the boot subscriber does.
            tokio::time::sleep(Duration::from_millis(200)).await;
            clock.arm(Instant::now() + clock.budget());
            // The second, 15 s before C1 at the earliest.
            tokio::time::sleep(Duration::from_millis(300)).await;
            *signalled.lock().unwrap() = Some(std::time::Instant::now());
            clock.expire_now();
        })
    };
    let code = tokio::time::timeout(Duration::from_secs(5), finish(post, &drain))
        .await
        .expect("the second signal ends the drain long before its budget");
    let returned = std::time::Instant::now();
    signals.await.unwrap();
    let signalled = signalled.lock().unwrap().expect("the second signal fired");
    assert!(
        returned.duration_since(signalled) < Duration::from_millis(100),
        "the deadline branch within 100 ms of the second signal: {:?}",
        returned.duration_since(signalled)
    );
    assert_eq!(code, 75);
    assert!(drain.clock().expired());
}

/// Drops set the flag: a task that is cancelled drops its state.
struct DroppedFlag(Arc<std::sync::atomic::AtomicBool>);
impl Drop for DroppedFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// A work-recovery task that never stops is cut at C1 and detached, not aborted: the drain
/// goes on and exits 75 well before the deadline, and the task was never cancelled.
#[tokio::test(flavor = "current_thread")]
async fn a_stalled_work_recovery_is_cut_at_c1_and_never_cancelled() {
    let fixture = Fixture::new(16).await;
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let (mut post, _seen) = fixture.post(false, None, &shutdown_tx, None);
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = DroppedFlag(Arc::clone(&dropped));
    post.work_recovery = tokio::spawn(async move {
        let _flag = flag;
        std::future::pending::<()>().await;
    });
    let drain = ShutdownDrain::new(DrainClock::new(SHORT));
    coordinate_test(&drain, &shutdown_tx);
    let (code, took) = finished(post, &drain).await;
    assert_eq!(code, 75, "work recovery that did not stop is undrained");
    assert!(drain.detached() >= 1);
    assert!(
        took >= SHORT * 3 / 4 - Duration::from_millis(100),
        "held to C1: {took:?}"
    );
    assert!(
        !dropped.load(Ordering::SeqCst),
        "the detached task was never cancelled"
    );
}

/// Unarmed primitives: serving longer than the budget with no signal cuts nothing and detaches
/// nothing, because no limit exists before the first broadcast; then the drain runs normally
/// and the writer retires.
#[tokio::test(flavor = "current_thread")]
async fn serving_longer_than_the_budget_cuts_nothing_before_the_first_signal() {
    let fixture = Fixture::new(16).await;
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
    let (mut post, _seen) = fixture.post(false, None, &shutdown_tx, None);
    let budget = Duration::from_secs(3);
    post.admin = Some(Box::pin(async move {
        tokio::time::sleep(budget + Duration::from_secs(1)).await;
    }));
    let drain = ShutdownDrain::new(DrainClock::new(budget));
    coordinate_test(&drain, &shutdown_tx);
    let started = std::time::Instant::now();
    let code = tokio::time::timeout(budget * 3, finish(post, &drain))
        .await
        .expect("the drain runs once serving ends");
    assert!(started.elapsed() >= budget + Duration::from_secs(1));
    assert_eq!(code, 0, "nothing was cut, so the writer retires");
    assert_eq!(drain.detached(), 0, "no detach before the first broadcast");
}

/// (a) A running unit's persist select the store never answers, and (b) a finished unit's
/// recovery select the store never answers: the money driver's unit pass holds that write, is
/// detached at C3 (never aborted), and the exit is 70 with the running unit flush `in_doubt`;
/// released, the held write still lands.
#[tokio::test(flavor = "current_thread")]
async fn a_held_unit_select_detaches_the_money_driver_and_exits_70() {
    for recovery in [false, true] {
        let fixture = Fixture::new(16).await;
        fixture.attach_sinks().await;
        let unit = fixture.unit();
        if recovery {
            assert!(fixture.seen.gov.finish_unit_checkpoint(unit));
        } else {
            fixture.seen.gov.stage_unit_checkpoint(unit);
        }
        let gate = Arc::new(FlushGate::default());
        let held = if recovery {
            &fixture.seen.backend.recovery
        } else {
            &fixture.seen.backend.unitcp
        };
        *held.lock().unwrap() = Some(gate.clone());
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        let clock = DrainClock::new(SHORT);
        let flusher = money_driver(&fixture.seen.gov, &clock, &shutdown_tx);
        let (post, seen) = fixture.post(true, Some(flusher), &shutdown_tx, None);
        let drain = ShutdownDrain::new(clock);
        coordinate_test(&drain, &shutdown_tx);
        let (code, _) = finished(post, &drain).await;
        assert_eq!(
            code, 70,
            "recovery={recovery}: the held unit write is in doubt"
        );
        assert!(
            drain.detached() >= 1,
            "recovery={recovery}: the money driver was detached at C3"
        );
        let custody = seen.gov.spend_custody();
        assert!(
            custody
                .in_doubt
                .iter()
                .any(|item| item.kind == "unit_flush"),
            "recovery={recovery}: {custody:?}"
        );
        gate.release();
        let gov = Arc::clone(&seen.gov);
        eventually(
            "the detached unit pass ends once its write lands",
            move || {
                let gov = Arc::clone(&gov);
                async move {
                    !gov.spend_custody()
                        .in_doubt
                        .iter()
                        .any(|item| item.kind == "unit_flush")
                }
            },
        )
        .await;
    }
}
