// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SHUTDOWN-HANG test 8.13 (the admission gate) and the drain clock's cut arithmetic.

use super::*;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

fn gate(terminal: u64) -> (Arc<AdmissionGate>, Arc<AtomicU64>) {
    let counter = Arc::new(AtomicU64::new(terminal));
    (Arc::new(AdmissionGate::over(Arc::clone(&counter))), counter)
}

#[test]
fn admission_gate_counts_until_the_hold_drops() {
    let (gate, _) = gate(0);
    let hold = gate.enter().expect("an open gate admits");
    assert_eq!(gate.live(), 1);
    let second = gate.enter().expect("an open gate admits");
    assert_eq!(gate.live(), 2);
    drop(hold);
    assert_eq!(gate.live(), 1);
    drop(second);
    assert_eq!(gate.live(), 0);
}

#[test]
fn a_closed_gate_refuses_with_drain_and_never_rises() {
    let (gate, _) = gate(0);
    let hold = gate.enter().unwrap();
    gate.close();
    gate.close();
    assert!(gate.is_closed());
    assert!(matches!(gate.enter(), Err(LimitBlocked::Draining)));
    assert_eq!(
        gate.live(),
        1,
        "an admission counted before close stays counted"
    );
    drop(hold);
    assert_eq!(gate.live(), 0);
}

#[test]
fn a_closed_gate_says_drain_even_with_a_full_backlog() {
    let (gate, _) = gate(10);
    gate.set_cap(5);
    gate.close();
    assert!(matches!(gate.enter(), Err(LimitBlocked::Draining)));
}

#[test]
fn the_terminal_backlog_cap_refuses_and_clears() {
    let (gate, terminal) = gate(0);
    gate.set_cap(3);
    terminal.store(3, std::sync::atomic::Ordering::Relaxed);
    match gate.enter() {
        Err(LimitBlocked::CustodyFull { backlog, cap }) => assert_eq!((backlog, cap), (3, 3)),
        other => panic!("expected CustodyFull, got {other:?}"),
    }
    assert_eq!(gate.live(), 0, "a refusal leaks no count");
    terminal.store(2, std::sync::atomic::Ordering::Relaxed);
    let hold = gate.enter().expect("below the cap admits");
    assert_eq!(gate.live(), 1);
    drop(hold);
}

#[test]
fn the_cap_is_at_least_one() {
    let (gate, _) = gate(0);
    gate.set_cap(0);
    assert_eq!(gate.cap(), 1);
    assert_eq!(DEFAULT_MAX_PENDING_CHECKPOINTS, 20_000);
}

#[test]
fn close_racing_admissions_counts_each_once() {
    for _ in 0..200 {
        let (gate, _) = gate(0);
        let barrier = Arc::new(std::sync::Barrier::new(33));
        let threads: Vec<_> = (0..32)
            .map(|_| {
                let gate = Arc::clone(&gate);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    gate.enter().ok()
                })
            })
            .collect();
        barrier.wait();
        gate.close();
        let live_at_close = gate.live();
        let holds: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        let admitted = holds.iter().filter(|h| h.is_some()).count() as u64;
        assert_eq!(
            gate.live(),
            admitted,
            "every admission is counted exactly once"
        );
        assert!(
            admitted <= live_at_close,
            "no admission is counted after close"
        );
        assert!(matches!(gate.enter(), Err(LimitBlocked::Draining)));
        drop(holds);
        assert_eq!(gate.live(), 0);
    }
}

#[test]
fn the_cuts_sit_inside_the_reserve() {
    let clock = DrainClock::new(Duration::from_secs(20));
    let deadline = Instant::now() + Duration::from_secs(20);
    assert_eq!(clock.limit(deadline, Cut::Deadline), deadline);
    assert_eq!(
        deadline - clock.limit(deadline, Cut::Requests),
        Duration::from_secs(5)
    );
    assert_eq!(
        deadline - clock.limit(deadline, Cut::Settle),
        Duration::from_millis(2_500)
    );
    assert_eq!(
        deadline - clock.limit(deadline, Cut::Seal),
        Duration::from_millis(1_250)
    );
}

#[tokio::test]
async fn the_clock_arms_once_and_expiry_wakes_every_waiter() {
    let clock = DrainClock::new(Duration::from_secs(60));
    assert_eq!(clock.armed_at(), None);
    let first = Instant::now() + Duration::from_secs(60);
    assert!(clock.arm(first));
    assert!(!clock.arm(first + Duration::from_secs(5)), "arming is once");
    assert_eq!(clock.armed().await, first);
    let mut expired = clock.expired_rx();
    let waiter = tokio::spawn(async move {
        let _ = expired.wait_for(|e| *e).await;
    });
    assert!(!clock.expired());
    clock.expire_now();
    tokio::time::timeout(Duration::from_millis(500), waiter)
        .await
        .expect("expiry wakes a running wait at once")
        .unwrap();
    assert!(clock.expired());
}

#[tokio::test(start_paused = true)]
async fn the_deadline_timer_expires_the_clock() {
    let clock = DrainClock::new(Duration::from_secs(1));
    clock.arm(Instant::now() + Duration::from_secs(1));
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert!(clock.expired());
}

#[test]
fn money_stop_and_passes_are_observable() {
    let clock = DrainClock::new(Duration::from_secs(20));
    let passes = clock.passes_rx();
    assert!(!clock.money_stopped());
    clock.stop_money();
    assert!(clock.money_stopped());
    clock.note_pass();
    clock.note_pass();
    assert_eq!(*passes.borrow(), 2);
    assert!(!clock.requests_done());
    clock.set_requests_done();
    assert!(clock.requests_done());
}

#[test]
fn exit_codes_follow_the_custody_lists() {
    let mut custody = SpendCustody::default();
    assert_eq!(custody.exit_code(), 75);
    custody
        .custody_only
        .push(item("running_unit", format_args!("x")));
    assert_eq!(
        custody.exit_code(),
        75,
        "running units never change the code"
    );
    custody
        .in_doubt
        .push(item("budget_flight", format_args!("y")));
    assert_eq!(custody.exit_code(), 70);
    let mut unpersisted = SpendCustody::default();
    unpersisted
        .unpersisted
        .push(item("metering", format_args!("z")));
    assert_eq!(unpersisted.exit_code(), 70);
}

/// 8.13: every refusal after the gate's hold (a full concurrency gauge, a spent requests limit)
/// drops the grant and its hold with it, so no refused admission leaks a live count.
#[tokio::test]
async fn a_refusal_after_the_hold_leaks_no_live_count() {
    use crate::config::groups::{GroupCfg, LimitCfg, LimitMetric, LimitWindow};
    let gov = GovState::new_with_core(crate::real_store::core().await, None, None)
        .await
        .expect("native Store constructs");
    let limit = |metric: LimitMetric, amount: u64, per: Option<LimitWindow>| LimitCfg {
        metric,
        amount,
        per,
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
    };
    let group = |limits: Vec<LimitCfg>| GroupCfg {
        enabled: true,
        limits,
        ..Default::default()
    };
    let groups = std::collections::BTreeMap::from([
        (
            "concurrent".to_string(),
            group(vec![limit(LimitMetric::Concurrent, 1, None)]),
        ),
        (
            "requests".to_string(),
            group(vec![limit(
                LimitMetric::Requests,
                1,
                Some(LimitWindow::Minute),
            )]),
        ),
    ]);
    let cost = crate::cost::CostModel::resolve_parts(None, 0, &groups);
    let key = |id: &str, group: &str| crate::governance::VirtualKey {
        id: id.into(),
        generation_hash: format!("h:{id}"),
        name: id.into(),
        enabled: true,
        group: Some(group.into()),
        revision: 1,
        ..Default::default()
    };
    let now = 1_700_000_000;

    let concurrent = key("vk_gate_concurrent", "concurrent");
    let held = gov
        .try_admit(&cost, &concurrent, "", now)
        .expect("the first admission fits the gauge");
    assert_eq!(gov.admissions().live(), 1);
    assert!(
        gov.try_admit(&cost, &concurrent, "", now).is_err(),
        "the concurrency gauge is full"
    );
    assert_eq!(
        gov.admissions().live(),
        1,
        "the refused admission's hold dropped with its grant"
    );
    drop(held);
    assert_eq!(gov.admissions().live(), 0);

    let requests = key("vk_gate_requests", "requests");
    drop(
        gov.try_admit(&cost, &requests, "", now)
            .expect("the minute's one request"),
    );
    assert_eq!(gov.admissions().live(), 0);
    assert!(
        gov.try_admit(&cost, &requests, "", now).is_err(),
        "the requests limit is spent"
    );
    assert_eq!(gov.admissions().live(), 0, "a limit refusal leaks no count");
}
