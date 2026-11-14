// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WASTE-CORE-LIFECYCLE W8: the pool watchdog wakes at the deadlines its own scan saw, not on a
//! fixed 50 ms poll. Hung-crossing detection timing is pinned by the existing watchdog fault tests
//! (`worker_unit_cancel_tests`, `dispatch_tests`), which run unchanged.

use super::super::worker::{Budgets, DispatchConfig, Dispatcher};
use std::time::Duration;

fn idle_scans(config: DispatchConfig, idle: Duration) -> u64 {
    let d = Dispatcher::new(config, busbar_contract::services::test_caller_binding());
    let before = d.stats().watchdog_scans;
    std::thread::sleep(idle);
    d.stats().watchdog_scans - before
}

#[test]
fn idle_watchdog_wakes_at_most_once_per_second() {
    let scans = idle_scans(DispatchConfig::default(), Duration::from_secs(5));
    assert!(
        scans <= 6,
        "an idle pool with default budgets scans about once per second, not every 50 ms: {scans} \
         scans in 5 s"
    );
}

#[test]
fn tiny_budget_never_wakes_faster_than_period() {
    let config = DispatchConfig {
        budgets: Budgets {
            call: Duration::from_millis(5),
            stream: Duration::from_millis(5),
            connection: Duration::from_millis(5),
            write_behind: Duration::from_millis(5),
            lifecycle: Duration::from_millis(5),
        },
        ..DispatchConfig::default()
    };
    let scans = idle_scans(config, Duration::from_secs(1));
    assert!(
        scans <= 21,
        "the period floors the wake whatever the budgets: {scans} scans in 1 s"
    );
}

#[test]
fn wake_is_the_earliest_deadline_floored_by_the_period() {
    let period = Duration::from_millis(50);
    let min_budget = Duration::from_secs(1);
    // Idle: the smallest budget, since no crossing can start and breach sooner.
    assert_eq!(super::next_wake(period, min_budget, None), min_budget);
    // A crossing in flight with 200 ms left: wake at its deadline.
    assert_eq!(
        super::next_wake(period, min_budget, Some(Duration::from_millis(200))),
        Duration::from_millis(200)
    );
    // A deadline closer than the period never wakes faster than today.
    assert_eq!(
        super::next_wake(period, min_budget, Some(Duration::from_millis(1))),
        period
    );
    // A deadline beyond the smallest budget still wakes by the smallest budget, so a crossing
    // started right after this scan is seen within its own budget plus the period.
    assert_eq!(
        super::next_wake(period, min_budget, Some(Duration::from_secs(25))),
        min_budget
    );
    // Budgets below the period: the period floors it.
    assert_eq!(
        super::next_wake(period, Duration::from_millis(5), None),
        period
    );
}

#[test]
fn smallest_budget_bounds_every_class() {
    let budgets = Budgets {
        call: Duration::from_millis(900),
        stream: Duration::from_millis(700),
        connection: Duration::from_millis(800),
        write_behind: Duration::from_millis(300),
        lifecycle: Duration::from_secs(30),
    };
    assert_eq!(budgets.min(), Duration::from_millis(300));
    assert_eq!(Budgets::default().min(), Duration::from_secs(1));
}
