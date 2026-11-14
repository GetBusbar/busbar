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
