// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A HEALTH PROBE'S ANSWER reaches every cell of its destination, as 1.5.5's `health.rs`
//! `probe_lane` folded it: a success recovers a tripped destination in the default cell and every
//! pool's; a client fault records nothing; a transient failure is recorded under each pool's own
//! configuration. Moved from `busbar-kernel-breaker`'s `src/tests/probe.rs` (#450): these drive the
//! unit's public `Pass<Route>`-taking seam, and minting that token is the kernel's. The prober's
//! trigger test (the crate-private cell census) stays in the breaker crate.

use busbar_contract::caps::{Pass, Route};
use busbar_kernel_breaker::cfg::BreakerCfg;
use busbar_kernel_breaker::{Breaker, BreakerUnit, DestinationId, LaneState, Outcome};

/// A fixed "now": the kernel supplies this value on the real path.
const NOW: u64 = 1_700_000_000;

/// A fresh `Pass<Route>` for one call, from the kernel's test token helper.
fn route_token() -> Pass<Route> {
    crate::test_support::tokens::pass::<Route>()
}

const POOL: &str = "p";

fn every_cell() -> impl Fn(&str) -> Option<BreakerCfg> {
    |_| Some(BreakerCfg::default())
}

/// A unit whose destination has a cell in [`POOL`] and is parked hard-down in every cell.
fn tripped() -> (BreakerUnit, DestinationId) {
    let unit = BreakerUnit::new();
    let d = DestinationId::new(1);
    let _ = unit.cell(POOL, d);
    assert!(unit.hard_down_all(d, NOW));
    (unit, d)
}

fn state(unit: &BreakerUnit, pool: &str, d: DestinationId) -> LaneState {
    unit.state(pool, d, NOW, &route_token())
}

#[test]
fn a_probe_success_recovers_a_tripped_destination_in_every_cell() {
    let (unit, d) = tripped();
    assert!(unit.suppressing(d, NOW));
    assert!(matches!(
        state(&unit, POOL, d),
        LaneState::Suppressed { .. }
    ));

    unit.probed(d, Outcome::Success, &every_cell(), NOW, &route_token());

    assert!(!unit.suppressing(d, NOW));
    assert_eq!(state(&unit, "", d), LaneState::Ready);
    assert_eq!(state(&unit, POOL, d), LaneState::Ready);
    // The success is in every cell's window too.
    assert_eq!(unit.cell(POOL, d).outcomes_in_window(NOW, 60), (1, 0));
}

/// `n` probe answers of `outcome` against `d`, every cell under the default configuration.
fn probe_n(unit: &BreakerUnit, d: DestinationId, outcome: Outcome, n: usize) {
    for _ in 0..n {
        unit.probed(d, outcome, &every_cell(), NOW, &route_token());
    }
}

/// F25 row 225: rehomed from the retired engine crate's src/engine/tests/health_tests.rs::test_probe_success_recorded_so_intermittent_failures_dont_trip.
/// Seven successful probes then five failing ones against a healthy destination under the default
/// error-rate breaker (min_requests 5, threshold 0.5): the successes sit in every cell's window and
/// dilute the failures to 5 of 12, so the default cell and the pool cell both stay Closed. The same
/// five failures alone trip a fresh destination (5 of 5), so the successes are what held it.
#[test]
fn test_probe_success_recorded_so_intermittent_failures_dont_trip() {
    use busbar_kernel_breaker::cell::BreakerState;
    let unit = BreakerUnit::new();
    let d = DestinationId::new(1);
    let _ = unit.cell(POOL, d);

    probe_n(&unit, d, Outcome::Success, 7);
    probe_n(&unit, d, Outcome::Transient { retry_after: None }, 5);

    assert_eq!(unit.cell("", d).outcomes_in_window(NOW, 60), (12, 5));
    assert_eq!(unit.cell(POOL, d).outcomes_in_window(NOW, 60), (12, 5));
    assert_eq!(
        unit.cell("", d).state(),
        BreakerState::Closed,
        "5 of 12 outcomes is below the 0.5 trip threshold: the default cell stays Closed"
    );
    assert_eq!(
        unit.cell(POOL, d).state(),
        BreakerState::Closed,
        "and so does the pool cell organic traffic routes against"
    );

    // The control: the same five failures with no successes before them trip.
    let bare = DestinationId::new(2);
    let _ = unit.cell(POOL, bare);
    probe_n(&unit, bare, Outcome::Transient { retry_after: None }, 5);
    assert!(
        matches!(unit.cell("", bare).state(), BreakerState::Open { .. }),
        "five failures alone are 5 of 5 and trip: got {:?}",
        unit.cell("", bare).state()
    );
}

/// F25 row 226: rehomed from the retired engine crate's src/engine/tests/health_tests.rs::test_probe_success_recorded_even_on_healthy_lane.
/// A successful probe of a never-tripped destination still enters the window: one success then four
/// failures is 5 outcomes at 0.8 and trips the default cell Open. Without the success the window
/// holds 4 failures, under min_requests (5), and stays Closed.
#[test]
fn test_probe_success_recorded_even_on_healthy_lane() {
    use busbar_kernel_breaker::cell::BreakerState;
    let unit = BreakerUnit::new();
    let d = DestinationId::new(1);
    let _ = unit.cell(POOL, d);

    probe_n(&unit, d, Outcome::Success, 1);
    assert_eq!(
        unit.cell("", d).outcomes_in_window(NOW, 60),
        (1, 0),
        "the success on a healthy destination is in the window"
    );
    probe_n(&unit, d, Outcome::Transient { retry_after: None }, 4);

    assert!(
        matches!(unit.cell("", d).state(), BreakerState::Open { .. }),
        "1 success + 4 failures = 5 outcomes at 0.8 trips the default cell; got {:?}",
        unit.cell("", d).state()
    );

    // The control: four failures alone stay under min_requests and the cell stays Closed.
    let bare = DestinationId::new(2);
    probe_n(&unit, bare, Outcome::Transient { retry_after: None }, 4);
    assert_eq!(unit.cell("", bare).state(), BreakerState::Closed);
}

#[test]
fn a_client_fault_probe_records_nothing() {
    let (unit, d) = tripped();
    let parked = unit.cell(POOL, d).cooldown_until();
    unit.probed(
        d,
        Outcome::RecordNothing,
        &every_cell(),
        NOW,
        &route_token(),
    );
    assert!(unit.suppressing(d, NOW));
    assert_eq!(unit.cell(POOL, d).cooldown_until(), parked);

    // On a healthy destination it leaves every window as it was.
    let healthy = DestinationId::new(2);
    let cell = unit.cell(POOL, healthy);
    unit.probed(
        healthy,
        Outcome::RecordNothing,
        &every_cell(),
        NOW,
        &route_token(),
    );
    assert_eq!(cell.outcomes_in_window(NOW, 60), (0, 0));
    assert_eq!(unit.cell("", healthy).outcomes_in_window(NOW, 60), (0, 0));
    assert!(!unit.suppressing(healthy, NOW));
}

#[test]
fn a_transient_probe_failure_is_recorded_under_each_pools_own_configuration() {
    let unit = BreakerUnit::new();
    let d = DestinationId::new(1);
    let _ = unit.cell(POOL, d);
    // Only the named pool is configured: the default cell records nothing, as an organic
    // observation with no configuration does.
    let only_pool = |pool: &str| (pool == POOL).then(BreakerCfg::default);
    unit.probed(
        d,
        Outcome::Transient { retry_after: None },
        &only_pool,
        NOW,
        &route_token(),
    );
    assert_eq!(unit.cell(POOL, d).err_count(), 1);
    assert_eq!(unit.cell("", d).err_count(), 0);
}
