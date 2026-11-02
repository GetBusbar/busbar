// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::{Pass, Route};
use busbar_kernel_breaker::cfg::BreakerCfg;
use busbar_kernel_breaker::{Breaker, BreakerUnit, DestinationId, LaneState, Outcome};

const NOW: u64 = 1_700_000_000;

fn route_token() -> Pass<Route> {
    crate::test_support::tokens::pass::<Route>()
}

const POOL: &str = "p";

fn every_cell() -> impl Fn(&str) -> Option<BreakerCfg> {
    |_| Some(BreakerCfg::default())
}

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

    assert_eq!(unit.cell(POOL, d).outcomes_in_window(NOW, 60), (1, 0));
}

fn probe_n(unit: &BreakerUnit, d: DestinationId, outcome: Outcome, n: usize) {
    for _ in 0..n {
        unit.probed(d, outcome, &every_cell(), NOW, &route_token());
    }
}

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

    let bare = DestinationId::new(2);
    let _ = unit.cell(POOL, bare);
    probe_n(&unit, bare, Outcome::Transient { retry_after: None }, 5);
    assert!(
        matches!(unit.cell("", bare).state(), BreakerState::Open { .. }),
        "five failures alone are 5 of 5 and trip: got {:?}",
        unit.cell("", bare).state()
    );
}

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
