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
