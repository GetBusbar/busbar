// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HEALTH PROBE'S ANSWER on the lane store, carried over from the previous release's prober
//! tests. On the door path the root's breaker port folds a probe's answer into this store exactly
//! so: the answer's status is classified by the breaker unit's classifier, then a hard-down parks
//! the lane in every cell, a transient joins every cell's window under its pool's ladder, and a
//! success recovers a suppressed lane and joins every cell's window, counted once on the lane.
//!
//! Each test names the legacy test it carries over and keeps its inputs and expected states; only
//! the harness is new: the store is driven through the calls the port makes, not through a real
//! probe over a real socket.

use super::*;
use busbar_kernel::store::BreakerCfg;
use busbar_kernel_breaker::classify::NoopDiagnostics;
use busbar_kernel_breaker::port::{classify_upstream, UpstreamCode, UpstreamStatus};
use busbar_kernel_breaker::Outcome;

fn lane(id: usize) -> LaneData {
    LaneData {
        model: format!("model-{id}"),
        provider: format!("provider-{id}"),
        max: 10,
        sem: Arc::new(Semaphore::new(10)),
        limited: false,
        budget: -1,
        cooldown_until: 0,
        streak: 0,
        dead: false,
        dead_reason: String::new(),
        ok: 0,
        err: 0,
        client_fault: 0,
        upstream_model: None,
        attempt_timeout_ms: None,
        reasoning: false,
        prompt_caching: false,
    }
}

/// What the breaker unit's classifier makes of a probe answered with the HTTP `status`.
fn probe_answered(status: u16) -> Outcome {
    classify_upstream(
        &std::collections::HashMap::new(),
        UpstreamStatus {
            code: Some(UpstreamCode::Http(status)),
            retry_after: None,
        },
        &NoopDiagnostics,
    )
    .outcome
}

/// Ports legacy `health_tests.rs::test_probe_auth_failure_is_hard_down_not_transient`: a probe
/// answered 401 is a hard-down, not a recoverable transient: the lane is parked in the default cell
/// and in its pool's cell under the long sticky cooldown.
#[test]
fn a_probe_answered_401_parks_the_lane_hard_down_in_every_cell() {
    let store = Arc::new(HealthState::new(vec![lane(0)]));
    set_now_for_test(9_000);
    // The lane's pool cell exists, as it does for a lane a pool fronts.
    store.record_success_in("p", 0);

    assert_eq!(probe_answered(401), Outcome::HardDown);
    store.record_hard_down_all_cells(0, "health-probe hard-down (auth/billing)");

    assert!(
        matches!(store.breaker_state(0), BreakerState::Open { .. }),
        "a 401 probe trips the default cell open, got {:?}",
        store.breaker_state(0)
    );
    assert!(
        store.cooldown_remaining_in("p", 0, 9_000) > 60,
        "a 401 probe arms the long sticky hard-down cooldown on the pool's cell, not a short \
         transient one"
    );
}

/// Ports legacy `health_tests.rs::test_probe_server_error_is_transient_not_hard_down`: a single
/// probe answered 503 is a transient under the default breaker, below its trip threshold: the lane
/// stays closed.
#[test]
fn a_single_probe_answered_503_is_a_transient_that_leaves_the_lane_closed() {
    let store = Arc::new(HealthState::new(vec![lane(0)]));
    set_now_for_test(9_000);
    store.record_success_in("p", 0);

    let Outcome::Transient { retry_after } = probe_answered(503) else {
        panic!("a 503 probe is a transient, got {:?}", probe_answered(503));
    };
    store.record_probe_failure_all_cells(
        0,
        "health-probe",
        &|_: &str| BreakerCfg::default(),
        retry_after,
    );

    assert!(
        matches!(store.breaker_state(0), BreakerState::Closed),
        "a single 503 probe records a transient, with no hard-down trip, got {:?}",
        store.breaker_state(0)
    );
}

/// Ports legacy `health_tests.rs::test_probe_success_recorded_even_on_healthy_lane`: a probe
/// success on a lane that never tripped is still pushed into the window. One success and four
/// failures fill the window to its five-request minimum at a 0.8 error rate and trip it; had the
/// success been dropped, four failures alone stay under the minimum and the lane stays closed.
#[test]
fn a_probe_success_on_a_healthy_lane_still_joins_the_window() {
    let store = Arc::new(HealthState::new(vec![lane(0)]));
    set_now_for_test(9_000);
    store.record_success_in("p", 0);
    assert!(matches!(store.breaker_state(0), BreakerState::Closed));

    if store.lane_needs_probe(0, 9_000) {
        store.recover_lane(0);
    }
    store.record_probe_success_all_cells(0);
    for _ in 0..4 {
        store.record_probe_failure_all_cells(
            0,
            "health-probe",
            &|_: &str| BreakerCfg::default(),
            None,
        );
    }

    assert!(
        matches!(store.breaker_state(0), BreakerState::Open { .. }),
        "the healthy lane's probe success must reach the window so one success and four failures \
         trip it; a closed cell means the success was dropped, got {:?}",
        store.breaker_state(0)
    );
}

/// Ports legacy `health_tests.rs::test_probe_success_bumps_lane_ok_once_not_per_cell`: a successful
/// probe counts one success on the lane however many pools front it: a lane in three pools probed
/// twice reads two, not eight.
#[test]
fn a_probe_success_counts_once_on_the_lane_not_once_per_cell() {
    let store = Arc::new(HealthState::new(vec![lane(0)]));
    set_now_for_test(9_000);
    for pool in ["a", "b", "c"] {
        store.record_success_in(pool, 0);
    }
    let before = store.snapshot(0, 9_000).ok;

    for _ in 0..2 {
        if store.lane_needs_probe(0, 9_000) {
            store.recover_lane(0);
        }
        store.record_probe_success_all_cells(0);
    }

    assert_eq!(
        store.snapshot(0, 9_000).ok - before,
        2,
        "a lane in three pools probed twice reads two successes, never one per cell"
    );
}
