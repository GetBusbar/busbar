// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The breaker unit driven through its public [`Breaker`] seam, which takes a `Pass<Route>` on
//! every call. Moved from `busbar-kernel-breaker`'s own suite (`src/tests/mod.rs`): minting that
//! token is the kernel's, so the tests that need one run here, against the unit's public API.

use crate::test_support::tokens::pass;
use busbar_contract::caps::Route;
use busbar_kernel_breaker::cfg::{BreakerCfg, TripConfig, TripMode};
use busbar_kernel_breaker::{Admit, Breaker, BreakerUnit, DestinationId, LaneState, Outcome};

fn consecutive_cfg(base_cooldown_secs: u64, max_cooldown_secs: u64) -> BreakerCfg {
    BreakerCfg {
        base_cooldown_secs,
        max_cooldown_secs,
        honor_retry_after: true,
        trip: TripConfig {
            mode: TripMode::Consecutive,
            consecutive_n: 1,
            ..TripConfig::default()
        },
        bench_below_trip_threshold: true,
    }
}

#[test]
fn trip_then_cooldown_then_half_open_then_success_closes() {
    let unit: BreakerUnit = BreakerUnit::new();
    let cfg = consecutive_cfg(100, 10_000);
    let now = 1_000;

    // One failure trips a Consecutive(1) cell.
    let tripped = unit.observe(
        "pool",
        DestinationId::new(1),
        Outcome::Transient { retry_after: None },
        &cfg,
        now,
        &pass::<Route>(),
    );
    assert!(tripped, "a single failure must trip a consecutive_n=1 cell");
    let LaneState::Suppressed { until } =
        unit.state("pool", DestinationId::new(1), now, &pass::<Route>())
    else {
        panic!("expected Suppressed immediately after a trip");
    };
    assert!(until > now, "cooldown must extend into the future");

    // Still cooling: try_admit is refused.
    assert_eq!(
        unit.try_admit("pool", DestinationId::new(1), now),
        Err(LaneState::Suppressed { until })
    );

    // Past the cooldown: the cell is probe-winnable and try_admit wins the single-flight probe.
    let past = until;
    let admit = unit
        .try_admit("pool", DestinationId::new(1), past)
        .expect("expired cooldown must admit a probe");
    assert!(matches!(
        admit,
        Admit {
            probe_epoch: Some(_)
        }
    ));
    assert_eq!(
        unit.state("pool", DestinationId::new(1), past, &pass::<Route>()),
        LaneState::ProbeInFlight
    );

    // The probe succeeds: the cell recovers to Closed/Ready.
    let re_tripped = unit.observe(
        "pool",
        DestinationId::new(1),
        Outcome::Success,
        &cfg,
        past,
        &pass::<Route>(),
    );
    assert!(!re_tripped, "a success is never reported as a trip");
    assert_eq!(
        unit.state("pool", DestinationId::new(1), past, &pass::<Route>()),
        LaneState::Ready
    );
}

#[test]
fn a_failed_probe_re_trips_with_the_shifted_cooldown() {
    let unit: BreakerUnit = BreakerUnit::new();
    let cfg = consecutive_cfg(200, 100_000);
    let now = 1_000;

    unit.observe(
        "pool",
        DestinationId::new(1),
        Outcome::Transient { retry_after: None },
        &cfg,
        now,
        &pass::<Route>(),
    );
    let LaneState::Suppressed { until: first_until } =
        unit.state("pool", DestinationId::new(1), now, &pass::<Route>())
    else {
        panic!("expected Suppressed after the first trip");
    };
    let first_cooldown = first_until - now;
    // The consecutive-failure streak is bumped BEFORE the cooldown is computed (matching the
    // ported source exactly — see `cell::BreakerCell::record_failure`'s `ST_CLOSED` arm), so even
    // this FIRST trip computes off streak == 1: duration = (200 << 1) = 400, +/-10% jitter, clamped
    // to >= 200 — i.e. in [360, 440].
    assert!(
        (360..=440).contains(&first_cooldown),
        "got {first_cooldown}"
    );

    // Win the probe, then fail it: reopens with a FURTHER escalated (streak == 2) cooldown.
    let admit = unit
        .try_admit("pool", DestinationId::new(1), first_until)
        .unwrap();
    assert!(admit.probe_epoch.is_some());
    unit.observe(
        "pool",
        DestinationId::new(1),
        Outcome::Transient { retry_after: None },
        &cfg,
        first_until,
        &pass::<Route>(),
    );
    let LaneState::Suppressed {
        until: second_until,
    } = unit.state("pool", DestinationId::new(1), first_until, &pass::<Route>())
    else {
        panic!("expected Suppressed after the re-trip");
    };
    let second_cooldown = second_until - first_until;
    // streak == 2 duration is (200 << 2) = 800 +/- 10%, clamped to >= 400 — strictly larger than
    // any streak == 1 draw above.
    assert!(second_cooldown > first_cooldown, "escalated cooldown ({second_cooldown}) must exceed the first trip's cooldown ({first_cooldown})");
}

#[test]
fn an_exhausted_destination_budget_is_excluded_not_ordered_last() {
    let unit: BreakerUnit = BreakerUnit::new();
    let cfg = BreakerCfg::default();
    let now = 1_000;
    unit.set_budget(DestinationId::new(1), 0); // already exhausted

    // The breaker cell itself is perfectly healthy (never observed a failure) — a
    // "budget exhausted" verdict must come from the budget check EXCLUDING the destination before
    // the breaker is even consulted, not from ranking it behind healthy destinations.
    assert_eq!(
        unit.state("pool", DestinationId::new(1), now, &pass::<Route>()),
        LaneState::BudgetExhausted
    );
    assert_eq!(
        unit.try_admit("pool", DestinationId::new(1), now),
        Err(LaneState::BudgetExhausted)
    );

    // Confirm it really is budget, not the breaker: observing outcomes never touches budget state,
    // and the destination's own cell reads Ready underneath the budget exclusion.
    unit.observe(
        "pool",
        DestinationId::new(1),
        Outcome::Success,
        &cfg,
        now,
        &pass::<Route>(),
    );
    assert_eq!(
        unit.state("pool", DestinationId::new(1), now, &pass::<Route>()),
        LaneState::BudgetExhausted
    );
}

#[test]
fn hard_down_trips_every_pool_cell_for_the_destination() {
    let unit: BreakerUnit = BreakerUnit::new();
    let cfg = BreakerCfg::default();
    let now = 1_000;

    // Touch three cells for the same destination (the default "" cell, and two named pools) so
    // each exists before the hard-down fan-out.
    assert_eq!(
        unit.state("", DestinationId::new(1), now, &pass::<Route>()),
        LaneState::Ready
    );
    assert_eq!(
        unit.state("pool-a", DestinationId::new(1), now, &pass::<Route>()),
        LaneState::Ready
    );
    assert_eq!(
        unit.state("pool-b", DestinationId::new(1), now, &pass::<Route>()),
        LaneState::Ready
    );

    let fresh = unit.observe(
        "pool-a",
        DestinationId::new(1),
        Outcome::HardDown,
        &cfg,
        now,
        &pass::<Route>(),
    );
    assert!(fresh, "the first hard-down trip must be reported fresh");

    for pool in ["", "pool-a", "pool-b"] {
        match unit.state(pool, DestinationId::new(1), now, &pass::<Route>()) {
            LaneState::Suppressed { until } => {
                assert!(until > now, "pool {pool:?} must carry a sticky cooldown")
            }
            other => panic!("pool {pool:?} expected Suppressed after hard-down, got {other:?}"),
        }
    }

    // A second hard-down (e.g. a repeated probe failure) is not a FRESH trip.
    let fresh_again = unit.observe(
        "pool-a",
        DestinationId::new(1),
        Outcome::HardDown,
        &cfg,
        now,
        &pass::<Route>(),
    );
    assert!(!fresh_again);
}

/// A pool a walk has only read readiness in is parked by a bad key seen through another pool.
///
/// The read creates no cell. The pool reads the hard-down through the destination's default cell,
/// which every hard-down parks, as the cell its first touch would create.
#[test]
fn a_pool_that_only_read_readiness_is_parked_by_a_hard_down_through_another() {
    let unit = BreakerUnit::new();
    let destination = DestinationId::new(9);
    let now = 1_000;

    assert_eq!(
        unit.state("considered", destination, now, &pass::<Route>()),
        LaneState::Ready
    );
    let _ = unit.hard_down_all(destination, now);

    assert!(
        matches!(
            unit.state("considered", destination, now, &pass::<Route>()),
            LaneState::Suppressed { .. }
        ),
        "a hard-down left a pool serving that a walk had already read the destination in"
    );
}

/// A readiness read leaves nothing behind (audit kernel-breaker: "the readiness read creates
/// cells while documented as side-effect-free").
///
/// The read used to create the pool's cell Closed. A pool asked about before its destination's
/// default cell tripped then kept that Closed cell: it read Ready, and admitted, through a trip
/// any pool not yet asked about would carry. Read-only, the earlier read changes nothing, and the
/// two pools read alike.
#[test]
fn a_readiness_read_creates_no_cell_that_a_subsequent_trip_would_miss() {
    let unit = BreakerUnit::new();
    let cfg = consecutive_cfg(100, 10_000);
    let destination = DestinationId::new(11);
    let now = 1_000;

    assert_eq!(
        unit.state("asked", destination, now, &pass::<Route>()),
        LaneState::Ready
    );
    // The default cell trips on its own, without a hard-down's fan-out.
    assert!(unit.observe(
        "",
        destination,
        Outcome::Transient { retry_after: None },
        &cfg,
        now,
        &pass::<Route>(),
    ));

    for pool in ["asked", "never-asked"] {
        assert!(
            matches!(
                unit.state(pool, destination, now, &pass::<Route>()),
                LaneState::Suppressed { until } if until > now
            ),
            "pool {pool:?} must read the destination's trip"
        );
        assert!(
            matches!(
                unit.try_admit(pool, destination, now),
                Err(LaneState::Suppressed { .. })
            ),
            "pool {pool:?} must not admit through the destination's trip"
        );
    }
}

/// A pool whose first touch comes after a hard-down is parked by it (1.5.5 parity: a new pool cell
/// inherits the lane's known health, v1.5.5 `crates/busbar/src/store/in_memory/mod.rs` `cell`).
#[test]
fn a_pool_first_touched_after_a_hard_down_is_parked_by_it() {
    let unit = BreakerUnit::new();
    let destination = DestinationId::new(12);
    let now = 1_000;

    assert!(unit.hard_down_all(destination, now));

    let LaneState::Suppressed { until } = unit.state("late", destination, now, &pass::<Route>())
    else {
        panic!("a pool first read after a hard-down must read it");
    };
    assert_eq!(
        unit.try_admit("late", destination, now),
        Err(LaneState::Suppressed { until })
    );
}

/// A refused admission never names a state that would have admitted.
///
/// `try_admit` used to decide the refusal from a SECOND read of the cell, taken after the read that
/// denied it: the probe owner completing recovery in that gap left the refusal describing a cell
/// that was by then Closed and ready — a `Ready` refusal, which its callers are entitled to treat
/// as impossible. The admit decision and the reason for it now come out of one read.
#[test]
fn a_refusal_never_reports_a_state_that_would_have_admitted() {
    let cfg = consecutive_cfg(1, 5);
    let token = pass::<Route>();
    let destination = DestinationId::new(1);

    // One cell, cycled through Open -> HalfOpen -> Closed under a crowd asking it for admission:
    // the gap being probed is a few instructions wide, so it is walked into repeatedly rather than
    // aimed at once.
    const ROUNDS: usize = 40_000;
    let unit = BreakerUnit::new();
    let ready_refusals = std::sync::atomic::AtomicUsize::new(0);
    let gate = std::sync::Barrier::new(4);

    std::thread::scope(|scope| {
        // The recovery side: trip the cell, and complete whatever probe an asker has since won.
        scope.spawn(|| {
            gate.wait();
            for _ in 0..ROUNDS {
                unit.observe(
                    "pool",
                    destination,
                    Outcome::Transient { retry_after: None },
                    &cfg,
                    1_000,
                    &token,
                );
                unit.observe(
                    "pool",
                    destination,
                    Outcome::Success,
                    &cfg,
                    2_000_000,
                    &token,
                );
            }
        });
        for _ in 0..3 {
            scope.spawn(|| {
                gate.wait();
                for _ in 0..ROUNDS {
                    // Well past the armed cooldown, so a refusal here can only be a peer's probe.
                    match unit.try_admit("pool", destination, 2_000_000) {
                        Ok(admit) => {
                            if let Some(epoch) = admit.probe_epoch {
                                unit.release_probe("pool", destination, epoch);
                            }
                        }
                        Err(LaneState::Ready) => {
                            ready_refusals.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        Err(_) => {}
                    }
                }
            });
        }
    });

    assert_eq!(
        ready_refusals.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "an admission was refused with a state that would have admitted"
    );
}

/// RED (ARCHITECT row 68): six 502s in a row that the plane reads as HEALTHY are six successes:
/// they never trip a cell, even one that benches nothing below its trip threshold. The same six read
/// as TRANSIENT trip it, so the cell under test is one six failures do trip.
#[test]
fn six_healthy_502s_in_a_row_do_not_trip_a_cell() {
    use busbar_kernel_breaker::classify::{Reading, WireFault};
    use busbar_kernel_breaker::port::{classify_upstream, UpstreamStatus};
    let cfg = BreakerCfg {
        bench_below_trip_threshold: false,
        ..BreakerCfg::default()
    };
    let read = |fault| {
        classify_upstream(UpstreamStatus {
            reading: Reading::Answered(Some(fault)),
            retry_after: None,
        })
        .outcome
    };
    assert_eq!(read(WireFault::Healthy), Outcome::Success);
    let healthy: BreakerUnit = BreakerUnit::new();
    let now = 1_000;
    for i in 0..6 {
        let tripped = healthy.observe(
            "pool",
            DestinationId::new(1),
            read(WireFault::Healthy),
            &cfg,
            now,
            &pass::<Route>(),
        );
        assert!(!tripped, "healthy answer {i} must not trip");
    }
    assert_eq!(
        healthy.state("pool", DestinationId::new(1), now, &pass::<Route>()),
        LaneState::Ready
    );

    let transient: BreakerUnit = BreakerUnit::new();
    let tripped = (0..6).any(|_| {
        transient.observe(
            "pool",
            DestinationId::new(1),
            read(WireFault::Transient),
            &cfg,
            now,
            &pass::<Route>(),
        )
    });
    assert!(tripped, "six transient 502s trip the same cell");
}
