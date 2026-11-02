// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::Pass;
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

    let tripped = unit.observe(
        "pool",
        DestinationId::new(1),
        Outcome::Transient { retry_after: None },
        &cfg,
        now,
        &Pass::<Route>::mint(&crate::seal::acquire()),
    );
    assert!(tripped, "a single failure must trip a consecutive_n=1 cell");
    let LaneState::Suppressed { until } = unit.state(
        "pool",
        DestinationId::new(1),
        now,
        &Pass::<Route>::mint(&crate::seal::acquire()),
    ) else {
        panic!("expected Suppressed immediately after a trip");
    };
    assert!(until > now, "cooldown must extend into the future");

    assert_eq!(
        unit.try_admit("pool", DestinationId::new(1), now),
        Err(LaneState::Suppressed { until })
    );

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
        unit.state(
            "pool",
            DestinationId::new(1),
            past,
            &Pass::<Route>::mint(&crate::seal::acquire())
        ),
        LaneState::ProbeInFlight
    );

    let re_tripped = unit.observe(
        "pool",
        DestinationId::new(1),
        Outcome::Success,
        &cfg,
        past,
        &Pass::<Route>::mint(&crate::seal::acquire()),
    );
    assert!(!re_tripped, "a success is never reported as a trip");
    assert_eq!(
        unit.state(
            "pool",
            DestinationId::new(1),
            past,
            &Pass::<Route>::mint(&crate::seal::acquire())
        ),
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
        &Pass::<Route>::mint(&crate::seal::acquire()),
    );
    let LaneState::Suppressed { until: first_until } = unit.state(
        "pool",
        DestinationId::new(1),
        now,
        &Pass::<Route>::mint(&crate::seal::acquire()),
    ) else {
        panic!("expected Suppressed after the first trip");
    };
    let first_cooldown = first_until - now;

    assert!(
        (360..=440).contains(&first_cooldown),
        "got {first_cooldown}"
    );

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
        &Pass::<Route>::mint(&crate::seal::acquire()),
    );
    let LaneState::Suppressed {
        until: second_until,
    } = unit.state(
        "pool",
        DestinationId::new(1),
        first_until,
        &Pass::<Route>::mint(&crate::seal::acquire()),
    )
    else {
        panic!("expected Suppressed after the re-trip");
    };
    let second_cooldown = second_until - first_until;

    assert!(second_cooldown > first_cooldown, "escalated cooldown ({second_cooldown}) must exceed the first trip's cooldown ({first_cooldown})");
}

#[test]
fn an_exhausted_destination_budget_is_excluded_not_ordered_last() {
    let unit: BreakerUnit = BreakerUnit::new();
    let cfg = BreakerCfg::default();
    let now = 1_000;
    unit.set_budget(DestinationId::new(1), 0);

    assert_eq!(
        unit.state(
            "pool",
            DestinationId::new(1),
            now,
            &Pass::<Route>::mint(&crate::seal::acquire())
        ),
        LaneState::BudgetExhausted
    );
    assert_eq!(
        unit.try_admit("pool", DestinationId::new(1), now),
        Err(LaneState::BudgetExhausted)
    );

    unit.observe(
        "pool",
        DestinationId::new(1),
        Outcome::Success,
        &cfg,
        now,
        &Pass::<Route>::mint(&crate::seal::acquire()),
    );
    assert_eq!(
        unit.state(
            "pool",
            DestinationId::new(1),
            now,
            &Pass::<Route>::mint(&crate::seal::acquire())
        ),
        LaneState::BudgetExhausted
    );
}

#[test]
fn hard_down_trips_every_pool_cell_for_the_destination() {
    let unit: BreakerUnit = BreakerUnit::new();
    let cfg = BreakerCfg::default();
    let now = 1_000;

    assert_eq!(
        unit.state(
            "",
            DestinationId::new(1),
            now,
            &Pass::<Route>::mint(&crate::seal::acquire())
        ),
        LaneState::Ready
    );
    assert_eq!(
        unit.state(
            "pool-a",
            DestinationId::new(1),
            now,
            &Pass::<Route>::mint(&crate::seal::acquire())
        ),
        LaneState::Ready
    );
    assert_eq!(
        unit.state(
            "pool-b",
            DestinationId::new(1),
            now,
            &Pass::<Route>::mint(&crate::seal::acquire())
        ),
        LaneState::Ready
    );

    let fresh = unit.observe(
        "pool-a",
        DestinationId::new(1),
        Outcome::HardDown,
        &cfg,
        now,
        &Pass::<Route>::mint(&crate::seal::acquire()),
    );
    assert!(fresh, "the first hard-down trip must be reported fresh");

    for pool in ["", "pool-a", "pool-b"] {
        match unit.state(
            pool,
            DestinationId::new(1),
            now,
            &Pass::<Route>::mint(&crate::seal::acquire()),
        ) {
            LaneState::Suppressed { until } => {
                assert!(until > now, "pool {pool:?} must carry a sticky cooldown")
            }
            other => panic!("pool {pool:?} expected Suppressed after hard-down, got {other:?}"),
        }
    }

    let fresh_again = unit.observe(
        "pool-a",
        DestinationId::new(1),
        Outcome::HardDown,
        &cfg,
        now,
        &Pass::<Route>::mint(&crate::seal::acquire()),
    );
    assert!(!fresh_again);
}

#[test]
fn a_pool_that_only_read_readiness_is_parked_by_a_hard_down_through_another() {
    let unit = BreakerUnit::new();
    let destination = DestinationId::new(9);
    let now = 1_000;

    assert_eq!(
        unit.state(
            "considered",
            destination,
            now,
            &Pass::<Route>::mint(&crate::seal::acquire())
        ),
        LaneState::Ready
    );
    let _ = unit.hard_down_all(destination, now);

    assert!(
        matches!(
            unit.state(
                "considered",
                destination,
                now,
                &Pass::<Route>::mint(&crate::seal::acquire())
            ),
            LaneState::Suppressed { .. }
        ),
        "a hard-down left a pool serving that a walk had already read the destination in"
    );
}

#[test]
fn a_readiness_read_creates_no_cell_that_a_subsequent_trip_would_miss() {
    let unit = BreakerUnit::new();
    let cfg = consecutive_cfg(100, 10_000);
    let destination = DestinationId::new(11);
    let now = 1_000;

    assert_eq!(
        unit.state(
            "asked",
            destination,
            now,
            &Pass::<Route>::mint(&crate::seal::acquire())
        ),
        LaneState::Ready
    );

    assert!(unit.observe(
        "",
        destination,
        Outcome::Transient { retry_after: None },
        &cfg,
        now,
        &Pass::<Route>::mint(&crate::seal::acquire()),
    ));

    for pool in ["asked", "never-asked"] {
        assert!(
            matches!(
                unit.state(pool, destination, now, &Pass::<Route>::mint(&crate::seal::acquire())),
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

#[test]
fn a_pool_first_touched_after_a_hard_down_is_parked_by_it() {
    let unit = BreakerUnit::new();
    let destination = DestinationId::new(12);
    let now = 1_000;

    assert!(unit.hard_down_all(destination, now));

    let LaneState::Suppressed { until } = unit.state(
        "late",
        destination,
        now,
        &Pass::<Route>::mint(&crate::seal::acquire()),
    ) else {
        panic!("a pool first read after a hard-down must read it");
    };
    assert_eq!(
        unit.try_admit("late", destination, now),
        Err(LaneState::Suppressed { until })
    );
}

#[test]
fn a_refusal_never_reports_a_state_that_would_have_admitted() {
    let cfg = consecutive_cfg(1, 5);
    let token = Pass::<Route>::mint(&crate::seal::acquire());
    let destination = DestinationId::new(1);

    const ROUNDS: usize = 40_000;
    let unit = BreakerUnit::new();
    let ready_refusals = std::sync::atomic::AtomicUsize::new(0);
    let gate = std::sync::Barrier::new(4);

    std::thread::scope(|scope| {
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
            &Pass::<Route>::mint(&crate::seal::acquire()),
        );
        assert!(!tripped, "healthy answer {i} must not trip");
    }
    assert_eq!(
        healthy.state(
            "pool",
            DestinationId::new(1),
            now,
            &Pass::<Route>::mint(&crate::seal::acquire())
        ),
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
            &Pass::<Route>::mint(&crate::seal::acquire()),
        )
    });
    assert!(tripped, "six transient 502s trip the same cell");
}
