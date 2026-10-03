// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The breaker unit driven through its public [`Breaker`] seam, which takes a `Pass<Route>` on
//! every call. Moved from `busbar-kernel-breaker`'s own suite (`src/tests/mod.rs`): minting that
//! token is the kernel's, so the tests that need one run here, against the unit's public API.

use busbar_contract::caps::{KernelSeal, Pass, Route};
use busbar_kernel_breaker::cfg::{BreakerCfg, TripConfig, TripMode};
use busbar_kernel_breaker::journal::JournalSink;
use busbar_kernel_breaker::{Admit, Breaker, BreakerUnit, DestinationId, LaneState, Outcome};

/// A fresh `Pass<Route>` for one `observe`/`state` call — test-only, minted through the
/// kernel seal exactly as CG-29 says a real deployment would (`KernelSeal::acquire_for_kernel` is
/// `// contract:` kernel-only outside test modules).
fn route_token() -> Pass<Route> {
    Pass::mint(&KernelSeal::acquire_for_kernel())
}

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
        &route_token(),
    );
    assert!(tripped, "a single failure must trip a consecutive_n=1 cell");
    let LaneState::Suppressed { until } =
        unit.state("pool", DestinationId::new(1), now, &route_token())
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
        unit.state("pool", DestinationId::new(1), past, &route_token()),
        LaneState::ProbeInFlight
    );

    // The probe succeeds: the cell recovers to Closed/Ready.
    let re_tripped = unit.observe(
        "pool",
        DestinationId::new(1),
        Outcome::Success,
        &cfg,
        past,
        &route_token(),
    );
    assert!(!re_tripped, "a success is never reported as a trip");
    assert_eq!(
        unit.state("pool", DestinationId::new(1), past, &route_token()),
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
        &route_token(),
    );
    let LaneState::Suppressed { until: first_until } =
        unit.state("pool", DestinationId::new(1), now, &route_token())
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
        &route_token(),
    );
    let LaneState::Suppressed {
        until: second_until,
    } = unit.state("pool", DestinationId::new(1), first_until, &route_token())
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
        unit.state("pool", DestinationId::new(1), now, &route_token()),
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
        &route_token(),
    );
    assert_eq!(
        unit.state("pool", DestinationId::new(1), now, &route_token()),
        LaneState::BudgetExhausted
    );

    // PB-4's soonest-cooldown Retry-After walk must never see this destination as a candidate with
    // a cooldown of 0 (which would wrongly win the "soonest" comparison) — it contributes nothing.
    let retry_after =
        BreakerUnit::<busbar_kernel_breaker::journal::NoopJournal>::on_exhausted_retry_after(
            [unit.state("pool", DestinationId::new(1), now, &route_token())],
            now,
        );
    assert_eq!(
        retry_after,
        busbar_kernel_breaker::AT_CAPACITY_RETRY_AFTER_SECS
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
        unit.state("", DestinationId::new(1), now, &route_token()),
        LaneState::Ready
    );
    assert_eq!(
        unit.state("pool-a", DestinationId::new(1), now, &route_token()),
        LaneState::Ready
    );
    assert_eq!(
        unit.state("pool-b", DestinationId::new(1), now, &route_token()),
        LaneState::Ready
    );

    let fresh = unit.observe(
        "pool-a",
        DestinationId::new(1),
        Outcome::HardDown,
        &cfg,
        now,
        &route_token(),
    );
    assert!(fresh, "the first hard-down trip must be reported fresh");

    for pool in ["", "pool-a", "pool-b"] {
        match unit.state(pool, DestinationId::new(1), now, &route_token()) {
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
        &route_token(),
    );
    assert!(!fresh_again);
}

// ── The probe journal is a function of what the cell actually did ───────────────────────────────

/// A journal that keeps what it was handed, so a test can ask what the unit said happened.
#[derive(Debug, Default)]
struct RecordingJournal {
    events: std::sync::Mutex<Vec<busbar_kernel_breaker::journal::ProbeEvent>>,
}

impl RecordingJournal {
    fn events(&self) -> Vec<busbar_kernel_breaker::journal::ProbeEvent> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// The unit owns the sink it is handed; the test keeps a second handle on the same recording so it
/// can read back what the unit said. A local newtype, because `JournalSink` and `Arc` are both
/// foreign to this crate and the orphan rule refuses an impl for `Arc<RecordingJournal>` here.
struct SharedJournal(std::sync::Arc<RecordingJournal>);

impl JournalSink for SharedJournal {
    fn record(&self, event: busbar_kernel_breaker::journal::ProbeEvent) {
        self.0
            .events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(event);
    }
}

/// A failure that freshly tripped a cell is never journaled as a failed probe.
///
/// `observe` used to decide this from a state it read BEFORE calling `record_failure`, so a
/// concurrent success winning the recovery CAS in between turned a genuine Closed→Open trip into a
/// journal line claiming a probe had failed — a combination the cell's own contract says cannot
/// happen. Gating on what the call reports closes both directions of that race.
#[test]
fn a_fresh_trip_is_never_journaled_as_a_failed_probe() {
    let cfg = consecutive_cfg(1, 5);
    let token = route_token();
    let destination = DestinationId::new(1);

    let mut disagreements = 0usize;
    for _ in 0..500 {
        let journal = std::sync::Arc::new(RecordingJournal::default());
        let unit = BreakerUnit::with_journal(SharedJournal(journal.clone()));

        // Trip it, then win the recovery probe: the cell is HalfOpen and both threads below can see
        // it that way.
        unit.observe(
            "pool",
            destination,
            Outcome::Transient { retry_after: None },
            &cfg,
            1_000,
            &token,
        );
        let admit = unit
            .try_admit("pool", destination, 1_000_000)
            .expect("the cooldown is long past, so the probe is winnable");
        assert!(admit.probe_epoch.is_some(), "this call won the probe");

        // A degraded fallback path recording a transient failure against the same cell the probe
        // holder is recording a success against — a shape `record_success` documents as supported.
        let tripped = std::thread::scope(|scope| {
            let failing = scope.spawn(|| {
                unit.observe(
                    "pool",
                    destination,
                    Outcome::Transient { retry_after: None },
                    &cfg,
                    1_000_000,
                    &token,
                )
            });
            scope.spawn(|| {
                unit.observe(
                    "pool",
                    destination,
                    Outcome::Success,
                    &cfg,
                    1_000_000,
                    &token,
                )
            });
            failing.join().expect("the failing thread did not panic")
        });

        let journaled_a_failed_probe = journal
            .events()
            .iter()
            .any(|e| matches!(e, busbar_kernel_breaker::journal::ProbeEvent::Failed { .. }));
        if tripped && journaled_a_failed_probe {
            disagreements += 1;
        }
    }

    assert_eq!(
        disagreements, 0,
        "a call that reported a fresh Closed->Open trip also journaled a failed probe"
    );
}

/// A probe that closed the cell is always journaled as having succeeded.
///
/// The mirror of the failure race above, and it runs the other way. `observe` decided `was_probe`
/// from a state it read BEFORE `record_success`, so a peer winning the recovery probe in between
/// left this call closing a HalfOpen cell while believing it had been Closed all along — a won
/// probe with no terminal event in the journal at all. The CAS's own answer is the proof: it can
/// only succeed from HalfOpen.
#[test]
fn a_probe_that_closed_the_cell_is_always_journaled_as_succeeded() {
    let cfg = consecutive_cfg(1, 5);
    let token = route_token();
    let destination = DestinationId::new(2);

    let mut orphans = 0usize;
    for _ in 0..2_000 {
        let journal = std::sync::Arc::new(RecordingJournal::default());
        let unit = BreakerUnit::with_journal(SharedJournal(journal.clone()));

        // Trip the cell and leave the cooldown long past, so the probe is there to be won.
        unit.observe(
            "pool",
            destination,
            Outcome::Transient { retry_after: None },
            &cfg,
            1_000,
            &token,
        );

        // One thread records a success against a cell it did not probe — the degraded-fallback
        // shape `record_success` documents. The other wins the recovery probe. If the win lands
        // between the first thread's state read and its CAS, the first thread does the closing.
        let barrier = std::sync::Barrier::new(2);
        let barrier = &barrier;
        let unit = &unit;
        let cfg = &cfg;
        let token = &token;
        std::thread::scope(|scope| {
            scope.spawn(move || {
                barrier.wait();
                unit.observe("pool", destination, Outcome::Success, cfg, 1_000_000, token);
            });
            scope.spawn(move || {
                barrier.wait();
                let _ = unit.try_admit("pool", destination, 1_000_000);
            });
        });

        let events = journal.events();
        let won = events
            .iter()
            .any(|e| matches!(e, busbar_kernel_breaker::journal::ProbeEvent::Won { .. }));
        let succeeded = events.iter().any(|e| {
            matches!(
                e,
                busbar_kernel_breaker::journal::ProbeEvent::Succeeded { .. }
            )
        });
        let closed = matches!(
            unit.cell("pool", destination).state(),
            busbar_kernel_breaker::cell::BreakerState::Closed
        );
        if won && closed && !succeeded {
            orphans += 1;
        }
    }

    assert_eq!(
        orphans, 0,
        "a won probe whose cell then closed left no Succeeded record in the journal"
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
    let token = route_token();
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
                                unit.release_probe("pool", destination, epoch, 2_000_000);
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
