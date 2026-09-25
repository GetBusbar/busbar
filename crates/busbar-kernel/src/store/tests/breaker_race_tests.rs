//! Item 142 exit tests: the three races the admission-path breaker held before it was folded into
//! the one breaker (`busbar-kernel-breaker`).
//!
//! Each test races a real transition against a real read on the kernel's `LaneRuntime` surface, many
//! times over, with the two threads released together by a barrier and the cell reset while both are
//! parked. A consistent breaker can only ever give the answers each test allows; the pre-fold FSM gave
//! a third one whenever the transition landed inside its read.

use super::*;

use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::Barrier;

/// Cycles per race. Each cycle is one reset, one release of both threads, one transition. Race 1's
/// window is two adjacent loads wide, so it gets more rounds than the two admission races.
const CYCLES: usize = 20_000;
const CYCLES_RACE1: usize = 300_000;

fn one_lane() -> Arc<HealthState> {
    Arc::new(HealthState::new(vec![LaneData::for_test("m", "p", 4)]))
}

/// Run `cycles` rounds of: `reset` (both threads parked), then `transition` on this thread racing
/// `observe` on another. `observe` is called repeatedly until the transition has finished and once
/// more after, and returns `true` for an answer the breaker must never give. Returns how many such
/// answers were seen.
fn race(
    store: &Arc<HealthState>,
    reset: impl Fn(&HealthState),
    transition: impl Fn(&HealthState),
    observe: impl Fn(&HealthState) -> bool + Send + Sync + 'static,
    once: bool,
    cycles: usize,
) -> usize {
    let start = Arc::new(Barrier::new(2));
    let end = Arc::new(Barrier::new(2));
    let done = Arc::new(AtomicBool::new(false));
    let bad = Arc::new(AtomicUsize::new(0));
    let reader = {
        let (store, start, end, done, bad) = (
            Arc::clone(store),
            Arc::clone(&start),
            Arc::clone(&end),
            Arc::clone(&done),
            Arc::clone(&bad),
        );
        std::thread::spawn(move || {
            for _ in 0..cycles {
                start.wait();
                loop {
                    let finished = done.load(Ordering::Acquire);
                    if observe(&store) {
                        bad.fetch_add(1, Ordering::Relaxed);
                    }
                    if finished || once {
                        break;
                    }
                }
                end.wait();
            }
        })
    };
    for _ in 0..cycles {
        reset(store);
        done.store(false, Ordering::Release);
        start.wait();
        transition(store);
        done.store(true, Ordering::Release);
        end.wait();
    }
    reader.join().expect("reader thread");
    bad.load(Ordering::Relaxed)
}

/// RACE 1 (pre-fold `breaker.rs:400`): the decoder read `cooldown_until` BEFORE `breaker_state`, while
/// every writer stores the cooldown first and the state second. A read straddling a hard-down paired
/// the fresh Open with the stale zero cooldown and decoded a cell parked for thirty minutes as an
/// expired Open — `Open { until <= now }`, a state the cell was never in.
#[test]
fn race1_a_fresh_trip_is_never_read_with_a_stale_cooldown() {
    let store = one_lane();
    let now = busbar_kernel::store::now();
    let bad = race(
        &store,
        |s| s.recover_lane(0),
        |s| {
            let _ = s.record_hard_down_all_cells(0, "race1");
        },
        move |s| matches!(s.lane_breaker_state(0, now), BreakerState::Open { until } if until <= now),
        false,
        CYCLES_RACE1,
    );
    assert_eq!(
        bad, 0,
        "a cell tripped hard-down was decoded as an already-expired Open {bad} time(s)"
    );
}

/// RACE 2 (pre-fold `breaker.rs:795`): an admission read the cell Open-and-expired without the lock,
/// then took the lock and re-read; a recovery that closed the cell in between made the re-read see
/// Closed, and the admission was DENIED — a Closed, ready cell refused as a probe in flight.
#[test]
fn race2_a_just_closed_cell_is_never_denied() {
    let store = one_lane();
    let now = busbar_kernel::store::now();
    let bad = race(
        &store,
        |s| s.force_open_in("p", 0, 0),
        |s| s.recover_lane(0),
        move |s| s.try_admit_breaker("p", 0, now).is_err(),
        true,
        CYCLES,
    );
    assert_eq!(
        bad, 0,
        "an expired-Open cell recovering to Closed refused its admission {bad} time(s)"
    );
}

/// RACE 3 (pre-fold `availability.rs:355`): an admission that lost its probe acquisition reported
/// `ProbeInFlight` whatever the reason — so when a hard-down parked the cell for thirty minutes
/// between the verdict and the acquisition, the caller was told to retry in 250 ms against a
/// 1,800,000 ms cooldown.
#[test]
fn race3_a_refusal_carries_the_cooldown_that_refused_it() {
    let store = one_lane();
    let now = busbar_kernel::store::now();
    let bad = race(
        &store,
        |s| s.force_open_in("p", 0, 0),
        |s| {
            let _ = s.record_hard_down_all_cells(0, "race3");
        },
        move |s| match s.try_admit_breaker("p", 0, now) {
            Ok(_) => false,
            Err(u) => u.recovery_hint_ms(now).unwrap_or(0) < 1_000_000,
        },
        true,
        CYCLES,
    );
    assert_eq!(
        bad, 0,
        "an admission refused by a thirty-minute hard-down reported a short retry hint {bad} time(s)"
    );
}
