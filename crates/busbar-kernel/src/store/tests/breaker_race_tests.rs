use super::*;

use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::Barrier;

const CYCLES: usize = 20_000;
const CYCLES_RACE1: usize = 300_000;

fn one_lane() -> Arc<HealthState> {
    Arc::new(HealthState::new(vec![LaneData::for_test("m", "p", 4)]))
}

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

#[test]
fn race1_a_fresh_trip_is_never_read_with_a_stale_cooldown() {
    let store = one_lane();
    let now = busbar_kernel::store::now();
    let bad = race(
        &store,
        |s| s.recover_lane(0, HealthState::now_secs()),
        |s| {
            let _ = s.record_hard_down_all_cells(0, "race1", HealthState::now_secs());
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

#[test]
fn race2_a_just_closed_cell_is_never_denied() {
    let store = one_lane();
    let now = busbar_kernel::store::now();
    let bad = race(
        &store,
        |s| s.force_open_in("p", 0, 0),
        |s| s.recover_lane(0, HealthState::now_secs()),
        move |s| s.try_admit_breaker("p", 0, now).is_err(),
        true,
        CYCLES,
    );
    assert_eq!(
        bad, 0,
        "an expired-Open cell recovering to Closed refused its admission {bad} time(s)"
    );
}

#[test]
fn race3_a_refusal_carries_the_cooldown_that_refused_it() {
    let store = one_lane();
    let now = busbar_kernel::store::now();
    let bad = race(
        &store,
        |s| s.force_open_in("p", 0, 0),
        |s| {
            let _ = s.record_hard_down_all_cells(0, "race3", HealthState::now_secs());
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
