use super::*;

use busbar_kernel::store::{BreakerCfg, TripConfig, TripMode};

fn poke(store: &HealthState, lane: usize, f: impl FnOnce(&mut CellSnapshot)) {
    let cell = &store.get_lane(lane).cell;
    let mut snap = cell.snapshot();
    f(&mut snap);
    cell.restore(snap);
}

fn set_state(store: &HealthState, lane: usize, st: u64) {
    if st == 2 {
        let until = store.get_lane(lane).cell.cooldown_until();
        poke(store, lane, |c| c.state = 1);
        assert!(matches!(
            store.get_lane(lane).cell.acquire(until),
            ProbeAdmit::ProbeWon(_)
        ));
    } else {
        poke(store, lane, |c| c.state = st);
    }
}

fn seed_outcome(store: &HealthState, lane: usize, t: u64, is_error: bool) {
    let cell = &store.get_lane(lane).cell;
    if is_error {
        let inert = BreakerCfg {
            honor_retry_after: false,
            bench_below_trip_threshold: false,
            trip: TripConfig {
                min_requests: usize::MAX,
                ..TripConfig::default()
            },
            ..BreakerCfg::default()
        };
        let _ = cell.record_failure(t, &fsm_cfg(&inert), None, 0);
    } else {
        let _ = cell.record_success(t);
    }
}

fn make_lane_data(id: usize, max_permits: usize) -> LaneData {
    LaneData {
        member: format!("model-{}", id),
        route: format!("provider-{}", id),
        max: max_permits,
        sem: Arc::new(Semaphore::new(max_permits)),
        limited: false,
        budget: -1,
        cooldown_until: 0,
        streak: 0,
        dead: false,
        dead_reason: String::new(),
        ok: 0,
        err: 0,
        client_fault: 0,
    }
}

#[test]
fn test_health_state_follows_identity_across_rebuild() {
    set_now_for_test(1000);

    let a = HealthState::new(vec![make_lane_data(0, 10), make_lane_data(1, 10)]);
    let cfg = BreakerCfg::default();

    for _ in 0..5 {
        a.record_transient_in("p", 1, "5xx", &cfg, None);
    }
    assert!(!a.ready_in("p", 1, 1000), "model-1 tripped in pool p");
    a.record_latency_in("p", 1, 123.0);
    let snaps = a.export_health();
    assert_eq!(snaps.len(), 2);
    let s1 = snaps.iter().find(|s| s.member == "model-1").unwrap();
    assert!(
        !s1.cells.is_empty(),
        "the tripped pool cell must be exported"
    );

    let b = HealthState::new_with_limits_restored(
        vec![make_lane_data(9, 10), make_lane_data(1, 10)],
        crate::config::DEFAULT_HARD_DOWN_COOLDOWN_SECS,
        crate::config::DEFAULT_MAX_HONORED_RETRY_AFTER_SECS,
        &snaps,
    );

    assert!(
        !b.ready_in("p", 1, 1000),
        "the tripped breaker must follow model-1's identity into the new store"
    );

    assert_eq!(
        b.lane_latency_ms(1),
        a.lane_latency_ms(1),
        "latency EWMA carries by identity"
    );

    assert!(b.ready_in("p", 0, 1000), "a new lane starts fresh");
    assert_eq!(b.lane_latency_ms(0), None, "no inherited latency");

    let b_snaps = b.export_health();
    assert!(b_snaps.iter().all(|s| s.member != "model-0"));

    set_now_for_test(1000 + 24 * 3600);
    assert!(
        b.usable_in("p", 1, 1000 + 24 * 3600),
        "a restored cooldown still expires on schedule (usable_in performs the \
             Open->HalfOpen probe transition)"
    );
}

#[test]
fn test_hard_down_follows_identity_across_rebuild() {
    set_now_for_test(5000);
    let a = HealthState::new(vec![make_lane_data(3, 4)]);
    a.record_hard_down(0, "auth rejected (HTTP 401)");
    assert!(!a.usable(0, 5000), "hard-down blocks the default cell");
    let snaps = a.export_health();
    let b = HealthState::new_with_limits_restored(
        vec![make_lane_data(3, 4)],
        crate::config::DEFAULT_HARD_DOWN_COOLDOWN_SECS,
        crate::config::DEFAULT_MAX_HONORED_RETRY_AFTER_SECS,
        &snaps,
    );
    assert!(!b.usable(0, 5000), "hard-down must survive the rebuild");
    let restored = &b.export_health()[0];

    assert_eq!(restored.dead_reason, "auth rejected (HTTP 401)");
}

#[test]
fn restored_halfopen_state_normalizes_to_open() {
    for (from, to) in [(2, 1), (1, 1), (0, 0)] {
        let c = FsmCell::new();
        c.restore(CellSnapshot {
            state: from,
            ..CellSnapshot::default()
        });
        assert_eq!(c.snapshot().state, to);
    }

    set_now_for_test(9000);
    let a = HealthState::new(vec![make_lane_data(3, 4)]);
    let mut snaps = a.export_health();
    snaps[0].breaker_state = 2;
    let b = HealthState::new_with_limits_restored(
        vec![make_lane_data(3, 4)],
        crate::config::DEFAULT_HARD_DOWN_COOLDOWN_SECS,
        crate::config::DEFAULT_MAX_HONORED_RETRY_AFTER_SECS,
        &snaps,
    );
    assert_eq!(
        b.get_lane(0).cell.snapshot().state,
        1,
        "a restored HalfOpen must become Open, or the lane wedges and never self-recovers"
    );
}

#[test]
fn restore_does_not_clobber_new_limit_with_unlimited_sentinel() {
    set_now_for_test(9000);

    let unlimited = HealthState::new(vec![make_lane_data(3, 4)]);
    let snaps = unlimited.export_health();
    assert_eq!(
        snaps[0].budget, -1,
        "an unlimited lane exports the -1 sentinel"
    );

    let limited_ld = LaneData {
        limited: true,
        budget: 100,
        ..make_lane_data(3, 4)
    };
    let restored = HealthState::new_with_limits_restored(
        vec![limited_ld],
        crate::config::DEFAULT_HARD_DOWN_COOLDOWN_SECS,
        crate::config::DEFAULT_MAX_HONORED_RETRY_AFTER_SECS,
        &snaps,
    );
    assert_eq!(
            restored.get_lane(0).budget.remaining().unwrap_or(-1),
            100,
            "the fresh cap must survive; the unlimited -1 sentinel must NOT clobber it (lane would wedge)"
        );
    assert!(
        restored.usable(0, 9000),
        "the newly-limited lane must remain admissible, not permanently benched"
    );

    let mut spent = snaps.clone();
    spent[0].budget = 40;
    let carried = HealthState::new_with_limits_restored(
        vec![LaneData {
            limited: true,
            budget: 100,
            ..make_lane_data(3, 4)
        }],
        crate::config::DEFAULT_HARD_DOWN_COOLDOWN_SECS,
        crate::config::DEFAULT_MAX_HONORED_RETRY_AFTER_SECS,
        &spent,
    );
    assert_eq!(
        carried.get_lane(0).budget.remaining().unwrap_or(-1),
        40,
        "limited→limited must carry the remaining budget, not reset to the full cap"
    );

    let mut over = snaps.clone();
    over[0].budget = 400;
    let clamped = HealthState::new_with_limits_restored(
        vec![LaneData {
            limited: true,
            budget: 300, // operator LOWERED max_requests
            ..make_lane_data(3, 4)
        }],
        crate::config::DEFAULT_HARD_DOWN_COOLDOWN_SECS,
        crate::config::DEFAULT_MAX_HONORED_RETRY_AFTER_SECS,
        &over,
    );
    assert_eq!(
        clamped.get_lane(0).budget.remaining().unwrap_or(-1),
        300,
        "a carried remaining above the NEW cap must clamp to the cap, not over-serve"
    );
}

#[test]
fn test_floor_prevents_trip() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(1000);

    let cfg = BreakerCfg::default();
    for _ in 0..4 {
        store.record_transient(0, "5xx", &cfg, None);
    }

    assert_eq!(
        store.breaker_state(0),
        BreakerState::Closed,
        "below min_requests the fraction is not consulted at all — 4 errors must not trip"
    );

    store.record_transient(0, "5xx", &cfg, None);
    assert!(
        matches!(store.breaker_state(0), BreakerState::Open { .. }),
        "the request that meets min_requests must trip at fraction 1.0"
    );
}

#[test]
fn test_trip_on_error_rate() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(1000);

    let cfg = BreakerCfg::default();
    for _ in 0..5 {
        store.record_transient(0, "5xx", &cfg, None);
    }

    let state = store.breaker_state(0);
    assert!(
            matches!(state, BreakerState::Open { .. }),
            "error-rate breaker must trip Open once min_requests met and fraction >= threshold (got {state:?})"
        );

    assert!(
        !store.usable(0, 1000),
        "a tripped (Open) lane must not be usable during its cooldown"
    );
}

#[test]
fn test_record_failure_returns_true_only_on_threshold_trip() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);

    let cfg = BreakerCfg::default();
    for n in 1..=4 {
        assert!(
            !store.record_transient(0, "5xx", &cfg, None),
            "failure {n} (below min_requests floor) must NOT report a trip"
        );
    }

    assert!(
        store.record_transient(0, "5xx", &cfg, None),
        "the threshold-breaching failure must report a Closed→Open trip (true)"
    );
    assert!(matches!(store.breaker_state(0), BreakerState::Open { .. }));

    assert!(
        !store.record_transient(0, "5xx", &cfg, None),
        "a failure on an already-Open cell must NOT report a fresh trip (no multi-count)"
    );

    set_state(&store, 0, 2);
    assert!(
        !store.record_transient(0, "5xx", &cfg, None),
        "a HalfOpen→Open reopen (failed probe) must NOT report a fresh trip"
    );
    assert!(matches!(store.breaker_state(0), BreakerState::Open { .. }));
}

#[test]
fn cooldown_never_zero_for_base_one() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    let lane = store.get_lane(0).clone();
    assert_eq!(lane.cell.streak(), 0);
    let cfg = BreakerCfg {
        base_cooldown_secs: 1,
        max_cooldown_secs: 1000,
        honor_retry_after: false,

        bench_below_trip_threshold: true,
        trip: TripConfig {
            mode: TripMode::Consecutive,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            consecutive_n: 2,
        },
    };

    for t in 0..600u64 {
        set_now_for_test(t);
        let cd = lane
            .cell
            .compute_cooldown_with_retry_after(t, &fsm_cfg(&cfg), None, 3600);
        assert!(
            cd >= 1,
            "base_cooldown_secs=1 must never yield a 0 cooldown (t={t} gave {cd})"
        );
    }
}

#[test]
fn backoff_saturates_not_wraps_at_high_streak() {
    set_now_for_test(0);
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    let lane = store.get_lane(0).clone();
    let cfg = BreakerCfg {
        base_cooldown_secs: 10,
        max_cooldown_secs: 3600,
        honor_retry_after: false,

        bench_below_trip_threshold: true,
        trip: TripConfig {
            mode: TripMode::Consecutive,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            consecutive_n: 2,
        },
    };

    for streak in [63u32, 64, 100, 1000] {
        poke(&store, 0, |c| c.streak = streak);
        for t in 0..80u64 {
            set_now_for_test(t);
            let cd = lane
                .cell
                .compute_cooldown_with_retry_after(t, &fsm_cfg(&cfg), None, 3600);
            assert!(
                    cd >= 1,
                    "even base at streak {streak} must saturate toward max, never wrap to 0 (t={t} gave {cd})"
                );
        }
    }
}

#[test]
fn test_spend_refund_budget_contract() {
    let mut ld = make_lane_data(0, 10);
    ld.limited = true;
    ld.budget = 1;
    let store = Arc::new(HealthState::new(vec![ld]));

    assert!(
        store.spend_budget(0),
        "spend on a positive budget must succeed"
    );
    assert_eq!(store.get_lane(0).budget.remaining().unwrap_or(-1), 0);

    store.refund_budget(0);
    assert_eq!(
        store.get_lane(0).budget.remaining().unwrap_or(-1),
        1,
        "a refund paired with a real spend must restore the cap exactly"
    );

    assert!(store.spend_budget(0), "spend to drain to 0");
    assert_eq!(store.get_lane(0).budget.remaining().unwrap_or(-1), 0);
    let spent_again = store.spend_budget(0);
    assert!(
        !spent_again,
        "spend on an exhausted (0) budget must be a no-op reporting false"
    );
    assert_eq!(
        store.get_lane(0).budget.remaining().unwrap_or(-1),
        0,
        "the no-op spend must NOT drive the budget negative"
    );

    store.refund_budget(0);
    assert_eq!(
        store.get_lane(0).budget.remaining().unwrap_or(-1),
        1,
        "an UNGUARDED refund over-raises the budget above its effective ceiling — this is why the \
             forward path must refund ONLY when `budget_spent` is true"
    );

    let mut un = make_lane_data(1, 10);
    un.limited = false;
    un.budget = -1;
    let ustore = Arc::new(HealthState::new(vec![un]));
    assert!(
        ustore.spend_budget(0),
        "spend on an unlimited lane must report true (so the forward guard treats it as spent)"
    );
    ustore.refund_budget(0);
    assert_eq!(
        ustore.get_lane(0).budget.remaining().unwrap_or(-1),
        -1,
        "refund on an unlimited lane must be a no-op (budget stays the unlimited sentinel)"
    );
}

#[test]
fn test_is_ready_any_cell_false_when_every_cell_open() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    let now = 100_000;

    store.force_open_in("", 0, now + 600);
    store.force_open_in("poolA", 0, now + 600);
    store.force_open_in("poolB", 0, now + 600);
    assert!(
        !store.is_ready_any_cell(0, now),
        "is_ready_any_cell must be NOT-ready when every cell (default + all pool cells) is Open"
    );

    store.recover_lane(0, HealthState::now_secs());
    assert!(
        store.is_ready_any_cell(0, now),
        "after recovery the lane is serviceable in some cell → is_ready_any_cell must be ready"
    );
}

#[test]
fn test_is_ready_any_cell_false_when_pool_cells_open_default_untouched() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    let now = 100_000;

    store.force_open_in("poolA", 0, now + 600);
    store.force_open_in("poolB", 0, now + 600);
    assert!(
        store.is_ready(0, now),
        "sanity: the untouched default cell reads ready (the over-reporting source)"
    );
    assert!(
        !store.is_ready_any_cell(0, now),
        "every per-pool cell Open → lane is unserviceable for pool traffic; the always-ready \
             default cell must NOT make is_ready_any_cell report ready"
    );

    store.recover_lane(0, HealthState::now_secs());
    assert!(
        store.is_ready_any_cell(0, now),
        "after recovery a per-pool cell admits → is_ready_any_cell must be ready"
    );
}

#[test]
fn test_is_ready_any_cell_falls_back_to_default_when_no_pool_cells() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    let now = 100_000;

    store.force_open_in("", 0, now + 600);
    assert!(
        !store.is_ready_any_cell(0, now),
        "no pool cells + default cell Open → lane is unserviceable → not ready"
    );
    store.recover_lane(0, HealthState::now_secs());
    assert!(
        store.is_ready_any_cell(0, now),
        "default cell recovered (only routed cell) → ready"
    );
}

#[test]
fn test_recover_close_does_not_clobber_concurrent_harddown() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    let now = 100_000;
    let observed = now + 600;

    let sticky = now + HARD_DOWN_COOLDOWN_SECS;
    store.force_open_in("", 0, sticky);

    let closed = store.recover_close_if_recoverable("", 0, now, observed);
    assert!(
            !closed,
            "a hard-down re-armed a cooldown stricter than the probe observed → recovery must NOT close"
        );
    assert!(
        matches!(store.breaker_state_in("", 0), BreakerState::Open { .. }),
        "the cell must remain Open after a clobber-suppressed recovery close"
    );
    assert_eq!(
        store.cell_cooldown_until("", 0),
        sticky,
        "the hard-down's sticky cooldown must survive the racing recovery close intact"
    );
}

#[test]
fn test_recover_close_recovers_tripped_cell_when_unraced() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    let now = 100_000;
    let observed = now + 600;
    store.force_open_in("", 0, observed);

    let closed = store.recover_close_if_recoverable("", 0, now, observed);
    assert!(
        closed,
        "an unraced tripped cell whose cooldown the probe observed must be recovered"
    );
    assert!(
        matches!(store.breaker_state_in("", 0), BreakerState::Closed),
        "the recovered cell must be Closed"
    );
    assert_eq!(
        store.cell_cooldown_until("", 0),
        0,
        "recovery must clear the observed cooldown"
    );
}

#[test]
fn test_recover_close_ignores_expired_past_cooldown_on_closed_cell() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    let now = 100_000;
    let past_cooldown = now - 600;

    {
        poke(&store, 0, |c| {
            c.cooldown_until = past_cooldown;
            c.state = 0;
        });
    }

    let closed = store.recover_close_if_recoverable("", 0, now, past_cooldown);
    assert!(
            !closed,
            "an already-expired (past) cooldown on a Closed cell is NOT a suppression → no spurious close"
        );
}

#[test]
fn test_is_ready_any_cell_true_when_a_pool_cell_is_ready() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    let now = 100_000;

    let _ = store.usable_in("poolA", 0, now);

    store.force_open_in("", 0, now + 600);
    assert!(
        !store.is_ready(0, now),
        "default cell is Open → default-cell-only is_ready is not-ready"
    );
    assert!(
        store.is_ready_any_cell(0, now),
        "a Closed pool cell makes the lane serviceable → is_ready_any_cell must be ready"
    );
}

#[test]
fn test_cooldown_jitter_is_symmetric() {
    let cfg = BreakerCfg::default();

    let expected_base = cfg.max_cooldown_secs;
    let r = expected_base / 10;
    let lo = expected_base - r;
    let hi = expected_base + r;
    let mut saw_below_base = false;
    for seed in 0..400u64 {
        set_now_for_test(1_000_000 + seed * 7);
        let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
        for _ in 0..5 {
            store.record_transient(0, "5xx", &cfg, None);
        }
        let now = crate::store::now_for_test();
        let remaining = store.cooldown_remaining(0, now);
        assert!(
            remaining >= lo && remaining <= hi,
            "cooldown {remaining}s must stay within symmetric [{lo}, {hi}] (seed {seed})"
        );
        if remaining < expected_base {
            saw_below_base = true;
        }
    }

    assert!(
        saw_below_base,
        "jitter must sometimes shorten the cooldown below the base (symmetric distribution)"
    );
}

#[test]
fn test_small_base_cooldown_still_jitters() {
    let cfg = BreakerCfg {
        base_cooldown_secs: 4,
        max_cooldown_secs: 120,
        honor_retry_after: false,

        bench_below_trip_threshold: true,
        trip: TripConfig::default(),
    };
    let mut seen = std::collections::BTreeSet::new();
    for seed in 0..200u64 {
        set_now_for_test(1_000_000 + seed * 13);
        let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
        store.record_transient(0, "5xx", &cfg, None);
        let now = crate::store::now_for_test();
        seen.insert(store.cooldown_remaining(0, now));
    }
    assert!(
        seen.len() > 1,
        "a small base_cooldown must still jitter across seeds (got single value {seen:?}); \
             old code collapsed jitter_range to 0 for duration < 10"
    );

    let &min = seen.iter().next().expect("non-empty");
    let &max = seen.iter().next_back().expect("non-empty");
    assert!(
        (4..=12).contains(&min) && (4..=12).contains(&max),
        "jittered small cooldowns must stay near the base 8 (saw {min}..={max})"
    );
}

#[test]
fn test_set_now_for_test_zero_is_a_legal_mock_instant() {
    set_now_for_test(0);
    assert_eq!(
        crate::store::now_for_test(),
        0,
        "set_now_for_test(0) must pin the clock to 0, not fall back to wall-clock time"
    );

    set_now_for_test(4242);
    assert_eq!(crate::store::now_for_test(), 4242);
}

#[test]
fn test_client_fault_never_trips() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(1000);

    for _ in 0..100 {
        store.record_client_fault(0);
    }

    let snap = store.snapshot(0, 1000);
    assert_eq!(
        snap.client_fault, 100,
        "every client fault is counted for observability"
    );
    assert_eq!(snap.err, 0, "a client fault is NOT an upstream error");
    assert_eq!(
        snap.streak, 0,
        "a client fault must not extend the consecutive-failure streak"
    );
    assert_eq!(
        snap.cooldown_remaining_s, 0,
        "a client fault must not schedule a cooldown"
    );
    assert_eq!(
        store.breaker_state(0),
        BreakerState::Closed,
        "100 client faults — 20x the min_requests floor — must leave the breaker Closed"
    );
    assert!(store.usable(0, 1000));
}

#[test]
fn test_cooldown_expiry_to_halfopen() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(2000);

    poke(&store, 0, |c| c.cooldown_until = 1500);
    set_state(&store, 0, 1);

    assert!(
        !store.usable(0, 1499),
        "should not be usable before cooldown"
    );

    assert!(
        store.usable(0, 2001),
        "first request in HalfOpen should win probe"
    );
    let state = store.breaker_state(0);
    assert!(
        matches!(state, BreakerState::HalfOpen),
        "an expired-cooldown Open lane must transition to HalfOpen on admission (got {state:?})"
    );
}

#[test]
fn test_hard_down_long_cooldown_and_recovery() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);

    store.record_hard_down(0, "billing / insufficient balance");

    let ls = store.get_lane(0);
    let until = ls.cell.cooldown_until();

    assert!(
        !ls.dead.load(Ordering::Relaxed),
        "hard-down must NOT set dead — it is recoverable"
    );

    assert_eq!(ls.cell.snapshot().state, 1, "hard-down → Open");

    assert!(
        until > COOLDOWN_TRANSIENT_SECS,
        "sticky cooldown, not a short transient"
    );

    assert!(
        !store.usable(0, until - 1),
        "should be down during the sticky cooldown"
    );
    assert!(
        store.usable(0, until + 1),
        "hard-down lane must recover via the half-open probe once the long cooldown expires"
    );
}

#[test]
fn test_single_flight_probe() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(2000);

    poke(&store, 0, |c| c.cooldown_until = 1500);
    set_state(&store, 0, 1);

    let first_usable = store.usable(0, 2000);

    println!(
        "first_usable={}, probe_in_flight={}",
        first_usable,
        store.get_lane(0).cell.probe_in_flight()
    );

    let second_usable = store.usable(0, 2000);

    println!(
        "second_usable={}, probe_in_flight={}",
        second_usable,
        store.get_lane(0).cell.probe_in_flight()
    );

    assert!(
        first_usable || second_usable,
        "exactly one should win probe"
    );
    assert!(
        !(first_usable && second_usable),
        "only ONE request should be usable as probe"
    );
}

#[test]
fn test_probe_success_to_closed() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    set_state(&store, 0, 2);

    store.closed_state(0, 1500);

    assert!(
        store.usable(0, 1500),
        "should be usable after probe success"
    );

    let state = store.breaker_state(0);
    assert!(
        matches!(state, BreakerState::Closed),
        "a successful probe must close the breaker (got {state:?})"
    );
}

#[test]
fn test_probe_failure_to_open_with_escalated_cooldown() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    poke(&store, 0, |c| c.streak = 2);

    set_now_for_test(1500);

    set_state(&store, 0, 2);

    let state_before = store.breaker_state(0);
    assert!(
        matches!(state_before, BreakerState::HalfOpen),
        "lane should start HalfOpen for this probe-failure scenario (got {state_before:?})"
    );

    seed_outcome(&store, 0, 1500, true);

    let cfg = BreakerCfg::default();
    store.open_state(0, 1500, &cfg);

    let state_after = store.breaker_state(0);
    match state_after {
        BreakerState::Open { until } => {
            assert!(
                until > 1500 + 15,
                "cooldown should be escalated (longer than base 15s)"
            );
        }
        _ => panic!("should transition to Open on probe failure"),
    }
}

#[test]
fn test_probe_failure_honors_retry_after_floor() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(50_000);
    poke(&store, 0, |c| c.streak = 0);

    let cfg = BreakerCfg {
        base_cooldown_secs: 15,
        max_cooldown_secs: 120,
        honor_retry_after: true,

        bench_below_trip_threshold: true,
        trip: TripConfig::default(),
    };

    set_state(&store, 0, 2);
    store.record_probe_failure_all_cells(
        0,
        "health-probe",
        &|_pool| cfg.clone(),
        Some(90),
        HealthState::now_secs(),
    );
    let until = store.get_lane(0).cell.cooldown_until();
    assert!(
            until >= 50_000 + 90,
            "probe failure must honor the retry_after=90 floor (got cooldown_until={until}, base ~15s would be ~50015)"
        );

    let store2 = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(50_000);
    poke(&store2, 0, |c| c.streak = 0);
    set_state(&store2, 0, 2);
    store2.record_probe_failure_all_cells(
        0,
        "health-probe",
        &|_pool| cfg.clone(),
        None,
        HealthState::now_secs(),
    );
    let until_no_ra = store2.get_lane(0).cell.cooldown_until();
    assert!(
            until_no_ra < 50_000 + 90,
            "without retry_after the cooldown must be the base backoff (< 90s floor), got {until_no_ra}"
        );
}

#[test]
fn test_exhaustive_match_no_fallback() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(1000);

    set_state(&store, 0, 0);
    assert!(store.usable(0, 1000), "Closed should be usable");

    poke(&store, 0, |c| c.cooldown_until = 2000);
    set_state(&store, 0, 1);
    assert!(!store.usable(0, 1500), "Open before expiry not usable");

    set_state(&store, 0, 2);
    assert!(
        !store.usable(0, 1500),
        "HalfOpen not usable (only via CAS winner)"
    );
}

#[test]
fn test_streak_reset_on_success() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    poke(&store, 0, |c| c.streak = 5);

    set_now_for_test(1000);

    store.record_success(0);

    assert_eq!(
        store.get_lane(0).cell.streak(),
        0,
        "streak should reset on success"
    );
}

#[test]
fn test_success_on_open_cell_preserves_streak_for_backoff_escalation() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);

    set_state(&store, 0, 1);
    poke(&store, 0, |c| c.streak = 5);

    store.record_success(0);

    assert_eq!(
        store.get_lane(0).cell.streak(),
        5,
        "a success on a still-Open cell must NOT zero the streak (preserves backoff escalation)"
    );
    assert_eq!(
        store.get_lane(0).cell.snapshot().state,
        1,
        "the cell must remain Open (success on Open does not recover it)"
    );

    set_state(&store, 0, 0);
    poke(&store, 0, |c| c.streak = 4);
    store.record_success(0);
    assert_eq!(
        store.get_lane(0).cell.streak(),
        0,
        "a success on a Closed cell must reset the streak"
    );
}

#[test]
fn test_consecutive_trip_mode() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(4000);

    let cfg = BreakerCfg {
        base_cooldown_secs: 15,
        max_cooldown_secs: 120,
        honor_retry_after: true,

        bench_below_trip_threshold: true,
        trip: TripConfig {
            mode: TripMode::Consecutive,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            consecutive_n: 3,
        },
    };

    store.record_transient(0, "5xx", &cfg, None);
    store.record_transient(0, "5xx", &cfg, None);
    assert_eq!(
        store.breaker_state(0),
        BreakerState::Closed,
        "consecutive(n=3) must NOT trip before the 3rd failure"
    );

    store.record_transient(0, "5xx", &cfg, None);
    let state = store.breaker_state(0);
    assert!(
        matches!(state, BreakerState::Open { .. }),
        "with 3 consecutive errors (n=3) the breaker must trip Open (got {state:?})"
    );
}

#[test]
fn test_configured_consecutive_trip_fires_at_n() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(5000);

    let cfg = BreakerCfg {
        base_cooldown_secs: 15,
        max_cooldown_secs: 120,
        honor_retry_after: true,

        bench_below_trip_threshold: true,
        trip: TripConfig {
            mode: TripMode::Consecutive,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            consecutive_n: 2,
        },
    };

    store.record_transient(0, "5xx", &cfg, None);
    assert_eq!(
        store.breaker_state(0),
        BreakerState::Closed,
        "one failure must not trip a consecutive(n=2) breaker"
    );

    store.record_transient(0, "5xx", &cfg, None);
    assert!(
        matches!(store.breaker_state(0), BreakerState::Open { .. }),
        "the configured consecutive threshold (n=2) must trip on the 2nd failure"
    );
}

#[test]
fn test_default_error_rate_does_not_trip_below_floor() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(6000);

    let cfg = BreakerCfg::default();
    store.record_transient(0, "5xx", &cfg, None);
    store.record_transient(0, "5xx", &cfg, None);

    assert_eq!(
        store.breaker_state(0),
        BreakerState::Closed,
        "2 failures are below the default min_requests floor (5) → no trip"
    );
}

#[test]
fn test_configured_error_rate_trip_fires() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(7000);

    let cfg = BreakerCfg {
        base_cooldown_secs: 15,
        max_cooldown_secs: 120,
        honor_retry_after: true,

        bench_below_trip_threshold: true,
        trip: TripConfig {
            mode: TripMode::ErrorRate,
            window_s: 100,
            threshold: 0.5,
            min_requests: 3,
            consecutive_n: 99,
        },
    };

    store.record_transient(0, "5xx", &cfg, None);
    assert_eq!(store.breaker_state(0), BreakerState::Closed);
    store.record_transient(0, "5xx", &cfg, None);
    assert_eq!(store.breaker_state(0), BreakerState::Closed);
    store.record_transient(0, "5xx", &cfg, None);
    assert!(
        matches!(store.breaker_state(0), BreakerState::Open { .. }),
        "error-rate breaker must trip once floor is met and fraction exceeds threshold"
    );
}

#[test]
fn test_config_breaker_conversion() {
    let ccfg = crate::config::BreakerCfg {
        base_cooldown_secs: 7,
        max_cooldown_secs: 99,
        trip: Some(crate::config::BreakerTripConfig {
            mode: crate::config::BreakerTripMode::Consecutive,
            window_secs: 42,
            threshold: 0.8,
            min_requests: 9,
            consecutive_n: 4,
        }),
    };
    let rcfg = crate::store::breaker_cfg_to_runtime(&ccfg);
    assert_eq!(rcfg.base_cooldown_secs, 7);
    assert_eq!(rcfg.max_cooldown_secs, 99);
    assert!(rcfg.honor_retry_after, "always honored (no config knob)");
    assert!(matches!(rcfg.trip.mode, TripMode::Consecutive));
    assert_eq!(rcfg.trip.window_s, 42);
    assert_eq!(rcfg.trip.consecutive_n, 4);

    let bare = crate::config::BreakerCfg {
        base_cooldown_secs: 10,
        max_cooldown_secs: 120,
        trip: None,
    };
    let rbare = crate::store::breaker_cfg_to_runtime(&bare);
    assert!(matches!(rbare.trip.mode, TripMode::ErrorRate));
    assert_eq!(rbare.trip.min_requests, 5);
}

#[test]
fn test_half_open_success_recovers_to_closed() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(3000);

    poke(&store, 0, |c| c.cooldown_until = 2000);
    set_state(&store, 0, 1);

    assert!(store.usable(0, 3000), "first request should win the probe");
    assert_eq!(store.breaker_state(0), BreakerState::HalfOpen);

    store.record_success(0);
    assert_eq!(
        store.breaker_state(0),
        BreakerState::Closed,
        "a successful half-open probe must close the breaker"
    );
    assert!(
        store.usable(0, 3001),
        "lane must be admitted again after recovery (not stuck HalfOpen)"
    );
    assert!(
        store.usable(0, 3002),
        "and keep being admitted — recovery is sticky, not a one-shot"
    );
    assert!(
        !store.get_lane(0).cell.probe_in_flight(),
        "the single-flight probe must be released on recovery"
    );
}

#[test]
fn test_concurrent_open_to_half_open_single_probe_winner() {
    use std::sync::atomic::AtomicUsize;
    use std::sync::Barrier;

    for _ in 0..2000 {
        let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
        let now = 3000u64;

        poke(&store, 0, |c| c.cooldown_until = 1000);
        set_state(&store, 0, 1);

        let winners = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(2));

        let handles: Vec<_> = (0..2)
            .map(|_| {
                let store = Arc::clone(&store);
                let winners = Arc::clone(&winners);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    if store.usable(0, now) {
                        winners.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("racing thread must not panic");
        }

        assert_eq!(
            winners.load(Ordering::Relaxed),
            1,
            "exactly one thread must win the single-flight recovery probe"
        );

        assert_eq!(
            store.breaker_state(0),
            BreakerState::HalfOpen,
            "the probe winner must leave the cell HalfOpen"
        );
        assert!(
            store.get_lane(0).cell.probe_in_flight(),
            "the winner must hold the single-flight probe"
        );
    }
}

#[test]
fn test_concurrent_acquire_racing_probe_success_never_wedges_flag() {
    use std::sync::Barrier;

    for _ in 0..2000 {
        let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
        let now = 3000u64;
        poke(&store, 0, |c| c.cooldown_until = 1000);
        set_state(&store, 0, 1);

        let barrier = Arc::new(Barrier::new(2));

        let store_a = Arc::clone(&store);
        let barrier_a = Arc::clone(&barrier);
        let a = std::thread::spawn(move || {
            assert!(store_a.usable(0, now), "A must win the initial probe");
            barrier_a.wait();

            store_a.record_success(0);
        });

        let store_b = Arc::clone(&store);
        let barrier_b = Arc::clone(&barrier);
        let b = std::thread::spawn(move || {
            barrier_b.wait();

            let _ = store_b.usable(0, now);
        });

        a.join().expect("A must not panic");
        b.join().expect("B must not panic");

        let state = store.breaker_state(0);
        let probe_held = store.get_lane(0).cell.probe_in_flight();
        match state {
            BreakerState::Closed => assert!(
                !probe_held,
                "a Closed cell must never retain probe_in_flight=true (wedged lane)"
            ),
            BreakerState::HalfOpen => assert!(
                probe_held,
                "a HalfOpen cell that B re-acquired must hold the probe"
            ),
            BreakerState::Open { .. } => {
                assert!(!probe_held, "an Open cell must not retain the probe flag");
            }
        }
    }
}

#[test]
fn test_concurrent_success_racing_hard_down_never_drops_sticky_cooldown() {
    use std::sync::Barrier;

    for _ in 0..2000 {
        let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
        let now = 3000u64;

        poke(&store, 0, |c| c.cooldown_until = 1000);
        set_state(&store, 0, 2);

        let barrier = Arc::new(Barrier::new(2));

        let store_a = Arc::clone(&store);
        let barrier_a = Arc::clone(&barrier);
        let a = std::thread::spawn(move || {
            barrier_a.wait();
            store_a.record_success(0);
        });

        let store_b = Arc::clone(&store);
        let barrier_b = Arc::clone(&barrier);
        let b = std::thread::spawn(move || {
            barrier_b.wait();
            store_b.record_hard_down_all_cells(
                0,
                "billing / insufficient balance",
                HealthState::now_secs(),
            );
        });

        a.join().expect("A must not panic");
        b.join().expect("B must not panic");

        let state = store.breaker_state(0);
        let cooldown = store.get_lane(0).cell.cooldown_until();
        match state {
            BreakerState::Closed => assert_eq!(
                cooldown, 0,
                "a Closed (recovered) cell must not retain a stale cooldown"
            ),

            BreakerState::Open { until } => {
                assert!(
                        cooldown > now,
                        "a hard-down Open cell must keep its sticky cooldown (got {cooldown}, now {now})"
                    );
                assert!(until > now, "Open until must be in the future");
            }
            BreakerState::HalfOpen => {
                panic!("cell must not remain HalfOpen after both writers ran")
            }
        }
    }
}

#[test]
fn test_pool_breaker_isolation() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(8000);

    let cfg = BreakerCfg {
        base_cooldown_secs: 15,
        max_cooldown_secs: 120,
        honor_retry_after: true,

        bench_below_trip_threshold: true,
        trip: TripConfig {
            mode: TripMode::Consecutive,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            consecutive_n: 1,
        },
    };

    store.record_transient_in("A", 0, "5xx", &cfg, None);

    assert!(
        !store.usable_in("A", 0, 8000),
        "pool A's cell must be tripped"
    );
    assert!(
        store.usable_in("B", 0, 8000),
        "pool B's cell must be unaffected by pool A's trip"
    );
    assert!(
        store.usable(0, 8000),
        "the lane-default cell must be unaffected by pool A's trip"
    );
    assert!(
        store.lane_needs_probe(0, 8000),
        "lane is suppressed in at least one cell (pool A)"
    );

    store.recover_lane(0, HealthState::now_secs());
    assert!(
        !store.lane_needs_probe(0, 8000),
        "recover_lane must clear every cell (probe tests the shared upstream)"
    );
    assert!(store.usable_in("A", 0, 8000), "pool A recovered");
}

#[test]
fn test_named_pool_failure_bumps_lane_global_err() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);
    let cfg = BreakerCfg::default();

    assert_eq!(store.snapshot(0, 1000).err, 0, "starts at zero");
    store.record_transient_in("prod-pool", 0, "5xx", &cfg, None);
    store.record_transient_in("prod-pool", 0, "5xx", &cfg, None);
    assert_eq!(
        store.snapshot(0, 1000).err,
        2,
        "named-pool failures must increment the lane-global err counter (/stats observability)"
    );
}

#[test]
fn test_default_cell_failure_counts_lane_global_err_once() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);
    let cfg = BreakerCfg::default();

    assert_eq!(store.snapshot(0, 1000).err, 0, "starts at zero");

    store.record_transient(0, "5xx", &cfg, None);
    store.record_transient(0, "5xx", &cfg, None);
    store.record_transient(0, "5xx", &cfg, None);
    assert_eq!(
        store.snapshot(0, 1000).err,
        3,
        "default-cell failures must count err exactly once each (was 2x before the fix)"
    );
}

#[test]
fn test_default_cell_recovery_does_not_zero_lane_err() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);
    let cfg = BreakerCfg::default();

    let failures = 50u64;
    for _ in 0..failures {
        store.record_transient(0, "5xx", &cfg, None);
    }
    assert_eq!(
        store.snapshot(0, 1000).err,
        failures,
        "each default-cell failure bumps the lane-global err counter"
    );

    let cooled = 1000 + store.cooldown_remaining(0, 1000) + 1;
    set_now_for_test(cooled);
    store.recover_lane(0, HealthState::now_secs());

    assert!(
        !store.lane_needs_probe(0, cooled),
        "recover_lane must clear the tripped default cell"
    );

    assert_eq!(
        store.snapshot(0, cooled).err,
        failures,
        "default-cell recovery must NOT zero the lane-global err counter (must stay monotonic)"
    );
}

#[test]
fn test_release_probe_reverts_undispatched_probe_winner() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);
    let cfg = BreakerCfg::default();

    for _ in 0..50 {
        store.record_transient_in("p", 0, "5xx", &cfg, None);
    }
    let cooled = 1000 + store.cooldown_remaining_in("p", 0, 1000) + 1;
    set_now_for_test(cooled);

    assert!(
        store.acquire_for_dispatch_in("p", 0, cooled),
        "first dispatch wins the recovery probe"
    );

    assert!(
        !store.acquire_for_dispatch_in("p", 0, cooled),
        "HalfOpen with an in-flight probe admits nobody else"
    );

    store.release_probe_in("p", 0);

    assert!(
        store.acquire_for_dispatch_in("p", 0, cooled),
        "after release_probe_in the lane must be re-probeable (not wedged HalfOpen)"
    );
}

#[test]
fn test_usable_in_wins_probe_and_must_be_released_on_sticky_path() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);
    let cfg = BreakerCfg::default();

    for _ in 0..50 {
        store.record_transient_in("p", 0, "5xx", &cfg, None);
    }
    let cooled = 1000 + store.cooldown_remaining_in("p", 0, 1000) + 1;
    set_now_for_test(cooled);

    assert!(
        store.usable_in("p", 0, cooled),
        "usable_in admits (and wins the probe for) an expired-Open lane on the sticky path"
    );

    assert!(
        !store.acquire_for_dispatch_in("p", 0, cooled),
        "usable_in already won the single-flight probe; the lane is now HalfOpen and benched"
    );

    store.release_probe_in("p", 0);
    assert!(
        store.acquire_for_dispatch_in("p", 0, cooled),
        "after the sticky path releases the won-but-undispatched probe, the lane is re-probeable"
    );
}

#[test]
fn test_client_fault_on_halfopen_lane_releases_probe() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);
    let cfg = BreakerCfg::default();

    for _ in 0..50 {
        store.record_transient_in("p", 0, "5xx", &cfg, None);
    }
    let cooled = 1000 + store.cooldown_remaining_in("p", 0, 1000) + 1;
    set_now_for_test(cooled);

    assert!(
        store.acquire_for_dispatch_in("p", 0, cooled),
        "the client-fault request wins the recovery probe"
    );

    store.record_client_fault(0);
    assert!(
        !store.acquire_for_dispatch_in("p", 0, cooled),
        "record_client_fault must NOT release the probe (still wedged HalfOpen at this point)"
    );

    store.release_probe_in("p", 0);
    assert!(
        store.acquire_for_dispatch_in("p", 0, cooled),
        "after the ClientFault arm releases the probe the lane must be re-probeable (not wedged)"
    );
}

#[test]
fn test_context_length_on_halfopen_lane_releases_probe() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);
    let cfg = BreakerCfg::default();

    for _ in 0..50 {
        store.record_transient_in("p", 0, "5xx", &cfg, None);
    }
    let cooled = 1000 + store.cooldown_remaining_in("p", 0, 1000) + 1;
    set_now_for_test(cooled);

    assert!(
        store.acquire_for_dispatch_in("p", 0, cooled),
        "the context-length request wins the recovery probe"
    );

    assert!(
        !store.acquire_for_dispatch_in("p", 0, cooled),
        "no breaker outcome was recorded; the probe is still held (wedged HalfOpen)"
    );

    store.release_probe_in("p", 0);
    assert!(
        store.acquire_for_dispatch_in("p", 0, cooled),
        "after the ContextLength arm releases the probe the lane must be re-probeable (not wedged)"
    );
}

#[test]
fn test_lock_recover_recovers_from_poison() {
    let m = std::sync::Arc::new(std::sync::Mutex::new(42u32));

    let m2 = m.clone();
    let _ = std::thread::spawn(move || {
        let _g = m2.lock().unwrap();
        panic!("poison the mutex while holding the guard");
    })
    .join();
    assert!(
        m.is_poisoned(),
        "the mutex must be poisoned after the panic"
    );

    let g = lock_recover(&m);
    assert_eq!(
        *g, 42,
        "lock_recover recovers the inner value past the poison"
    );
}

#[test]
fn test_new_pool_cell_does_not_inherit_wedged_halfopen() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);
    let cfg = BreakerCfg::default();

    for _ in 0..50 {
        store.record_transient(0, "5xx", &cfg, None);
    }
    let cooled = 1000 + store.cooldown_remaining(0, 1000) + 1;
    set_now_for_test(cooled);
    assert!(
        store.acquire_for_dispatch_in("", 0, cooled),
        "the default cell transitions Open → HalfOpen (probe won) here"
    );

    assert!(
        store.acquire_for_dispatch_in("freshpool", 0, cooled),
        "a new pool cell created while a sibling is HalfOpen must be probe-eligible, not wedged"
    );
}

#[test]
fn test_hostile_retry_after_does_not_bypass_breaker() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);
    let cfg = BreakerCfg {
        honor_retry_after: true,
        ..BreakerCfg::default()
    };

    store.record_rate_limit_in("prod-pool", 0, 1000, &cfg, Some(u64::MAX));

    assert!(
        !store.usable_in("prod-pool", 0, 1000),
        "a hostile Retry-After must not wrap the cooldown into the past (breaker bypass)"
    );

    let remaining = store.cooldown_remaining_in("prod-pool", 0, 1000);
    assert!(
        remaining > 0 && remaining <= MAX_HONORED_RETRY_AFTER_SECS,
        "cooldown must be clamped to the absolute ceiling; got {remaining}s"
    );
}

#[test]
fn test_lane_latency_ewma_records_and_reads() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    assert_eq!(store.lane_latency_ms(0), None);

    store.record_latency_in("p", 0, 100.0);
    assert_eq!(store.lane_latency_ms(0), Some(100.0));

    store.record_latency_in("p", 0, 200.0);
    let v = store.lane_latency_ms(0).unwrap();
    assert!((v - 120.0).abs() < 1e-9, "EWMA must be 120, got {v}");

    store.record_latency_in("p", 0, f64::NAN);
    store.record_latency_in("p", 0, 0.0);
    store.record_latency_in("p", 0, -5.0);
    let v2 = store.lane_latency_ms(0).unwrap();
    assert!(
        (v2 - 120.0).abs() < 1e-9,
        "bad samples must not move the EWMA, got {v2}"
    );
}

#[test]
fn test_cell_read_path_returns_stable_identity() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(1000);

    store.record_success_in("p", 0, HealthState::now_secs());
    store.record_transient_in("p", 0, "x", &BreakerCfg::default(), None);

    assert!(
        store.cell_err_for_test("p", 0) >= 1,
        "the read path must resolve the existing per-pool cell, not a fresh duplicate"
    );
}

#[test]
fn test_budget_is_lane_global_across_pools() {
    let mut ld = make_lane_data(0, 10);
    ld.limited = true;
    ld.budget = 1;
    let store = Arc::new(HealthState::new(vec![ld]));
    set_now_for_test(8100);

    assert!(store.spend_budget(0), "first spend succeeds");
    assert!(
        !store.spend_budget(0),
        "lifetime budget of 1 is now exhausted"
    );

    assert!(
        !store.usable_in("A", 0, 8100),
        "exhausted budget blocks pool A"
    );
    assert!(
        !store.usable_in("B", 0, 8100),
        "exhausted budget blocks pool B"
    );
    assert!(
        !store.usable(0, 8100),
        "exhausted budget blocks direct route"
    );
}

#[test]
fn test_refund_budget_restores_a_spent_unit() {
    let mut ld = make_lane_data(0, 10);
    ld.limited = true;
    ld.budget = 2;
    let store = Arc::new(HealthState::new(vec![ld]));
    set_now_for_test(8100);

    assert!(store.spend_budget(0), "spend 1 of 2");
    assert!(store.spend_budget(0), "spend 2 of 2 (now exhausted)");
    assert!(!store.spend_budget(0), "budget exhausted");

    store.refund_budget(0);
    assert!(
        store.spend_budget(0),
        "after a refund the lane has one spendable unit again"
    );
    assert!(
        !store.spend_budget(0),
        "and only one — refund is not a reset"
    );
}

#[test]
fn test_refund_budget_unlimited_is_noop() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(8100);
    store.refund_budget(0);
    assert!(store.spend_budget(0), "unlimited lane still spends freely");
    assert!(
        store.usable(0, 8100),
        "unlimited lane still usable after refund"
    );
}

#[test]
fn test_record_hard_down_all_cells_trips_default_and_every_pool() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(9000);

    store.record_success_in("A", 0, HealthState::now_secs());
    store.record_success_in("B", 0, HealthState::now_secs());
    assert!(store.usable(0, 9000), "default cell starts usable");
    assert!(store.usable_in("A", 0, 9000), "pool A starts usable");
    assert!(store.usable_in("B", 0, 9000), "pool B starts usable");

    store.record_hard_down_all_cells(0, "billing / insufficient balance", HealthState::now_secs());

    assert!(
        !store.usable(0, 9000),
        "default cell (named/adhoc/direct routes) MUST be tripped by an all-cells hard-down"
    );
    assert!(
        !store.usable_in("A", 0, 9000),
        "pool A cell MUST be tripped"
    );
    assert!(
        !store.usable_in("B", 0, 9000),
        "pool B cell MUST be tripped"
    );

    assert!(
        !store.get_lane(0).dead.load(Ordering::Relaxed),
        "hard-down must NOT set dead — it recovers via the half-open probe"
    );
}

#[test]
fn hard_down_all_cells_records_a_logical_trip() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(9000);

    assert_eq!(store.snapshot(0, 9000).trips, 0, "no trip yet");
    store.record_hard_down_all_cells(0, "billing / insufficient balance", HealthState::now_secs());
    let snap = store.snapshot(0, 9000);
    assert_eq!(
        snap.trips, 1,
        "a hard-down classification is a genuine Closed->Open trip and must count once"
    );
    assert_eq!(
        snap.last_trip_at, 9000,
        "last_trip_at must stamp the hard-down's timestamp"
    );

    set_now_for_test(9100);
    store.record_hard_down_all_cells(0, "billing / insufficient balance", HealthState::now_secs());
    assert_eq!(
        store.snapshot(0, 9100).trips,
        1,
        "a re-classification of an already-Open lane must not double-count the trip"
    );
}

#[test]
fn test_spend_budget_concurrent_never_over_spends() {
    use std::thread;
    const BUDGET: i64 = 50;
    const THREADS: usize = 16;
    const PER_THREAD: usize = 100;

    let mut ld = make_lane_data(0, 10_000);
    ld.limited = true;
    ld.budget = BUDGET;
    let store = Arc::new(HealthState::new(vec![ld]));

    let mut handles = Vec::new();
    for _ in 0..THREADS {
        let s = store.clone();
        handles.push(thread::spawn(move || {
            let mut wins = 0usize;
            for _ in 0..PER_THREAD {
                if s.spend_budget(0) {
                    wins += 1;
                }
            }
            wins
        }));
    }
    let total_wins: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();

    assert_eq!(
        total_wins, BUDGET as usize,
        "exactly {BUDGET} spends may succeed under contention; got {total_wins}"
    );
    assert_eq!(
        store.get_lane(0).budget.remaining().unwrap_or(-1),
        0,
        "budget must settle at exactly 0 — never driven negative by a concurrent burst"
    );
}

#[test]
fn test_concurrent_pool_isolation_stress() {
    use std::thread;

    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10_000)]));

    let cfg = BreakerCfg {
        base_cooldown_secs: 1,
        max_cooldown_secs: 1,
        honor_retry_after: false,

        bench_below_trip_threshold: true,
        trip: TripConfig {
            mode: TripMode::ErrorRate,
            window_s: 1,
            threshold: 2.0,
            min_requests: usize::MAX,
            consecutive_n: u32::MAX,
        },
    };

    const THREADS: usize = 8;
    const ITERS: usize = 500;

    let mut handles = Vec::new();
    for _ in 0..THREADS {
        let s = store.clone();
        let c = cfg.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..ITERS {
                s.record_success_in("A", 0, HealthState::now_secs());

                s.record_transient_in("B", 0, "5xx", &c, None);

                let t = busbar_kernel::store::now();
                let _ = s.usable_in("A", 0, t);
                let _ = s.usable_in("B", 0, t);
            }
        }));
    }
    for h in handles {
        h.join().expect("worker thread panicked");
    }

    let total = (THREADS * ITERS) as u64;

    assert_eq!(
        store.snapshot(0, busbar_kernel::store::now()).ok,
        total,
        "lane-global ok must be exact under concurrency"
    );

    assert_eq!(
        store.cell_err_for_test("B", 0),
        total,
        "pool B's cell must have recorded every transient (no lost updates)"
    );
    assert_eq!(
        store.cell_err_for_test("A", 0),
        0,
        "pool A's cell must be untouched by pool B's transients (isolation under load)"
    );
}

#[test]
fn test_error_rate_ignores_stale_errors_outside_window() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    let cfg = BreakerCfg {
        base_cooldown_secs: 15,
        max_cooldown_secs: 120,
        honor_retry_after: true,

        bench_below_trip_threshold: true,
        trip: TripConfig {
            mode: TripMode::ErrorRate,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            consecutive_n: u32::MAX,
        },
    };

    set_now_for_test(1000);
    for _ in 0..100 {
        seed_outcome(&store, 0, 1000, true);
    }

    set_now_for_test(2000);
    for _ in 0..5 {
        seed_outcome(&store, 0, 2000, false);
    }

    store.record_transient(0, "5xx", &cfg, None);
    assert_eq!(
        store.breaker_state(0),
        BreakerState::Closed,
        "stale out-of-window errors must not trip a lane on clean recent traffic"
    );
}

#[test]
fn test_soft_cooldown_is_probeable_and_recoverable() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(9000);

    let cfg = BreakerCfg {
        base_cooldown_secs: 15,
        max_cooldown_secs: 120,
        honor_retry_after: true,

        bench_below_trip_threshold: true,
        trip: TripConfig {
            mode: TripMode::ErrorRate,
            window_s: 30,
            threshold: 0.5,
            min_requests: usize::MAX,
            consecutive_n: u32::MAX,
        },
    };

    store.record_transient(0, "5xx", &cfg, None);
    assert_eq!(
        store.breaker_state(0),
        BreakerState::Closed,
        "sub-threshold transient must NOT trip the breaker"
    );
    assert!(
        !store.usable(0, 9000),
        "but the soft cooldown makes the lane unusable"
    );
    assert!(
        store.lane_needs_probe(0, 9000),
        "dead-mode probing must see a soft-cooldown lane"
    );

    store.recover_lane(0, HealthState::now_secs());
    assert!(
        store.usable(0, 9000),
        "a successful probe must clear the soft cooldown"
    );
    assert!(!store.lane_needs_probe(0, 9000));
}

#[test]
fn test_try_acquire_probe_exclusivity() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    set_state(&store, 0, 1);

    assert!(
        matches!(store.get_lane(0).cell.acquire(0), ProbeAdmit::ProbeWon(_)),
        "first probe acquisition should succeed"
    );

    assert!(
        matches!(store.get_lane(0).cell.acquire(0), ProbeAdmit::Denied(_)),
        "second probe acquisition should fail"
    );
}

#[test]
fn test_clear_probe_after_success() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    set_state(&store, 0, 1);
    let ProbeAdmit::ProbeWon(epoch) = store.get_lane(0).cell.acquire(0) else {
        panic!("should acquire probe");
    };

    store.release_probe_owned_in("", 0, epoch);

    assert!(
        matches!(store.get_lane(0).cell.acquire(0), ProbeAdmit::ProbeWon(_)),
        "should be able to re-acquire after clear"
    );
}

#[test]
fn test_bounded_window_memory() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(1000);

    for i in 0..2000 {
        seed_outcome(&store, 0, 1000 + i as u64, true);
    }

    let (entries, _) = store.get_lane(0).cell.outcomes_in_window(3000, u64::MAX);
    assert!(entries <= 1024, "outcomes window should be bounded");
}

#[test]
fn test_usable_transitions_on_clock_advance() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(2500);

    poke(&store, 0, |c| c.cooldown_until = 2000);
    set_state(&store, 0, 1);

    assert!(!store.usable(0, 1999), "not usable before cooldown expires");

    assert!(
        store.usable(0, 2500),
        "first request in HalfOpen should win probe"
    );
    let state = store.breaker_state(0);
    assert!(
        matches!(state, BreakerState::HalfOpen),
        "an expired-cooldown Open lane must be HalfOpen after admission (got {state:?})"
    );

    assert!(
        !store.usable(0, 2501),
        "second request not usable after probe acquired"
    );
}

#[test]
fn test_escalating_cooldown_on_repeated_trips() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(1000);

    let cfg = BreakerCfg::default();

    poke(&store, 0, |c| c.streak = 1);
    store.open_state(0, 1000, &cfg);
    let until1 = store.cooldown_remaining(0, 1000);

    set_now_for_test(2000);

    poke(&store, 0, |c| c.streak = 2);
    store.open_state(0, 2000, &cfg);
    let until2 = store.cooldown_remaining(0, 2000);

    assert!(
        until2 > until1,
        "second cooldown should be longer than first"
    );
}

#[test]
fn test_client_fault_counter_increments_separately() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(1000);

    for _ in 0..5 {
        store.record_client_fault(0);
    }

    let snap = store.snapshot(0, 1000);
    assert_eq!(
        snap.client_fault, 5,
        "client_fault counter should increment"
    );
    assert_eq!(
        snap.err, 0,
        "err should NOT be incremented by client faults"
    );
    assert_eq!(
        snap.streak, 0,
        "streak should NOT be incremented by client faults"
    );

    assert!(
        store.usable(0, 1000),
        "lane should remain usable after client faults"
    );
}

#[test]
fn test_client_fault_does_not_affect_breaker_state() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(1000);

    for _ in 0..100 {
        store.record_client_fault(0);
    }

    let state = store.breaker_state(0);
    assert_eq!(
        state,
        BreakerState::Closed,
        "breaker should remain Closed after client faults"
    );

    let snap = store.snapshot(0, 1000);
    assert_eq!(snap.client_fault, 100);
    assert_eq!(snap.err, 0);
}

#[test]
fn test_retry_after_429_with_computed_backoff_lower() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(70000);

    poke(&store, 0, |c| c.streak = 0);

    let cfg = BreakerCfg {
        base_cooldown_secs: 15,
        max_cooldown_secs: 120,
        honor_retry_after: true,

        bench_below_trip_threshold: true,
        trip: TripConfig::default(),
    };
    store.open_state_with_retry_after(0, 70000, &cfg, Some(30));

    let until = store.get_lane(0).cell.cooldown_until();
    assert!(
        until >= 70030,
        "cooldown floor should honor retry_after when larger than computed backoff (got {until})"
    );

    let test_now = store.get_lane(0).cell.cooldown_until() - 10;
    assert!(
        !store.usable(0, test_now),
        "lane should be down during retry-after period"
    );

    assert!(
        store.usable(0, until + 1),
        "lane should become usable after retry_after expires (got usable={})",
        store.usable(0, until + 1)
    );
}

#[test]
fn test_retry_after_exceeds_max_cooldown() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(1000);

    let cfg = BreakerCfg {
        base_cooldown_secs: 15,
        max_cooldown_secs: 120,
        honor_retry_after: true,

        bench_below_trip_threshold: true,
        trip: TripConfig::default(),
    };

    store.open_state_with_retry_after(0, 1000, &cfg, Some(300));

    let until = store.get_lane(0).cell.cooldown_until();
    assert_eq!(
        until, 1300,
        "server retry-after must be honored even when exceeding max_cooldown"
    );

    assert!(
        !store.usable(0, 1299),
        "lane should respect server's explicit Retry-After past cap"
    );
}

#[test]
fn test_retry_after_absent_fallback_to_computed() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(60000);

    poke(&store, 0, |c| c.streak = 0);

    let cfg = BreakerCfg {
        base_cooldown_secs: 15,
        max_cooldown_secs: 120,
        honor_retry_after: true,

        bench_below_trip_threshold: true,
        trip: TripConfig::default(),
    };
    store.open_state_with_retry_after(0, 60000, &cfg, None);

    let until = store.get_lane(0).cell.cooldown_until();
    assert!(
            (60013..=60017).contains(&until),
            "should fall back to the (jittered ~15s) computed backoff when retry_after absent (got {until})"
        );
}

#[test]
fn test_retry_after_record_rate_limit_uses_floor() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(1000);

    store.record_rate_limit(0, 1000, &BreakerCfg::default(), Some(45));

    let until = store.get_lane(0).cell.cooldown_until();
    assert_eq!(
        until, 1045,
        "record_rate_limit should honor retry_after as cooldown floor"
    );
}

#[test]
fn test_retry_after_record_transient_uses_floor() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(50000);

    poke(&store, 0, |c| c.streak = 0);

    store.record_transient(0, "timeout", &BreakerCfg::default(), Some(60));

    let until = store.get_lane(0).cell.cooldown_until();

    assert!(
        until >= 50060,
        "record_transient should honor retry_after as cooldown floor (got {until})"
    );
}

#[test]
fn test_retry_after_not_honored_ignores_server_value() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(80000);
    poke(&store, 0, |c| c.streak = 0);

    let cfg = BreakerCfg {
        base_cooldown_secs: 15,
        max_cooldown_secs: 120,
        honor_retry_after: false,

        bench_below_trip_threshold: true,
        trip: TripConfig::default(),
    };

    store.open_state_with_retry_after(0, 80000, &cfg, Some(1));
    let until = store.get_lane(0).cell.cooldown_until();

    assert!(
        (80013..=80017).contains(&until),
        "honor_retry_after=false must ignore the 1s server value and use the (jittered ~15s) \
             computed backoff; got {until}"
    );
    assert_ne!(until, 80001, "must not use the 1s server Retry-After value");
}

#[test]
fn test_failed_probe_does_not_permanently_lock_lane() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    let cfg = BreakerCfg::default();

    set_now_for_test(10_000);
    poke(&store, 0, |c| c.cooldown_until = 9_000);
    set_state(&store, 0, 1);

    assert!(
        store.usable(0, 10_000),
        "first request wins the half-open probe"
    );
    assert!(
        store.get_lane(0).cell.probe_in_flight(),
        "probe should be in flight"
    );

    store.record_transient(0, "probe-failed", &cfg, None);
    assert!(
        matches!(store.breaker_state(0), BreakerState::Open { .. }),
        "a failed probe reopens the breaker"
    );
    assert!(
        !store.get_lane(0).cell.probe_in_flight(),
        "cell_open MUST release the probe (else the lane is locked out forever)"
    );

    let until = store.get_lane(0).cell.cooldown_until();
    set_now_for_test(until + 1);
    assert!(
            store.usable(0, until + 1),
            "lane must be probeable again after the next cooldown (not locked out by a stale probe flag)"
        );
    assert_eq!(
        store.breaker_state(0),
        BreakerState::HalfOpen,
        "the new probe re-enters HalfOpen"
    );
}

#[test]
fn test_hard_down_while_probing_does_not_wedge_lane() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    set_now_for_test(50_000);
    poke(&store, 0, |c| c.cooldown_until = 49_000);
    set_state(&store, 0, 1);
    assert!(store.usable(0, 50_000), "request wins the half-open probe");
    assert!(
        store.get_lane(0).cell.probe_in_flight(),
        "probe is in flight (HalfOpen)"
    );

    store.record_hard_down(0, "billing / insufficient balance");
    assert!(
        matches!(store.breaker_state(0), BreakerState::Open { .. }),
        "hard-down opens the breaker with a sticky cooldown"
    );

    assert!(
        !store.get_lane(0).cell.probe_in_flight(),
        "record_hard_down MUST release the probe (else the lane is locked out forever)"
    );

    let until = store.get_lane(0).cell.cooldown_until();
    set_now_for_test(until + 1);
    assert!(
        store.usable(0, until + 1),
        "lane must be probeable again after the sticky cooldown (not wedged by a stale probe flag)"
    );
    assert_eq!(
        store.breaker_state(0),
        BreakerState::HalfOpen,
        "the recovery probe re-enters HalfOpen"
    );
    assert!(
        store.get_lane(0).cell.probe_in_flight(),
        "the recovery request holds the single-flight probe"
    );
}

#[test]
fn test_is_ready_is_side_effect_free() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(30_000);
    poke(&store, 0, |c| c.cooldown_until = 29_000);
    set_state(&store, 0, 1);

    for _ in 0..100 {
        assert!(
            store.is_ready(0, 30_000),
            "expired-Open lane reads as ready"
        );
    }
    assert_eq!(
        store.get_lane(0).cell.snapshot().state,
        1,
        "is_ready must NOT transition Open→HalfOpen"
    );
    assert!(
        !store.get_lane(0).cell.probe_in_flight(),
        "is_ready must NOT acquire the single-flight probe"
    );
}

#[test]
fn test_probe_success_all_cells_closes_half_open_cells() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    set_now_for_test(5000);

    store.arm_half_open("", 0, 1000);
    store.arm_half_open("pool-a", 0, 1000);

    store.record_probe_success_all_cells(0, HealthState::now_secs());

    assert_eq!(
        store.breaker_state(0),
        BreakerState::Closed,
        "default cell must recover HalfOpen→Closed on the probe success"
    );
    assert_eq!(
        store.breaker_state_in("pool-a", 0),
        BreakerState::Closed,
        "per-pool cell must recover HalfOpen→Closed on the probe success"
    );
}

#[test]
fn test_open_cell_probe_failures_do_not_inflate_streak() {
    set_now_for_test(1_000);
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));

    let cfg = BreakerCfg {
        base_cooldown_secs: 4,
        max_cooldown_secs: 100_000,
        honor_retry_after: false,

        bench_below_trip_threshold: true,
        trip: TripConfig {
            mode: TripMode::Consecutive,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            consecutive_n: 2,
        },
    };

    store.force_open_in("", 0, 0);
    let lane = store.get_lane(0).clone();
    assert_eq!(lane.cell.streak(), 0, "starts at streak 0");

    for _ in 0..20 {
        store.record_transient(0, "5xx", &cfg, None);
    }
    assert_eq!(
        lane.cell.streak(),
        0,
        "failures recorded against an already-Open cell must NOT advance the streak"
    );

    set_state(&store, 0, 2);
    store.record_transient(0, "5xx", &cfg, None);
    assert_eq!(
        lane.cell.streak(),
        1,
        "the HalfOpen probe failure is the first real consecutive failure → streak 1"
    );

    let until = store.cell_cooldown_until("", 0);
    let cooldown = until - 1_000;
    assert!(
            cooldown < 100,
            "cooldown must reflect the real streak (~base<<1), not an inflated one pinned at max; got {cooldown}"
        );
    assert!(
        cooldown < cfg.max_cooldown_secs,
        "inflated-streak cooldown would pin at max ({}); fixed value must be well under it",
        cfg.max_cooldown_secs
    );
}

#[test]
fn test_streak_zero_base_cooldown_is_jittered_and_desynced() {
    set_now_for_test(5_000);

    let store = Arc::new(HealthState::new(
        (0..8).map(|i| make_lane_data(i, 10)).collect(),
    ));

    let cfg = BreakerCfg {
        base_cooldown_secs: 200,
        max_cooldown_secs: 100_000,
        honor_retry_after: false,

        bench_below_trip_threshold: true,
        trip: TripConfig::default(),
    };

    let cooldowns: Vec<u64> = (0..8)
        .map(|i| {
            let c = store.get_lane(i).clone();

            assert_eq!(c.cell.streak(), 0);
            c.cell
                .compute_cooldown_with_retry_after(5_000, &fsm_cfg(&cfg), None, 0)
        })
        .collect();

    assert!(
            cooldowns.iter().any(|d| *d != cooldowns[0]),
            "8 streak==0 cells with the same base must not all get the SAME cooldown; jitter/desync is not applying: {cooldowns:?}"
        );
    for d in &cooldowns {
        assert!(
            (100..=100_000).contains(d),
            "jittered streak==0 cooldown must stay within [base/2, max]; got {d}"
        );
    }
}

#[test]
fn test_export_health_reads_consistent_state_cooldown_pair() {
    set_now_for_test(10_000);
    let store = HealthState::new(vec![make_lane_data(0, 4)]);

    store.force_open_in("", 0, 10_600);

    let cfg = BreakerCfg::default();
    for _ in 0..5 {
        store.record_transient_in("poolA", 0, "5xx", &cfg, None);
    }

    let snaps = store.export_health();
    let s0 = &snaps[0];

    assert_eq!(s0.breaker_state, 1, "default cell exported as Open");
    assert!(
        s0.cooldown_until >= 10_600,
        "an Open default cell must export its paired future cooldown, not a torn 0: got {}",
        s0.cooldown_until
    );

    let pool_cell = s0
        .cells
        .iter()
        .find(|c| c.pool == "poolA")
        .expect("the tripped poolA cell must be exported");
    assert_eq!(pool_cell.breaker_state, 1, "poolA cell exported as Open");
    assert!(
        pool_cell.cooldown_until > 10_000,
        "an Open per-pool cell must export its paired future cooldown, not a torn 0: got {}",
        pool_cell.cooldown_until
    );
}

#[test]
fn test_unbounded_lane_skips_the_semaphore_bounded_still_enforces() {
    use busbar_kernel::store::Permit;

    let unbounded = HealthState::new(vec![make_lane_data(0, tokio::sync::Semaphore::MAX_PERMITS)]);
    let before = unbounded.available_permits(0);
    let p = unbounded.try_acquire(0).expect("unbounded always admits");
    assert!(matches!(p, Permit::Unbounded), "no slot was counted");
    assert_eq!(
        unbounded.available_permits(0),
        before,
        "the semaphore was never touched"
    );
    drop(p);

    let bounded = HealthState::new(vec![make_lane_data(0, 1)]);
    let held = bounded.try_acquire(0).expect("first slot admits");
    assert!(matches!(held, Permit::Bounded(_)));
    assert!(
        bounded.try_acquire(0).is_none(),
        "at the cap: the second concurrent request must be refused"
    );
    drop(held);
    assert!(
        bounded.try_acquire(0).is_some(),
        "the released slot admits again"
    );
}

fn make_limited_lane(id: usize, max_permits: usize, budget: i64) -> LaneData {
    LaneData {
        limited: true,
        budget,
        ..make_lane_data(id, max_permits)
    }
}

#[test]
fn test_breaker_verdict_maps_each_cell_state() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    let now = 1000u64;

    let cell = store.cell("p", 0);
    assert_eq!(
        cell.verdict(now),
        BreakerVerdict::Ready,
        "a Closed, elapsed-cooldown cell is Ready"
    );

    store.force_open_in("p", 0, now + 600);
    let cell = store.cell("p", 0);
    assert_eq!(
        cell.verdict(now),
        BreakerVerdict::Open { until: now + 600 },
        "an unexpired Open cell reports Open with its exact until"
    );

    store.force_open_in("p", 0, 0);
    let cell = store.cell("p", 0);
    assert_eq!(
        cell.verdict(now),
        BreakerVerdict::ProbeWinnable,
        "an expired Open cell is ProbeWinnable"
    );

    assert!(
        store.acquire_for_dispatch_in("p", 0, now),
        "precondition: win the probe"
    );
    let cell = store.cell("p", 0);
    assert_eq!(
        cell.verdict(now),
        BreakerVerdict::HalfOpen,
        "a HalfOpen (probe-in-flight) cell reports HalfOpen"
    );
}

#[test]
fn test_cell_ready_breaker_matches_verdict() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    let now = 1000u64;

    assert!(store.ready_in("p", 0, now));

    store.force_open_in("p", 0, now + 600);
    assert!(!store.ready_in("p", 0, now));

    store.force_open_in("p", 0, 0);
    assert!(store.ready_in("p", 0, now));
}

#[test]
fn test_classify_emits_each_reason() {
    let now = 1000u64;

    let healthy = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    assert_eq!(healthy.classify("p", 0, now), Ok(()));

    let dead_ld = LaneData {
        dead: true,
        ..make_lane_data(0, 10)
    };
    let dead = Arc::new(HealthState::new(vec![dead_ld]));
    assert_eq!(dead.classify("p", 0, now), Err(Unavailable::Dead));

    let broke = Arc::new(HealthState::new(vec![make_limited_lane(0, 10, 0)]));
    assert_eq!(
        broke.classify("p", 0, now),
        Err(Unavailable::BudgetExhausted)
    );

    let open = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    open.force_open_in("p", 0, now + 300);
    assert_eq!(
        open.classify("p", 0, now),
        Err(Unavailable::BreakerOpen { until: now + 300 })
    );

    let full = Arc::new(HealthState::new(vec![make_lane_data(0, 1)]));
    let _held = full.try_acquire(0).expect("occupy the only permit");
    assert_eq!(
        full.classify("p", 0, now),
        Err(Unavailable::AtCapacity {
            drain_hint_ms: None
        })
    );

    assert!(matches!(
        full.breaker_state_in("p", 0),
        BreakerState::Closed
    ));

    let probing = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    probing.force_open_in("p", 0, 0);
    assert!(
        probing.acquire_for_dispatch_in("p", 0, now),
        "win the probe"
    );
    assert_eq!(
        probing.classify("p", 0, now),
        Err(Unavailable::ProbeInFlight)
    );
}

#[test]
fn test_classify_lane_emits_each_reason() {
    let now = 1000u64;

    let healthy = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    assert_eq!(healthy.classify_lane(0, now), Ok(()));
    assert!(matches!(
        healthy.lane_breaker_state(0, now),
        BreakerState::Closed
    ));

    let dead = Arc::new(HealthState::new(vec![LaneData {
        dead: true,
        ..make_lane_data(0, 10)
    }]));
    assert_eq!(dead.classify_lane(0, now), Err(Unavailable::Dead));
    assert!(matches!(
        dead.lane_breaker_state(0, now),
        BreakerState::Open { .. }
    ));

    let broke = Arc::new(HealthState::new(vec![make_limited_lane(0, 10, 0)]));
    assert_eq!(
        broke.classify_lane(0, now),
        Err(Unavailable::BudgetExhausted)
    );

    let open = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    open.force_open_in("p", 0, now + 300);
    assert_eq!(
        open.classify_lane(0, now),
        Err(Unavailable::BreakerOpen { until: now + 300 })
    );
    assert!(matches!(
        open.lane_breaker_state(0, now),
        BreakerState::Open { until } if until == now + 300
    ));

    let full = Arc::new(HealthState::new(vec![make_lane_data(0, 1)]));
    let _held = full.try_acquire(0).expect("occupy the only permit");
    assert_eq!(
        full.classify_lane(0, now),
        Err(Unavailable::AtCapacity {
            drain_hint_ms: None
        })
    );
    assert!(matches!(
        full.lane_breaker_state(0, now),
        BreakerState::Closed
    ));
}

#[test]
fn test_classify_lane_open_and_at_capacity_both_visible() {
    let now = 1000u64;

    let wedged = Arc::new(HealthState::new(vec![make_lane_data(0, 1)]));
    wedged.force_open_in("p", 0, now + 60);
    let _held = wedged.try_acquire(0).expect("hold the only permit");
    assert_eq!(
        wedged.classify_lane(0, now),
        Err(Unavailable::BreakerOpen { until: now + 60 })
    );
    assert!(matches!(
        wedged.lane_breaker_state(0, now),
        BreakerState::Open { .. }
    ));
    assert!(
        wedged.snapshot(0, now).at_capacity,
        "the capacity axis stays independently true for an Open+saturated lane"
    );

    let expired = Arc::new(HealthState::new(vec![make_lane_data(0, 1)]));
    expired.force_open_in("p", 0, now);
    let _held2 = expired.try_acquire(0).expect("hold the only permit");
    assert_eq!(
        expired.classify_lane(0, now),
        Err(Unavailable::AtCapacity {
            drain_hint_ms: None
        })
    );
    assert!(
        matches!(
            expired.lane_breaker_state(0, now),
            BreakerState::Open { .. }
        ),
        "an expired-Open cell is still FSM-Open in /stats even though it would win a probe"
    );
    assert!(expired.snapshot(0, now).at_capacity);
}

#[test]
fn test_try_admit_ok_holds_permit() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 1)]));
    let now = 1000u64;
    let admit = store.try_admit("p", 0, now).expect("healthy lane admits");

    assert!(
        store.try_acquire(0).is_none(),
        "the Admit holds the lane's only permit"
    );
    drop(admit);
    assert!(
        store.try_acquire(0).is_some(),
        "dropping the Admit releases the permit"
    );
}

#[test]
fn test_try_admit_error_variants() {
    let now = 1000u64;

    let dead = Arc::new(HealthState::new(vec![LaneData {
        dead: true,
        ..make_lane_data(0, 10)
    }]));
    assert!(matches!(
        dead.try_admit("p", 0, now),
        Err(Unavailable::Dead)
    ));

    let broke = Arc::new(HealthState::new(vec![make_limited_lane(0, 10, 0)]));
    assert!(matches!(
        broke.try_admit("p", 0, now),
        Err(Unavailable::BudgetExhausted)
    ));

    let open = Arc::new(HealthState::new(vec![make_lane_data(0, 10)]));
    open.force_open_in("p", 0, now + 300);
    assert!(matches!(
        open.try_admit("p", 0, now),
        Err(Unavailable::BreakerOpen { until }) if until == now + 300
    ));
}

/// THE probe-leak proof: a lane that is BOTH expired-Open (so `try_admit` wins
/// its single-flight probe) AND at capacity (so no permit can be acquired) must:
///   1. return `Err(AtCapacity)`, and
///   2. NOT leave the cell wedged HalfOpen — the won-but-undispatched probe is released EXACTLY
///      (owner-checked), reverting HalfOpen→Open, so the lane is not benched; and
///   3. NOT double-release — the cell is cleanly re-winnable afterwards.
#[test]
fn test_try_admit_at_capacity_does_not_leak_probe() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 1)]));
    let now = 1000u64;

    let _held = store.try_acquire(0).expect("occupy the only permit");

    store.force_open_in("p", 0, 0);

    assert!(
        matches!(
            store.try_admit("p", 0, now),
            Err(Unavailable::AtCapacity {
                drain_hint_ms: None
            })
        ),
        "an at-capacity expired-Open lane yields AtCapacity"
    );

    assert!(
        matches!(store.breaker_state_in("p", 0), BreakerState::Open { .. }),
        "the won-but-undispatched probe must be released (HalfOpen→Open), not leaked"
    );

    assert!(
        store.acquire_for_dispatch_in("p", 0, now),
        "the cell is cleanly re-winnable after the exact release"
    );

    let epoch = store.probe_epoch_in("p", 0);
    store.release_probe_owned_in("p", 0, epoch);
    assert!(
        matches!(store.breaker_state_in("p", 0), BreakerState::Open { .. }),
        "a single owner-checked release reverts HalfOpen→Open exactly once"
    );
}

#[test]
fn test_try_admit_probe_winnable_at_capacity_preserves_probe() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 1)]));
    let now = 1000u64;

    store.force_open_in("p", 0, 0);
    let epoch_before = store.probe_epoch_in("p", 0);

    let held = store.try_acquire(0).expect("occupy the only permit");

    assert!(
        matches!(
            store.try_admit("p", 0, now),
            Err(Unavailable::AtCapacity {
                drain_hint_ms: None
            })
        ),
        "a ProbeWinnable lane at capacity yields AtCapacity"
    );

    assert_eq!(
        store.probe_epoch_in("p", 0),
        epoch_before,
        "an at-capacity ProbeWinnable attempt must NOT win/burn the probe (epoch unchanged)"
    );
    assert!(
        matches!(store.breaker_state_in("p", 0), BreakerState::Open { .. }),
        "the cell stays Open (its recovery probe is preserved, not consumed)"
    );

    drop(held);
    let admit = store
        .try_admit("p", 0, now)
        .expect("with a free permit the preserved probe is won and the lane admits");
    assert!(
        matches!(store.breaker_state_in("p", 0), BreakerState::HalfOpen),
        "winning the preserved probe flips the cell HalfOpen"
    );

    store.record_success_in("p", 0, HealthState::now_secs());
    assert!(
        matches!(store.breaker_state_in("p", 0), BreakerState::Closed),
        "a success on the recovery probe closes the breaker — the wedge is gone"
    );
    drop(admit);
}

#[test]
fn test_try_admit_probe_winnable_free_permit_succeeds() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 1)]));
    let now = 1000u64;
    store.force_open_in("p", 0, 0);

    let admit = store
        .try_admit("p", 0, now)
        .expect("a ProbeWinnable lane with a free permit admits");
    assert!(
        matches!(store.breaker_state_in("p", 0), BreakerState::HalfOpen),
        "a won probe transitions the cell to HalfOpen"
    );

    let epoch = admit
        .probe_epoch
        .expect("a won ProbeWinnable probe carries Some(epoch)");
    assert_eq!(
        epoch,
        store.probe_epoch_in("p", 0),
        "the Admit surfaces the cell's current probe epoch for owner-checked release"
    );

    store.release_probe_owned_in("p", 0, epoch);
    assert!(
        matches!(store.breaker_state_in("p", 0), BreakerState::Open { .. }),
        "the surfaced epoch is the correct owner token (single owner-checked revert)"
    );
    drop(admit);
}

#[test]
fn test_try_admit_closed_ready_yields_no_probe_token() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 1)]));
    let now = 1000u64;

    let admit = store
        .try_admit("p", 0, now)
        .expect("a Closed-ready lane admits");
    assert_eq!(
        admit.probe_epoch, None,
        "a Closed-ready admit wins no single-flight probe → no owner token"
    );
    assert!(
        matches!(store.breaker_state_in("p", 0), BreakerState::Closed),
        "a Closed-ready admit is a pure no-op — it must NOT transition the cell to HalfOpen"
    );
    drop(admit);

    store.force_open_in("p", 0, 0);
    let admit2 = store
        .try_admit("p", 0, now)
        .expect("a ProbeWinnable lane admits");
    assert_eq!(
        admit2.probe_epoch,
        Some(store.probe_epoch_in("p", 0)),
        "a won recovery probe carries Some(current epoch) as its owner token"
    );
    assert!(
        matches!(store.breaker_state_in("p", 0), BreakerState::HalfOpen),
        "a won probe transitions the cell to HalfOpen"
    );
    drop(admit2);
}

#[test]
fn test_try_admit_closed_at_capacity_leaves_breaker_closed() {
    let store = Arc::new(HealthState::new(vec![make_lane_data(0, 1)]));
    let now = 1000u64;
    let _held = store.try_acquire(0).expect("occupy the only permit");
    assert!(matches!(
        store.try_admit("p", 0, now),
        Err(Unavailable::AtCapacity {
            drain_hint_ms: None
        })
    ));
    assert!(
        matches!(store.breaker_state_in("p", 0), BreakerState::Closed),
        "a Closed-ready lane at capacity stays Closed (no probe was burned)"
    );
}

#[test]
fn test_recovery_hint_ms() {
    let now = 1000u64;

    assert_eq!(Unavailable::Dead.recovery_hint_ms(now), None);
    assert_eq!(Unavailable::BudgetExhausted.recovery_hint_ms(now), None);

    assert_eq!(
        Unavailable::BreakerOpen { until: now + 5 }.recovery_hint_ms(now),
        Some(5000)
    );

    let floor = Unavailable::AtCapacity {
        drain_hint_ms: None,
    }
    .recovery_hint_ms(now)
    .expect("at-capacity has an honest floor");
    assert!(
        floor >= 2000,
        "at-capacity floor must be >= the shipped 2s, got {floor}ms"
    );

    assert_eq!(
        Unavailable::AtCapacity {
            drain_hint_ms: Some(75)
        }
        .recovery_hint_ms(now),
        Some(75)
    );

    assert!(Unavailable::ProbeInFlight.recovery_hint_ms(now).is_some());
    assert!(Unavailable::Shedding.recovery_hint_ms(now).is_some());
}
