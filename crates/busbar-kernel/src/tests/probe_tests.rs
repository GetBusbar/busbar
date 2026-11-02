// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::plane_driver::route_input::HealthModeInput as HealthMode;
use crate::probe::{
    advance_owned_deadline, due, probe_deadline, spawn_probers, ProbeCfg, ProbeMember,
    ProbeSchedule, ProbeTarget, NEVER_PROBE_DEADLINE,
};

#[derive(Default)]
struct Double {
    suppressing: AtomicBool,
    probed: AtomicUsize,
}

impl ProbeTarget for Double {
    fn suppressing(&self, _member: usize) -> bool {
        self.suppressing.load(Ordering::Relaxed)
    }
    async fn probe(&self, _member: usize, _timeout: Duration) {
        self.probed.fetch_add(1, Ordering::Relaxed);
    }
}

fn member(mode: HealthMode, interval_secs: u64) -> Vec<ProbeMember> {
    vec![ProbeMember {
        index: 0,
        name: "m".into(),
        cfg: ProbeCfg::resolve(mode, Some(interval_secs), None, 30, 5),
    }]
}

async fn run_for(secs: u64) {
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(secs)).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

#[test]
fn settings_resolve_to_the_member_then_the_default_floored_at_one_second() {
    let c = ProbeCfg::resolve(HealthMode::Active, None, None, 30, 5);
    assert_eq!(
        (c.interval, c.timeout),
        (Duration::from_secs(30), Duration::from_secs(5))
    );
    let c = ProbeCfg::resolve(HealthMode::Dead, Some(7), Some(2), 30, 5);
    assert_eq!(
        (c.interval, c.timeout),
        (Duration::from_secs(7), Duration::from_secs(2))
    );
    let c = ProbeCfg::resolve(HealthMode::Active, Some(0), Some(0), 0, 0);
    assert_eq!(
        (c.interval, c.timeout),
        (Duration::from_secs(1), Duration::from_secs(1))
    );
    assert!(!ProbeCfg::resolve(HealthMode::None, None, None, 30, 5).probes());
}

#[test]
fn the_modes_decide_what_a_tick_probes() {
    assert!(due(HealthMode::Active, false));
    assert!(due(HealthMode::Active, true));
    assert!(!due(HealthMode::Dead, false));
    assert!(due(HealthMode::Dead, true));
    assert!(!due(HealthMode::None, true));
}

#[tokio::test(start_paused = true)]
async fn the_first_probe_is_one_interval_after_the_start() {
    let t = Arc::new(Double::default());
    let s = Arc::new(ProbeSchedule::new(1));
    spawn_probers(&t, &s, &member(HealthMode::Active, 10));
    run_for(9).await;
    assert_eq!(
        t.probed.load(Ordering::Relaxed),
        0,
        "not before one interval"
    );
    run_for(2).await;
    assert_eq!(t.probed.load(Ordering::Relaxed), 1, "one interval in");
    run_for(10).await;
    assert_eq!(t.probed.load(Ordering::Relaxed), 2, "then every interval");
}

#[tokio::test(start_paused = true)]
async fn dead_mode_probes_only_a_suppressed_member() {
    let t = Arc::new(Double::default());
    let s = Arc::new(ProbeSchedule::new(2));
    let mut ms = member(HealthMode::Dead, 10);
    ms.push(ProbeMember {
        index: 1,
        name: "off".into(),
        cfg: ProbeCfg::resolve(HealthMode::None, Some(10), None, 30, 5),
    });
    spawn_probers(&t, &s, &ms);
    run_for(35).await;
    assert_eq!(
        t.probed.load(Ordering::Relaxed),
        0,
        "healthy: nothing to recover"
    );
    assert_eq!(s.deadline(1), None, "a `none` member is never scheduled");
    t.suppressing.store(true, Ordering::Relaxed);
    run_for(10).await;
    assert_eq!(
        t.probed.load(Ordering::Relaxed),
        1,
        "suppressed: probed at the next tick"
    );
}

#[tokio::test(start_paused = true)]
async fn a_snapshot_swap_never_pushes_the_probe_deadline_out() {
    let t = Arc::new(Double::default());
    let s = Arc::new(ProbeSchedule::new(1));
    let ms = member(HealthMode::Active, 10);
    spawn_probers(&t, &s, &ms);
    let first = s.deadline(0).expect("scheduled");
    for _ in 0..5 {
        tokio::time::advance(Duration::from_secs(1)).await;
        spawn_probers(&t, &s, &ms);
        assert_eq!(
            s.deadline(0),
            Some(first),
            "a re-spawn inherits the deadline"
        );
    }
    assert_eq!(s.generation(), 6);
    run_for(6).await;
    assert_eq!(
        t.probed.load(Ordering::Relaxed),
        1,
        "probed once at the inherited deadline, by the live generation only"
    );
}

#[tokio::test(start_paused = true)]
async fn a_shortened_interval_takes_effect_on_the_inherited_deadlines() {
    let t = Arc::new(Double::default());
    let s = Arc::new(ProbeSchedule::new(1));
    spawn_probers(&t, &s, &member(HealthMode::Active, 3600));
    assert!(s.deadline(0).unwrap() >= 3_600_000);
    spawn_probers(&t, &s, &member(HealthMode::Active, 10));
    assert!(
        s.deadline(0).unwrap() <= 10_000,
        "clamped to the new interval"
    );
    run_for(11).await;
    assert_eq!(t.probed.load(Ordering::Relaxed), 1);
}

#[test]
fn a_late_tick_never_reverts_a_newer_generations_clamp() {
    let slot = std::sync::atomic::AtomicU64::new(3_600_000);
    slot.fetch_min(10_000, Ordering::Relaxed);
    let got = advance_owned_deadline(&slot, 3_600_000, 3_610_000);
    assert_eq!(slot.load(Ordering::Relaxed), 10_000);
    assert_eq!(got, 10_000, "the late prober adopts the newer value");
}

#[tokio::test(start_paused = true)]
async fn a_dropped_target_ends_its_probers_and_is_never_pinned() {
    let t = Arc::new(Double::default());
    let s = Arc::new(ProbeSchedule::new(1));
    spawn_probers(&t, &s, &member(HealthMode::Active, 10));
    assert_eq!(
        Arc::strong_count(&t),
        1,
        "the service holds no strong reference"
    );
    let weak = Arc::downgrade(&t);
    drop(t);
    run_for(30).await;
    assert!(weak.upgrade().is_none());
}

#[tokio::test(start_paused = true)]
async fn an_unrepresentable_timeout_falls_back_to_never() {
    let d = probe_deadline(Duration::MAX);
    assert!(d >= tokio::time::Instant::now() + NEVER_PROBE_DEADLINE - Duration::from_secs(1));
    let d = probe_deadline(Duration::from_secs(5));
    assert!(d <= tokio::time::Instant::now() + Duration::from_secs(5));
}
