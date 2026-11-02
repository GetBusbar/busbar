// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use crate::plane_driver::route_input::HealthModeInput as HealthMode;

pub const NEVER_PROBE_DEADLINE: Duration = Duration::from_secs(30 * 365 * 86_400);

const UNSCHEDULED: u64 = u64::MAX;

/// One member's resolved probe settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeCfg {
    /// The strategy.
    pub mode: HealthMode,
    /// Between probes; at least one second.
    pub interval: Duration,
    /// One probe's whole lifecycle; at least one second.
    pub timeout: Duration,
}

impl ProbeCfg {
    #[must_use]
    pub fn resolve(
        mode: HealthMode,
        interval_secs: Option<u64>,
        timeout_secs: Option<u64>,
        default_interval_secs: u64,
        default_timeout_secs: u64,
    ) -> Self {
        Self {
            mode,
            interval: Duration::from_secs(interval_secs.unwrap_or(default_interval_secs).max(1)),
            timeout: Duration::from_secs(timeout_secs.unwrap_or(default_timeout_secs).max(1)),
        }
    }

    #[must_use]
    pub fn probes(&self) -> bool {
        self.mode != HealthMode::None
    }
}

#[must_use]
pub fn due(mode: HealthMode, breaker_suppressing: bool) -> bool {
    match mode {
        HealthMode::Active => true,
        HealthMode::Dead => breaker_suppressing,
        HealthMode::None => false,
    }
}

pub struct ProbeSchedule {
    generation: AtomicU64,

    origin: tokio::time::Instant,

    deadlines: Vec<AtomicU64>,
}

impl ProbeSchedule {
    #[must_use]
    pub fn new(members: usize) -> Self {
        Self {
            generation: AtomicU64::new(0),
            origin: tokio::time::Instant::now(),
            deadlines: (0..members).map(|_| AtomicU64::new(UNSCHEDULED)).collect(),
        }
    }

    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn deadline(&self, i: usize) -> Option<u64> {
        self.deadlines
            .get(i)
            .map(|d| d.load(Ordering::Relaxed))
            .filter(|d| *d != UNSCHEDULED)
    }

    fn elapsed_ms(&self) -> u64 {
        tokio::time::Instant::now()
            .saturating_duration_since(self.origin)
            .as_millis() as u64
    }

    fn begin(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn claim_first(&self, i: usize, interval: Duration) -> u64 {
        let first = self
            .elapsed_ms()
            .saturating_add(interval.as_millis() as u64);
        match self.deadlines.get(i) {
            Some(slot) => slot.fetch_min(first, Ordering::Relaxed).min(first),

            None => first,
        }
    }

    fn advance(&self, i: usize, owned: u64, interval: Duration) -> u64 {
        let next = self
            .elapsed_ms()
            .saturating_add(interval.as_millis() as u64);
        match self.deadlines.get(i) {
            Some(slot) => advance_owned_deadline(slot, owned, next),
            None => next,
        }
    }
}

fn advance_owned_deadline(slot: &AtomicU64, owned: u64, next: u64) -> u64 {
    match slot.compare_exchange(owned, next, Ordering::Relaxed, Ordering::Relaxed) {
        Ok(_) => next,
        Err(theirs) => theirs,
    }
}

pub trait ProbeTarget: Send + Sync + 'static {
    fn suppressing(&self, member: usize) -> bool;

    fn probe(&self, member: usize, timeout: Duration) -> impl Future<Output = ()> + Send;
}

/// One member the service may probe.
#[derive(Debug, Clone)]
pub struct ProbeMember {
    /// The member's index in the schedule's table.
    pub index: usize,
    /// The operator's name for it, for the log lines.
    pub name: String,
    /// Its resolved settings.
    pub cfg: ProbeCfg,
}

pub fn spawn_probers<T: ProbeTarget>(
    target: &Arc<T>,
    schedule: &Arc<ProbeSchedule>,
    members: &[ProbeMember],
) -> u64 {
    let my_gen = schedule.begin();
    for m in members.iter().filter(|m| m.cfg.probes()) {
        let deadline_ms = schedule.claim_first(m.index, m.cfg.interval);

        if my_gen == 1 {
            tracing::info!(
                lane = %m.name,
                mode = ?m.cfg.mode,
                interval_secs = m.cfg.interval.as_secs(),
                "active health probing enabled for lane"
            );
        }
        let weak: Weak<T> = Arc::downgrade(target);
        let schedule = schedule.clone();
        let m = m.clone();
        tokio::spawn(async move {
            let start = schedule.origin + Duration::from_millis(deadline_ms);
            let mut ticker = tokio::time::interval_at(start, m.cfg.interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut owned = deadline_ms;
            loop {
                ticker.tick().await;
                if schedule.generation() != my_gen {
                    return;
                }
                owned = schedule.advance(m.index, owned, m.cfg.interval);

                let Some(target) = weak.upgrade() else {
                    tracing::debug!(lane = %m.name, "health prober exiting: generation replaced");
                    return;
                };
                if due(m.cfg.mode, target.suppressing(m.index)) {
                    target.probe(m.index, m.cfg.timeout).await;
                }
            }
        });
    }
    my_gen
}

#[must_use]
pub fn probe_deadline(timeout: Duration) -> tokio::time::Instant {
    let now = tokio::time::Instant::now();
    now.checked_add(timeout)
        .unwrap_or_else(|| now + NEVER_PROBE_DEADLINE)
}

#[cfg(test)]
#[path = "tests/probe_tests.rs"]
mod probe_tests;
