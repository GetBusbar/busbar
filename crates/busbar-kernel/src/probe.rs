// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HEALTH-PROBE SERVICE (`BUSBAR-1.6.0.md` Part 3, §C K7; F23): the breaker service that
//! drives active health probing. The kernel owns WHEN a member is probed (the cadence below,
//! 1.5.5's verbatim) and WHAT the answer means to the breaker (the same classification an organic
//! attempt gets). The plane owns WHAT the probe is: a plane whose tail states `TAIL_PROBES`
//! answers the kernel-originated probe unit's `arrive` (claim `CLAIM_PROBE`) and ATTEMPT piece
//! with its probe request. This module names no plane type.
//!
//! The cadence, unchanged from 1.5.5 (`health:` per member, `none | dead | active`):
//!
//! - `none` never probes. `dead` probes only a member the breaker is suppressing, so a recovered
//!   upstream is picked back up promptly. `active` probes every member.
//! - The interval and timeout default to the process-wide defaults (30 s / 5 s), a member's own
//!   value wins, and neither is ever below one second.
//! - The FIRST probe is one interval after the schedule began, never at boot: a cold upstream is
//!   not probed before traffic has established health.
//! - The schedule is phase-stable across snapshot swaps. Every generation inherits each member's
//!   deadline, so a swap burst faster than the interval cannot starve probing; a shortened
//!   interval takes effect within one new interval; a stale generation exits at its next tick.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use crate::plane_host::HealthModeInput as HealthMode;

/// The probe deadline used when `now + timeout` is unrepresentable: 30 years, tokio's own
/// `far_future` horizon and the config-validation ceiling on every duration (item 147).
pub const NEVER_PROBE_DEADLINE: Duration = Duration::from_secs(30 * 365 * 86_400);

/// The cap on the bytes read from a non-2xx probe answer before classification: a hostile or
/// misconfigured upstream must not force an unbounded allocation because a probe failed.
pub const PROBE_ERROR_BODY_CAP: usize = 64 * 1024;

/// Sentinel for "this member has no deadline yet". `0` is a legitimate deadline at the origin.
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
    /// The member's settings: its own `interval_secs` / `timeout_secs` where stated, else the
    /// process-wide defaults, each floored at one second.
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

    /// Whether the service runs a task for this member at all.
    #[must_use]
    pub fn probes(&self) -> bool {
        self.mode != HealthMode::None
    }
}

/// Whether a tick probes: `active` always; `dead` only while the breaker suppresses the member in
/// ANY cell (fully tripped, or a soft cooldown armed by a sub-threshold transient); `none` never.
#[must_use]
pub fn due(mode: HealthMode, breaker_suppressing: bool) -> bool {
    match mode {
        HealthMode::Active => true,
        HealthMode::Dead => breaker_suppressing,
        HealthMode::None => false,
    }
}

/// The probe schedule, shared by every snapshot-derived generation of one member table.
pub struct ProbeSchedule {
    /// Bumped by every [`spawn_probers`]. A prober whose captured generation is no longer current
    /// exits at its next tick, so generations never double-probe.
    generation: AtomicU64,
    /// The reference the deadlines are measured from: a MONOTONIC instant, so the schedule neither
    /// drifts with wall-clock adjustments nor ignores a paused test clock.
    origin: tokio::time::Instant,
    /// Per-member next-probe deadline, milliseconds after `origin`.
    deadlines: Vec<AtomicU64>,
}

impl ProbeSchedule {
    /// A schedule for `members` members, nothing scheduled.
    #[must_use]
    pub fn new(members: usize) -> Self {
        Self {
            generation: AtomicU64::new(0),
            origin: tokio::time::Instant::now(),
            deadlines: (0..members).map(|_| AtomicU64::new(UNSCHEDULED)).collect(),
        }
    }

    /// The generation now current.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    /// Member `i`'s deadline in milliseconds after the origin; `None` when unscheduled.
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

    /// Take a new generation; the older ones exit at their next tick.
    fn begin(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Spawn-time claim of member `i`'s first deadline: one interval from now, MONOTONE-EARLIEST.
    /// An unscheduled slot takes it; a scheduled one keeps whichever is sooner, so a racing
    /// generation's landed deadline is inherited and never pushed out, and a SHORTENED interval
    /// takes effect within one new interval. Returns the deadline the caller now starts from.
    fn claim_first(&self, i: usize, interval: Duration) -> u64 {
        let first = self
            .elapsed_ms()
            .saturating_add(interval.as_millis() as u64);
        match self.deadlines.get(i) {
            Some(slot) => slot.fetch_min(first, Ordering::Relaxed).min(first),
            // The member count grew without a rebuild: an unshared schedule for this member.
            None => first,
        }
    }

    /// Tick-time advance of THIS prober's slot, and only this prober's: a `compare_exchange` on the
    /// value it last owned. Neither `store` (it would revert a newer generation's spawn-time clamp)
    /// nor `fetch_min` (`next` is always later, so the slot would freeze in the past) is right:
    /// spawn only biases EARLIER, tick only moves LATER.
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

/// Advance a slot from `owned` to `next`; if someone else moved it, adopt their value.
fn advance_owned_deadline(slot: &AtomicU64, owned: u64, next: u64) -> u64 {
    match slot.compare_exchange(owned, next, Ordering::Relaxed, Ordering::Relaxed) {
        Ok(_) => next,
        Err(theirs) => theirs,
    }
}

/// What the service probes: the composition root's per-generation object, held by `Weak` so a
/// stale generation never pins its snapshot. The real one is
/// [`crate::plane_driver::PlaneProbes`] (`arrive` with the probe claim, the ATTEMPT piece, the far
/// end's send, the breaker's classification); the pure cadence above is proven against a test
/// double.
pub trait ProbeTarget: Send + Sync + 'static {
    /// Whether the breaker suppresses `member` in any cell (the `dead` mode's trigger).
    fn suppressing(&self, member: usize) -> bool;
    /// Run one probe of `member` under `timeout` and fold the answer into the breaker.
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

/// Spawn one prober task per member whose mode is not `none`, as a new generation of `schedule`.
/// Every task holds a `Weak` to `target`: when the composition root drops a generation's target the
/// tasks exit at their next tick. Returns the generation taken.
pub fn spawn_probers<T: ProbeTarget>(
    target: &Arc<T>,
    schedule: &Arc<ProbeSchedule>,
    members: &[ProbeMember],
) -> u64 {
    let my_gen = schedule.begin();
    for m in members.iter().filter(|m| m.cfg.probes()) {
        let deadline_ms = schedule.claim_first(m.index, m.cfg.interval);
        // Only the FIRST generation announces: a swap burst would otherwise repeat a line that
        // claims probing was just enabled.
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
                // Upgraded per tick, never held across the wait.
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

/// The one deadline a probe's send and its capped error-body read share, so a black-holed upstream
/// can never hang a prober past its `timeout`. A timeout the clock cannot represent falls back to
/// tokio's own "never" instead of panicking (item 147).
#[must_use]
pub fn probe_deadline(timeout: Duration) -> tokio::time::Instant {
    let now = tokio::time::Instant::now();
    now.checked_add(timeout)
        .unwrap_or_else(|| now + NEVER_PROBE_DEADLINE)
}

#[cfg(test)]
#[path = "tests/probe_tests.rs"]
mod probe_tests;
