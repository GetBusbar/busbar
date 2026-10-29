//! The kernel's per-cell HANDLES onto the one breaker (`busbar-kernel-breaker`, item 142).
//!
//! The breaker's state machine — trip, escalating cooldown, the Retry-After floor, the single-flight
//! half-open probe — lives in that crate and nowhere else. What stays here is the striped success
//! counter and the two translations into the breaker's own words.

use super::*;

/// A monotonic event counter STRIPED PER DATA-PLANE WORKER: the hot writer (`add`, one success
/// per request) increments its own cache-line-padded slot — no cross-core RMW ping-pong — and the
/// rare readers (`/stats` snapshot, `export_health`) fold with `sum()`, which is EXACT: counter
/// addition is order-free, so the fold is byte-identical to the single shared counter it replaces.
/// `reset_to` (health restore) parks the restored value in the fallback slot and zeroes the rest.
pub(crate) struct StripedCounter {
    slots: Box<[PaddedU64]>,
}

#[repr(align(64))]
struct PaddedU64(AtomicU64);

impl StripedCounter {
    pub(crate) fn new(initial: u64) -> Self {
        let c = Self {
            slots: (0..crate::state::worker_stripes())
                .map(|_| PaddedU64(AtomicU64::new(0)))
                .collect(),
        };
        c.slots[c.slots.len() - 1]
            .0
            .store(initial, Ordering::Relaxed);
        c
    }

    /// One event on the calling thread's stripe.
    pub(crate) fn add(&self) {
        let i = crate::state::worker_stripe(self.slots.len());
        self.slots[i].0.fetch_add(1, Ordering::Relaxed);
    }

    /// Fold: the exact total (addition is order-free across stripes).
    pub(crate) fn sum(&self) -> u64 {
        self.slots.iter().map(|s| s.0.load(Ordering::Relaxed)).sum()
    }

    /// Restore to an absolute value (health import): fallback slot carries it, others zero.
    pub(crate) fn reset_to(&self, v: u64) {
        for (i, s) in self.slots.iter().enumerate() {
            s.0.store(
                if i == self.slots.len() - 1 { v } else { 0 },
                Ordering::Relaxed,
            );
        }
    }
}

/// The breaker's own reading of a cell, in the store vocabulary's words.
pub(crate) fn to_state(s: FsmState) -> BreakerState {
    match s {
        FsmState::Closed => BreakerState::Closed,
        FsmState::Open { until } => BreakerState::Open { until },
        FsmState::HalfOpen => BreakerState::HalfOpen,
    }
}

/// The resolved pool config, as the one breaker's state machine takes it. Field for field: the
/// store's `BreakerCfg` is the plane-facing carrier of the same data.
pub(crate) fn fsm_cfg(c: &BreakerCfg) -> busbar_kernel_breaker::cfg::BreakerCfg {
    use busbar_kernel_breaker::cfg as b;
    b::BreakerCfg {
        base_cooldown_secs: c.base_cooldown_secs,
        max_cooldown_secs: c.max_cooldown_secs,
        honor_retry_after: c.honor_retry_after,
        bench_below_trip_threshold: c.bench_below_trip_threshold,
        trip: b::TripConfig {
            mode: match c.trip.mode {
                TripMode::ErrorRate => b::TripMode::ErrorRate,
                TripMode::Consecutive => b::TripMode::Consecutive,
            },
            window_s: c.trip.window_s,
            threshold: c.trip.threshold,
            min_requests: c.trip.min_requests,
            consecutive_n: c.trip.consecutive_n,
        },
    }
}
