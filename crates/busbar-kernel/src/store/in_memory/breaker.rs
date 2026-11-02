use super::*;

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

    pub(crate) fn add(&self) {
        let i = crate::state::worker_stripe(self.slots.len());
        self.slots[i].0.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn sum(&self) -> u64 {
        self.slots.iter().map(|s| s.0.load(Ordering::Relaxed)).sum()
    }

    pub(crate) fn reset_to(&self, v: u64) {
        for (i, s) in self.slots.iter().enumerate() {
            s.0.store(
                if i == self.slots.len() - 1 { v } else { 0 },
                Ordering::Relaxed,
            );
        }
    }
}

pub(crate) fn to_state(s: FsmState) -> BreakerState {
    match s {
        FsmState::Closed => BreakerState::Closed,
        FsmState::Open { until } => BreakerState::Open { until },
        FsmState::HalfOpen => BreakerState::HalfOpen,
    }
}

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
