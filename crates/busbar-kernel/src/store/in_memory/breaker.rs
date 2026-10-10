//! The kernel's per-cell HANDLES onto the one breaker (`busbar-kernel-breaker`, item 142).
//!
//! The breaker's state machine — trip, escalating cooldown, the Retry-After floor, the single-flight
//! half-open probe — lives in that crate and nowhere else. What stays here is what selection owns
//! beside it: the per-worker SWRR stripes each cell is weighted by, and the striped success counter.

use super::*;

/// One per-worker SWRR accumulator slot, cache-line padded so adjacent workers' slots in a cell's
/// stripe array never false-share. `weight` is the classic smooth-weighted-round-robin running
/// value; `seen_gen` is the cell reset generation this slot last observed (see [`SwrrStripes`]).
#[repr(align(64))]
pub(crate) struct SwrrSlot {
    pub(crate) weight: AtomicI64,
    seen_gen: AtomicU64,
}

/// A cell's SWRR state, STRIPED PER DATA-PLANE WORKER (thread-per-core): each worker runs the
/// add/find-max/subtract over its OWN slot — single-writer, no lock, no cross-core ping-pong —
/// and the classic SWRR sequence per worker over the same config weight RATIOS preserves the
/// global distribution (a sum of proportional streams is proportional). The LAST slot is the
/// shared FALLBACK stripe for non-worker threads; selections on it stay serialized by the pool's
/// SWRR shard lock, exactly the pre-stripe discipline.
///
/// RESET (recovery rejoining the healthy set) is GENERATIONAL, not a store: `reset()` bumps `gen`
/// once, and each stripe lazily zeroes itself the next time its owning worker touches it and sees
/// a stale `seen_gen` (`slot()`). That keeps reset race-free against lock-free in-flight
/// selections — the old `store(0)` under the shard lock could not serialize against workers that
/// no longer take that lock, and an unserialized store landing between a worker's `fetch_add` and
/// its compensating `fetch_sub` would break the per-stripe `Σ == 0` invariant. Lazy zeroing is
/// the same outcome the eager reset bought — the stripe rejoins from 0 — delivered on the owning
/// worker's own thread.
pub(crate) struct SwrrStripes {
    gen: AtomicU64,
    slots: Box<[SwrrSlot]>,
}

impl SwrrStripes {
    pub(crate) fn new() -> Self {
        Self {
            gen: AtomicU64::new(0),
            slots: (0..crate::state::worker_stripes())
                .map(|_| SwrrSlot {
                    weight: AtomicI64::new(0),
                    seen_gen: AtomicU64::new(0),
                })
                .collect(),
        }
    }

    /// This thread's slot for `stripe`, generation-checked: a stale slot zeroes itself first, so a
    /// recovered cell's stripe always rejoins selection from 0. Single-writer for worker stripes
    /// (the owning worker is the only thread that ever indexes them); the fallback stripe's callers
    /// hold the pool shard lock, so its check-then-zero is serialized too.
    pub(crate) fn slot(&self, stripe: usize) -> &AtomicI64 {
        let s = &self.slots[stripe.min(self.slots.len() - 1)];
        let g = self.gen.load(Ordering::Relaxed);
        if s.seen_gen.load(Ordering::Relaxed) != g {
            s.weight.store(0, Ordering::Relaxed);
            s.seen_gen.store(g, Ordering::Relaxed);
        }
        &s.weight
    }

    /// Recovery reset: one generation bump; every stripe lazily zeroes on next touch. See the
    /// type doc for why this replaces the eager under-lock `store(0)`.
    pub(crate) fn reset(&self) {
        self.gen.fetch_add(1, Ordering::Relaxed);
    }

    /// Sum of the LIVE stripes (stale-generation slots count as their logical 0) — the whole-cell
    /// accumulator view the SWRR invariant assertions read. Test-only, like its reader
    /// `cell_current_weight`.
    #[cfg(any(test, feature = "test-support"))]
    #[allow(dead_code)]
    pub(crate) fn sum(&self) -> i64 {
        let g = self.gen.load(Ordering::Relaxed);
        self.slots
            .iter()
            .filter(|s| s.seen_gen.load(Ordering::Relaxed) == g)
            .map(|s| s.weight.load(Ordering::Relaxed))
            .sum()
    }

    /// TEST-ONLY: force the CALLING thread's stripe to `v` at the current generation (and settle
    /// every other stripe at a live 0), so the summed accumulator view reads exactly `v` — the
    /// stale-accumulator precondition of the SWRR-reset regression tests.
    #[cfg(any(test, feature = "test-support"))]
    #[allow(dead_code)]
    pub(crate) fn force(&self, v: i64) {
        let g = self.gen.load(Ordering::Relaxed);
        let mine = crate::state::worker_stripe(self.slots.len());
        for (i, s) in self.slots.iter().enumerate() {
            s.weight
                .store(if i == mine { v } else { 0 }, Ordering::Relaxed);
            s.seen_gen.store(g, Ordering::Relaxed);
        }
    }
}

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

/// A named pool's cell: the one breaker's FSM cell for this `(pool, lane)`, and the SWRR stripes
/// selection weighs it by. The lane-default cell is the same pair, carried on [`LaneState`].
pub(crate) struct PoolCell {
    pub(crate) fsm: Arc<FsmCell>,
    pub(crate) swrr: SwrrStripes,
}

/// Either shape of routed cell — a named pool's [`PoolCell`] or the lane-default cell on
/// [`LaneState`] — as the two halves selection and admission read.
pub(crate) trait CellRef: Send + Sync {
    fn fsm(&self) -> &FsmCell;
    fn swrr(&self) -> &SwrrStripes;
}

impl CellRef for PoolCell {
    fn fsm(&self) -> &FsmCell {
        &self.fsm
    }
    fn swrr(&self) -> &SwrrStripes {
        &self.swrr
    }
}

impl CellRef for LaneState {
    fn fsm(&self) -> &FsmCell {
        &self.cell
    }
    fn swrr(&self) -> &SwrrStripes {
        &self.swrr
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
