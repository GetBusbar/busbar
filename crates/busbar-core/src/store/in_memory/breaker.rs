use super::*;

use crate::diagnostics::{
    diag_debug, diag_warn, BREAKER_UNEXPECTED_STATE_CLASSIFY, BREAKER_UNEXPECTED_STATE_PROBE,
    BREAKER_UNEXPECTED_STATE_READ, BREAKER_UNEXPECTED_STATE_RECORD_FAILURE,
};

/// Bounded sliding window of recent request outcomes, each tagged success/error, used to compute
/// the error-rate trip signal. Backed by a `VecDeque` so dropping the oldest entry at capacity is
/// O(1). Memory is bounded by `capacity`.
#[derive(Debug, Clone)]
pub(crate) struct OutcomeWindow {
    /// (timestamp_secs, is_error) per outcome, oldest at the front.
    pub(crate) entries: std::collections::VecDeque<(u64, bool)>,
    pub(crate) capacity: usize,
}

impl OutcomeWindow {
    /// The backing deque starts EMPTY and grows on demand toward `capacity`, rather than
    /// eagerly reserving the full window up front. Eager was 16 KiB per window
    /// (`OUTCOME_WINDOW_CAPACITY` = 1024 × 16-byte entries) allocated at CONSTRUCTION — once per
    /// `LaneState` and AGAIN per `BreakerCell` — so a many-lane/many-pool deployment paid the
    /// whole window's RAM for every cell that never saw 1024 outcomes. Growth is `VecDeque`'s
    /// amortized doubling on `push_back`, entirely off the steady state: `capacity` is a power of
    /// two, so a window that DOES fill lands on exactly the same 1024-entry buffer the eager
    /// reserve produced (and [`Self::push`]'s pop-before-push keeps `len <= capacity` thereafter,
    /// so no further growth ever happens) — capacity behavior at the cap is byte-identical, only
    /// the idle-window cost changed. Construction is boot/config-apply work, never per-request
    /// (the alloc gate pins that).
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            entries: std::collections::VecDeque::new(),
            capacity,
        }
    }

    /// Record a timestamped outcome (`is_error` true for a failure). Drops the oldest at capacity.
    pub(crate) fn push(&mut self, ts: u64, is_error: bool) {
        if self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back((ts, is_error));
    }

    /// Total outcomes within `window_s` seconds of `now`.
    pub(crate) fn count_in_window(&self, now: u64, window_s: u64) -> usize {
        let start = now.saturating_sub(window_s);
        self.entries.iter().filter(|(ts, _)| *ts >= start).count()
    }

    /// Error outcomes within `window_s` seconds of `now`.
    pub(crate) fn error_count_in_window(&self, now: u64, window_s: u64) -> usize {
        let start = now.saturating_sub(window_s);
        self.entries
            .iter()
            .filter(|(ts, is_error)| *ts >= start && *is_error)
            .count()
    }

    /// Clear all entries.
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }
}

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

/// The per-cell circuit-breaker FSM state. `LaneState` embeds these fields directly (the default
/// cell, used by direct/ad-hoc routes and `/stats`); named pools get their own `BreakerCell` per
/// member lane so a lane shared across pools carries independent Open/Closed status per pool.
///
/// Lane-global concerns (the concurrency semaphore and the lifetime `max_requests` budget) are NOT
/// here — they stay on `LaneState` and are shared across every pool routing to that lane, so the
/// cost/concurrency caps remain per-upstream regardless of how many pools front it.
pub(crate) struct BreakerCell {
    pub(crate) breaker_state: AtomicU64, // 0=Closed, 1=Open, 2=HalfOpen
    pub(crate) streak: AtomicU32,
    pub(crate) cooldown_until: AtomicU64,
    pub(crate) probe_in_flight: AtomicBool,
    // MONOTONIC single-flight probe generation, bumped each time a probe is WON (Open→HalfOpen CAS in
    // `cell_acquire_breaker`). It is the probe's OWNER TOKEN: the winner captures the post-bump value
    // and passes it back to `cell_release_probe`, which reverts the cell ONLY if the epoch still
    // matches. Without it, a stalled undispatched-probe release (a `ProbeGuard` dropped LATE, after the
    // cell already recorded an outcome AND a NEW probe was won) would CAS the fresh winner's HalfOpen
    // back to Open and clear its `probe_in_flight`, so a third caller could win a DUPLICATE concurrent
    // probe on a lane already being probed. Benign (an extra recovery probe, no correctness loss) but
    // real; the epoch check makes release a strict no-op for any but the current probe owner.
    pub(crate) probe_epoch: AtomicU64,
    pub(crate) err: AtomicU64,
    pub(crate) outcome_window: std::sync::Mutex<OutcomeWindow>,
    pub(crate) swrr: SwrrStripes, // SWRR state, striped per worker (per pool — selection runs over a pool's set)
    // Serializes every state+cooldown TRANSITION on this cell. `breaker_state` and `cooldown_until`
    // are two separate atomics, so a transition that touches BOTH (open: Open+long cooldown; closed:
    // Closed+clear cooldown; the Open→HalfOpen probe acquire) is not atomic across the pair on its
    // own. Two such transitions racing (e.g. a half-open probe SUCCESS recovering the cell to Closed
    // while a concurrent hard-down trips it Open with a 30-min sticky cooldown) could interleave their
    // individual stores into an INCONSISTENT pair — a hard-down lane left Open with a cleared/short
    // cooldown (sticky cooldown silently dropped → the dead lane keeps receiving traffic), or Closed
    // with a stale cooldown. Holding this lock across each transition's read-modify-write makes the
    // (state, cooldown) pair move as a unit with a single linearization point, so racing transitions
    // serialize and the last writer's consistent pair always wins. The hot read path
    // (`cell_ready_breaker`/`cell_acquire_breaker` selection) does NOT take this lock — it stays
    // lock-free; only the (comparatively rare) transitions serialize against each other.
    pub(crate) transition_lock: std::sync::Mutex<()>,
}

impl BreakerCell {
    pub(crate) fn new() -> Self {
        Self {
            breaker_state: AtomicU64::new(ST_CLOSED),
            streak: AtomicU32::new(0),
            cooldown_until: AtomicU64::new(0),
            probe_in_flight: AtomicBool::new(false),
            probe_epoch: AtomicU64::new(0),
            err: AtomicU64::new(0),
            outcome_window: std::sync::Mutex::new(OutcomeWindow::new(OUTCOME_WINDOW_CAPACITY)),
            swrr: SwrrStripes::new(),
            transition_lock: std::sync::Mutex::new(()),
        }
    }
}

/// The decoded breaker situation for ONE cell at an instant — the output of the single
/// `breaker_verdict` decoder. Read-only: `ProbeWinnable` reports that a probe COULD be won here,
/// it does not win one (the mutating `cell_acquire_breaker` still owns the CAS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BreakerVerdict {
    /// Closed and any pending soft cooldown has elapsed — admit without a probe.
    Ready,
    /// Suppressed: Open (or Closed still inside a soft cooldown) whose deadline has NOT elapsed.
    Open { until: u64 },
    /// A peer holds the single-flight recovery probe (HalfOpen) — not winnable right now.
    HalfOpen,
    /// Expired-Open — a single-flight recovery probe could be won here (a mutating acquire is needed).
    ProbeWinnable,
}

/// Outcome of the mutating probe-acquisition step ([`HealthState::cell_acquire_breaker`]). The two
/// ADMIT arms are DISTINCT because only one of them actually won a single-flight recovery probe:
/// `ReadyNoProbe` is a Closed-and-ready cell admitted by a pure no-op CAS (it owns NOTHING to
/// release), while `ProbeWon` won the Open→HalfOpen race and carries the owner-token epoch. A caller
/// must build a probe-release guard (or carry a release token) ONLY for `ProbeWon` — an armed guard
/// on a `ReadyNoProbe` admit would, on drop, run an epoch-keyed release against a probe it never won,
/// which (paired with an unowned release, or with the cell's live epoch handed to an armed guard)
/// could revert a peer's genuine in-flight probe. Representing "no probe" as its own variant is what
/// lets the dispatch paths carry `probe_epoch: None` and build no guard at all.
pub(crate) enum ProbeAdmit {
    /// The breaker refused admission (HalfOpen with a peer's probe in flight, a still-cooling Open
    /// cell, or a Closed cell inside a lingering cooldown).
    Denied,
    /// Admitted on a Closed-and-ready cell — a pure no-op CAS that won NO single-flight probe, so
    /// there is nothing to release.
    ReadyNoProbe,
    /// Won the single-flight recovery probe (Open→HalfOpen). Carries the owner-token epoch, captured
    /// under the transition lock before any await (no peer can win a newer probe while the cell is
    /// HalfOpen), for the caller's owner-checked release.
    ProbeWon(u64),
}

/// Read access to the breaker atomics, so the FSM logic can be written once and run against either
/// a `LaneState` (the default cell) or a per-pool `BreakerCell` without duplication.
pub(crate) trait BreakerCellAccess {
    fn breaker_state(&self) -> &AtomicU64;
    fn streak(&self) -> &AtomicU32;
    fn cooldown_until(&self) -> &AtomicU64;
    fn probe_in_flight(&self) -> &AtomicBool;
    /// Monotonic single-flight probe owner token (see `BreakerCell::probe_epoch`).
    fn probe_epoch(&self) -> &AtomicU64;
    fn err(&self) -> &AtomicU64;
    fn outcome_window(&self) -> &std::sync::Mutex<OutcomeWindow>;
    fn swrr(&self) -> &SwrrStripes;
    /// Serializes state+cooldown transitions on this cell (see `BreakerCell::transition_lock`).
    fn transition_lock(&self) -> &std::sync::Mutex<()>;
}

impl BreakerCellAccess for BreakerCell {
    fn breaker_state(&self) -> &AtomicU64 {
        &self.breaker_state
    }
    fn streak(&self) -> &AtomicU32 {
        &self.streak
    }
    fn cooldown_until(&self) -> &AtomicU64 {
        &self.cooldown_until
    }
    fn probe_in_flight(&self) -> &AtomicBool {
        &self.probe_in_flight
    }
    fn probe_epoch(&self) -> &AtomicU64 {
        &self.probe_epoch
    }
    fn err(&self) -> &AtomicU64 {
        &self.err
    }
    fn outcome_window(&self) -> &std::sync::Mutex<OutcomeWindow> {
        &self.outcome_window
    }
    fn swrr(&self) -> &SwrrStripes {
        &self.swrr
    }
    fn transition_lock(&self) -> &std::sync::Mutex<()> {
        &self.transition_lock
    }
}

impl BreakerCellAccess for LaneState {
    fn breaker_state(&self) -> &AtomicU64 {
        &self.breaker_state
    }
    fn streak(&self) -> &AtomicU32 {
        &self.streak
    }
    fn cooldown_until(&self) -> &AtomicU64 {
        &self.cooldown_until
    }
    fn probe_in_flight(&self) -> &AtomicBool {
        &self.probe_in_flight
    }
    fn probe_epoch(&self) -> &AtomicU64 {
        &self.probe_epoch
    }
    fn err(&self) -> &AtomicU64 {
        &self.err
    }
    fn outcome_window(&self) -> &std::sync::Mutex<OutcomeWindow> {
        &self.outcome_window
    }
    fn swrr(&self) -> &SwrrStripes {
        &self.swrr
    }
    fn transition_lock(&self) -> &std::sync::Mutex<()> {
        &self.transition_lock
    }
}

/// Side-effect-FREE readiness check (the breaker portion of `usable`): true if the cell would
/// admit a request right now, WITHOUT mutating any state. Closed honors any pending cooldown; an
/// Open lane whose cooldown has expired is "ready" (a probe could be admitted) but is NOT yet
/// transitioned here; HalfOpen admits nobody but the in-flight probe winner.
///
/// This is the predicate used by the selection filter and by `/healthz` — neither should steal
/// the single-flight recovery probe. The Open→HalfOpen transition + probe CAS is performed
/// exactly once, on the single lane selection actually dispatches, via `cell_acquire_breaker`.
pub(crate) fn cell_ready_breaker(c: &dyn BreakerCellAccess, now: u64) -> bool {
    // Delegate to the single `breaker_verdict` decoder so there is exactly ONE implementation
    // of "would this breaker admit". A cell is ready-to-admit iff a request could proceed WITHOUT
    // losing a race: Closed-and-elapsed (`Ready`) or expired-Open where a probe could be won
    // (`ProbeWinnable`). `Open`/`HalfOpen` are not ready. Behaviour is byte-identical to the prior
    // hand-rolled match (an unexpected encoding still fails SAFE — `breaker_verdict` maps it to
    // `Open`, i.e. not ready — preserving the no-panic-on-request-path invariant).
    matches!(
        breaker_verdict(c, now),
        BreakerVerdict::Ready | BreakerVerdict::ProbeWinnable
    )
}

/// THE single decoder of a cell's breaker situation into [`BreakerVerdict`]. Read-only — no
/// Open→HalfOpen transition, no probe CAS. Every "is the breaker open" question (`cell_ready_breaker`
/// for the selection filter, `classify` for observability, and `try_admit` before its CAS) resolves
/// here, so the notions can never drift. An unexpected state fails SAFE (mapped to `Open`), matching
/// the request-path no-panic invariant.
pub(crate) fn breaker_verdict(c: &dyn BreakerCellAccess, now: u64) -> BreakerVerdict {
    let until = c.cooldown_until().load(Ordering::Acquire);
    match c.breaker_state().load(Ordering::Acquire) {
        ST_CLOSED => {
            if now >= until {
                BreakerVerdict::Ready
            } else {
                // A Closed cell inside a pending soft cooldown is breaker-suppressed until `until`.
                BreakerVerdict::Open { until }
            }
        }
        ST_OPEN => {
            if now >= until {
                BreakerVerdict::ProbeWinnable
            } else {
                BreakerVerdict::Open { until }
            }
        }
        ST_HALF_OPEN => BreakerVerdict::HalfOpen,
        other => {
            // Warn-once latch: this "impossible" (atomic-sentinel invariant) state is on the
            // request path, so an unlatched warn would spam if the invariant ever broke. Warn once
            // per process on first sighting; hold subsequent sightings at debug.
            static WARNED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !WARNED.swap(true, Ordering::Relaxed) {
                diag_warn!(
                    BREAKER_UNEXPECTED_STATE_CLASSIFY,
                    state = other,
                    "unexpected breaker state; treating cell as Open (deny admission)"
                );
            } else {
                diag_debug!(
                    BREAKER_UNEXPECTED_STATE_CLASSIFY,
                    state = other,
                    "unexpected breaker state; treating cell as Open (deny admission)"
                );
            }
            // Fail SAFE: never-elapsing Open so both `classify` and `try_admit` deny admission.
            BreakerVerdict::Open { until: u64::MAX }
        }
    }
}

impl HealthState {
    /// Evaluate trip condition for Closed → Open transition. Returns true if the cell should trip.
    pub(crate) fn should_trip(c: &dyn BreakerCellAccess, now: u64, cfg: &BreakerCfg) -> bool {
        let window = lock_recover(c.outcome_window());

        match cfg.trip.mode {
            TripMode::ErrorRate => {
                // Both numerator and denominator come from the SAME sliding window, so the fraction
                // reflects RECENT health only. (Previously the numerator was the cumulative error
                // counter, which could exceed the windowed count and spuriously trip a long-running
                // lane on clean traffic.)
                let count = window.count_in_window(now, cfg.trip.window_s);
                if count < cfg.trip.min_requests {
                    return false; // Below floor
                }
                let errors = window.error_count_in_window(now, cfg.trip.window_s);
                (errors as f64 / count as f64) >= cfg.trip.threshold
            }
            TripMode::Consecutive => c.streak().load(Ordering::Relaxed) >= cfg.trip.consecutive_n,
        }
    }

    /// Compute escalating cooldown duration with optional Retry-After floor.
    /// If retry_after is Some and honor_retry_after is true, the cooldown is max(computed_backoff, retry_after).
    /// The server's explicit Retry-After is always respected even if it exceeds max_cooldown_secs.
    // NOTE: the honored-`Retry-After` CEILING is threaded in as a parameter (rather than read from
    // `&self`) because this and the `cell_*` helpers below are STATIC (`c: &dyn BreakerCellAccess`,
    // not `&self`) so they can run under the per-cell transition lock without re-borrowing the store.
    // Every caller is an `&self` method that passes `self.max_honored_retry_after_secs`.
    pub(crate) fn compute_cooldown_with_retry_after(
        c: &dyn BreakerCellAccess,
        _now: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
        max_honored_retry_after_secs: u64,
    ) -> u64 {
        let streak = c.streak().load(Ordering::Relaxed);

        // Exponential backoff capped at max_cooldown_secs, computed in O(1) (NOT an O(streak) loop —
        // on a long-running hard-failing lane the streak grows unboundedly and this runs on every
        // failure record, exactly when failure volume is highest). `base * 2^streak` saturates at
        // max after a handful of doublings, so clamp the shift exponent to 63 (a u64 shift of >=64
        // is UB / panics) and saturate the multiply before taking the min.
        let mut duration = if streak == 0 {
            cfg.base_cooldown_secs
        } else {
            // `base * 2^streak`, saturating. NOTE: `checked_shl` only guards the shift COUNT (>= 64),
            // NOT value overflow — `10u64.checked_shl(63)` is `Some(0)` (the high bits shift out), so
            // an even `base_cooldown_secs` at `streak >= 63` WRAPPED TO 0, giving a zero cooldown
            // (tripped cell re-admits instantly) exactly when the lane is failing hardest. Compute in
            // u128 (base < 2^64, shift <= 63 → product < 2^127, no overflow) then saturate to u64.
            let shift = streak.min(63);
            let shifted = (cfg.base_cooldown_secs as u128) << shift;
            u64::try_from(shifted)
                .unwrap_or(u64::MAX)
                .min(cfg.max_cooldown_secs)
        };

        // Add bounded jitter ±10% on EVERY trip, including the `streak == 0` base path. Gating jitter
        // on `streak > 0` left the first-trip / sub-threshold cooldown (the `streak == 0` base,
        // reachable from the sub-threshold cooldown arm and direct `cell_open` callers) un-jittered, so
        // a fleet of lanes tripping together on the same base got the IDENTICAL cooldown → synchronized
        // half-open probes (thundering herd). Hoisting the computation here desyncs the base too; for
        // `streak == 0`, `duration == base_cooldown_secs` and the same `jitter_range = (duration/10)
        // .max(1)` and `[duration/2, max]` clamp apply.
        {
            // Floor the band at >=1s. On tight cooldowns (`duration < 10`) the ±10% range
            // `duration / 10` truncates to 0 → `span == 1` → jitter always 0 → EVERY lane that trips
            // on a small `base_cooldown_secs` gets the identical cooldown, defeating the
            // anti-thundering-herd desync exactly when the herd is densest (many lanes, short retry
            // loop). A 1s band restores a real spread for small bases; for `duration >= 10` this is a
            // no-op (`duration / 10 >= 1`), so larger cooldowns keep the documented ±10%.
            let jitter_range = (duration / 10).max(1);
            #[cfg(test)]
            let time_seed = crate::store::now_for_test() as u128;
            #[cfg(not(test))]
            use std::time::{SystemTime, UNIX_EPOCH};
            #[cfg(not(test))]
            let time_seed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();

            // Decorrelate lanes that fail within nanoseconds of each other (a cascading upstream
            // outage trips them ~simultaneously, so the wall-clock alone is near-identical across
            // them and `% (2*jitter_range+1)` collapses to the same value → synchronized cooldowns →
            // thundering-herd of half-open probes). Mix a per-CELL identity (its stable address) and
            // the current streak into the seed so each lane's jitter is independent regardless of
            // wall-clock proximity. FNV-1a folds the mixed inputs into a well-distributed value.
            let cell_id = c as *const _ as *const () as usize as u128;
            let mut seed = FNV1A_OFFSET_BASIS as u128;
            for part in [time_seed, cell_id, streak as u128] {
                seed = (seed ^ part).wrapping_mul(FNV1A_PRIME as u128);
            }
            let jitter_seed = seed;

            // Signed jitter in [-jitter_range, +jitter_range]; apply its sign so cooldowns are
            // spread both shorter AND longer (desyncing lanes). Using the absolute value here was a
            // bug — it only ever lengthened the cooldown.
            // Reduce the u128 FNV seed into an UNSIGNED bounded value BEFORE centering. Casting the
            // seed `as i64` first (the old bug) reinterprets the low 64 bits as signed — frequently
            // negative — and Rust's truncated `%` then yields a value in (-2r, +2r), so subtracting
            // `r` skewed the final jitter to roughly (-3r, +r) instead of the documented symmetric
            // [-r, +r]. Taking `% span` on the unsigned u128 keeps the remainder in [0, 2r], so the
            // centered result is exactly [-r, +r].
            let span = 2 * jitter_range as u128 + 1;
            let unbiased = (jitter_seed % span) as i64;
            let jitter = unbiased - jitter_range as i64;
            let jittered = if jitter >= 0 {
                duration.saturating_add(jitter as u64)
            } else {
                duration.saturating_sub(jitter.unsigned_abs())
            };
            duration = jittered.clamp(
                // At least half of base, but NEVER below 1s. For `base_cooldown_secs = 1` (the
                // minimum config_validate permits) the integer floor `1/2` truncates to 0, and a
                // −1 jitter draw (~1/3 of trips) then produced a ZERO cooldown — the tripped cell
                // re-admits instantly (`now >= cooldown_until`), the exact zero-backoff outcome the
                // validator rejects a static `base_cooldown_secs = 0` to prevent.
                (duration / 2).max(1),
                cfg.max_cooldown_secs,
            );
        }

        // Honor Retry-After as cooldown floor if present and configured. Exhaustive on the bool —
        // no `_` wildcard (breaker-match hard rule). When honoring, the server's explicit
        // Retry-After is a FLOOR (max with the computed backoff), respected even past the configured
        // `max_cooldown_secs` cap (a legit upstream hint may exceed it) — BUT clamped to an absolute
        // ceiling so a hostile/buggy upstream cannot drive the cooldown to near `u64::MAX`
        // (`Retry-After: 18446744073709551615`): that would overflow `now + duration` downstream
        // (breaker bypass in release, panic in debug) or park a lane out for millennia. When NOT
        // honoring, the server value is ignored entirely and the computed backoff stands (returning
        // `ra` verbatim there could SHORTEN the cooldown below the backoff floor).
        match (cfg.honor_retry_after, retry_after) {
            (true, Some(ra)) => duration.max(ra.min(max_honored_retry_after_secs)),
            (false, Some(_)) => duration,
            (true, None) | (false, None) => duration,
        }
    }

    /// Transition the cell to Open with an escalated cooldown (streak is owned by the record path,
    /// only read here). Acquires the per-cell transition lock so the Open state + cooldown move as a
    /// consistent pair against any racing transition; see `cell_open_locked`. Release code reaches
    /// the trip via `cell_open_locked` (already holding the lock), so only the test helpers call this
    /// lock-acquiring wrapper — hence release-dead.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn cell_open(
        c: &dyn BreakerCellAccess,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
        max_honored_retry_after_secs: u64,
    ) {
        let _tx = lock_recover(c.transition_lock());
        Self::cell_open_locked(c, now_time, cfg, retry_after, max_honored_retry_after_secs);
    }

    /// `cell_open` body, assuming the caller already holds `c.transition_lock()`. Used by the record
    /// paths that take the lock once and may then call `cell_open` under it (re-taking the std Mutex
    /// would deadlock), so they call this instead.
    pub(crate) fn cell_open_locked(
        c: &dyn BreakerCellAccess,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
        max_honored_retry_after_secs: u64,
    ) {
        let duration = Self::compute_cooldown_with_retry_after(
            c,
            now_time,
            cfg,
            retry_after,
            max_honored_retry_after_secs,
        );
        // saturating_add: `duration` can be a server-supplied Retry-After (clamped in
        // compute_cooldown_with_retry_after, but defense-in-depth) — never wrap `now + duration`,
        // which in release would land `cooldown_until` in the past and instantly re-ready a tripped
        // lane (breaker bypass), and in debug would panic on the request path.
        c.cooldown_until()
            .store(now_time.saturating_add(duration), Ordering::Release);
        c.breaker_state().store(ST_OPEN, Ordering::Release);
        // Opening releases the single-flight probe back to Open. A failed half-open probe routes
        // here (ST_HALF_OPEN → cell_open); without this reset the flag stayed `true` forever, so the
        // next cooldown expiry transitioned the cell to HalfOpen but no request could ever win the
        // probe CAS — the lane was benched permanently. Clearing it lets the next cooldown re-probe.
        c.probe_in_flight().store(false, Ordering::Release);
    }

    /// Transition the cell to Closed (full recovery): reset streak/window, clear the cooldown
    /// and release the single-flight probe. Acquires the per-cell transition lock so the Closed state
    /// and cleared cooldown move as a consistent pair against any racing transition (see
    /// `cell_closed_locked`).
    ///
    /// NOTE: this does NOT reset the cell's SWRR `current_weight`. That reset must run under the
    /// per-pool SWRR shard lock (which serializes selection and owns the `Σ current_weight == 0`
    /// invariant), and only the CALLER knows the pool the cell belongs to. Callers perform the reset
    /// via `reset_swrr_for(pool, cell)` AFTER this returns — a single generation bump on the cell's
    /// striped accumulator (see `SwrrStripes`), lock-free, so no ordering constraint against
    /// selection remains.
    ///
    /// Test-only: the production recovery path (`recover_lane`) now closes cells through
    /// `cell_closed_if_recoverable` (which re-validates suppression under the lock); the only
    /// remaining caller of this unconditional close is the `closed_state` test handle.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn cell_closed(c: &dyn BreakerCellAccess) {
        let _tx = lock_recover(c.transition_lock());
        Self::cell_closed_locked(c);
    }

    /// Recovery close for `recover_lane`: close a cell whose suppression the probe is entitled to
    /// clear, re-validating UNDER the transition lock that no concurrent transition has re-armed the
    /// cell since the probe snapshotted it. Returns true iff the cell was actually closed.
    ///
    /// `observed_cooldown` is the `cooldown_until` value the lock-free pre-filter read for this cell.
    /// A successful 2xx probe is authoritative for the upstream state it OBSERVED, so it may clear the
    /// trip/cooldown it saw — but it must NOT clobber a STRICTER suppression a peer armed in the
    /// meantime. The race this closes: between the pre-filter read and the close, a
    /// concurrent `record_hard_down_all_cells` / `cell_record_failure` parks the cell Open with a
    /// FRESH sticky cooldown (`now_hd + HARD_DOWN_COOLDOWN_SECS`, strictly later than anything the
    /// probe saw). An unconditional close would drop that just-armed cooldown and recover a lane the
    /// hard-down meant to keep suppressed.
    ///
    /// Discipline (mirrors `cell_record_success`'s CAS-under-lock): take the transition lock once —
    /// the SAME lock every trip/close uses, so this serializes against them — then re-read the
    /// cooldown. If it now extends BEYOND what the probe observed (`> observed_cooldown`), a peer
    /// re-armed a stricter suppression after the snapshot; leave the cell untouched. Otherwise (cell
    /// still non-Closed, OR a cooldown no later than observed) the probe's clearance still applies and
    /// we close. A future cooldown the probe ITSELF saw (`<= observed_cooldown`) is still cleared —
    /// that is the legitimate recovery of a tripped lane.
    pub(crate) fn cell_closed_if_recoverable(
        c: &dyn BreakerCellAccess,
        now: u64,
        observed_cooldown: u64,
    ) -> bool {
        let _tx = lock_recover(c.transition_lock());
        // A peer armed a stricter cooldown than the probe observed → its suppression is newer than the
        // probe's clearance; do not clobber it.
        if c.cooldown_until().load(Ordering::Acquire) > observed_cooldown {
            return false;
        }
        // Still suppressed (tripped breaker OR a cooldown still in the FUTURE relative to the caller's
        // `now` snapshot) → the probe clears it. An already-expired (past) nonzero `cooldown_until` on
        // a Closed cell is NOT a suppression — recovery already lapsed — so `> now`, not `> 0`, avoids
        // a spurious close + SWRR reset on an already-recovered lane.
        let suppressed = c.breaker_state().load(Ordering::Acquire) != ST_CLOSED
            || c.cooldown_until().load(Ordering::Acquire) > now;
        if suppressed {
            Self::cell_closed_locked(c);
        }
        suppressed
    }

    /// `cell_closed` body, assuming the caller already holds `c.transition_lock()`. Does NOT touch
    /// `current_weight` — see `cell_closed` and `reset_swrr_for` for why the SWRR reset is the
    /// caller's job (it must hold the per-pool shard lock).
    pub(crate) fn cell_closed_locked(c: &dyn BreakerCellAccess) {
        c.streak().store(0, Ordering::Release);
        // Do NOT zero `c.err()` here. For the default cell `c.err()` IS the PUBLIC `/stats`
        // lifetime `LaneState.err` counter, which must stay monotonic (like `LaneState.ok`).
        // The breaker FSM never reads `err()` — `should_trip` keys off `outcome_window` + `streak`
        // — so this zeroing was dead for recovery health yet corrupted the stats counter, making
        // `LaneState.err` non-monotonic on every default-cell recovery. Recovery health
        // is fully reset by the `streak`/`outcome_window`/`cooldown`/`state` stores below.
        lock_recover(c.outcome_window()).clear();
        c.cooldown_until().store(0, Ordering::Release);
        c.breaker_state().store(ST_CLOSED, Ordering::Release);
        c.probe_in_flight().store(false, Ordering::Release);
    }

    /// Release an UNDISPATCHED single-flight probe: a probe winner (HalfOpen + `probe_in_flight ==
    /// true`) that abandoned the dispatch before recording any outcome. Revert the cell to Open and
    /// clear the probe flag WITHOUT escalating the cooldown — the existing cooldown is already expired
    /// (that is why the cell was probe-eligible), so leaving it intact lets the next request re-win the
    /// probe immediately. Only acts when the cell is still HalfOpen (a concurrent success/failure may
    /// have already moved it); otherwise it just clears the flag defensively. The mirror of the
    /// `cell_open` probe-release, but for the no-outcome abandon path rather than a recorded failure.
    // Reached only via the (now production-unused) `release_probe_in`; the dispatch paths cover their
    // won probe with an owner-checked `ProbeGuard` instead. Retained for the store regression tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn cell_release_probe(c: &dyn BreakerCellAccess) {
        // Serialize against other transitions: this leaves the existing (expired) cooldown intact and
        // only reverts the state HalfOpen → Open, but it must not interleave with a concurrent
        // open/close/trip that is mid-way through its own (state, cooldown) pair.
        let _tx = lock_recover(c.transition_lock());
        // CAS the state HalfOpen → Open so we don't clobber a concurrent transition (e.g. a success
        // that already moved the cell to Closed). The probe flag is cleared regardless so a stale
        // `true` can never wedge the lane.
        let _ = c.breaker_state().compare_exchange(
            ST_HALF_OPEN,
            ST_OPEN,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        c.probe_in_flight().store(false, Ordering::Release);
    }

    /// OWNER-CHECKED probe release: the same revert as [`cell_release_probe`], but a strict NO-OP
    /// unless `owned_epoch` still equals the cell's current `probe_epoch`. This closes a stalled-
    /// release duplication: a `ProbeGuard` can outlive its acquisition across the
    /// permit-wait await, so it may drop LATE - after the cell already recorded an outcome (advancing
    /// past the probe) and a NEW probe was won (bumping the epoch). The un-owned `cell_release_probe`
    /// would then CAS the FRESH winner's HalfOpen back to Open and clear its `probe_in_flight`, letting
    /// a third caller win a duplicate concurrent probe on an already-probing lane. Checking the epoch
    /// under the transition lock - the epoch is bumped under the same lock in `cell_acquire_breaker` -
    /// makes a late release affect only the probe it actually won, and nothing once that probe is gone.
    pub(crate) fn cell_release_probe_owned(c: &dyn BreakerCellAccess, owned_epoch: u64) {
        let _tx = lock_recover(c.transition_lock());
        // Not (still) the owner: the probe we won has already been consumed/superseded. Do nothing -
        // reverting here would clobber whatever transition or newer probe now holds the cell.
        if c.probe_epoch().load(Ordering::Acquire) != owned_epoch {
            return;
        }
        let _ = c.breaker_state().compare_exchange(
            ST_HALF_OPEN,
            ST_OPEN,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        c.probe_in_flight().store(false, Ordering::Release);
    }

    /// The mutating probe-acquisition step, run ONLY on the single lane a dispatch path actually
    /// chose. Closed honors any pending cooldown; an expired-cooldown Open lane transitions to
    /// HalfOpen and admits exactly one probe (CAS); HalfOpen admits nobody else. Returns
    /// [`ProbeAdmit`]: `ReadyNoProbe` (Closed-and-ready, won no probe), `ProbeWon(epoch)` (the probe
    /// winner), or `Denied`.
    pub(crate) fn cell_acquire_breaker(c: &dyn BreakerCellAccess, now: u64) -> ProbeAdmit {
        // Fast lock-free pre-check: only an Open cell whose cooldown has expired needs the mutating
        // Open→HalfOpen probe-acquisition (which must serialize against trips/closes). Closed and
        // HalfOpen, and a not-yet-expired Open, are decided by a plain consistent read with no lock —
        // keeping the common dispatch case lock-free. We re-confirm the state under the lock below.
        match c.breaker_state().load(Ordering::Acquire) {
            ST_CLOSED => {
                // Closed-and-ready admits WITHOUT winning any probe (a pure no-op — no CAS, no epoch
                // bump, no `probe_in_flight`): there is nothing to release, so callers carry `None`.
                if now >= c.cooldown_until().load(Ordering::Acquire) {
                    ProbeAdmit::ReadyNoProbe
                } else {
                    ProbeAdmit::Denied
                }
            }
            ST_OPEN => {
                let until = c.cooldown_until().load(Ordering::Acquire);
                if now >= until {
                    // The Open→HalfOpen probe acquisition reads BOTH state and cooldown and must move
                    // as an atomic pair against a concurrent trip/close (which writes both). Take the
                    // transition lock so a hard-down parking the cell Open with a fresh sticky
                    // cooldown can't interleave with this acquisition and let a probe slip through on
                    // a just-parked lane. Re-read under the lock: a peer transition may have changed
                    // the state or re-armed the cooldown since the lock-free check above.
                    let _tx = lock_recover(c.transition_lock());
                    if c.breaker_state().load(Ordering::Acquire) != ST_OPEN
                        || now < c.cooldown_until().load(Ordering::Acquire)
                    {
                        return ProbeAdmit::Denied;
                    }
                    // Single CAS Open→HalfOpen under the lock: the state and probe acquisition move as
                    // an atomic pair. A non-CAS `store(ST_HALF_OPEN)` followed by a separate
                    // `probe_in_flight` CAS opens a window where a delayed store can clobber a
                    // concurrent `cell_closed` (which writes ST_CLOSED + clears the probe flag),
                    // leaving a Closed cell with probe_in_flight wedged true and permanently
                    // benching the lane. Only the thread that wins this CAS owns the cell's
                    // single-flight probe; losers observed the transition already happened and
                    // must treat the probe as taken.
                    if c.breaker_state()
                        .compare_exchange(
                            ST_OPEN,
                            ST_HALF_OPEN,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        // Won the single-flight probe: bump the owner-token epoch BEFORE publishing the
                        // in-flight flag. The winner will read `probe_epoch` (synchronously, before any
                        // await - the cell is HalfOpen so no peer can win a new probe in between) and
                        // pass it to `cell_release_probe_owned`, which reverts ONLY on an epoch match.
                        // Bumping under the transition lock keeps it paired with the state store.
                        c.probe_epoch().fetch_add(1, Ordering::AcqRel);
                        c.probe_in_flight().store(true, Ordering::Release);
                        // Capture the owner token synchronously, still under the transition lock: no
                        // peer can win a newer probe while the cell is HalfOpen, so this is the exact
                        // epoch a later owner-checked release must match. (Byte-identical to the old
                        // `probe_epoch().load()` the callers ran immediately after this returned.)
                        ProbeAdmit::ProbeWon(c.probe_epoch().load(Ordering::Acquire))
                    } else {
                        ProbeAdmit::Denied
                    }
                } else {
                    ProbeAdmit::Denied
                }
            }
            ST_HALF_OPEN => ProbeAdmit::Denied,
            // Request-path probe acquisition: fail SAFE (admit nobody) on an unexpected state rather
            // than `unreachable!()`-panicking the dispatching task. Not reachable under today's
            // atomic-sentinel invariant; this only guards a future/corrupt encoding gracefully.
            other => {
                // Warn-once latch (request path; impossible under the atomic-sentinel invariant).
                static WARNED: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                if !WARNED.swap(true, Ordering::Relaxed) {
                    diag_warn!(
                        BREAKER_UNEXPECTED_STATE_PROBE,
                        state = other,
                        "unexpected breaker state; refusing probe acquisition"
                    );
                } else {
                    diag_debug!(
                        BREAKER_UNEXPECTED_STATE_PROBE,
                        state = other,
                        "unexpected breaker state; refusing probe acquisition"
                    );
                }
                ProbeAdmit::Denied
            }
        }
    }

    /// Query the cell's breaker state (does NOT account for lane-global `dead`/budget).
    #[cfg_attr(not(test), allow(dead_code))] // reached only via the test-exercised `breaker_state`
    pub(crate) fn cell_breaker_state(c: &dyn BreakerCellAccess) -> BreakerState {
        match c.breaker_state().load(Ordering::Acquire) {
            ST_CLOSED => BreakerState::Closed,
            ST_OPEN => BreakerState::Open {
                until: c.cooldown_until().load(Ordering::Acquire),
            },
            ST_HALF_OPEN => BreakerState::HalfOpen,
            // Not reachable under the atomic-sentinel invariant; report the benign Closed default
            // rather than panic, keeping this read total and side-effect-free for any encoding.
            other => {
                // Warn-once latch (total, side-effect-free read; impossible under the invariant).
                static WARNED: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                if !WARNED.swap(true, Ordering::Relaxed) {
                    diag_warn!(
                        BREAKER_UNEXPECTED_STATE_READ,
                        state = other,
                        "unexpected breaker state; reporting Closed"
                    );
                } else {
                    diag_debug!(
                        BREAKER_UNEXPECTED_STATE_READ,
                        state = other,
                        "unexpected breaker state; reporting Closed"
                    );
                }
                BreakerState::Closed
            }
        }
    }

    /// Record a failure (transient or rate-limit — identical breaker handling) against the cell:
    /// push the outcome, bump err + consecutive streak, then trip-or-cooldown per the config.
    ///
    /// RETURNS `true` IFF this failure drove a logical Closed→Open trip (a threshold breach that
    /// transitioned the cell from Closed to Open). A HalfOpen→Open reopen (a failed recovery probe)
    /// is NOT counted as a fresh trip — the lane was already tripped and is merely re-arming its
    /// cooldown — nor is an already-Open no-op. The caller emits `BREAKER_TRIPS_TOTAL` once per
    /// `true`, so the counter reflects logical trips, not per-cell or per-cooldown-bump events.
    pub(crate) fn cell_record_failure(
        c: &dyn BreakerCellAccess,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
        max_honored_retry_after_secs: u64,
    ) -> bool {
        lock_recover(c.outcome_window()).push(now_time, true); // error outcome
        c.err().fetch_add(1, Ordering::Relaxed);

        // The state-dependent transition reads BOTH state and cooldown and writes the (state,
        // cooldown) pair, so serialize it under the transition lock (re-reading the state under the
        // lock) — a concurrent close/trip must not interleave its pair with this one. The order-
        // insensitive `err()` bump and outcome_window push above are independent of the streak and
        // need no lock. `should_trip` (which also locks the outcome_window) and the inner
        // `cell_open_locked` run UNDER this lock; we call the `_locked` open variant so we never
        // re-take this std Mutex (which would deadlock).
        let _tx = lock_recover(c.transition_lock());
        // Bump the consecutive-failure streak UNDER the transition lock (was previously an
        // unconditional fetch_add outside it). `should_trip` (Consecutive mode) and
        // `compute_cooldown_with_retry_after` both read the streak under THIS lock; bumping it
        // outside let concurrent failures over-count the streak before the trip/cooldown read,
        // inflating the first-trip escalation/cooldown level. Serializing the bump with the
        // should_trip/compute_cooldown read makes the escalation level reflect the serialized
        // consecutive-failure count.
        //
        // The bump is NOT unconditional: it runs ONLY in the ST_CLOSED and ST_HALF_OPEN arms — the two
        // that READ/ACT on the streak (Closed's `should_trip`/`compute_cooldown`, HalfOpen's reopen
        // escalation). The ST_OPEN arm is a true no-op on the streak: an out-of-band probe failure
        // against an already-Open cell must NOT advance the consecutive count, or a later HalfOpen
        // re-trip computes an over-long cooldown (pinned at max) off an inflated streak.
        match c.breaker_state().load(Ordering::Acquire) {
            ST_CLOSED => {
                // Bump BEFORE `should_trip` — Consecutive mode reads the streak.
                c.streak().fetch_add(1, Ordering::Relaxed);
                if Self::should_trip(c, now_time, cfg) {
                    Self::cell_open_locked(
                        c,
                        now_time,
                        cfg,
                        retry_after,
                        max_honored_retry_after_secs,
                    );
                    // A genuine Closed→Open trip — the only path that should mint a BREAKER_TRIPS_TOTAL.
                    true
                } else if !cfg.bench_below_trip_threshold {
                    // NO WALK TO PREFER ANOTHER MEMBER, SO NOTHING TO PREFER IT TO — see
                    // `BreakerCfg::bench_below_trip_threshold`. On a degenerate single-member cell
                    // the store below is not a routing hint, it is a REFUSAL of the caller, and a
                    // sub-threshold failure has not earned one: the cell is still Closed and
                    // `should_trip` just said so.
                    //
                    // An upstream that ASKED to be left alone is a different fact, and it is still
                    // honoured — but for exactly as long as it asked for, not for the escalating
                    // backoff a real trip earns. That ceiling is `max_honored_retry_after_secs`,
                    // the same one `compute_cooldown_with_retry_after` applies.
                    if cfg.honor_retry_after {
                        if let Some(asked) = retry_after {
                            c.cooldown_until().store(
                                now_time.saturating_add(asked.min(max_honored_retry_after_secs)),
                                Ordering::Release,
                            );
                        }
                    }
                    false
                } else {
                    let duration = Self::compute_cooldown_with_retry_after(
                        c,
                        now_time,
                        cfg,
                        retry_after,
                        max_honored_retry_after_secs,
                    );
                    // saturating_add: see cell_open — never wrap `now + duration` (breaker-bypass /
                    // debug-panic on a hostile upstream's unbounded Retry-After).
                    c.cooldown_until()
                        .store(now_time.saturating_add(duration), Ordering::Release);
                    false
                }
            }
            // probe failed → reopen: the lane was already tripped (Open) and won the half-open probe;
            // reopening it re-arms the cooldown but is NOT a fresh Closed→Open trip, so do NOT count it.
            ST_HALF_OPEN => {
                // The probe lane reopened: bump the streak so the reopen escalates off the real
                // consecutive count (`cell_open_locked` → `compute_cooldown_with_retry_after` reads it).
                c.streak().fetch_add(1, Ordering::Relaxed);
                Self::cell_open_locked(c, now_time, cfg, retry_after, max_honored_retry_after_secs);
                false
            }
            // Already Open: a failure while Open is an intentional no-op (the cooldown is already
            // armed; we don't re-escalate on every failed request during a cooldown). Enumerated
            // explicitly per the breaker-match hard rule — no `_ =>` catch-all.
            ST_OPEN => false,
            // Request-path failure recording: an unexpected state encoding is treated as a no-op
            // (like the already-Open case) rather than `unreachable!()`-panicking the task. Not
            // reachable under the atomic-sentinel invariant; this is the graceful backstop.
            other => {
                // Warn-once latch (request path; impossible under the atomic-sentinel invariant).
                static WARNED: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                if !WARNED.swap(true, Ordering::Relaxed) {
                    diag_warn!(
                        BREAKER_UNEXPECTED_STATE_RECORD_FAILURE,
                        state = other,
                        "unexpected breaker state in record_failure; no-op"
                    );
                } else {
                    diag_debug!(
                        BREAKER_UNEXPECTED_STATE_RECORD_FAILURE,
                        state = other,
                        "unexpected breaker state in record_failure; no-op"
                    );
                }
                false
            }
        }
    }

    /// Record a success against the cell: reset the streak (unless the cell is Open — see below),
    /// push the outcome, and — if this was the half-open probe — complete recovery to Closed. (The
    /// lane-global `ok` counter is bumped by the caller, since it is shared across pools.)
    ///
    /// Returns `true` iff this call won the HalfOpen→Closed recovery CAS (i.e. it actually closed the
    /// cell). The caller uses that to perform the SWRR `current_weight` reset under the pool's shard
    /// bump (`reset_swrr_for`) — the reset is NOT done here because only the CALLER knows which
    /// pool's cell this is; the generational bump itself is lock-free (see `SwrrStripes`).
    pub(crate) fn cell_record_success(c: &dyn BreakerCellAccess, now_time: u64) -> bool {
        // FAST PATH — the overwhelmingly common success shape: a Closed cell with no failure
        // streak. Nothing state-dependent remains to do (the streak reset below is a no-op at 0,
        // and the HalfOpen→Closed CAS cannot apply to a Closed cell), so skip the transition lock
        // and record only the outcome. A transition racing these two Acquire loads linearizes
        // this success BEFORE itself — a valid ordering the old lock also permitted (it decided
        // the same race by arrival order), and one no observer can distinguish: the outcome
        // timestamp is second-resolution, and a failure landing concurrently keeps its streak
        // bump either way. Any other shape (streak in progress, HalfOpen recovery, Open) takes
        // the full locked path below, byte-identical to before.
        if c.breaker_state().load(Ordering::Acquire) == ST_CLOSED
            && c.streak().load(Ordering::Acquire) == 0
        {
            lock_recover(c.outcome_window()).push(now_time, false); // success outcome
            return false;
        }
        // Serialize the whole state-dependent transition (the streak-reset gate reads the state, and
        // the HalfOpen→Closed recovery writes the (state, cooldown) pair) under the transition lock,
        // so a concurrent hard-down trip (Open + sticky cooldown) can't interleave its pair with this
        // recovery — the exact race this lock closes. `cell_closed` is reached via `cell_closed_locked`
        // below so we never re-take this std Mutex (deadlock). The outcome_window push is a leaf lock
        // taken under this one (consistent ordering, no other path takes them in the reverse order).
        let _tx = lock_recover(c.transition_lock());
        // Reset the consecutive-failure streak on a success — but NOT while the cell is Open. A bare
        // `record_success(lane)` can land on an Open cell via the degraded-forward path
        // (proxy engine `record_success` on a lane whose cell is still Open): the HalfOpen→Closed CAS
        // below then fails (Open ≠ HalfOpen) so no recovery occurs, yet an unconditional reset would
        // already have wiped the streak. In Consecutive mode the streak drives the escalating
        // backoff cooldown (`compute_cooldown_with_retry_after`); zeroing it on a still-Open cell
        // resets that escalation, letting a persistently-failing upstream be re-probed more
        // aggressively than designed. So only reset when the cell is NOT Open — the Closed happy path
        // resets here, and the HalfOpen→Closed recovery resets again via `cell_closed` below (which
        // also zeroes the streak), keeping the recovered cell's memory clean.
        if c.breaker_state().load(Ordering::Acquire) != ST_OPEN {
            c.streak().store(0, Ordering::Release);
        }
        lock_recover(c.outcome_window()).push(now_time, false); // success outcome
                                                                // CAS HalfOpen → Closed rather than a plain load-then-act. A non-atomic
                                                                // `load(HalfOpen) … store(Closed)` opens a TOCTOU window: a concurrent
                                                                // `record_hard_down_all_cells` / `record_probe_failure_all_cells` can move the cell
                                                                // HalfOpen → Open (re-arming the sticky cooldown) between the read and the write, and the
                                                                // unconditional `cell_closed` store would then silently recover a lane the hard-down just
                                                                // parked — bypassing the cooldown and dropping the hard-down entirely. Only the thread that
                                                                // wins this CAS owns the HalfOpen → Closed recovery; if the cell is no longer HalfOpen
                                                                // (already Open, or already Closed by a peer), we record the success outcome but leave the
                                                                // state transition to whoever owns it. Mirrors the CAS pattern in `cell_acquire_breaker`
                                                                // (Open → HalfOpen) and `cell_release_probe` (HalfOpen → Open).
        if c.breaker_state()
            .compare_exchange(ST_HALF_OPEN, ST_CLOSED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            Self::cell_closed_locked(c);
            return true;
        }
        false
    }
}
