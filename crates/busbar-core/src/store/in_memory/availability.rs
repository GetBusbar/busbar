use super::*;

use crate::diagnostics::{diag_warn, LANE_HARD_DOWN_ALL_CELLS};

impl HealthState {
    /// Aggregate the per-cell [`breaker_verdict`](breaker_verdict) (the SINGLE decoder)
    /// across the cells production actually routes through — the SAME cell-selection rule as
    /// [`lane_usable_any_cell`](Self::lane_usable_any_cell): the per-pool cells if the lane has any,
    /// else the lane-default cell — into ONE lane-global verdict. "Best" wins so the aggregate matches
    /// `usable` (any admitting cell ⇒ the lane can serve): `Ready` beats `ProbeWinnable` beats
    /// `HalfOpen` beats `Open`; among `Open` cells the SOONEST recovery deadline is kept (when the lane
    /// could next serve). Read-only — no probe CAS, no Open→HalfOpen transition. There is exactly one
    /// breaker decoder, so this can never drift from the per-(pool, lane) `classify`/`try_admit`.
    fn lane_breaker_verdict(&self, lane: usize, now: u64) -> BreakerVerdict {
        // Priority-fold two verdicts, keeping the more-available (and, among Opens, the sooner).
        fn better(a: BreakerVerdict, b: BreakerVerdict) -> BreakerVerdict {
            fn rank(v: BreakerVerdict) -> u8 {
                match v {
                    BreakerVerdict::Ready => 3,
                    BreakerVerdict::ProbeWinnable => 2,
                    BreakerVerdict::HalfOpen => 1,
                    BreakerVerdict::Open { .. } => 0,
                }
            }
            match (a, b) {
                (BreakerVerdict::Open { until: ua }, BreakerVerdict::Open { until: ub }) => {
                    BreakerVerdict::Open { until: ua.min(ub) }
                }
                _ if rank(a) >= rank(b) => a,
                _ => b,
            }
        }
        let cells = read_recover(&self.pool_cells);
        match cells.get(&lane) {
            Some(per_lane) if !per_lane.is_empty() => per_lane
                .iter()
                .map(|(_, c)| breaker_verdict(c.as_ref(), now))
                .reduce(better)
                .unwrap_or(BreakerVerdict::Ready),
            // Direct/ad-hoc-only lane (no per-pool cells): the default cell IS the routed cell.
            _ => breaker_verdict(self.get_lane(lane).as_ref(), now),
        }
    }

    /// READ-ONLY lane-GLOBAL classification over the shared [`Unavailable`] taxonomy — the `/stats`
    /// (per-lane, pool-agnostic) analogue of the per-(pool, lane) [`classify`](LaneRuntime::classify).
    /// Same lane-global gates read SEPARATELY (`Dead` vs `BudgetExhausted`), the SAME
    /// `breaker_verdict` decoder aggregated across routed cells via
    /// [`lane_breaker_verdict`](Self::lane_breaker_verdict), then the SAME lane-global permit peek —
    /// so the `/stats` availability can never drift from the routing verdict. Side-effect-free.
    /// Breaker-first: an Open-and-at-capacity lane returns `BreakerOpen` (the orthogonal
    /// `at_capacity`/`breaker_state` snapshot fields keep each axis independently legible).
    // Retained as the direct (verdict-computing) entry point exercised by the store tests as the
    // canonical statement of the lane-global taxonomy; `snapshot` uses the `_from_verdict` arm to avoid
    // a second fold, so this has no non-test caller.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn classify_lane(&self, lane: usize, now: u64) -> Result<(), Unavailable> {
        self.classify_lane_from_verdict(lane, self.lane_breaker_verdict(lane, now))
    }

    /// [`classify_lane`](Self::classify_lane) with a PRE-COMPUTED breaker verdict. `snapshot` derives
    /// both the availability and the breaker-state axes from ONE `lane_breaker_verdict` call (an RwLock
    /// read + per-cell fold) rather than folding it twice; this arm carries the verdict in. The
    /// dead/budget/permit reads are cheap atomics, so recomputing them per axis costs nothing.
    fn classify_lane_from_verdict(
        &self,
        lane: usize,
        verdict: BreakerVerdict,
    ) -> Result<(), Unavailable> {
        let ls = self.get_lane(lane);
        if ls.dead.load(Ordering::Relaxed) {
            return Err(Unavailable::Dead);
        }
        if ls.limited && ls.budget.load(Ordering::Relaxed) <= 0 {
            return Err(Unavailable::BudgetExhausted);
        }
        match verdict {
            BreakerVerdict::Open { until } => return Err(Unavailable::BreakerOpen { until }),
            BreakerVerdict::HalfOpen => return Err(Unavailable::ProbeInFlight),
            BreakerVerdict::Ready | BreakerVerdict::ProbeWinnable => {}
        }
        // Permits are lane-global (shared across pools). `available_permits` reports an effectively-
        // unbounded count for an unbounded lane, so `== 0` is only ever a bounded lane at its cap.
        if self.available_permits(lane) == 0 {
            Err(Unavailable::AtCapacity {
                drain_hint_ms: None,
            })
        } else {
            Ok(())
        }
    }

    /// Lane-GLOBAL aggregate breaker FSM state for `/stats`, mapped from
    /// [`lane_breaker_verdict`](Self::lane_breaker_verdict) so it shares the ONE decoder. A dead lane
    /// reports `Open { until: u64::MAX }` (matching `breaker_state_for`). An expired-Open cell maps to
    /// `Open` (its cooldown deadline is in the past) even though it would win a probe — the RAW FSM
    /// state, so an operator sees `open` alongside `at_capacity` for the wedge case.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn lane_breaker_state(&self, lane: usize, now: u64) -> BreakerState {
        self.lane_breaker_state_from_verdict(lane, self.lane_breaker_verdict(lane, now), now)
    }

    /// [`lane_breaker_state`](Self::lane_breaker_state) with a PRE-COMPUTED breaker verdict — the
    /// breaker-state twin of [`classify_lane_from_verdict`](Self::classify_lane_from_verdict), so
    /// `snapshot` derives both axes from a SINGLE `lane_breaker_verdict` fold.
    fn lane_breaker_state_from_verdict(
        &self,
        lane: usize,
        verdict: BreakerVerdict,
        now: u64,
    ) -> BreakerState {
        if self.get_lane(lane).dead.load(Ordering::Relaxed) {
            return BreakerState::Open { until: u64::MAX };
        }
        match verdict {
            BreakerVerdict::Ready => BreakerState::Closed,
            BreakerVerdict::HalfOpen => BreakerState::HalfOpen,
            // Expired-Open (`ProbeWinnable`) is still FSM-Open until a probe actually closes it; its
            // cooldown deadline has already elapsed, so report `until = now`.
            BreakerVerdict::ProbeWinnable => BreakerState::Open { until: now },
            BreakerVerdict::Open { until } => BreakerState::Open { until },
        }
    }
}

impl LaneRuntime for HealthState {
    #[cfg(test)]
    fn usable(&self, lane: usize, now: u64) -> bool {
        self.usable_for("", lane, now)
    }

    fn usable_in(&self, pool: &str, lane: usize, now: u64) -> bool {
        self.usable_for(pool, lane, now)
    }

    #[cfg(test)]
    fn is_ready(&self, lane: usize, now: u64) -> bool {
        self.ready_for("", lane, now)
    }

    fn is_ready_any_cell(&self, lane: usize, now: u64) -> bool {
        self.lane_usable_any_cell(lane, now)
    }

    fn ready_in(&self, pool: &str, lane: usize, now: u64) -> bool {
        // Read-only, pool-aware health peek — the EXACT predicate `select_weighted_in` uses to filter
        // its healthy candidate set (lane-admissible + non-mutating `cell_ready_breaker`), exposed for
        // the routing-policy ordered walk. Never the probe-stealing `usable`.
        self.ready_for(pool, lane, now)
    }

    fn available_permits(&self, lane: usize) -> usize {
        // Read-only snapshot of free concurrency permits — racy by nature (a ranking hint).
        self.get_lane(lane).sem.available_permits()
    }

    fn lane_admissible(&self, lane: usize) -> bool {
        HealthState::lane_admissible(self, lane)
    }

    fn lane_budget_remaining(&self, lane: usize) -> Option<i64> {
        let ls = self.get_lane(lane);
        if ls.limited {
            Some(ls.budget.load(Ordering::Relaxed))
        } else {
            None // unlimited / unmetered
        }
    }

    fn lane_latency_ms(&self, lane: usize) -> Option<f64> {
        // `0` bits is the "no sample yet" sentinel (a real latency EWMA is strictly positive).
        let bits = self
            .get_lane(lane)
            .latency_ewma_bits
            .load(Ordering::Relaxed);
        if bits == 0 {
            None
        } else {
            Some(f64::from_bits(bits))
        }
    }

    fn record_latency_in(&self, _pool: &str, lane: usize, latency_ms: f64) {
        // Ignore a non-finite or non-positive sample — it would poison the EWMA (and `<= 0` collides
        // with the "no sample" sentinel). A real end-to-end latency is always strictly positive.
        if !latency_ms.is_finite() || latency_ms <= 0.0 {
            return;
        }
        let atomic = &self.get_lane(lane).latency_ewma_bits;
        // Lock-free read-modify-write CAS loop, the same idiom `spend_budget` uses. Contention here is
        // negligible (one update per completed request, off the selection path), so a CAS retry is far
        // cheaper than a lock and keeps the no-new-locks-on-the-hot-path requirement.
        let mut cur = atomic.load(Ordering::Relaxed);
        loop {
            let next = if cur == 0 {
                // First sample seeds the EWMA directly.
                latency_ms
            } else {
                let prev = f64::from_bits(cur);
                LATENCY_EWMA_ALPHA * latency_ms + (1.0 - LATENCY_EWMA_ALPHA) * prev
            };
            // Guard against a degenerate update landing on the sentinel (e.g. underflow to +0.0),
            // which would silently reset the lane to "no sample". Keep the previous value instead.
            let next_bits = next.to_bits();
            if next_bits == 0 {
                return;
            }
            match atomic.compare_exchange_weak(cur, next_bits, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(observed) => cur = observed, // a concurrent update won; retry on the fresh value
            }
        }
    }

    fn acquire_for_dispatch_in(&self, pool: &str, lane: usize, now: u64) -> bool {
        // Mutating: the single dispatched lane does the Open→HalfOpen + probe CAS here. Lane-global
        // gates are re-checked (state may have changed since selection's read-only filter).
        self.usable_for(pool, lane, now)
    }

    // (lane-global classify + aggregate breaker state live as inherent helpers above `snapshot`.)

    fn classify(&self, pool: &str, lane: usize, now: u64) -> Result<(), Unavailable> {
        // Read `dead` and `budget` SEPARATELY (NOT the bool-collapsing `lane_admissible`) so a
        // dead lane and a budget-exhausted lane get DISTINCT taxonomy variants.
        let ls = self.get_lane(lane);
        if ls.dead.load(Ordering::Relaxed) {
            return Err(Unavailable::Dead);
        }
        if ls.limited && ls.budget.load(Ordering::Relaxed) <= 0 {
            return Err(Unavailable::BudgetExhausted);
        }
        // Breaker peek via the SAME decoder `try_admit` uses — read-only, no probe CAS.
        match breaker_verdict(self.cell(pool, lane).as_ref(), now) {
            BreakerVerdict::Open { until } => Err(Unavailable::BreakerOpen { until }),
            BreakerVerdict::HalfOpen => Err(Unavailable::ProbeInFlight),
            // Breaker would admit; peek permits (racy — advisory). `available_permits` reports an
            // effectively-unbounded count for unbounded lanes, so `== 0` is only ever a bounded lane
            // truly at its `max_concurrent` limit.
            BreakerVerdict::Ready | BreakerVerdict::ProbeWinnable => {
                if self.available_permits(lane) == 0 {
                    Err(Unavailable::AtCapacity {
                        drain_hint_ms: None,
                    })
                } else {
                    Ok(())
                }
            }
        }
    }

    fn try_admit(&self, pool: &str, lane: usize, now: u64) -> Result<Admit, Unavailable> {
        // Same lane-global gates as `classify`, same SEPARATE reads.
        let ls = self.get_lane(lane);
        if ls.dead.load(Ordering::Relaxed) {
            return Err(Unavailable::Dead);
        }
        if ls.limited && ls.budget.load(Ordering::Relaxed) <= 0 {
            return Err(Unavailable::BudgetExhausted);
        }
        let cell = self.cell(pool, lane);
        // Consume the SINGLE `breaker_verdict` decoder BEFORE the mutating CAS below, to decide
        // the failure taxonomy without re-deriving "is the breaker open".
        match breaker_verdict(cell.as_ref(), now) {
            BreakerVerdict::Open { until } => return Err(Unavailable::BreakerOpen { until }),
            BreakerVerdict::HalfOpen => return Err(Unavailable::ProbeInFlight),
            BreakerVerdict::Ready | BreakerVerdict::ProbeWinnable => {}
        }
        // Acquire the concurrency PERMIT before the breaker probe CAS. For a `ProbeWinnable`
        // (expired-Open) cell that is ALSO at capacity, the old breaker-first order won the single-flight
        // recovery probe and then immediately reverted it when `try_acquire` failed — every attempt,
        // forever, so a tripped+saturated lane could never observe a real dispatch outcome and never
        // recovered. By peeking capacity FIRST we return `AtCapacity` WITHOUT ever touching the probe,
        // so the breaker probe is preserved for when a permit is actually available (see the
        // `test_try_admit_probe_winnable_at_capacity_preserves_probe` store test). For a Closed-ready
        // cell the CAS below is a pure no-op, so acquiring the permit first is byte-for-byte identical to
        // the shipped order; on the has-permit path the outcome (`Admit`) is likewise unchanged. The Err
        // reason on a saturated lane is `AtCapacity` either way, so failover behaviour is unaffected.
        let permit = match self.try_acquire(lane) {
            Some(p) => p,
            None => {
                return Err(Unavailable::AtCapacity {
                    drain_hint_ms: None,
                })
            }
        };
        // Mutating probe acquisition — the Open→HalfOpen CAS for an expired-Open cell, a no-op for a
        // Closed-ready one. We hold a permit now, so a probe won here is always dispatchable.
        if !Self::cell_acquire_breaker(cell.as_ref(), now) {
            // Lost the single-flight race (or a peer moved the cell on since the verdict peek). Release
            // the permit we grabbed — never hold a slot we won't dispatch to.
            drop(permit);
            return Err(Unavailable::ProbeInFlight);
        }
        // Owner token for the (possibly newly-won) probe, captured synchronously — the cell is HalfOpen
        // (single-flight), so no peer can win a newer probe before we read it. Mirrors `pick_among`'s
        // capture discipline; the dispatched request releases via `release_probe_owned_in`.
        let probe_epoch = cell.probe_epoch().load(Ordering::Acquire);
        Ok(Admit {
            permit,
            probe_epoch,
        })
    }

    fn lane_semaphore(&self, lane: usize) -> Option<Arc<Semaphore>> {
        let ls = self.get_lane(lane);
        // An unbounded lane's `max` is `>= Semaphore::MAX_PERMITS` (the same sentinel `try_acquire`
        // reads to short-circuit to `Permit::Unbounded`); it is never `AtCapacity`, so it is never a
        // queue candidate — hand back `None` rather than a semaphore whose permits are meaningless.
        if ls.max >= Semaphore::MAX_PERMITS {
            return None;
        }
        Some(ls.sem.clone())
    }

    fn try_admit_breaker(&self, pool: &str, lane: usize, now: u64) -> Result<u64, Unavailable> {
        // Same lane-global gates as `try_admit` (SEPARATE reads): the lane may have gone
        // dead/budget-exhausted while the caller was parked on the semaphore.
        let ls = self.get_lane(lane);
        if ls.dead.load(Ordering::Relaxed) {
            return Err(Unavailable::Dead);
        }
        if ls.limited && ls.budget.load(Ordering::Relaxed) <= 0 {
            return Err(Unavailable::BudgetExhausted);
        }
        let cell = self.cell(pool, lane);
        // Consume the SINGLE `breaker_verdict` decoder — the breaker may have TRIPPED Open (or a
        // peer may have taken the probe) while the caller was queued, so this re-check is load-bearing:
        // it is what prevents the queue from ever dispatching onto a now-Open lane.
        match breaker_verdict(cell.as_ref(), now) {
            BreakerVerdict::Open { until } => return Err(Unavailable::BreakerOpen { until }),
            BreakerVerdict::HalfOpen => return Err(Unavailable::ProbeInFlight),
            BreakerVerdict::Ready | BreakerVerdict::ProbeWinnable => {}
        }
        // Win the single-flight probe (a no-op CAS on a Closed-ready cell). Unlike `try_admit` this
        // does NOT then acquire a permit — the queue caller already holds one from the lane's own
        // semaphore. On success the probe ownership transfers to the caller (the dispatched request
        // releases it OWNER-CHECKED via `release_probe_owned_in`, using the returned epoch — matching
        // `try_admit`'s `Admit.probe_epoch` discipline); on a lost race we report `ProbeInFlight` and
        // leave nothing armed.
        if !Self::cell_acquire_breaker(cell.as_ref(), now) {
            return Err(Unavailable::ProbeInFlight);
        }
        // Owner token for the (possibly newly-won) probe, captured synchronously — the cell is HalfOpen
        // (single-flight), so no peer can win a newer probe before we read it. Handed back so the queue
        // dispatch path can release it OWNER-CHECKED, exactly like `try_admit`'s `Admit.probe_epoch`.
        Ok(cell.probe_epoch().load(Ordering::Acquire))
    }

    fn release_probe_in(&self, pool: &str, lane: usize) {
        Self::cell_release_probe(self.cell(pool, lane).as_ref());
    }

    fn probe_epoch_in(&self, pool: &str, lane: usize) -> u64 {
        self.cell(pool, lane).probe_epoch().load(Ordering::Acquire)
    }

    fn release_probe_owned_in(&self, pool: &str, lane: usize, owned_epoch: u64) {
        Self::cell_release_probe_owned(self.cell(pool, lane).as_ref(), owned_epoch);
    }

    fn breaker_state_snapshot_in(&self, pool: &str, lane: usize) -> BreakerState {
        // Same PURE-projection core the `#[cfg(test)]` `breaker_state`/`breaker_state_in` methods
        // use (`breaker_state_for`) — no probe CAS, no Open→HalfOpen transition — just released
        // for production reads (the `CandidateBreakerState` catalog entry).
        self.breaker_state_for(pool, lane)
    }

    fn error_rate_in(&self, pool: &str, lane: usize, now: u64) -> Option<f64> {
        // The breaker's OWN sliding outcome window — already maintained on every success/error
        // regardless of whether any consumer declares this signal (it feeds the error-rate trip
        // mode), so this is a pure projection, not new collection. A fixed window matching
        // `TripConfig::default().window_s` (30s): precise per-pool trip-window alignment is a
        // config-plumbing follow-up, not required for an O(1), always-computable health signal.
        let cell = self.cell(pool, lane);
        let window = lock_recover(cell.outcome_window());
        let count = window.count_in_window(now, DEFAULT_ERROR_RATE_WINDOW_S);
        if count == 0 {
            return None;
        }
        let errors = window.error_count_in_window(now, DEFAULT_ERROR_RATE_WINDOW_S);
        Some(errors as f64 / count as f64)
    }

    #[cfg(test)]
    fn breaker_state(&self, lane: usize) -> BreakerState {
        self.breaker_state_for("", lane)
    }

    #[cfg(test)]
    fn breaker_state_in(&self, pool: &str, lane: usize) -> BreakerState {
        self.breaker_state_for(pool, lane)
    }

    #[cfg(test)]
    fn force_open_in(&self, pool: &str, lane: usize, cooldown_until: u64) {
        let cell = self.cell(pool, lane);
        let _tx = lock_recover(cell.transition_lock());
        cell.cooldown_until()
            .store(cooldown_until, Ordering::Release);
        cell.breaker_state().store(ST_OPEN, Ordering::Release);
        cell.probe_in_flight().store(false, Ordering::Release);
    }

    #[cfg(test)]
    fn cooldown_remaining(&self, lane: usize, now: u64) -> u64 {
        self.cooldown_remaining_for("", lane, now)
    }

    fn cooldown_remaining_in(&self, pool: &str, lane: usize, now: u64) -> u64 {
        self.cooldown_remaining_for(pool, lane, now)
    }

    #[cfg(test)]
    fn record_success(&self, lane: usize) {
        self.record_success_for("", lane);
    }

    fn record_success_in(&self, pool: &str, lane: usize) {
        self.record_success_for(pool, lane);
    }

    fn record_probe_success_all_cells(&self, lane: usize) {
        let ls = self.get_lane(lane);
        // Administratively-dead lane: count the success for observability (matching
        // `record_success_for`'s dead-lane branch) but do not touch the breaker. Bump `ok` exactly
        // once and return, mirroring `record_probe_failure_all_cells`'s dead-lane early-out.
        if ls.dead.load(Ordering::Relaxed) {
            ls.ok.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let now = Self::now_secs();
        // Default cell (direct/ad-hoc routes) — IS the `LaneState`. `cell_record_success` pushes the
        // success outcome and runs the HalfOpen→Closed CAS. It does NOT touch `ok`/`err`, so it never
        // double-counts the lane-global stat. The CAS is *usually* a no-op here because the 2xx caller
        // runs `recover_lane` first — but only when `lane_needs_probe` is true, and even then a peer
        // (organic request, hard-down) can move a cell back to HalfOpen between that recovery and this
        // push. If this push then wins the HalfOpen→Closed CAS, `cell_closed_locked` zeroed the cell's
        // SWRR `current_weight` under the transition lock, so the matching `reset_swrr_for` MUST run to
        // hold the pool's `Σ current_weight == 0` invariant — gate it on the recovered-bool exactly
        // like `record_success_for` and `recover_lane` do.
        if Self::cell_record_success(ls.as_ref(), now) {
            // Default cell belongs to the no-pool ("") set; reset runs after the transition lock is
            // released (it is a leaf within `cell_record_success`), so the shard lock is un-nested.
            self.reset_swrr_for("", ls.as_ref());
        }
        // Every existing per-pool cell for this lane — the cells organic traffic is selected against,
        // so the probe success dilutes the SAME per-pool error-rate windows the failed-probe path
        // trips against. Mirrors `record_probe_failure_all_cells`'s `pool_cells` iteration exactly
        // (existing cells only — a cell not yet created inherits health lazily on first access).
        let cells = read_recover(&self.pool_cells);
        for (pool_name, cell) in cells.get(&lane).into_iter().flatten() {
            // Same SWRR gate per cell: a real HalfOpen→Closed close here re-admits the cell to
            // selection with a zeroed accumulator, so reset it under THIS pool's shard lock (keyed by
            // the pool name), serializing against that pool's selections — mirrors `recover_lane`.
            if Self::cell_record_success(cell.as_ref(), now) {
                self.reset_swrr_for(pool_name, cell.as_ref());
            }
        }
        // Bump the lane-GLOBAL `ok` counter EXACTLY ONCE per probe (not once per cell): the prior
        // per-cell `record_success_in` loop bumped `LaneState.ok` (N+1) times for a lane in N pools.
        // Mirrors `record_probe_failure_all_cells`, which bumps `LaneState.err` once.
        ls.ok.fetch_add(1, Ordering::Relaxed);
    }

    fn record_client_fault(&self, lane: usize) {
        let ls = self.get_lane(lane);
        // Client faults do NOT increment err, streak, or trigger cooldowns.
        // They are tracked separately for observability.
        ls.client_fault.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(test)]
    fn record_transient(
        &self,
        lane: usize,
        _what: &str,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool {
        self.record_failure_for("", lane, Self::now_secs(), cfg, retry_after)
    }

    fn record_transient_in(
        &self,
        pool: &str,
        lane: usize,
        _what: &str,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool {
        self.record_failure_for(pool, lane, Self::now_secs(), cfg, retry_after)
    }

    #[cfg(test)]
    fn record_rate_limit(
        &self,
        lane: usize,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool {
        self.record_failure_for("", lane, now_time, cfg, retry_after)
    }

    fn record_rate_limit_in(
        &self,
        pool: &str,
        lane: usize,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool {
        self.record_failure_for(pool, lane, now_time, cfg, retry_after)
    }

    #[cfg(test)]
    fn record_hard_down(&self, lane: usize, reason: &str) {
        self.record_hard_down_for("", lane, reason);
    }

    fn record_hard_down_all_cells(&self, lane: usize, reason: &str) -> bool {
        // Mirror `record_probe_failure_all_cells` exactly: operate on the per-pool cell Arcs while
        // holding the `pool_cells` lock, applying the SAME cell mutation `record_hard_down_for` does
        // (sticky Open + cooldown, probe released) — NOT by re-calling `record_hard_down_for`, which
        // re-locks `pool_cells` via `self.cell()` and would deadlock here.
        let ls = self.get_lane(lane);
        // Hard-down is RECOVERABLE: a sticky cooldown + Open, recovered via the half-open probe; do
        // NOT set `dead` (that would block recovery). Record the reason once, lane-wide.
        *lock_recover(&ls.dead_reason) = reason.to_string();
        let hard_down_cooldown_secs = self.hard_down_cooldown_secs;
        diag_warn!(
            LANE_HARD_DOWN_ALL_CELLS,
            model = %ls.model,
            reason,
            cooldown_secs = hard_down_cooldown_secs,
            "lane hard-down (all cells); sticky cooldown (recovers via half-open probe)"
        );
        let now = Self::now_secs();
        let trip = |c: &dyn BreakerCellAccess| {
            // Per-cell transition lock so the (Open + sticky cooldown) pair lands atomically against a
            // racing recovery/probe-acquire on the SAME cell (the torn-write race). Each cell has its
            // own lock and we take them one at a time (never nested), so iterating all cells here
            // cannot deadlock; the `pool_cells` READ lock held by the caller is a different,
            // strictly-outer lock (transition fns never reach back to `pool_cells`).
            let _tx = lock_recover(c.transition_lock());
            c.cooldown_until().store(
                now.saturating_add(hard_down_cooldown_secs),
                Ordering::Release,
            );
            c.breaker_state().store(ST_OPEN, Ordering::Release);
            // Release any in-flight single-flight probe back to Open (see `record_hard_down_for`):
            // without this a hard-down classified while HalfOpen leaves the cell Open with
            // `probe_in_flight == true`, benching the lane permanently after cooldown.
            c.probe_in_flight().store(false, Ordering::Release);
        };
        // Was the default cell a genuine fresh trip (Closed → Open)? Capture BEFORE tripping so the
        // caller can gate BREAKER_TRIPS_TOTAL on a logical trip, not a HalfOpen/Open re-classification
        // that recurs on every recovery-probe cycle of a persistently-dead lane. Best-effort metric: a
        // rare concurrent trip may miscount by one — far better than the prior unconditional per-probe
        // over-count.
        let default_was_closed = ls.as_ref().breaker_state().load(Ordering::Acquire) == ST_CLOSED;
        // Default cell (direct/`named`/`adhoc` routes that read the "" cell).
        trip(ls.as_ref());
        // Every existing per-pool cell for this lane — the cells organic pool-routed traffic is
        // selected against. (A cell not yet created inherits the lane default lazily on first
        // access.)
        let cells = read_recover(&self.pool_cells);
        for (_, cell) in cells.get(&lane).into_iter().flatten() {
            trip(cell.as_ref());
        }
        // Same seam `record_failure_for` bumps at (:1524-1528): a genuine Closed->Open trip counts
        // once against the lane's MONOTONIC trip counter, gated on the same bool that already keeps
        // this from inflating once per recovery-probe cycle on a persistently-dead lane.
        if default_was_closed {
            ls.trips.fetch_add(1, Ordering::Relaxed);
            ls.last_trip_at.store(now, Ordering::Relaxed);
        }
        default_was_closed
    }

    fn recover_lane(&self, lane: usize) {
        // A health probe tests the UPSTREAM, which is shared across pools — so a successful probe
        // recovers EVERY cell for this lane (the default/direct-route cell and all per-pool cells),
        // clearing both a tripped (non-Closed) breaker AND a soft cooldown on a Closed cell.
        let now = Self::now_secs();
        // Lock-free pre-filter: skip cells that are plainly Closed-and-cooled so we don't take the
        // transition lock (and, on close, the SWRR shard lock) for the common already-healthy case.
        // It returns the cooldown value it OBSERVED (`Some(observed)`) so the under-lock close can
        // re-validate against it. This pre-read is ONLY a fast path AND the snapshot — the
        // authoritative decision happens under the transition lock in `cell_closed_if_recoverable`,
        // which closes the TOCTOU: a concurrent hard-down can park a cell Open with a fresh
        // sticky cooldown between this read and the close, and an unconditional close would clobber
        // that just-armed cooldown.
        let observe = |c: &dyn BreakerCellAccess| -> Option<u64> {
            let cooldown = c.cooldown_until().load(Ordering::Acquire);
            let suppressed =
                c.breaker_state().load(Ordering::Acquire) != ST_CLOSED || cooldown > now;
            suppressed.then_some(cooldown)
        };
        // Close a cell only if it both passed the pre-filter and survives the under-lock re-validation
        // against the cooldown the pre-filter observed. Returns whether the close actually happened so
        // the caller can gate the SWRR reset on a real close — a cell a peer re-armed mid-race is left
        // suppressed and must NOT have its accumulator zeroed.
        let close = |c: &dyn BreakerCellAccess| -> bool {
            match observe(c) {
                Some(observed) => Self::cell_closed_if_recoverable(c, now, observed),
                None => false,
            }
        };
        let ls = self.get_lane(lane);
        // The default cell belongs to the no-pool ("") set. The SWRR reset runs after the close
        // returns (transition lock released), so the shard lock is taken un-nested — see
        // `reset_swrr_for`.
        if close(ls.as_ref()) {
            self.reset_swrr_for("", ls.as_ref());
        }
        let cells = read_recover(&self.pool_cells);
        for (pool_name, cell) in cells.get(&lane).into_iter().flatten() {
            if close(cell.as_ref()) {
                // Each per-pool cell's SWRR reset runs under ITS pool's shard lock (the map key is
                // the pool name), serializing against that pool's selections.
                self.reset_swrr_for(pool_name, cell.as_ref());
            }
        }
    }

    fn record_probe_failure_all_cells(
        &self,
        lane: usize,
        _what: &str,
        resolve_cfg: &dyn Fn(&str) -> BreakerCfg,
        retry_after: Option<u64>,
    ) {
        // Administratively-dead lanes ignore failure recording (matches record_failure_for).
        if self.get_lane(lane).dead.load(Ordering::Relaxed) {
            return;
        }
        let now = Self::now_secs();
        // Default cell (direct/ad-hoc routes) — resolved against the `""` (no-pool) config. The
        // returned trip bool is intentionally discarded: the out-of-band prober does not emit
        // `BREAKER_TRIPS_TOTAL` (that counter is reserved for the organic request path). `retry_after`
        // (the probe's server-requested cooldown floor) is forwarded so a 429/Retry-After probe honors
        // the upstream's backoff; `cell_record_failure` applies it only when `honor_retry_after` is set.
        let default_cfg = resolve_cfg("");
        let max_honored_retry_after_secs = self.max_honored_retry_after_secs;
        let _ = Self::cell_record_failure(
            self.get_lane(lane).as_ref(),
            now,
            &default_cfg,
            retry_after,
            max_honored_retry_after_secs,
        );
        // Every existing per-pool cell for this lane — the cells organic traffic is selected against,
        // each evaluated against ITS OWN pool's resolved breaker config (trip thresholds + cooldown
        // backoff), not a one-size default. (A cell not yet created inherits health lazily on first
        // access via `cell`.)
        let cells = read_recover(&self.pool_cells);
        for (pool_name, cell) in cells.get(&lane).into_iter().flatten() {
            let cfg = resolve_cfg(pool_name);
            let _ = Self::cell_record_failure(
                cell.as_ref(),
                now,
                &cfg,
                retry_after,
                max_honored_retry_after_secs,
            );
        }
    }

    fn lane_needs_probe(&self, lane: usize, now: u64) -> bool {
        let suppressed = |c: &dyn BreakerCellAccess| {
            c.breaker_state().load(Ordering::Acquire) != ST_CLOSED
                || c.cooldown_until().load(Ordering::Acquire) > now
        };
        if suppressed(self.get_lane(lane).as_ref()) {
            return true;
        }
        let cells = read_recover(&self.pool_cells);
        cells
            .get(&lane)
            .into_iter()
            .flatten()
            .any(|(_, cell)| suppressed(cell.as_ref()))
    }

    fn try_acquire(&self, lane: usize) -> Option<Permit> {
        let ls = self.get_lane(lane);
        // Unbounded lane (`max_concurrent` omitted, realized as MAX_PERMITS): nothing to enforce,
        // nothing counted — skip the semaphore's shared atomics entirely. /stats `inflight` reads
        // 0 for such lanes (observational; the routing seam's availability signal is unaffected —
        // it already reads "effectively infinite" either way).
        if ls.max >= Semaphore::MAX_PERMITS {
            return Some(Permit::Unbounded);
        }
        ls.sem.clone().try_acquire_owned().ok().map(Permit::Bounded)
    }

    fn spend_budget(&self, lane: usize) -> bool {
        let ls = self.get_lane(lane);
        if !ls.limited {
            return true; // unlimited budget
        }
        // Consume one unit of the lifetime request budget (the `max_requests` cost cap). The prior
        // implementation did an unconditional `fetch_sub(1)`: under a concurrent burst, up to
        // `max_concurrent` requests pass `lane_admissible` (which READS the budget without consuming
        // it) before any of them spends, then all `fetch_sub`, driving the budget NEGATIVE and
        // exceeding `max_requests` by up to `max_concurrent`. A compare-and-swap loop makes the gate
        // and the decrement ATOMIC: decrement ONLY while the budget is strictly positive, so the cap
        // is a hard ceiling — the (N+1)th concurrent spender loses the CAS once the budget hits 0 and
        // returns `false` without underflowing. Returns `false` when the lane is already exhausted.
        let mut cur = ls.budget.load(Ordering::Relaxed);
        loop {
            if cur <= 0 {
                return false; // already exhausted — never drive the budget negative
            }
            match ls.budget.compare_exchange_weak(
                cur,
                cur - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => cur = observed, // racing spender won; retry with the fresh value
            }
        }
    }

    fn refund_budget(&self, lane: usize) {
        let ls = self.get_lane(lane);
        if !ls.limited {
            return; // unlimited budget — nothing was spent
        }
        // Inverse of a single `spend_budget`: return the one unit charged on the 2xx headers when the
        // body then failed to transfer. This is ALWAYS paired with a prior successful spend on the
        // same request, so a plain increment can never push the budget above its configured ceiling.
        ls.budget.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self, lane: usize, t: u64) -> LaneSnapshot {
        let ls = self.get_lane(lane);
        // Compute the lane-global breaker verdict ONCE (RwLock read + per-cell fold) and derive both
        // the availability and breaker_state fields from it below (perf: was folded twice).
        let breaker_verdict = self.lane_breaker_verdict(lane, t);
        LaneSnapshot {
            model: ls.model.clone(),
            provider: ls.provider.clone(),
            max_concurrent: ls.max,
            // In-flight count derived from the semaphore (the source of truth): a held permit is an
            // in-flight request. `max - available` rather than a separate counter that can drift.
            inflight: ls.max.saturating_sub(ls.sem.available_permits()) as i64,
            free_slots: ls.sem.available_permits(),
            // Bounded lane (`max < MAX_PERMITS`): report real available permits and whether it is at
            // its cap. Unbounded lane: `available = None` (nothing to count) and never at-capacity.
            available: if ls.max >= Semaphore::MAX_PERMITS {
                None
            } else {
                Some(ls.sem.available_permits())
            },
            at_capacity: ls.max < Semaphore::MAX_PERMITS && ls.sem.available_permits() == 0,
            // Render availability from the SAME taxonomy routing dispatches on,
            // aggregated lane-globally, so `/stats` cannot silently drift from behaviour. The breaker
            // axis is surfaced separately via `lane_breaker_state`. BOTH axes derive from ONE
            // `lane_breaker_verdict` fold (RwLock read + per-cell scan) computed here, rather than each
            // helper re-folding it independently — halving snapshot()'s breaker-cell scan cost.
            availability: self.classify_lane_from_verdict(lane, breaker_verdict),
            breaker_state: self.lane_breaker_state_from_verdict(lane, breaker_verdict, t),
            ok: ls.ok.load(Ordering::Relaxed),
            err: ls.err.load(Ordering::Relaxed),
            client_fault: ls.client_fault.load(Ordering::Relaxed),
            // Side-effect-FREE readiness peek, NOT the mutating `usable()`. `snapshot` feeds the
            // /stats observer; the mutating path would transition an expired-Open default cell to
            // HalfOpen and CAS-acquire the single-flight recovery probe, so a monitor polling /stats
            // would steal the probe from organic traffic and falsely flip the reported state. `is_ready`
            // reports the same admission verdict without touching the breaker FSM.
            usable: self.lane_usable_any_cell(lane, t),
            dead: ls.dead.load(Ordering::Relaxed),
            dead_reason: lock_recover(&ls.dead_reason).clone(),
            cooldown_remaining_s: self.lane_max_cooldown_remaining(lane, t),
            streak: self.lane_max_streak(lane),
            budget: if ls.limited {
                ls.budget.load(Ordering::Relaxed)
            } else {
                -1
            },
            trips: ls.trips.load(Ordering::Relaxed),
            last_trip_at: ls.last_trip_at.load(Ordering::Relaxed),
        }
    }

    fn export_health(&self) -> Vec<LaneHealthSnapshot> {
        self.lanes
            .iter()
            .enumerate()
            .map(|(idx, ls)| {
                // Read (breaker_state, cooldown_until) as a CONSISTENT PAIR under a SINGLE hold of the
                // transition lock. They are two separate atomics that a trip/close/probe writes
                // together; a lock-free pair of loads can straddle a concurrent transition and observe
                // an INCONSISTENT pair (e.g. Open with a cleared/short cooldown), which this snapshot
                // then PERSISTS - on restore a hard-down lane would be revived as receiving traffic.
                // Holding the same lock the write path holds, for BOTH loads at once, makes the pair
                // move as a unit. Released immediately; the remaining fields are
                // independent counters with no cross-field invariant.
                let (breaker_state, cooldown_until) = {
                    let _tx = lock_recover(&ls.transition_lock);
                    (
                        ls.breaker_state.load(Ordering::Relaxed),
                        ls.cooldown_until.load(Ordering::Relaxed),
                    )
                };
                LaneHealthSnapshot {
                    model: ls.model.clone(),
                    provider: ls.provider.clone(),
                    budget: if ls.limited {
                        ls.budget.load(Ordering::Relaxed)
                    } else {
                        -1
                    },
                    breaker_state,
                    cooldown_until,
                    streak: ls.streak.load(Ordering::Relaxed),
                    dead: ls.dead.load(Ordering::Relaxed),
                    dead_reason: lock_recover(&ls.dead_reason).clone(),
                    ok: ls.ok.load(Ordering::Relaxed),
                    err: ls.err.load(Ordering::Relaxed),
                    client_fault: ls.client_fault.load(Ordering::Relaxed),
                    latency_ewma_bits: ls.latency_ewma_bits.load(Ordering::Relaxed),
                    trips: ls.trips.load(Ordering::Relaxed),
                    last_trip_at: ls.last_trip_at.load(Ordering::Relaxed),
                    cells: {
                        let map = self.pool_cells.read().unwrap_or_else(|e| e.into_inner());
                        map.get(&idx)
                            .map(|cells| {
                                cells
                                    .iter()
                                    .map(|(pool, cell)| {
                                        // Same consistent-pair read as the default cell above - the
                                        // per-pool cell's (state, cooldown) is written together under its
                                        // own transition lock, so snapshot both under one hold.
                                        let (breaker_state, cooldown_until) = {
                                            let _tx = lock_recover(&cell.transition_lock);
                                            (
                                                cell.breaker_state.load(Ordering::Relaxed),
                                                cell.cooldown_until.load(Ordering::Relaxed),
                                            )
                                        };
                                        PoolCellHealthSnapshot {
                                            pool: pool.to_string(),
                                            breaker_state,
                                            cooldown_until,
                                            streak: cell.streak.load(Ordering::Relaxed),
                                            err: cell.err.load(Ordering::Relaxed),
                                        }
                                    })
                                    .collect()
                            })
                            .unwrap_or_default()
                    },
                }
            })
            .collect()
    }

    // SWRR selection over the healthy subset (ADR-0001 algorithm). Uses the lane-default cells.
    #[cfg(test)]
    fn select_weighted(&self, candidates: &[usize], weights: &[u32], now: u64) -> Option<usize> {
        self.select_weighted_for("", candidates, weights, now)
    }

    fn select_weighted_in(
        &self,
        pool: &str,
        candidates: &[usize],
        weights: &[u32],
        now: u64,
    ) -> Option<usize> {
        self.select_weighted_for(pool, candidates, weights, now)
    }
}
