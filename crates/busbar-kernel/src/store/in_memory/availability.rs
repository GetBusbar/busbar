use super::*;

use crate::diagnostics::{diag_warn, LANE_HARD_DOWN_ALL_CELLS};

impl HealthState {
    /// The lane-global gates every availability answer reads first, SEPARATELY, so a dead lane and a
    /// budget-exhausted one get distinct taxonomy variants.
    fn lane_gates(&self, lane: usize) -> Result<(), Unavailable> {
        let ls = self.get_lane(lane);
        if ls.dead.load(Ordering::Relaxed) {
            return Err(Unavailable::Dead);
        }
        if Self::exhausted(ls) {
            return Err(Unavailable::BudgetExhausted);
        }
        Ok(())
    }

    /// A read-only verdict, as the availability taxonomy words a refusal.
    fn verdict_gate(v: BreakerVerdict) -> Result<(), Unavailable> {
        match v {
            BreakerVerdict::Open { until } => Err(Unavailable::BreakerOpen { until }),
            BreakerVerdict::HalfOpen => Err(Unavailable::ProbeInFlight),
            BreakerVerdict::Ready | BreakerVerdict::ProbeWinnable => Ok(()),
        }
    }

    /// The one breaker's admission, as the taxonomy words it. A refusal names the situation the
    /// SAME read refused on (item 142): a cooling cell is `BreakerOpen { until }` — its real
    /// deadline, never the 250 ms probe hint — and only a cell whose probe a peer holds is
    /// `ProbeInFlight`. `Some(epoch)` iff this admission won the half-open probe (the dispatch path
    /// then owns an owner-checked release); `None` is a Closed-ready admit that owns nothing.
    fn admission(a: ProbeAdmit) -> Result<Option<u64>, Unavailable> {
        match a {
            ProbeAdmit::Denied(DeniedBy::Cooling { until }) => {
                Err(Unavailable::BreakerOpen { until })
            }
            ProbeAdmit::Denied(DeniedBy::ProbeInFlight) => Err(Unavailable::ProbeInFlight),
            ProbeAdmit::ReadyNoProbe => Ok(None),
            ProbeAdmit::ProbeWon(epoch) => Ok(Some(epoch)),
        }
    }

    /// Aggregate the per-cell verdict (the one breaker's SINGLE decoder, `BreakerCell::verdict`)
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
                .map(|(_, c)| c.fsm.verdict(now))
                .reduce(better)
                .unwrap_or(BreakerVerdict::Ready),
            // Direct/ad-hoc-only lane (no per-pool cells): the default cell IS the routed cell.
            _ => self.get_lane(lane).cell.verdict(now),
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
        self.lane_gates(lane)?;
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
    #[cfg(any(test, feature = "test-support"))]
    fn usable(&self, lane: usize, now: u64) -> bool {
        self.usable_for("", lane, now)
    }

    fn usable_in(&self, pool: &str, lane: usize, now: u64) -> bool {
        self.usable_for(pool, lane, now)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn is_ready(&self, lane: usize, now: u64) -> bool {
        self.ready_for("", lane, now)
    }

    fn is_ready_any_cell(&self, lane: usize, now: u64) -> bool {
        self.lane_usable_any_cell(lane, now)
    }

    fn ready_in(&self, pool: &str, lane: usize, now: u64) -> bool {
        // Read-only, pool-aware health peek — the EXACT predicate `select_weighted_in` uses to filter
        // its healthy candidate set (lane-admissible + non-mutating `BreakerCell::ready`), exposed for
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
        self.get_lane(lane).budget.remaining() // None: unlimited / unmetered
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
        self.lane_gates(lane)?;
        // Breaker peek via the one breaker's decoder — read-only, no probe CAS.
        Self::verdict_gate(self.cell(pool, lane).fsm().verdict(now))?;
        // Breaker would admit; peek permits (racy — advisory). `available_permits` reports an
        // effectively-unbounded count for unbounded lanes, so `== 0` is only ever a bounded lane
        // truly at its `max_concurrent` limit.
        if self.available_permits(lane) == 0 {
            Err(Unavailable::AtCapacity {
                drain_hint_ms: None,
            })
        } else {
            Ok(())
        }
    }

    fn try_admit(&self, pool: &str, lane: usize, now: u64) -> Result<Admit, Unavailable> {
        // Same lane-global gates as `classify`, same SEPARATE reads.
        self.lane_gates(lane)?;
        let cell = self.cell(pool, lane);
        // Peek the breaker BEFORE the permit, so a refused lane never holds a slot.
        Self::verdict_gate(cell.fsm().verdict(now))?;
        // Acquire the concurrency PERMIT before the probe acquisition: an expired-Open cell that is
        // ALSO at capacity returns `AtCapacity` WITHOUT touching its probe, so the probe is kept for
        // an attempt that can actually dispatch (`test_try_admit_probe_winnable_at_capacity_
        // preserves_probe`).
        let permit = self.try_acquire(lane).ok_or(Unavailable::AtCapacity {
            drain_hint_ms: None,
        })?;
        // The one breaker's admission: a refusal carries the situation that refused it, decided by
        // the same read (item 142). A refused admission drops the permit it grabbed.
        let probe_epoch = Self::admission(cell.fsm().acquire(now))?;
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

    fn try_admit_breaker(
        &self,
        pool: &str,
        lane: usize,
        now: u64,
    ) -> Result<Option<u64>, Unavailable> {
        // Same lane-global gates as `try_admit`: the lane may have gone dead/budget-exhausted while
        // the caller was parked on the semaphore. The breaker may have TRIPPED Open (or a peer may
        // have taken the probe) meanwhile too, which the acquisition itself answers — with the
        // cooldown that refused it, not a guess (item 142).
        self.lane_gates(lane)?;
        Self::admission(self.cell(pool, lane).fsm().acquire(now))
    }

    fn release_probe_in(&self, pool: &str, lane: usize) {
        // Unowned: releases whichever probe is live now (the owner-checked form, at the live epoch).
        let cell = self.cell(pool, lane);
        cell.fsm().release_probe_owned(cell.fsm().probe_epoch());
    }

    fn probe_epoch_in(&self, pool: &str, lane: usize) -> u64 {
        self.cell(pool, lane).fsm().probe_epoch()
    }

    fn release_probe_owned_in(&self, pool: &str, lane: usize, owned_epoch: u64) {
        self.cell(pool, lane).fsm().release_probe_owned(owned_epoch);
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
        let (count, errors) = self
            .cell(pool, lane)
            .fsm()
            .outcomes_in_window(now, DEFAULT_ERROR_RATE_WINDOW_S);
        (count > 0).then(|| errors as f64 / count as f64)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn breaker_state(&self, lane: usize) -> BreakerState {
        self.breaker_state_for("", lane)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn breaker_state_in(&self, pool: &str, lane: usize) -> BreakerState {
        self.breaker_state_for(pool, lane)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn force_open_in(&self, pool: &str, lane: usize, cooldown_until: u64) {
        let cell = self.cell(pool, lane);
        let snap = cell.fsm().snapshot();
        cell.fsm().restore(CellSnapshot {
            state: 1,
            cooldown_until,
            ..snap
        });
    }

    #[cfg(any(test, feature = "test-support"))]
    fn cooldown_remaining(&self, lane: usize, now: u64) -> u64 {
        self.cooldown_remaining_for("", lane, now)
    }

    fn cooldown_remaining_in(&self, pool: &str, lane: usize, now: u64) -> u64 {
        self.cooldown_remaining_for(pool, lane, now)
    }

    #[cfg(any(test, feature = "test-support"))]
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
            ls.ok.add();
            return;
        }
        let now = Self::now_secs();
        // Default cell (direct/ad-hoc routes) — IS the `LaneState`. `record_success` pushes the
        // success outcome and runs the HalfOpen→Closed CAS. It does NOT touch `ok`/`err`, so it never
        // double-counts the lane-global stat. The CAS is *usually* a no-op here because the 2xx caller
        // runs `recover_lane` first — but only when `lane_needs_probe` is true, and even then a peer
        // (organic request, hard-down) can move a cell back to HalfOpen between that recovery and this
        // push. If this push then wins the HalfOpen→Closed CAS, the matching `reset_swrr_for`
        // (a generational stripe bump) MUST run so the recovered cell's stripes rejoin from 0 —
        // gate it on the recovered-bool exactly like `record_success_for` and `recover_lane` do.
        if ls.cell.record_success(now) {
            // Default cell belongs to the no-pool ("") set; the reset is the lock-free generational
            // bump (`reset_swrr_for` takes no shard lock), run after the transition lock is
            // released (it is a leaf within `record_success`).
            self.reset_swrr_for("", ls.as_ref());
        }
        // Every existing per-pool cell for this lane — the cells organic traffic is selected against,
        // so the probe success dilutes the SAME per-pool error-rate windows the failed-probe path
        // trips against. Mirrors `record_probe_failure_all_cells`'s `pool_cells` iteration exactly
        // (existing cells only — a cell not yet created inherits health lazily on first access).
        let cells = read_recover(&self.pool_cells);
        for (pool_name, cell) in cells.get(&lane).into_iter().flatten() {
            // Same SWRR gate per cell: a real HalfOpen→Closed close here re-admits the cell to
            // selection with a zeroed accumulator via the lock-free generational bump — each
            // stripe rejoins from 0 the next time a selection resolves its slot (a selection
            // observes the generation at exactly ONE point, its single `slot()` resolution, so
            // the bump can never zero an accumulator mid-sequence) — mirrors `recover_lane`.
            if cell.fsm.record_success(now) {
                self.reset_swrr_for(pool_name, cell.as_ref());
            }
        }
        // Bump the lane-GLOBAL `ok` counter EXACTLY ONCE per probe (not once per cell): the prior
        // per-cell `record_success_in` loop bumped `LaneState.ok` (N+1) times for a lane in N pools.
        // Mirrors `record_probe_failure_all_cells`, which bumps `LaneState.err` once.
        ls.ok.add();
    }

    fn record_client_fault(&self, lane: usize) {
        let ls = self.get_lane(lane);
        // Client faults do NOT increment err, streak, or trigger cooldowns.
        // They are tracked separately for observability.
        ls.client_fault.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-support"))]
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

    #[cfg(any(test, feature = "test-support"))]
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

    #[cfg(any(test, feature = "test-support"))]
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
        let hard_down_cooldown_secs = self.unit.hard_down_cooldown_secs();
        diag_warn!(
            LANE_HARD_DOWN_ALL_CELLS,
            model = %ls.model,
            reason,
            cooldown_secs = hard_down_cooldown_secs,
            "lane hard-down (all cells); sticky cooldown (recovers via half-open probe)"
        );
        let now = Self::now_secs();
        // The one breaker's fan-out: the default cell and every pool cell registered for this lane,
        // each under its own transition lock. `true` iff the DEFAULT cell was a genuine fresh trip
        // (Closed beforehand), so a persistently-dead lane's recovery-probe cycle counts nothing.
        let default_was_closed = self.unit.hard_down_all(lane_destination(lane), now);
        if default_was_closed {
            self.count_trip(ls, now);
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
        // authoritative decision happens under the transition lock in `close_if_recoverable`,
        // which closes the TOCTOU: a concurrent hard-down can park a cell Open with a fresh
        // sticky cooldown between this read and the close, and an unconditional close would clobber
        // that just-armed cooldown.
        let observe = |c: &FsmCell| -> Option<u64> {
            let cooldown = c.cooldown_until();
            let suppressed = !matches!(c.state(), FsmState::Closed) || cooldown > now;
            suppressed.then_some(cooldown)
        };
        // Close a cell only if it both passed the pre-filter and survives the under-lock re-validation
        // against the cooldown the pre-filter observed. Returns whether the close actually happened so
        // the caller can gate the SWRR reset on a real close — a cell a peer re-armed mid-race is left
        // suppressed and must NOT have its accumulator zeroed.
        let close = |c: &FsmCell| -> bool {
            match observe(c) {
                Some(observed) => c.close_if_recoverable(now, observed),
                None => false,
            }
        };
        let ls = self.get_lane(lane);
        if close(&ls.cell) {
            self.reset_swrr_for("", ls.as_ref());
        }
        let cells = read_recover(&self.pool_cells);
        for (pool_name, cell) in cells.get(&lane).into_iter().flatten() {
            if close(&cell.fsm) {
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
        // the upstream's backoff; `record_failure` applies it only when `honor_retry_after` is set.
        let max_honored = self.unit.max_honored_retry_after_secs();
        let record = |c: &FsmCell, cfg: BreakerCfg| {
            let _ = c.record_failure(now, &fsm_cfg(&cfg), retry_after, max_honored);
        };
        let ls = self.get_lane(lane);
        record(&ls.cell, resolve_cfg(""));
        // The lane-GLOBAL error counter, once per probe (not once per cell).
        ls.err.fetch_add(1, Ordering::Relaxed);
        // Every existing per-pool cell for this lane — the cells organic traffic is selected against,
        // each evaluated against ITS OWN pool's resolved breaker config. (A cell not yet created
        // inherits health lazily on first access via `cell`.)
        let cells = read_recover(&self.pool_cells);
        for (pool_name, cell) in cells.get(&lane).into_iter().flatten() {
            record(&cell.fsm, resolve_cfg(pool_name));
        }
    }

    fn lane_needs_probe(&self, lane: usize, now: u64) -> bool {
        let suppressed =
            |c: &FsmCell| !matches!(c.state(), FsmState::Closed) || c.cooldown_until() > now;
        if suppressed(&self.get_lane(lane).cell) {
            return true;
        }
        let cells = read_recover(&self.pool_cells);
        cells
            .get(&lane)
            .into_iter()
            .flatten()
            .any(|(_, cell)| suppressed(&cell.fsm))
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
        // One unit of the lane's `max_requests` budget, spent on the one breaker's own counter: a
        // CAS loop that never drives it negative, so the cap is a hard ceiling under a burst.
        self.get_lane(lane).budget.spend()
    }

    fn refund_budget(&self, lane: usize) {
        // Inverse of a single `spend_budget` (the 2xx headers were charged; the body then failed).
        self.get_lane(lane).budget.refund()
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
            ok: ls.ok.sum(),
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
            budget: ls.budget.remaining().unwrap_or(-1),
            trips: ls.trips.load(Ordering::Relaxed),
            last_trip_at: ls.last_trip_at.load(Ordering::Relaxed),
        }
    }

    #[cold] // boot/admin-only — keeps hot text dense (never inlined into a warm path)
    #[inline(never)]
    fn export_health(&self) -> Vec<LaneHealthSnapshot> {
        self.lanes
            .iter()
            .enumerate()
            .map(|(idx, ls)| {
                // (state, cooldown) read as ONE pair under the cell's transition lock — a lock-free
                // pair of loads can straddle a transition and persist a tripped lane as healthy.
                let cell = ls.cell.snapshot();
                LaneHealthSnapshot {
                    model: ls.model.clone(),
                    provider: ls.provider.clone(),
                    budget: ls.budget.remaining().unwrap_or(-1),
                    breaker_state: cell.state,
                    cooldown_until: cell.cooldown_until,
                    streak: cell.streak,
                    dead: ls.dead.load(Ordering::Relaxed),
                    dead_reason: lock_recover(&ls.dead_reason).clone(),
                    ok: ls.ok.sum(),
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
                                        let c = cell.fsm.snapshot();
                                        PoolCellHealthSnapshot {
                                            pool: pool.to_string(),
                                            breaker_state: c.state,
                                            cooldown_until: c.cooldown_until,
                                            streak: c.streak,
                                            err: c.err,
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
    #[cfg(any(test, feature = "test-support"))]
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

impl HealthState {
    /// READ-ONLY census of every NAMED `(pool, lane)` breaker cell materialized so far, as
    /// `(pool key, lane, the cell's OWN FSM state, the cell's own remaining cooldown secs)`. The
    /// state is the same pure projection as `breaker_state_for` (a dead lane reads
    /// `Open { until: u64::MAX }`). The lane-default (`""`) cells are not listed — they are not
    /// named. No cell is created, no probe CAS, no transition: the scrape reads what the dispatch
    /// path already wrote. Order is unspecified.
    pub(crate) fn named_cell_readings(
        &self,
        now: u64,
    ) -> Vec<(Box<str>, usize, BreakerState, u64)> {
        let cells = read_recover(&self.pool_cells);
        let mut out = Vec::new();
        for (&lane, per_lane) in cells.iter() {
            let dead = self.get_lane(lane).dead.load(Ordering::Relaxed);
            for (pool, cell) in per_lane {
                let state = if dead {
                    BreakerState::Open { until: u64::MAX }
                } else {
                    to_state(cell.fsm.state())
                };
                let cooldown = cell.fsm.cooldown_until().saturating_sub(now);
                out.push((pool.clone(), lane, state, cooldown));
            }
        }
        out
    }
}
