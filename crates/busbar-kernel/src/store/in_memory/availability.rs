use super::*;

use crate::diagnostics::{diag_warn, LANE_HARD_DOWN_ALL_CELLS};

impl HealthState {
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

    fn verdict_gate(v: BreakerVerdict) -> Result<(), Unavailable> {
        match v {
            BreakerVerdict::Open { until } => Err(Unavailable::BreakerOpen { until }),
            BreakerVerdict::HalfOpen => Err(Unavailable::ProbeInFlight),
            BreakerVerdict::Ready | BreakerVerdict::ProbeWinnable => Ok(()),
        }
    }

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

    fn lane_breaker_verdict(&self, lane: usize, now: u64) -> BreakerVerdict {
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
                .map(|(_, c)| c.verdict(now))
                .reduce(better)
                .unwrap_or(BreakerVerdict::Ready),

            _ => self.get_lane(lane).cell.verdict(now),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn classify_lane(&self, lane: usize, now: u64) -> Result<(), Unavailable> {
        self.classify_lane_from_verdict(lane, self.lane_breaker_verdict(lane, now))
    }

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

        if self.available_permits(lane) == 0 {
            Err(Unavailable::AtCapacity {
                drain_hint_ms: None,
            })
        } else {
            Ok(())
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn lane_breaker_state(&self, lane: usize, now: u64) -> BreakerState {
        self.lane_breaker_state_from_verdict(lane, self.lane_breaker_verdict(lane, now), now)
    }

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

            BreakerVerdict::ProbeWinnable => BreakerState::Open { until: now },
            BreakerVerdict::Open { until } => BreakerState::Open { until },
        }
    }
}

impl LaneRuntime for HealthState {
    fn breaker_unit(&self) -> std::sync::Arc<busbar_kernel_breaker::BreakerUnit> {
        std::sync::Arc::clone(&self.unit)
    }

    fn usable_in(&self, pool: &str, lane: usize, now: u64) -> bool {
        self.usable_for(pool, lane, now)
    }

    fn is_ready_any_cell(&self, lane: usize, now: u64) -> bool {
        self.lane_usable_any_cell(lane, now)
    }

    fn ready_in(&self, pool: &str, lane: usize, now: u64) -> bool {
        self.ready_for(pool, lane, now)
    }

    fn available_permits(&self, lane: usize) -> usize {
        self.get_lane(lane).sem.available_permits()
    }

    fn lane_admissible(&self, lane: usize) -> bool {
        HealthState::lane_admissible(self, lane)
    }

    fn lane_budget_remaining(&self, lane: usize) -> Option<i64> {
        self.get_lane(lane).budget.remaining()
    }

    fn lane_latency_ms(&self, lane: usize) -> Option<f64> {
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
        if !latency_ms.is_finite() || latency_ms <= 0.0 {
            return;
        }
        let atomic = &self.get_lane(lane).latency_ewma_bits;

        let mut cur = atomic.load(Ordering::Relaxed);
        loop {
            let next = if cur == 0 {
                latency_ms
            } else {
                let prev = f64::from_bits(cur);
                LATENCY_EWMA_ALPHA * latency_ms + (1.0 - LATENCY_EWMA_ALPHA) * prev
            };

            let next_bits = next.to_bits();
            if next_bits == 0 {
                return;
            }
            match atomic.compare_exchange_weak(cur, next_bits, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(observed) => cur = observed,
            }
        }
    }

    fn acquire_for_dispatch_in(&self, pool: &str, lane: usize, now: u64) -> bool {
        self.usable_for(pool, lane, now)
    }

    fn classify(&self, pool: &str, lane: usize, now: u64) -> Result<(), Unavailable> {
        self.lane_gates(lane)?;

        Self::verdict_gate(self.cell(pool, lane).verdict(now))?;

        if self.available_permits(lane) == 0 {
            Err(Unavailable::AtCapacity {
                drain_hint_ms: None,
            })
        } else {
            Ok(())
        }
    }

    fn try_admit(&self, pool: &str, lane: usize, now: u64) -> Result<Admit, Unavailable> {
        self.lane_gates(lane)?;
        let cell = self.cell(pool, lane);

        Self::verdict_gate(cell.verdict(now))?;

        let permit = self.try_acquire(lane).ok_or(Unavailable::AtCapacity {
            drain_hint_ms: None,
        })?;

        let probe_epoch = Self::admission(cell.acquire(now))?;
        Ok(Admit {
            permit,
            probe_epoch,
        })
    }

    fn lane_semaphore(&self, lane: usize) -> Option<Arc<Semaphore>> {
        let ls = self.get_lane(lane);

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
        self.lane_gates(lane)?;
        Self::admission(self.cell(pool, lane).acquire(now))
    }

    fn release_probe_in(&self, pool: &str, lane: usize) {
        let cell = self.cell(pool, lane);
        cell.release_probe_owned(cell.probe_epoch());
    }

    fn probe_epoch_in(&self, pool: &str, lane: usize) -> u64 {
        self.cell(pool, lane).probe_epoch()
    }

    fn release_probe_owned_in(&self, pool: &str, lane: usize, owned_epoch: u64) {
        self.cell(pool, lane).release_probe_owned(owned_epoch);
    }

    fn breaker_state_snapshot_in(&self, pool: &str, lane: usize) -> BreakerState {
        self.breaker_state_for(pool, lane)
    }

    fn error_rate_in(&self, pool: &str, lane: usize, now: u64) -> Option<f64> {
        let (count, errors) = self
            .cell(pool, lane)
            .outcomes_in_window(now, DEFAULT_ERROR_RATE_WINDOW_S);
        (count > 0).then(|| errors as f64 / count as f64)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn breaker_state_in(&self, pool: &str, lane: usize) -> BreakerState {
        self.breaker_state_for(pool, lane)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn force_open_in(&self, pool: &str, lane: usize, cooldown_until: u64) {
        let cell = self.cell(pool, lane);
        let snap = cell.snapshot();
        cell.restore(CellSnapshot {
            state: 1,
            cooldown_until,
            ..snap
        });
    }

    fn cooldown_remaining_in(&self, pool: &str, lane: usize, now: u64) -> u64 {
        self.cooldown_remaining_for(pool, lane, now)
    }

    fn record_success_in(&self, pool: &str, lane: usize, now: u64) {
        self.record_success_for(pool, lane, now);
    }

    fn record_probe_success_all_cells(&self, lane: usize, now: u64) {
        let ls = self.get_lane(lane);

        if ls.dead.load(Ordering::Relaxed) {
            ls.ok.add();
            return;
        }

        self.close_all_cells(lane, |c| {
            let _ = c.record_success(now);
        });

        ls.ok.add();
    }

    fn record_client_fault(&self, lane: usize) {
        let ls = self.get_lane(lane);

        ls.client_fault.fetch_add(1, Ordering::Relaxed);
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

    fn record_transient_in_at(
        &self,
        pool: &str,
        lane: usize,
        now: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool {
        self.record_failure_for(pool, lane, now, cfg, retry_after)
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

    fn record_hard_down_all_cells(&self, lane: usize, reason: &str, now: u64) -> bool {
        let ls = self.get_lane(lane);

        *lock_recover(&ls.dead_reason) = reason.to_string();
        let hard_down_cooldown_secs = self.unit.hard_down_cooldown_secs();
        diag_warn!(
            LANE_HARD_DOWN_ALL_CELLS,
            model = %ls.member,
            reason,
            cooldown_secs = hard_down_cooldown_secs,
            "lane hard-down (all cells); sticky cooldown (recovers via half-open probe)"
        );

        let default_was_closed = self.unit.hard_down_all(lane_destination(lane), now);
        if default_was_closed {
            self.count_trip(ls, now);
        }
        default_was_closed
    }

    fn recover_lane(&self, lane: usize, now: u64) {
        let observe = |c: &FsmCell| -> Option<u64> {
            let cooldown = c.cooldown_until();
            let suppressed = !matches!(c.state(), FsmState::Closed) || cooldown > now;
            suppressed.then_some(cooldown)
        };

        self.close_all_cells(lane, |c| {
            if let Some(observed) = observe(c) {
                let _ = c.close_if_recoverable(now, observed);
            }
        });
    }

    fn record_probe_failure_all_cells(
        &self,
        lane: usize,
        _what: &str,
        resolve_cfg: &dyn Fn(&str) -> BreakerCfg,
        retry_after: Option<u64>,
        now: u64,
    ) {
        if self.get_lane(lane).dead.load(Ordering::Relaxed) {
            return;
        }

        let max_honored = self.unit.max_honored_retry_after_secs();
        let record = |c: &FsmCell, cfg: BreakerCfg| {
            let _ = c.record_failure(now, &fsm_cfg(&cfg), retry_after, max_honored);
        };
        let ls = self.get_lane(lane);
        record(&ls.cell, resolve_cfg(""));

        ls.err.fetch_add(1, Ordering::Relaxed);

        let cells = read_recover(&self.pool_cells);
        for (pool_name, cell) in cells.get(&lane).into_iter().flatten() {
            record(cell, resolve_cfg(pool_name));
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
            .any(|(_, cell)| suppressed(cell))
    }

    fn try_acquire(&self, lane: usize) -> Option<Permit> {
        let ls = self.get_lane(lane);

        if ls.max >= Semaphore::MAX_PERMITS {
            return Some(Permit::Unbounded);
        }
        ls.sem.clone().try_acquire_owned().ok().map(Permit::Bounded)
    }

    fn spend_budget(&self, lane: usize) -> bool {
        self.get_lane(lane).budget.spend()
    }

    fn refund_budget(&self, lane: usize) {
        self.get_lane(lane).budget.refund()
    }

    fn snapshot(&self, lane: usize, t: u64) -> LaneSnapshot {
        let ls = self.get_lane(lane);

        let breaker_verdict = self.lane_breaker_verdict(lane, t);
        LaneSnapshot {
            member: ls.member.clone(),
            route: ls.route.clone(),
            max_concurrent: ls.max,

            inflight: ls.max.saturating_sub(ls.sem.available_permits()) as i64,
            free_slots: ls.sem.available_permits(),

            available: if ls.max >= Semaphore::MAX_PERMITS {
                None
            } else {
                Some(ls.sem.available_permits())
            },
            at_capacity: ls.max < Semaphore::MAX_PERMITS && ls.sem.available_permits() == 0,

            availability: self.classify_lane_from_verdict(lane, breaker_verdict),
            breaker_state: self.lane_breaker_state_from_verdict(lane, breaker_verdict, t),
            ok: ls.ok.sum(),
            err: ls.err.load(Ordering::Relaxed),
            client_fault: ls.client_fault.load(Ordering::Relaxed),

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

    #[cold]
    #[inline(never)]
    fn export_health(&self) -> Vec<LaneHealthSnapshot> {
        self.lanes
            .iter()
            .enumerate()
            .map(|(idx, ls)| {
                let cell = ls.cell.snapshot();
                LaneHealthSnapshot {
                    member: ls.member.clone(),
                    route: ls.route.clone(),
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
                                        let c = cell.snapshot();
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
}
