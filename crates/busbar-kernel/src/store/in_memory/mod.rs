use super::*;

use busbar_kernel::store::{LaneHealthSnapshot, PoolCellHealthSnapshot};

#[cfg(any(test, feature = "test-support"))]
use crate::diagnostics::{diag_warn, LANE_HARD_DOWN};

mod availability;
mod breaker;
pub(crate) use breaker::*;

pub(crate) use busbar_kernel_breaker::budget::LifetimeBudget;
pub(crate) use busbar_kernel_breaker::cell::{
    BreakerCell as FsmCell, BreakerState as FsmState, BreakerVerdict, CellSnapshot, DeniedBy,
    ProbeAdmit,
};
pub(crate) use busbar_kernel_breaker::{BreakerUnit, DestinationId};

pub(crate) fn lane_destination(lane: usize) -> DestinationId {
    DestinationId::new(lane as u64)
}

impl HealthState {
    pub(crate) fn restore_health_impl(&self, restored: &[LaneHealthSnapshot]) {
        for (idx, lane) in self.lanes.iter().enumerate() {
            let Some(snap) = restored
                .iter()
                .find(|s| s.member == lane.member && s.route == lane.route)
            else {
                continue;
            };

            if let (Some(new_cap), true) = (lane.budget.remaining(), snap.budget >= 0) {
                lane.budget.restore(snap.budget.min(new_cap));
            }
            lane.cell.restore(CellSnapshot {
                state: snap.breaker_state,
                cooldown_until: snap.cooldown_until,
                streak: snap.streak,
                err: 0,
            });
            lane.dead.store(snap.dead, Ordering::Relaxed);
            *lane.dead_reason.lock().unwrap_or_else(|e| e.into_inner()) = snap.dead_reason.clone();
            lane.ok.reset_to(snap.ok);
            lane.err.store(snap.err, Ordering::Relaxed);
            lane.client_fault
                .store(snap.client_fault, Ordering::Relaxed);
            lane.latency_ewma_bits
                .store(snap.latency_ewma_bits, Ordering::Relaxed);
            lane.trips.store(snap.trips, Ordering::Relaxed);
            lane.last_trip_at
                .store(snap.last_trip_at, Ordering::Relaxed);
            for cs in &snap.cells {
                self.pool_cell(&cs.pool, idx).restore(CellSnapshot {
                    state: cs.breaker_state,
                    cooldown_until: cs.cooldown_until,
                    streak: cs.streak,
                    err: cs.err,
                });
            }
        }
    }
}

pub(crate) type PoolCellMap = std::collections::HashMap<usize, Vec<(Box<str>, Arc<FsmCell>)>>;

pub struct HealthState {
    pub(crate) lanes: Vec<Arc<LaneState>>,

    pub(crate) pool_cells: std::sync::RwLock<PoolCellMap>,

    pub(crate) unit: Arc<BreakerUnit>,
}

pub(crate) struct LaneState {
    pub(crate) member: String,

    pub(crate) route: String,
    pub(crate) max: usize,
    pub(crate) sem: Arc<Semaphore>,

    pub(crate) budget: Arc<LifetimeBudget>,

    pub(crate) cell: Arc<FsmCell>,

    pub(crate) dead: AtomicBool,
    pub(crate) ok: StripedCounter,
    pub(crate) err: AtomicU64,
    pub(crate) client_fault: AtomicU64,

    pub(crate) latency_ewma_bits: AtomicU64,

    pub(crate) trips: AtomicU64,
    pub(crate) last_trip_at: AtomicU64,

    pub(crate) dead_reason: std::sync::Mutex<String>,
}

pub(crate) const LATENCY_EWMA_ALPHA: f64 = 0.2;

impl HealthState {
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn cell_err_for_test(&self, pool: &str, lane: usize) -> u64 {
        self.cell(pool, lane).err_count()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new(lanes: Vec<LaneData>) -> Self {
        Self::new_with_limits(
            lanes,
            crate::config::DEFAULT_HARD_DOWN_COOLDOWN_SECS,
            crate::config::DEFAULT_MAX_HONORED_RETRY_AFTER_SECS,
        )
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn new_with_limits(
        lanes: Vec<LaneData>,
        hard_down_cooldown_secs: u64,
        max_honored_retry_after_secs: u64,
    ) -> Self {
        let unit = Arc::new(
            BreakerUnit::new().with_limits(hard_down_cooldown_secs, max_honored_retry_after_secs),
        );
        let lane_states: Vec<Arc<LaneState>> = lanes
            .into_iter()
            .enumerate()
            .map(|(idx, ld)| {
                let dest = lane_destination(idx);
                unit.set_budget(dest, if ld.limited { ld.budget.max(0) } else { -1 });
                let cell = unit.cell("", dest);
                cell.restore(CellSnapshot {
                    state: 0,
                    cooldown_until: ld.cooldown_until,
                    streak: ld.streak,
                    err: 0,
                });
                Arc::new(LaneState {
                    member: ld.member,
                    route: ld.route,
                    max: ld.max,
                    sem: ld.sem,
                    budget: unit
                        .budget(dest)
                        .unwrap_or_else(|| Arc::new(LifetimeBudget::unlimited())),
                    cell,
                    dead: AtomicBool::new(ld.dead),
                    dead_reason: std::sync::Mutex::new(ld.dead_reason),
                    ok: StripedCounter::new(ld.ok),
                    err: AtomicU64::new(ld.err),
                    client_fault: AtomicU64::new(ld.client_fault),

                    latency_ewma_bits: AtomicU64::new(0),
                    trips: AtomicU64::new(0),
                    last_trip_at: AtomicU64::new(0),
                })
            })
            .collect();
        Self {
            lanes: lane_states,
            pool_cells: std::sync::RwLock::new(std::collections::HashMap::new()),
            unit,
        }
    }

    #[cold]
    #[inline(never)]
    pub(crate) fn new_with_limits_restored(
        lanes: Vec<LaneData>,
        hard_down_cooldown_secs: u64,
        max_honored_retry_after_secs: u64,
        restored: &[LaneHealthSnapshot],
    ) -> Self {
        let store =
            Self::new_with_limits(lanes, hard_down_cooldown_secs, max_honored_retry_after_secs);
        store.restore_health_impl(restored);
        store
    }

    pub(crate) fn get_lane(&self, lane: usize) -> &Arc<LaneState> {
        &self.lanes[lane]
    }

    pub(crate) fn cell(&self, pool: &str, lane: usize) -> Arc<FsmCell> {
        if pool.is_empty() {
            return Arc::clone(&self.lanes[lane].cell);
        }
        self.pool_cell(pool, lane)
    }

    pub(crate) fn pool_cell(&self, pool: &str, lane: usize) -> Arc<FsmCell> {
        let _t = crate::timeit!("store_cell_lookup");
        {
            let cells = read_recover(&self.pool_cells);
            if let Some(per_lane) = cells.get(&lane) {
                if let Some((_, c)) = per_lane.iter().find(|(p, _)| p.as_ref() == pool) {
                    return c.clone();
                }
            }
        }
        let mut cells = write_recover(&self.pool_cells);
        let per_lane = cells.entry(lane).or_default();

        if let Some((_, c)) = per_lane.iter().find(|(p, _)| p.as_ref() == pool) {
            return c.clone();
        }

        let c = self
            .unit
            .cell_seeded(pool, lane_destination(lane), |fresh| {
                fresh.restore(CellSnapshot {
                    err: 0,
                    ..self.lanes[lane].cell.snapshot()
                })
            });
        per_lane.push((Box::from(pool), c.clone()));
        c
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn open_state(&self, lane: usize, now_time: u64, cfg: &BreakerCfg) {
        self.open_state_with_retry_after(lane, now_time, cfg, None);
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn open_state_with_retry_after(
        &self,
        lane: usize,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) {
        self.get_lane(lane).cell.open(
            now_time,
            &fsm_cfg(cfg),
            retry_after,
            self.unit.max_honored_retry_after_secs(),
        );
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn closed_state(&self, lane: usize, _now_time: u64) {
        self.get_lane(lane).cell.close();
    }
}

#[derive(Clone)]
pub struct LaneData {
    /// The member the lane serves (the lane's identity, with `route`).
    pub(crate) member: String,
    /// The route the lane dials.
    pub(crate) route: String,
    pub(crate) max: usize,
    pub(crate) sem: Arc<Semaphore>,
    pub(crate) limited: bool,
    pub(crate) budget: i64,
    pub(crate) cooldown_until: u64,
    pub(crate) streak: u32,
    pub(crate) dead: bool,
    pub(crate) dead_reason: String,
    pub(crate) ok: u64,
    pub(crate) err: u64,
    pub(crate) client_fault: u64,
}

#[cfg(any(test, feature = "test-support"))]
impl LaneData {
    #[allow(clippy::too_many_arguments)]
    pub fn from_test_parts(
        member: String,
        route: String,
        max: usize,
        sem: Arc<Semaphore>,
        limited: bool,
        budget: i64,
        cooldown_until: u64,
        streak: u32,
        dead: bool,
        dead_reason: String,
        ok: u64,
        err: u64,
        client_fault: u64,
    ) -> Self {
        Self {
            member,
            route,
            max,
            sem,
            limited,
            budget,
            cooldown_until,
            streak,
            dead,
            dead_reason,
            ok,
            err,
            client_fault,
        }
    }
}

#[cfg(test)]
impl LaneData {
    pub fn for_test(member: &str, route: &str, max: usize) -> Self {
        LaneData {
            member: member.into(),
            route: route.into(),
            max,
            sem: Arc::new(Semaphore::new(max)),
            limited: false,
            budget: -1,
            cooldown_until: 0,
            streak: 0,
            dead: false,
            dead_reason: String::new(),
            ok: 0,
            err: 0,
            client_fault: 0,
        }
    }
}

use busbar_kernel::store::{BreakerCfg, TripConfig, TripMode};

pub fn breaker_cfg_to_runtime(cfg: &crate::config::BreakerCfg) -> BreakerCfg {
    let trip = cfg
        .trip
        .as_ref()
        .map(|t| TripConfig {
            mode: match t.mode {
                crate::config::BreakerTripMode::ErrorRate => TripMode::ErrorRate,
                crate::config::BreakerTripMode::Consecutive => TripMode::Consecutive,
            },
            window_s: t.window_secs,
            threshold: t.threshold,
            min_requests: t.min_requests,
            consecutive_n: t.consecutive_n,
        })
        .unwrap_or_default();
    BreakerCfg {
        base_cooldown_secs: cfg.base_cooldown_secs,
        max_cooldown_secs: cfg.max_cooldown_secs,
        honor_retry_after: true,
        trip,

        bench_below_trip_threshold: true,
    }
}

pub fn pool_breaker_cfg(
    cfg: Option<&crate::config::BreakerCfg>,
) -> busbar_kernel_breaker::cfg::BreakerCfg {
    fsm_cfg(&cfg.map(breaker_cfg_to_runtime).unwrap_or_default())
}

pub(crate) const DEFAULT_ERROR_RATE_WINDOW_S: u64 = 30;

impl HealthState {
    #[cfg(test)]
    pub(crate) fn now_secs() -> u64 {
        crate::store::now_for_test()
    }
    #[cfg(not(test))]
    pub(crate) fn now_secs() -> u64 {
        now()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn usable_for(&self, pool: &str, lane: usize, now: u64) -> bool {
        self.lane_admissible(lane)
            && !matches!(self.cell(pool, lane).acquire(now), ProbeAdmit::Denied(_))
    }

    pub(crate) fn ready_for(&self, pool: &str, lane: usize, now: u64) -> bool {
        self.lane_admissible(lane) && self.cell(pool, lane).ready(now)
    }

    pub(crate) fn lane_admissible(&self, lane: usize) -> bool {
        let ls = self.get_lane(lane);
        !ls.dead.load(Ordering::Relaxed) && !Self::exhausted(ls)
    }

    pub(crate) fn exhausted(ls: &LaneState) -> bool {
        ls.budget.remaining().is_some_and(|r| r <= 0)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn breaker_state_for(&self, pool: &str, lane: usize) -> BreakerState {
        if self.get_lane(lane).dead.load(Ordering::Relaxed) {
            return BreakerState::Open { until: u64::MAX };
        }
        to_state(self.cell(pool, lane).state())
    }

    pub(crate) fn cooldown_remaining_for(&self, pool: &str, lane: usize, now: u64) -> u64 {
        self.cell(pool, lane).cooldown_until().saturating_sub(now)
    }

    pub(crate) fn lane_usable_any_cell(&self, lane: usize, now: u64) -> bool {
        if !self.lane_admissible(lane) {
            return false;
        }
        let cells = read_recover(&self.pool_cells);
        match cells.get(&lane) {
            Some(per_lane) if !per_lane.is_empty() => {
                per_lane.iter().any(|(_, cell)| cell.ready(now))
            }
            _ => self.get_lane(lane).cell.ready(now),
        }
    }

    pub(crate) fn lane_max_cooldown_remaining(&self, lane: usize, now: u64) -> u64 {
        self.lane_max(lane, FsmCell::cooldown_until)
            .saturating_sub(now)
    }

    pub(crate) fn lane_max_streak(&self, lane: usize) -> u32 {
        self.lane_max(lane, FsmCell::streak)
    }

    pub(crate) fn close_all_cells(&self, lane: usize, close: impl Fn(&FsmCell)) {
        close(&self.get_lane(lane).cell);
        let cells = read_recover(&self.pool_cells);
        for (_, cell) in cells.get(&lane).into_iter().flatten() {
            close(cell);
        }
    }

    fn lane_max<T: Ord>(&self, lane: usize, read: impl Fn(&FsmCell) -> T) -> T {
        let cells = read_recover(&self.pool_cells);
        cells
            .get(&lane)
            .into_iter()
            .flatten()
            .map(|(_, c)| read(c))
            .fold(read(&self.get_lane(lane).cell), T::max)
    }

    pub(crate) fn record_failure_for(
        &self,
        pool: &str,
        lane: usize,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool {
        let ls = self.get_lane(lane);
        if ls.dead.load(Ordering::Relaxed) {
            return false;
        }
        let tripped = self
            .cell(pool, lane)
            .record_failure(
                now_time,
                &fsm_cfg(cfg),
                retry_after,
                self.unit.max_honored_retry_after_secs(),
            )
            .tripped();

        ls.err.fetch_add(1, Ordering::Relaxed);
        if tripped {
            self.count_trip(ls, now_time);
        }
        tripped
    }

    fn count_trip(&self, ls: &LaneState, now: u64) {
        ls.trips.fetch_add(1, Ordering::Relaxed);
        ls.last_trip_at.store(now, Ordering::Relaxed);
    }

    pub(crate) fn record_success_for(&self, pool: &str, lane: usize, now: u64) {
        let ls = self.get_lane(lane);

        if !ls.dead.load(Ordering::Relaxed) {
            let _ = self.cell(pool, lane).record_success(now);
        }
        ls.ok.add();
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn record_hard_down_for(&self, pool: &str, lane: usize, reason: &str) {
        let ls = self.get_lane(lane);

        *lock_recover(&ls.dead_reason) = reason.to_string();
        diag_warn!(
            LANE_HARD_DOWN,
            model = %ls.member,
            reason,
            cooldown_secs = self.unit.hard_down_cooldown_secs(),
            "lane hard-down; sticky cooldown (recovers via half-open probe)"
        );
        let now_secs = Self::now_secs();
        if self
            .cell(pool, lane)
            .hard_down(now_secs, self.unit.hard_down_cooldown_secs())
        {
            self.count_trip(ls, now_secs);
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
impl HealthState {
    pub(crate) fn recover_close_if_recoverable(
        &self,
        pool: &str,
        lane: usize,
        now: u64,
        observed: u64,
    ) -> bool {
        self.cell(pool, lane).close_if_recoverable(now, observed)
    }

    pub(crate) fn cell_cooldown_until(&self, pool: &str, lane: usize) -> u64 {
        self.cell(pool, lane).cooldown_until()
    }

    pub(crate) fn force_cell(&self, pool: &str, lane: usize, state: u64, until: u64, streak: u32) {
        self.cell(pool, lane).restore(CellSnapshot {
            state,
            cooldown_until: until,
            streak,
            err: 0,
        });
    }

    pub(crate) fn arm_half_open(&self, pool: &str, lane: usize, cooldown: u64) {
        let c = self.cell(pool, lane);
        c.restore(CellSnapshot {
            state: 1,
            cooldown_until: cooldown,
            streak: 0,
            err: 0,
        });
        let _ = c.acquire(cooldown);
    }
}

#[cfg(test)]
mod fixture_lane_parts_tests {
    use super::*;
    use crate::store::LaneRuntime;

    #[test]
    fn explicit_fixture_state_reaches_health_and_retains_admission_invariants() {
        let permits = Arc::new(Semaphore::new(3));
        let held = permits.clone().try_acquire_owned().unwrap();
        let lane = LaneData::from_test_parts(
            "member".into(),
            "route".into(),
            3,
            permits,
            true,
            7,
            150,
            4,
            true,
            "held-down".into(),
            11,
            12,
            13,
        );
        let exhausted = LaneData::from_test_parts(
            "exhausted".into(),
            "other".into(),
            2,
            Arc::new(Semaphore::new(2)),
            true,
            -5,
            0,
            0,
            false,
            String::new(),
            0,
            0,
            0,
        );
        let unlimited = LaneData::from_test_parts(
            "unlimited".into(),
            "last".into(),
            2,
            Arc::new(Semaphore::new(2)),
            false,
            99,
            0,
            0,
            false,
            String::new(),
            0,
            0,
            0,
        );
        let store = HealthState::new(vec![lane, exhausted, unlimited]);
        let snapshot = store.snapshot(0, 100);
        assert_eq!(
            (snapshot.member.as_str(), snapshot.route.as_str()),
            ("member", "route")
        );
        assert_eq!(
            (
                snapshot.max_concurrent,
                snapshot.free_slots,
                snapshot.inflight
            ),
            (3, 2, 1)
        );
        assert_eq!(
            (
                snapshot.budget,
                snapshot.ok,
                snapshot.err,
                snapshot.client_fault
            ),
            (7, 11, 12, 13)
        );
        assert!(snapshot.dead);
        assert_eq!(snapshot.dead_reason, "held-down");
        assert_eq!(snapshot.availability, Err(crate::store::Unavailable::Dead));
        assert_eq!(snapshot.streak, 4);
        assert_eq!(snapshot.cooldown_remaining_s, 50);
        drop(held);
        assert_eq!(
            store.snapshot(0, 100).free_slots,
            3,
            "the supplied semaphore is the live permit source"
        );
        let exhausted = store.snapshot(1, 100);
        assert_eq!(exhausted.budget, 0, "limited budgets still clamp at zero");
        assert_eq!(
            exhausted.availability,
            Err(crate::store::Unavailable::BudgetExhausted)
        );
        let unlimited = store.snapshot(2, 100);
        assert_eq!(
            unlimited.budget, -1,
            "unlimited lanes do not acquire a finite budget from fixture data"
        );
        assert!(unlimited.usable);
    }
}
