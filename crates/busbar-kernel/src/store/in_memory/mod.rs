use super::*;

// R5-store: the two health-snapshot carriers are named from their DEFINING crate rather than through
// a `crate::store::…` re-export. They live in `busbar_kernel::store` and this engine — the config-
// apply export/restore path (`export_health`/`restore_health_impl`) — is their only reader left in
// core, so the shim had exactly one caller and is deleted instead of repointed twice.
use busbar_kernel::store::{LaneHealthSnapshot, PoolCellHealthSnapshot};

#[cfg(any(test, feature = "test-support"))]
use crate::diagnostics::{diag_warn, LANE_HARD_DOWN};

mod availability;
mod breaker;
pub(crate) use breaker::*;

// THE ONE BREAKER (item 142). Every cell's state machine is `busbar-kernel-breaker`'s; this store
// holds handles onto its cells and adds only the lane-global facts (dead, permits, counters).
pub(crate) use busbar_kernel_breaker::budget::LifetimeBudget;
pub(crate) use busbar_kernel_breaker::cell::{
    BreakerCell as FsmCell, BreakerState as FsmState, BreakerVerdict, CellSnapshot, DeniedBy,
    ProbeAdmit,
};
pub(crate) use busbar_kernel_breaker::{BreakerUnit, DestinationId};

/// The one breaker keys a cell by `(pool, destination)`; in this store a destination is its lane.
pub(crate) fn lane_destination(lane: usize) -> DestinationId {
    DestinationId::new(lane as u64)
}

impl HealthState {
    /// The identity-keyed restore shared by the state-carrying constructor (config apply) and the
    /// in-place boot restore: apply each matching snapshot's lane-global fields and recreate
    /// its per-pool breaker cells eagerly (a restored Open cell blocks dispatch from request one).
    pub(crate) fn restore_health_impl(&self, restored: &[LaneHealthSnapshot]) {
        for (idx, lane) in self.lanes.iter().enumerate() {
            let Some(snap) = restored
                .iter()
                .find(|s| s.member == lane.member && s.route == lane.route)
            else {
                continue;
            };
            // Carry over the remaining request budget ONLY when BOTH the snapshot and the new lane
            // are limited, and never above the NEW cap. `export_health` writes the sentinel -1 for
            // an unlimited lane; if the new config just ADDED `max_requests` to a lane that was
            // unlimited at snapshot time, storing that -1 over the freshly-set cap would make
            // `lane_admissible` (`limited && budget <= 0`) reject every dispatch with NO
            // self-recovery path (the budget only rises on a successful dispatch, which is itself
            // gated on admissibility). And if the operator LOWERED `max_requests`, the prior
            // (larger) remaining budget must be clamped to the freshly-set cap the constructor
            // already stored — otherwise the lane over-serves by up to (old_remaining - new_cap),
            // silently blowing past the operator's newly-lowered hard ceiling. `min` with the
            // current atomic (which holds the new cap at this point) handles same-cap and
            // cap-increase carry-over unchanged while capping a reduction.
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
                // In-place restore may find the cell already lazily created — restore INTO it.
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

/// Per-lane breaker cells, keyed by lane index for an O(1) lane lookup. Each lane maps to its small
/// set of per-pool cells (`(pool name, cell)`), so a (pool, lane) point lookup is an O(1) hash probe
/// plus a scan bounded by the number of POOLS ON THAT LANE (typically tiny) — never the full
/// cross-product of pools×lanes — and the per-lane aggregation/recovery sweeps touch only the
/// relevant lane's cells instead of scanning every cell in the deployment. No per-call key allocation
/// on the hot path (the lane index is `Copy`; the pool name is compared by `&str`).
pub(crate) type PoolCellMap = std::collections::HashMap<usize, Vec<(Box<str>, Arc<FsmCell>)>>;

/// Wraps the per-lane atomics/semaphores with per-(pool, lane) FSM breaker logic, populated lazily.
pub struct HealthState {
    pub(crate) lanes: Vec<Arc<LaneState>>,
    /// Per-(pool, lane) breaker cells, created lazily on first access. The lane-global fields
    /// (sem/budget/dead/ok) always live on `lanes[lane]`; only the breaker FSM is isolated per pool.
    ///
    /// An `RwLock` (not a plain `Mutex`): the overwhelmingly common access is a READ of an
    /// already-created cell on the hot dispatch path (`cell()` / the `/stats` aggregators), and many
    /// such reads can proceed concurrently under a shared lock. Only the rare lazy first-touch insert
    /// of a new (pool, lane) cell takes the exclusive write lock. The previous `Mutex` forced an
    /// exclusive acquisition for every read, serializing the selection path.
    pub(crate) pool_cells: std::sync::RwLock<PoolCellMap>,
    /// THE ONE BREAKER (item 142): every cell's state machine, every lane's lifetime request budget
    /// (`max_requests`, declared once through `set_budget`), and the two `limits.*` knobs
    /// (`with_limits`). The cells above are handles onto its cells, never copies of them.
    pub(crate) unit: Arc<BreakerUnit>,
}

// Field ORDER is perf-deliberate (hot-path cache locality): the per-request atomics are grouped
// into one cluster so a dispatch decision (dead check → breaker CAS → outcome counter) touches 1-2 cache lines instead of hopping over the Strings and Mutex blocks that used
// to interleave them. Boot-time read-only fields lead; Mutex-guarded cold state trails. Pure
// layout change — every constructor uses named fields, so semantics are untouched.
pub(crate) struct LaneState {
    // ── read-only after boot ──
    /// The member the lane serves; with `route`, the identity a restore matches on.
    pub(crate) member: String,
    /// The route the lane dials.
    pub(crate) route: String,
    pub(crate) max: usize,
    pub(crate) sem: Arc<Semaphore>,
    // The lane's `max_requests` budget: the one breaker's own counter for this destination, shared.
    pub(crate) budget: Arc<LifetimeBudget>,
    // The lane-default (`""` pool) cell: the one breaker's own cell for this destination, shared.
    pub(crate) cell: Arc<FsmCell>,
    // ── hot per-request atomics (keep contiguous) ──
    pub(crate) dead: AtomicBool,
    pub(crate) ok: StripedCounter,
    pub(crate) err: AtomicU64,
    pub(crate) client_fault: AtomicU64,
    // Rolling EWMA of observed end-to-end request latency for this lane, in MILLISECONDS, stored as
    // the raw bits of an `f64` (`f64::to_bits`) so it can be read/updated lock-free with a single
    // atomic — mirroring the lock-free atomic style the rest of this struct uses for cheap per-lane
    // signals. A sentinel of `0` bits (== `+0.0`) means "no sample yet" (a real end-to-end latency is
    // always strictly positive), which the routing-policy projection maps to `latency_ms: None`. This
    // is a lane-GLOBAL signal (latency is a property of the shared upstream, not of any one pool's
    // breaker cell), so it lives on `LaneState`, not on `BreakerCell`. Read by the `fastest` policy
    // via `lane_latency_ms`; updated after each request completes via `record_latency_in`.
    pub(crate) latency_ewma_bits: AtomicU64,
    // MONOTONIC count of genuine Closed→Open breaker trips on this lane (any cell) + the epoch of
    // the most recent one (0 = never). Breaker open→close is transient — a poll-only consumer can
    // miss the whole episode between two polls; a monotonic count + last-trip timestamp let it
    // detect "a trip happened since I last looked" without catching the live edge.
    // Lane-global (like ok/err): a trip in ANY pool cell counts. Carried across config apply /
    // restart with the rest of the learned health.
    pub(crate) trips: AtomicU64,
    pub(crate) last_trip_at: AtomicU64,
    // ── cold, Mutex-guarded state (rare paths: trips, window maintenance, transitions) ──
    pub(crate) dead_reason: std::sync::Mutex<String>,
}

/// Smoothing factor (α) for the per-lane latency EWMA: `ewma = α·sample + (1-α)·ewma`. A smaller α
/// gives a longer memory (steadier signal, slower to react); 0.2 weights the most recent ~5 requests
/// most heavily, which is responsive enough to notice a degrading upstream without thrashing the
/// `fastest` ranking on a single slow outlier. Cheap, bounded, allocation-free.
pub(crate) const LATENCY_EWMA_ALPHA: f64 = 0.2;

impl HealthState {
    /// Read a (pool, lane) cell's cumulative error counter — for concurrency/isolation tests.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn cell_err_for_test(&self, pool: &str, lane: usize) -> u64 {
        self.cell(pool, lane).err_count()
    }

    /// Construct with the historical hardcoded operational limits. Used by tests and any caller that
    /// does not thread operator config; production goes through [`new_with_limits`].
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new(lanes: Vec<LaneData>) -> Self {
        Self::new_with_limits(
            lanes,
            crate::config::DEFAULT_HARD_DOWN_COOLDOWN_SECS,
            crate::config::DEFAULT_MAX_HONORED_RETRY_AFTER_SECS,
        )
    }

    /// Construct with operator-configured hard-down cooldown + honored-`Retry-After` ceiling
    /// (`limits.hard_down_cooldown_secs` / `limits.max_honored_retry_after_secs`). Each defaults to
    /// its historical const at the config layer, so `new` and this share one source of truth.
    #[cold] // boot/admin-only — keeps hot text dense (never inlined into a warm path)
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
                    // `0` bits == "no latency sample yet" (see `latency_ewma_bits`).
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

    /// Construct with PRIOR HEALTH STATE restored by stable lane identity: each lane whose
    /// (member, route) appears in `restored` starts with that snapshot's breaker/cooldown/streak/
    /// hard-down/latency/counters instead of fresh state — the carry-over that makes a lane-set
    /// config APPLY (and, via the persistence layer, a restart) preserve learned reliability.
    /// Matching is by IDENTITY, never position, so added/removed/reordered lanes are immune to the
    /// index-shift misattribution this design exists to prevent. Unmatched snapshots are dropped
    /// (their lane no longer exists); unmatched lanes start fresh (they are new). `LaneData`
    /// baseline fields (budget/cooldown/streak/dead/counters) are OVERRIDDEN by a matching
    /// snapshot — the snapshot IS the live truth the previous store held; per-pool cells are
    /// re-created eagerly so a restored Open cell blocks dispatch from the first request.
    #[cold] // boot/admin-only — keeps hot text dense (never inlined into a warm path)
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

    /// Resolve the breaker cell for a (pool, lane). An empty pool name selects the lane-global
    /// default cell (the one on `LaneState`) — used by direct/ad-hoc routes. A named pool gets a
    /// dedicated cell, created on first access.
    pub(crate) fn cell(&self, pool: &str, lane: usize) -> Arc<FsmCell> {
        if pool.is_empty() {
            return Arc::clone(&self.lanes[lane].cell);
        }
        self.pool_cell(pool, lane)
    }

    /// A named pool's cell. Fast path: a SHARED read lock and a lookup with no key allocation —
    /// the cell almost always exists (created once, on the pool's first request). Only a genuine
    /// first-touch miss takes the write lock.
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
        // Re-check under the write lock: a racing writer may have inserted this (pool, lane) between
        // the read-lock miss above and acquiring the write lock.
        if let Some((_, c)) = per_lane.iter().find(|(p, _)| p.as_ref() == pool) {
            return c.clone();
        }
        // A new pool cell inherits the lane's current known health (state + pending cooldown +
        // streak) rather than blindly assuming Closed — so a pool whose first request arrives while
        // the lane is mid-cooldown respects it. An inherited HalfOpen restores as Open (the probe it
        // names belongs to the cell that won it; see `CellSnapshot`).
        // Only a cell this touch creates inherits: one the root's breaker already observed into
        // is the same cell, and its record stands.
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

    /// Transition the default cell Open with an escalated cooldown (test handle).
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn open_state(&self, lane: usize, now_time: u64, cfg: &BreakerCfg) {
        self.open_state_with_retry_after(lane, now_time, cfg, None);
    }

    /// Transition the default cell Open with an escalated cooldown and optional Retry-After floor.
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

    /// Transition the default cell to Closed (test handle).
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

#[cfg(test)]
impl LaneData {
    /// A minimal live lane (alive, unlimited budget, zero counters) with the given
    /// member/route/permit count, for the store's race tests.
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

// The RESOLVED runtime breaker cfg (`BreakerCfg`/`TripConfig`/`TripMode`) is neutral DATA and now
// lives in `busbar_kernel::store` (re-exported below via `pub use in_memory::*` from the parent
// `store` module) so an out-of-tree plugin crate names it without reaching into `busbar-core`. Its
// conversion helpers move WITH it; only the config->runtime lowering stays here (core owns the
// `config::BreakerCfg` grammar), rehomed from a `From` impl (orphan-rule blocked once the target type
// is foreign) to an inherent `to_runtime` method on the config type — the same shape `config`'s
// `on_exhausted`/`OnExhausted` lowering already uses.
// R5-store: a private import, not a re-export. `TripConfig`/`TripMode` never had a reader outside
// this engine, and `BreakerCfg`'s two — `failover/mod.rs` and the test-support pool builder — name
// `busbar_kernel::store::BreakerCfg` directly.
use busbar_kernel::store::{BreakerCfg, TripConfig, TripMode};

/// Resolve the parsed `breaker:` config into the runtime [`BreakerCfg`] the FSM evaluates.
/// `honor_retry_after` has no config knob (always honored), and an absent `trip` block falls
/// back to the ADR-0002 defaults. Was an inherent `config::BreakerCfg::to_runtime` method; now a
/// free function because BOTH the config type and the runtime type are foreign to this crate
/// (substrate-owned), which the orphan rule forbids an inherent impl over.
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
        // `pools.<pool>.breaker:` is the primary plane's only breaker surface, and that plane walks
        // its members. The plane cells do not parse config (see `PlaneBreakers::new`).
        bench_below_trip_threshold: true,
    }
}

/// A configured pool's breaker, as the one breaker's state machine takes it: its `breaker:` block
/// resolved, or the defaults when it declares none — the cfg the pool's own dispatch resolves.
pub fn pool_breaker_cfg(
    cfg: Option<&crate::config::BreakerCfg>,
) -> busbar_kernel_breaker::cfg::BreakerCfg {
    fsm_cfg(&cfg.map(breaker_cfg_to_runtime).unwrap_or_default())
}

// `TripMode` / `TripConfig` (+ its `Default`) moved to `busbar_kernel::store` with `BreakerCfg`
// (re-exported above); only the signal-catalog window const stays here.

/// The window (seconds) the `Signal::CandidateErrorRate` catalog entry reads the
/// breaker's existing outcome window over — matches `TripConfig::default`'s own `window_s` so
/// the projected error rate reads over the same horizon the default breaker trip mode does.
pub(crate) const DEFAULT_ERROR_RATE_WINDOW_S: u64 = 30;

// Pool-aware breaker operations, shared by the lane-default trait methods (pool "") and the
// `_in(pool, …)` trait methods. The lane-global checks (dead / budget) always read `lanes[lane]`;
// the breaker FSM runs against the resolved (pool, lane) cell.
impl HealthState {
    #[cfg(test)]
    pub(crate) fn now_secs() -> u64 {
        crate::store::now_for_test()
    }
    #[cfg(not(test))]
    pub(crate) fn now_secs() -> u64 {
        now()
    }

    /// Mutating admission check: an expired-Open lane transitions to HalfOpen and the caller wins
    /// the single-flight probe. Reached only via the test-exercised `usable`/`usable_in`/
    /// `acquire_for_dispatch_in` (production dispatch takes the richer `try_admit`).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn usable_for(&self, pool: &str, lane: usize, now: u64) -> bool {
        self.lane_admissible(lane)
            && !matches!(self.cell(pool, lane).acquire(now), ProbeAdmit::Denied(_))
    }

    /// Side-effect-FREE readiness check (lane-global gates + a non-mutating breaker peek). Shared
    /// body for both `is_ready` (test-gated) and `ready_in` (production-wired via the routing
    /// policy's ordered walk).
    pub(crate) fn ready_for(&self, pool: &str, lane: usize, now: u64) -> bool {
        self.lane_admissible(lane) && self.cell(pool, lane).ready(now)
    }

    /// Lane-global admission gates shared by both the mutating and read-only checks: a `dead` lane
    /// (administratively down) or an exhausted budget is never admissible regardless of breaker FSM.
    pub(crate) fn lane_admissible(&self, lane: usize) -> bool {
        let ls = self.get_lane(lane);
        !ls.dead.load(Ordering::Relaxed) && !Self::exhausted(ls)
    }

    /// The lane's `max_requests` budget is spent (never true for an unlimited lane).
    pub(crate) fn exhausted(ls: &LaneState) -> bool {
        ls.budget.remaining().is_some_and(|r| r <= 0)
    }

    #[cfg_attr(not(test), allow(dead_code))] // reached only via the test-exercised `breaker_state`
    pub(crate) fn breaker_state_for(&self, pool: &str, lane: usize) -> BreakerState {
        if self.get_lane(lane).dead.load(Ordering::Relaxed) {
            return BreakerState::Open { until: u64::MAX };
        }
        to_state(self.cell(pool, lane).state())
    }

    pub(crate) fn cooldown_remaining_for(&self, pool: &str, lane: usize, now: u64) -> u64 {
        self.cell(pool, lane).cooldown_until().saturating_sub(now)
    }

    /// Lane-global readiness for `/healthz` and `/stats`: true iff the lane is admissible (not dead /
    /// in budget) AND at least one breaker cell production ACTUALLY routes through would admit now.
    /// A lane with per-pool cells is read through those alone — pool-routed traffic never touches
    /// the default cell, which would otherwise read ready for a lane whose every pool has tripped.
    /// Only a lane with NO per-pool cells (direct/ad-hoc-only) falls back to the default cell.
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

    /// Worst-case remaining cooldown across the default cell and every per-pool cell for the lane.
    pub(crate) fn lane_max_cooldown_remaining(&self, lane: usize, now: u64) -> u64 {
        self.lane_max(lane, FsmCell::cooldown_until)
            .saturating_sub(now)
    }

    /// Worst-case consecutive-failure streak across the default cell and every per-pool cell.
    pub(crate) fn lane_max_streak(&self, lane: usize) -> u32 {
        self.lane_max(lane, FsmCell::streak)
    }

    /// Run `close` on the default cell and then on every EXISTING per-pool cell for the lane (a cell
    /// not yet created inherits health lazily on first access).
    pub(crate) fn close_all_cells(&self, lane: usize, close: impl Fn(&FsmCell)) {
        close(&self.get_lane(lane).cell);
        let cells = read_recover(&self.pool_cells);
        for (_, cell) in cells.get(&lane).into_iter().flatten() {
            close(cell);
        }
    }

    /// The largest `read` across the default cell and every per-pool cell for the lane.
    fn lane_max<T: Ord>(&self, lane: usize, read: impl Fn(&FsmCell) -> T) -> T {
        let cells = read_recover(&self.pool_cells);
        cells
            .get(&lane)
            .into_iter()
            .flatten()
            .map(|(_, c)| read(c))
            .fold(read(&self.get_lane(lane).cell), T::max)
    }

    /// Returns `true` iff this failure drove a Closed→Open trip on the (pool, lane) cell — threaded
    /// out so the proxy engine call site can emit `BREAKER_TRIPS_TOTAL` exactly once per logical trip.
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
            return false; // administratively down — ignore
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
        // The lane-GLOBAL `/stats` error counter, once per failure whichever cell recorded it.
        ls.err.fetch_add(1, Ordering::Relaxed);
        if tripped {
            self.count_trip(ls, now_time);
        }
        tripped
    }

    /// One genuine Closed→Open trip against the lane's MONOTONIC trip counter + its epoch stamp —
    /// the same seam that mints `BREAKER_TRIPS_TOTAL`, one logical trip counted once.
    fn count_trip(&self, ls: &LaneState, now: u64) {
        ls.trips.fetch_add(1, Ordering::Relaxed);
        ls.last_trip_at.store(now, Ordering::Relaxed);
    }

    pub(crate) fn record_success_for(&self, pool: &str, lane: usize, now: u64) {
        let ls = self.get_lane(lane);
        // Dead lane: count the success for observability, don't touch the breaker.
        if !ls.dead.load(Ordering::Relaxed) {
            let _ = self.cell(pool, lane).record_success(now);
        }
        ls.ok.add();
    }

    // One cell's hard-down, for the test-only `record_hard_down` trait wrapper.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn record_hard_down_for(&self, pool: &str, lane: usize, reason: &str) {
        let ls = self.get_lane(lane);
        // Hard-down is RECOVERABLE — long sticky cooldown + Open, recovered via the half-open
        // probe; `dead` is NOT set. Per (pool, lane): only the routing pool's view is tripped.
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

// Test-only handles onto the one breaker's cells, for the store's own regression tests.
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
impl HealthState {
    /// Drive the recovery-close gate directly against a named cell with an EXPLICIT
    /// `observed_cooldown` — the interleaving where an unconditional close would clobber a
    /// concurrent hard-down. Returns whether the cell was closed.
    pub(crate) fn recover_close_if_recoverable(
        &self,
        pool: &str,
        lane: usize,
        now: u64,
        observed: u64,
    ) -> bool {
        self.cell(pool, lane).close_if_recoverable(now, observed)
    }

    /// Read a cell's raw `cooldown_until` (no `now` subtraction), for race-regression assertions.
    pub(crate) fn cell_cooldown_until(&self, pool: &str, lane: usize) -> u64 {
        self.cell(pool, lane).cooldown_until()
    }

    /// Put a cell into an exact persisted state (the restore path's own write), for tests whose
    /// precondition is a state rather than the history that leads to it.
    pub(crate) fn force_cell(&self, pool: &str, lane: usize, state: u64, until: u64, streak: u32) {
        self.cell(pool, lane).restore(CellSnapshot {
            state,
            cooldown_until: until,
            streak,
            err: 0,
        });
    }

    /// Park a cell HalfOpen with the single-flight probe won — the precondition under which a
    /// recorded success drives a HalfOpen→Closed recovery. The probe is won the way a dispatch wins
    /// it: an expired Open.
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
