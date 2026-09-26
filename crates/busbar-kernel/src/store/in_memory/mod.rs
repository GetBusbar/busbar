use super::*;

// R5-store: the two health-snapshot carriers are named from their DEFINING crate rather than through
// a `crate::store::…` re-export. They live in `busbar_kernel::store` and this engine — the config-
// apply export/restore path (`export_health`/`restore_health_impl`) — is their only reader left in
// core, so the shim had exactly one caller and is deleted instead of repointed twice.
use busbar_kernel::store::{LaneHealthSnapshot, PoolCellHealthSnapshot};

use crate::diagnostics::{diag_warn, LANE_HARD_DOWN};

mod availability;
mod breaker;
pub(crate) use breaker::*;

// THE ONE BREAKER (item 142). Every cell's state machine is `busbar-kernel-breaker`'s; this store
// holds handles onto its cells and adds only what selection owns (SWRR) and the lane-global facts
// (dead, permits, counters).
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
                .find(|s| s.model == lane.model && s.provider == lane.provider)
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
                self.pool_cell(&cs.pool, idx).fsm.restore(CellSnapshot {
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
pub(crate) type PoolCellMap = std::collections::HashMap<usize, Vec<(Box<str>, Arc<PoolCell>)>>;

/// FNV-1a over a pool name → SWRR shard index. Pure (no `self`) so it can be unit-tested and reused
/// by the per-pool shard memo without duplicating the constants. Distribution, not cryptographic
/// strength, is all that matters: it only picks which lock shard a pool's selections serialize on.
/// `SWRR_SHARDS` is a power of two, so the reduction is a cheap mask.
pub(crate) fn swrr_shard_index(pool: &str) -> usize {
    (fnv1a_u64(pool) as usize) & (SWRR_SHARDS - 1)
}

// `fnv1a_u64` moved to `busbar_kernel::store`.
//
// R5-store: the re-export up through `crate::store` is DELETED — its four readers outside this
// engine (`governance/mod.rs`, `hooks/gate.rs`) name the substrate directly. What stays is a private
// import for this module's own shard-index and key hashing.
use busbar_kernel::store::fnv1a_u64;

/// Number of SWRR lock shards. The SWRR weight read-modify-write only needs to be serialized
/// PER POOL (the `Σ current_weight == 0` invariant is pool-local — two disjoint pools share no
/// `current_weight` cells), so a single global lock needlessly serialized every pool's selection.
/// A fixed shard array keyed by the pool-name hash lets disjoint pools select in parallel; only
/// pools that hash to the same shard contend (rare with this many shards), and the shard array
/// itself needs no allocation or new dependency. A power of two so the modulo is a cheap mask.
pub(crate) const SWRR_SHARDS: usize = 64;

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
    /// Sharded SWRR locks (see `SWRR_SHARDS`). A selection serializes only against other selections
    /// whose pool hashes to the same shard, so concurrent selections for disjoint pools run in
    /// parallel. Boxed slice so the struct stays movable without a const-generic array literal.
    pub(crate) swrr_shards: Box<[std::sync::Mutex<()>]>,
    /// THE ONE BREAKER (item 142): every cell's state machine, every lane's lifetime request budget
    /// (`max_requests`, declared once through `set_budget`), and the two `limits.*` knobs
    /// (`with_limits`). The cells above are handles onto its cells, never copies of them.
    pub(crate) unit: Arc<BreakerUnit>,
    /// Memoized pool-name → shard-index map. `swrr_shard` ran FNV-1a over the pool NAME on EVERY
    /// selection (the hot dispatch path); the index is a pure function of the (small, stable) set of
    /// pool names, so cache it on first touch and reuse thereafter. An append-only `Vec` scanned by
    /// byte-compare (the same idiom as `cell()`) — NOT a `HashMap`, whose SipHash lookup would cost
    /// more than the FNV it replaces. The cached value is identical to recomputing `swrr_shard_index`,
    /// so selection semantics are unchanged. `RwLock`: the common case is a shared-read hit; only a
    /// genuine first-touch miss takes the exclusive write lock to insert.
    pub(crate) pool_shards: std::sync::RwLock<Vec<(Box<str>, usize)>>,
}

// Field ORDER is perf-deliberate (hot-path cache locality): the per-request atomics are grouped
// into one cluster so a dispatch decision (dead check → SWRR weight → breaker CAS → outcome
// counter) touches 1-2 cache lines instead of hopping over the Strings and Mutex blocks that used
// to interleave them. Boot-time read-only fields lead; Mutex-guarded cold state trails. Pure
// layout change — every constructor uses named fields, so semantics are untouched.
pub(crate) struct LaneState {
    // ── read-only after boot ──
    pub(crate) model: String,
    pub(crate) provider: String,
    pub(crate) max: usize,
    pub(crate) sem: Arc<Semaphore>,
    // The lane's `max_requests` budget: the one breaker's own counter for this destination, shared.
    pub(crate) budget: Arc<LifetimeBudget>,
    // The lane-default (`""` pool) cell: the one breaker's own cell for this destination, shared.
    pub(crate) cell: Arc<FsmCell>,
    // ── hot per-request atomics (keep contiguous) ──
    pub(crate) dead: AtomicBool,
    // SWRR state per lane
    pub(crate) swrr: SwrrStripes,
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
    #[cfg(any(test, feature = "test-support"))]
    #[allow(dead_code)]
    pub(crate) fn cell_err_for_test(&self, pool: &str, lane: usize) -> u64 {
        self.cell(pool, lane).fsm().err_count()
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
                    model: ld.model,
                    provider: ld.provider,
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
                    swrr: SwrrStripes::new(),
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
            swrr_shards: (0..SWRR_SHARDS)
                .map(|_| std::sync::Mutex::new(()))
                .collect(),
            pool_shards: std::sync::RwLock::new(Vec::new()),
        }
    }

    /// Construct with PRIOR HEALTH STATE restored by stable lane identity: each lane whose
    /// (model, provider) appears in `restored` starts with that snapshot's breaker/cooldown/streak/
    /// hard-down/latency/counters instead of fresh state — the carry-over that makes a lane-set
    /// config APPLY (and, via the persistence layer, a restart) preserve learned reliability.
    /// Matching is by IDENTITY, never position, so added/removed/reordered lanes are immune to the
    /// index-shift misattribution this design exists to prevent. Unmatched snapshots are dropped
    /// (their lane no longer exists); unmatched lanes start fresh (they are new). `LaneData`
    /// baseline fields (budget/cooldown/streak/dead/counters) are OVERRIDDEN by a matching
    /// snapshot — the snapshot IS the live truth the previous store held; per-pool cells are
    /// re-created eagerly so a restored Open cell blocks dispatch from the first request.
    // Bin-target consumer is the config-apply core (next slice); the carry-over tests use it now.
    #[allow(dead_code)]
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

    /// Select the SWRR shard lock for a pool. The shard is keyed by the pool-name hash so all
    /// selections for a given pool serialize against each other (preserving the pool-local
    /// `Σ current_weight == 0` invariant), while selections for pools hashing to other shards run in
    /// parallel. `SWRR_SHARDS` is a power of two, so the index is a cheap mask.
    pub(crate) fn swrr_shard(&self, pool: &str) -> &std::sync::Mutex<()> {
        // Fast path: the pool's shard index was computed once on its first selection and memoized,
        // so subsequent selections reuse it WITHOUT re-running FNV-1a over the name on every call.
        // Shared read lock — concurrent selections for already-seen pools don't block each other.
        {
            let cache = read_recover(&self.pool_shards);
            if let Some((_, idx)) = cache.iter().find(|(p, _)| p.as_ref() == pool) {
                return &self.swrr_shards[*idx];
            }
        }
        // First-touch miss: compute and insert under the exclusive write lock. Re-check first — a
        // racing selection for the same pool may have inserted between the read miss and this acquire.
        let idx = swrr_shard_index(pool);
        let mut cache = write_recover(&self.pool_shards);
        if !cache.iter().any(|(p, _)| p.as_ref() == pool) {
            cache.push((Box::from(pool), idx));
        }
        // The cached value equals `idx` regardless of which writer won, so index by the just-computed
        // value (identical shard selection to the old direct-FNV path).
        &self.swrr_shards[idx]
    }

    /// Resolve the breaker cell for a (pool, lane). An empty pool name selects the lane-global
    /// default cell (the `LaneState` itself) — used by direct/ad-hoc routes. A named pool gets a
    /// dedicated [`PoolCell`], created on first access.
    pub(crate) fn cell(&self, pool: &str, lane: usize) -> Arc<dyn CellRef> {
        if pool.is_empty() {
            return self.lanes[lane].clone();
        }
        self.pool_cell(pool, lane)
    }

    /// A named pool's cell. Fast path: a SHARED read lock and a lookup with no key allocation —
    /// the cell almost always exists (created once, on the pool's first request). Only a genuine
    /// first-touch miss takes the write lock.
    pub(crate) fn pool_cell(&self, pool: &str, lane: usize) -> Arc<PoolCell> {
        let _t = busbar_timing::timeit!("store_cell_lookup");
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
        let fsm = self
            .unit
            .cell_seeded(pool, lane_destination(lane), |fresh| {
                fresh.restore(CellSnapshot {
                    err: 0,
                    ..self.lanes[lane].cell.snapshot()
                })
            });
        let c = Arc::new(PoolCell {
            fsm,
            swrr: SwrrStripes::new(),
        });
        per_lane.push((Box::from(pool), c.clone()));
        c
    }

    /// Reset a recovered cell's SWRR accumulator to 0 — a LOCK-FREE generational bump.
    ///
    /// While the member was tripped it was dropped from the healthy set in `select_weighted_for` and
    /// stopped receiving fetch_add/fetch_sub, freezing its `current_weight` at a stale value. On
    /// recovery it rejoins selection; carrying that stale value biases the first few selections and
    /// violates the `Σ current_weight == 0` invariant over the (now-changed) healthy set. Each
    /// stripe zeroes itself the next time its OWNING worker touches it (`SwrrStripes::slot`).
    /// `_pool` kept for signature stability at the call sites.
    pub(crate) fn reset_swrr_for(&self, _pool: &str, c: &dyn CellRef) {
        c.swrr().reset();
    }

    /// Transition the default cell Open with an escalated cooldown (test handle).
    #[cfg(any(test, feature = "test-support"))]
    #[allow(dead_code)]
    pub(crate) fn open_state(&self, lane: usize, now_time: u64, cfg: &BreakerCfg) {
        self.open_state_with_retry_after(lane, now_time, cfg, None);
    }

    /// Transition the default cell Open with an escalated cooldown and optional Retry-After floor.
    #[cfg(any(test, feature = "test-support"))]
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

    /// Transition the default cell to Closed, then reset its SWRR accumulator — the production
    /// recovery path's two steps (test handle).
    #[cfg(any(test, feature = "test-support"))]
    #[allow(dead_code)]
    pub(crate) fn closed_state(&self, lane: usize, _now_time: u64) {
        let cell = self.get_lane(lane);
        cell.cell.close();
        self.reset_swrr_for("", cell.as_ref());
    }
}

#[derive(Clone)]
pub struct LaneData {
    pub(crate) model: String,
    pub(crate) provider: String,
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
    /// Optional upstream model name override. When set, this value is sent to the provider as the
    /// model identifier in the request body and URL path, instead of `self.model` (the config key).
    pub(crate) upstream_model: Option<String>,
    /// Model-level per-attempt time-to-headers cap (ms); flows ModelCfg → LaneData → Lane.
    pub(crate) attempt_timeout_ms: Option<u64>,
    /// Operator-declared reasoning-capability flag (see `ModelCfg::reasoning`).
    pub(crate) reasoning: bool,
    /// Operator-declared prompt-caching capability flag (see `ModelCfg::prompt_caching`).
    pub(crate) prompt_caching: bool,
}

#[cfg(any(test, feature = "test-support"))]
impl LaneData {
    /// TEST-SUPPORT constructor: a minimal live lane (alive, unlimited budget, zero counters) with
    /// the given model/provider/permit count — the shape the relocated probe-guard tests need. Gated
    /// to the test-support surface so the plane's tests reach a `LaneData` through this public seam
    /// instead of a cross-crate struct literal over its private fields.
    pub fn for_test(model: &str, provider: &str, max: usize) -> Self {
        LaneData {
            reasoning: false,
            prompt_caching: false,
            model: model.into(),
            provider: provider.into(),
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
            upstream_model: None,
            attempt_timeout_ms: None,
        }
    }
}

/// Helper for weighted selection tests - creates a lane with specific weight.
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
pub(crate) fn make_lane_data_with_weight(id: usize, max_permits: usize) -> (LaneData, u32) {
    let lane = LaneData {
        model: format!("lane-{}", id),
        provider: format!("provider-{}", id),
        max: max_permits,
        sem: Arc::new(Semaphore::new(max_permits)),
        limited: false,
        budget: -1,
        cooldown_until: 0,
        streak: 0,
        dead: false,
        dead_reason: String::new(),
        ok: 0,
        err: 0,
        client_fault: 0,
        upstream_model: None,
        attempt_timeout_ms: None,
        reasoning: false,
        prompt_caching: false,
    };
    (lane, (id as u32) + 1) // weight = id + 1 (so lane 0 has weight 1, lane 1 has weight 2, etc.)
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
pub(crate) fn breaker_cfg_to_runtime(cfg: &crate::config::BreakerCfg) -> BreakerCfg {
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
            && !matches!(
                self.cell(pool, lane).fsm().acquire(now),
                ProbeAdmit::Denied(_)
            )
    }

    /// Side-effect-FREE readiness check (lane-global gates + a non-mutating breaker peek). Shared
    /// body for both `is_ready` (test-gated) and `ready_in` (production-wired via the routing
    /// policy's ordered walk).
    pub(crate) fn ready_for(&self, pool: &str, lane: usize, now: u64) -> bool {
        self.lane_admissible(lane) && self.cell(pool, lane).fsm().ready(now)
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
        to_state(self.cell(pool, lane).fsm().state())
    }

    pub(crate) fn cooldown_remaining_for(&self, pool: &str, lane: usize, now: u64) -> u64 {
        self.cell(pool, lane)
            .fsm()
            .cooldown_until()
            .saturating_sub(now)
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
                per_lane.iter().any(|(_, cell)| cell.fsm.ready(now))
            }
            _ => self.get_lane(lane).cell.ready(now),
        }
    }

    /// Worst-case remaining cooldown across the default cell and every per-pool cell for the lane.
    pub(crate) fn lane_max_cooldown_remaining(&self, lane: usize, now: u64) -> u64 {
        let cells = read_recover(&self.pool_cells);
        cells
            .get(&lane)
            .into_iter()
            .flatten()
            .map(|(_, c)| c.fsm.cooldown_until())
            .fold(self.get_lane(lane).cell.cooldown_until(), u64::max)
            .saturating_sub(now)
    }

    /// Worst-case consecutive-failure streak across the default cell and every per-pool cell.
    pub(crate) fn lane_max_streak(&self, lane: usize) -> u32 {
        let cells = read_recover(&self.pool_cells);
        cells
            .get(&lane)
            .into_iter()
            .flatten()
            .map(|(_, c)| c.fsm.streak())
            .fold(self.get_lane(lane).cell.streak(), u32::max)
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
            .fsm()
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

    pub(crate) fn record_success_for(&self, pool: &str, lane: usize) {
        let ls = self.get_lane(lane);
        // Dead lane: count the success for observability, don't touch the breaker.
        if !ls.dead.load(Ordering::Relaxed) {
            let cell = self.cell(pool, lane);
            // A HalfOpen→Closed recovery re-admits this cell to selection with a zeroed accumulator.
            if cell.fsm().record_success(Self::now_secs()) {
                self.reset_swrr_for(pool, cell.as_ref());
            }
        }
        ls.ok.add();
    }

    // Production callers: the test-only `record_hard_down` trait wrapper, and
    // `store::planes::PlaneBreakers::record_signal` — a secondary plane consumer's hard-down is PER
    // CELL by design (their degenerate cells share one lane index, so the all-cells primitive would
    // trip every other registered target). With BOTH planes compiled out that consumer is
    // vestigial, so this reads dead in a non-test both-off build alone.
    #[allow(dead_code)]
    pub(crate) fn record_hard_down_for(&self, pool: &str, lane: usize, reason: &str) {
        let ls = self.get_lane(lane);
        // Hard-down is RECOVERABLE — long sticky cooldown + Open, recovered via the half-open
        // probe; `dead` is NOT set. Per (pool, lane): only the routing pool's view is tripped.
        *lock_recover(&ls.dead_reason) = reason.to_string();
        diag_warn!(
            LANE_HARD_DOWN,
            model = %ls.model,
            reason,
            cooldown_secs = self.unit.hard_down_cooldown_secs(),
            "lane hard-down; sticky cooldown (recovers via half-open probe)"
        );
        let now_secs = Self::now_secs();
        if self
            .cell(pool, lane)
            .fsm()
            .hard_down(now_secs, self.unit.hard_down_cooldown_secs())
        {
            self.count_trip(ls, now_secs);
        }
    }

    pub(crate) fn select_weighted_for(
        &self,
        pool: &str,
        candidates: &[usize],
        weights: &[u32],
        now: u64,
    ) -> Option<usize> {
        // Filter to usable members and build (lane_idx, cell, effective_weight). The filter uses
        // the side-effect-FREE readiness check: a candidate enumeration must NOT transition lanes
        // Open→HalfOpen or steal the single-flight probe (the dispatched lane does that once, in
        // pick_among). We fetch the cell exactly once per candidate here (one pool_cells lock,
        // not the two a usable+re-cell pattern took) and reuse the Arc for the readiness peek.
        let mut healthy: Vec<(usize, Arc<dyn CellRef>, i64)> = Vec::with_capacity(candidates.len());
        for (&candidate, &weight) in candidates.iter().zip(weights.iter()) {
            // weight == 0 means "drain": never select this member. config.rs permits `weight: 0`
            // with no `weight > 0` validation, and without this filter an all-zero-weight healthy set
            // gives `total == 0`, every `fetch_add(0)` leaves `current_weight` unchanged, and the
            // max-finder degenerates to always picking the first candidate — so a member weighted to
            // 0 still receives (all) traffic. Excluding it here honors the drain intent and keeps the
            // SWRR proportional-distribution invariant exact over the remaining members.
            if weight == 0 {
                continue;
            }
            if !self.lane_admissible(candidate) {
                continue;
            }
            let cell = self.cell(pool, candidate);
            if cell.fsm().ready(now) {
                healthy.push((candidate, cell, weight as i64));
            }
        }
        if healthy.is_empty() {
            return None;
        }

        // Smooth weighted round-robin over the healthy subset, on THIS THREAD'S STRIPE of each
        // cell's per-worker SWRR state. A data worker's add/find-max/subtract runs on slots only
        // it ever writes — one logical step by single-writer construction, NO lock, no cross-core
        // weight ping-pong. Per-worker SWRR over the same config weight ratios preserves the
        // global distribution (each stripe emits the classic proportional sequence; a sum of
        // proportional streams is proportional), and the per-stripe `Σ == 0` invariant replaces
        // the old pool-global one. Only the shared FALLBACK stripe (non-worker threads: tests,
        // embedded callers) still serializes under the pool's shard lock — the exact pre-stripe
        // discipline, because multiple threads share that one stripe.
        let stripes = crate::state::worker_stripes();
        let stripe = crate::state::worker_stripe(stripes);
        let _swrr = (stripe == stripes - 1).then(|| lock_recover(self.swrr_shard(pool)));
        let total: i64 = healthy.iter().map(|(_, _, w)| *w).sum();
        // Each cell's stripe slot is resolved through `slot()` EXACTLY ONCE per selection, so the
        // reset GENERATION is observed at exactly one point per cell. `slot()` lazily zeroes a
        // stale-generation slot, and the first cut re-resolved it for each of the add, the
        // find-max load, and the compensating subtract — so a recovery `reset()` landing between
        // the add and the subtract zeroed the accumulator MID-SEQUENCE and the subtract then
        // drove the stripe to `-total`, breaking the per-stripe `Σ == 0` invariant and starving
        // the just-recovered cell until the skew washed out. With one resolution, a reset that
        // lands mid-selection is simply not observed until the NEXT selection's `slot()` call —
        // which zeroes the stripe whole, exactly the rejoin-from-0 the reset means.
        let slots: Vec<&AtomicI64> = healthy
            .iter()
            .map(|(_, cell, _)| cell.swrr().slot(stripe))
            .collect();
        for ((_, _, eff_wt), slot) in healthy.iter().zip(&slots) {
            slot.fetch_add(*eff_wt, Ordering::Relaxed);
        }
        let mut best: Option<usize> = None;
        let mut best_weight = i64::MIN;
        for (i, slot) in slots.iter().enumerate() {
            let cw = slot.load(Ordering::Relaxed);
            if cw > best_weight {
                best_weight = cw;
                best = Some(i);
            }
        }
        if let Some(i) = best {
            slots[i].fetch_sub(total, Ordering::Relaxed);
        }
        best.map(|i| healthy[i].0)
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
        self.cell(pool, lane)
            .fsm()
            .close_if_recoverable(now, observed)
    }

    /// Read a cell's raw `cooldown_until` (no `now` subtraction), for race-regression assertions.
    pub(crate) fn cell_cooldown_until(&self, pool: &str, lane: usize) -> u64 {
        self.cell(pool, lane).fsm().cooldown_until()
    }

    /// Put a cell into an exact persisted state (the restore path's own write), for tests whose
    /// precondition is a state rather than the history that leads to it.
    pub(crate) fn force_cell(&self, pool: &str, lane: usize, state: u64, until: u64, streak: u32) {
        self.cell(pool, lane).fsm().restore(CellSnapshot {
            state,
            cooldown_until: until,
            streak,
            err: 0,
        });
    }

    /// Park a named cell HalfOpen with the single-flight probe won and a STALE SWRR accumulator —
    /// the precondition under which a recorded success drives a HalfOpen→Closed recovery whose reset
    /// the caller is responsible for. The probe is won the way a dispatch wins it: an expired Open.
    pub(crate) fn arm_half_open_stale_swrr(
        &self,
        pool: &str,
        lane: usize,
        cooldown: u64,
        stale_weight: i64,
    ) {
        let c = self.cell(pool, lane);
        c.swrr().force(stale_weight);
        c.fsm().restore(CellSnapshot {
            state: 1,
            cooldown_until: cooldown,
            streak: 0,
            err: 0,
        });
        let _ = c.fsm().acquire(cooldown);
    }

    /// Read a cell's whole SWRR accumulator (live stripes summed), for the invariant assertion.
    pub(crate) fn cell_current_weight(&self, pool: &str, lane: usize) -> i64 {
        self.cell(pool, lane).swrr().sum()
    }
}
