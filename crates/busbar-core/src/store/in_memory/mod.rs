use super::*;

use crate::diagnostics::{diag_warn, LANE_HARD_DOWN};

mod availability;
mod breaker;
pub(crate) use breaker::*;

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
            if lane.limited && snap.budget >= 0 {
                let new_cap = lane.budget.load(Ordering::Relaxed);
                lane.budget
                    .store(snap.budget.min(new_cap), Ordering::Relaxed);
            }
            lane.breaker_state.store(
                restored_breaker_state(snap.breaker_state),
                Ordering::Relaxed,
            );
            lane.cooldown_until
                .store(snap.cooldown_until, Ordering::Relaxed);
            lane.streak.store(snap.streak, Ordering::Relaxed);
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
            let mut map = self.pool_cells.write().unwrap_or_else(|e| e.into_inner());
            let cells = map.entry(idx).or_default();
            for cs in &snap.cells {
                // In-place restore may find the cell already lazily created — restore INTO it.
                if let Some((_, cell)) = cells.iter().find(|(p, _)| p.as_ref() == cs.pool) {
                    cell.breaker_state
                        .store(restored_breaker_state(cs.breaker_state), Ordering::Relaxed);
                    cell.cooldown_until
                        .store(cs.cooldown_until, Ordering::Relaxed);
                    cell.streak.store(cs.streak, Ordering::Relaxed);
                    cell.err.store(cs.err, Ordering::Relaxed);
                } else {
                    let cell = Arc::new(BreakerCell::new());
                    cell.breaker_state
                        .store(restored_breaker_state(cs.breaker_state), Ordering::Relaxed);
                    cell.cooldown_until
                        .store(cs.cooldown_until, Ordering::Relaxed);
                    cell.streak.store(cs.streak, Ordering::Relaxed);
                    cell.err.store(cs.err, Ordering::Relaxed);
                    cells.push((cs.pool.clone().into_boxed_str(), cell));
                }
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
pub(crate) type PoolCellMap = std::collections::HashMap<usize, Vec<(Box<str>, Arc<BreakerCell>)>>;

/// FNV-1a over a pool name → SWRR shard index. Pure (no `self`) so it can be unit-tested and reused
/// by the per-pool shard memo without duplicating the constants. Distribution, not cryptographic
/// strength, is all that matters: it only picks which lock shard a pool's selections serialize on.
/// `SWRR_SHARDS` is a power of two, so the reduction is a cheap mask.
pub(crate) fn swrr_shard_index(pool: &str) -> usize {
    (fnv1a_u64(pool) as usize) & (SWRR_SHARDS - 1)
}

/// FNV-1a 64-bit offset-basis and prime (the canonical constants). Module-level so both the string
/// hash (`fnv1a_u64`) and the cooldown-jitter seed mixer (which folds 128-bit inputs with the same
/// FNV step) share one named definition instead of repeating the bare magic literals.
pub(crate) const FNV1A_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
pub(crate) const FNV1A_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Deterministic FNV-1a 64-bit hash of a string's bytes. Stable across processes/restarts (unlike
/// the std `DefaultHasher`, whose seed is randomized), so callers that need a process-independent
/// hash (SWRR shard selection, session affinity) get identical results everywhere. Distribution,
/// not cryptographic strength, is all that matters.
pub fn fnv1a_u64(s: &str) -> u64 {
    let mut hash = FNV1A_OFFSET_BASIS;
    for &byte in s.as_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV1A_PRIME);
    }
    hash
}

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
    /// Operator-configured hard-down sticky cooldown (seconds). Replaces the historical
    /// `HARD_DOWN_COOLDOWN_SECS` const at every hard-down trip; defaults to 1800 when the operator
    /// omits `limits.hard_down_cooldown_secs`.
    pub(crate) hard_down_cooldown_secs: u64,
    /// Operator-configured ceiling (seconds) on a honored upstream `Retry-After`. Replaces the
    /// historical `MAX_HONORED_RETRY_AFTER_SECS` const in `compute_cooldown_with_retry_after`;
    /// defaults to 86_400 (24h). Bounds a hostile/buggy `Retry-After` so it cannot park a lane for
    /// millennia or overflow the cooldown arithmetic.
    pub(crate) max_honored_retry_after_secs: u64,
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
    pub(crate) limited: bool,
    // ── hot per-request atomics (keep contiguous) ──
    pub(crate) dead: AtomicBool,
    // FSM state per lane
    pub(crate) breaker_state: AtomicU64, // stored as u64 (ST_CLOSED/ST_OPEN/ST_HALF_OPEN) so it can be CAS'd
    pub(crate) probe_in_flight: AtomicBool,
    // Single-flight probe owner token - see `BreakerCell::probe_epoch`.
    pub(crate) probe_epoch: AtomicU64,
    // SWRR state per lane
    pub(crate) swrr: SwrrStripes,
    pub(crate) cooldown_until: AtomicU64,
    pub(crate) budget: AtomicI64,
    pub(crate) streak: AtomicU32,
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
    pub(crate) outcome_window: std::sync::Mutex<OutcomeWindow>,
    // Serializes state+cooldown transitions on the default cell — see `BreakerCell::transition_lock`.
    pub(crate) transition_lock: std::sync::Mutex<()>,
}

/// Smoothing factor (α) for the per-lane latency EWMA: `ewma = α·sample + (1-α)·ewma`. A smaller α
/// gives a longer memory (steadier signal, slower to react); 0.2 weights the most recent ~5 requests
/// most heavily, which is responsive enough to notice a degrading upstream without thrashing the
/// `fastest` ranking on a single slow outlier. Cheap, bounded, allocation-free.
pub(crate) const LATENCY_EWMA_ALPHA: f64 = 0.2;

impl HealthState {
    /// Read a (pool, lane) cell's cumulative error counter — for concurrency/isolation tests.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn cell_err_for_test(&self, pool: &str, lane: usize) -> u64 {
        self.cell(pool, lane).err().load(Ordering::Relaxed)
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
        let lane_states: Vec<Arc<LaneState>> = lanes
            .into_iter()
            .map(|ld| {
                Arc::new(LaneState {
                    model: ld.model,
                    provider: ld.provider,
                    max: ld.max,
                    sem: ld.sem,
                    limited: ld.limited,
                    budget: AtomicI64::new(ld.budget),
                    cooldown_until: AtomicU64::new(ld.cooldown_until),
                    streak: AtomicU32::new(ld.streak),
                    dead: AtomicBool::new(ld.dead),
                    dead_reason: std::sync::Mutex::new(ld.dead_reason),
                    ok: StripedCounter::new(ld.ok),
                    err: AtomicU64::new(ld.err),
                    client_fault: AtomicU64::new(ld.client_fault),
                    breaker_state: AtomicU64::new(ST_CLOSED),
                    probe_in_flight: AtomicBool::new(false),
                    probe_epoch: AtomicU64::new(0),
                    outcome_window: std::sync::Mutex::new(OutcomeWindow::new(
                        OUTCOME_WINDOW_CAPACITY,
                    )),
                    swrr: SwrrStripes::new(),
                    transition_lock: std::sync::Mutex::new(()),
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
            hard_down_cooldown_secs,
            max_honored_retry_after_secs,
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
    /// dedicated `BreakerCell`, created Closed on first access.
    pub(crate) fn cell(&self, pool: &str, lane: usize) -> Arc<dyn BreakerCellAccess> {
        let _t = busbar_timing::timeit!("store_cell_lookup");
        if pool.is_empty() {
            return self.lanes[lane].clone();
        }
        // Fast path: the cell almost always already exists (it is created once, on the pool's first
        // request, then read on every subsequent dispatch). Take a SHARED read lock and look it up
        // WITHOUT allocating a `Box<str>` key — concurrent readers don't block each other, and the
        // hot path does zero heap allocation. Only a genuine first-touch miss falls through to the
        // exclusive write lock below.
        {
            let cells = read_recover(&self.pool_cells);
            // O(1) lane lookup, then a scan bounded by #pools-on-this-lane (typically tiny) with no
            // owned-key allocation — never the full pools×lanes cross-product.
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
        // A new pool cell inherits the lane's current known health (breaker state + pending cooldown
        // + streak) rather than blindly assuming Closed — so a pool whose first request arrives while
        // the lane is mid-cooldown respects it. In production cells are created while the lane is
        // healthy, so this is normally a no-op.
        let ls = &self.lanes[lane];
        let c = BreakerCell::new();
        // Normalize an inherited HalfOpen to Open. HalfOpen encodes "some cell owns the single-flight
        // probe right now" — but `probe_in_flight` lives on the cell that won it, NOT on this freshly-
        // created sibling (born with `probe_in_flight == false`). A sibling cell born ST_HALF_OPEN is
        // wedged: both `cell_ready_breaker` and `cell_acquire_breaker` return false unconditionally
        // for HalfOpen, and no probe outcome (cell_open/cell_closed) ever runs against it, so it never
        // self-recovers — organic traffic to this (pool, lane) is benched until an out-of-band
        // recover_lane happens to touch it (indefinitely when health probing is disabled). Storing
        // Open instead lets the inherited (already-expired) cooldown drive a fresh probe acquisition
        // on this cell's first request. The Open+cooldown inheritance below is still honored verbatim
        // so a sibling created mid-cooldown respects it.
        let inherited = ls.breaker_state.load(Ordering::Acquire);
        let normalized = if inherited == ST_HALF_OPEN {
            ST_OPEN
        } else {
            inherited
        };
        c.breaker_state.store(normalized, Ordering::Release);
        c.cooldown_until
            .store(ls.cooldown_until.load(Ordering::Acquire), Ordering::Release);
        c.streak
            .store(ls.streak.load(Ordering::Relaxed), Ordering::Relaxed);
        let c = Arc::new(c);
        per_lane.push((Box::from(pool), c.clone()));
        c
    }

    // ── Generic breaker-FSM core ──────────────────────────────────────────────────────────────
    // These operate on any `&dyn BreakerCellAccess` so the exact same logic runs against a
    // `LaneState` (the default/direct-route cell) or a per-pool `BreakerCell`. The `&self, lane`
    // and `_in(pool, lane)` methods are thin wrappers that resolve the right cell and delegate.

    /// Reset a recovered cell's SWRR accumulator to 0 — a LOCK-FREE generational bump (see below;
    /// no shard lock is taken here or needed).
    ///
    /// While the member was tripped it was dropped from the healthy set in `select_weighted_for` and
    /// stopped receiving fetch_add/fetch_sub, freezing its `current_weight` at a stale value. On
    /// recovery it rejoins selection; carrying that stale value biases the first few selections and
    /// violates the `Σ current_weight == 0` invariant over the (now-changed) healthy set.
    ///
    /// GENERATIONAL since the per-worker striping: the reset is one generation bump on the cell,
    /// and each stripe zeroes itself the next time its OWNING worker touches it (`SwrrStripes::
    /// slot`) — race-free against lock-free in-flight worker selections by single-writer
    /// construction, with no shard lock needed here at all (the old eager `store(0)` under the
    /// shard lock could not serialize against workers that no longer take that lock). `_pool` kept
    /// for signature stability at the call sites.
    pub(crate) fn reset_swrr_for(&self, _pool: &str, c: &dyn BreakerCellAccess) {
        c.swrr().reset();
    }

    // ── Thin lane-default wrappers ─────────────────────────────────────────────────────────────
    // These drive the breaker FSM by lane index against the default cell. Release code goes through
    // the cell-core fns directly (cell_open / cell_closed / cell_usable_breaker), so these exist
    // only to give the unit tests a concrete, lane-indexed handle — hence `#[cfg(test)]`.

    /// Attempt to acquire the single probe in HalfOpen state. True if this request wins the probe.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn try_acquire_probe(&self, lane: usize) -> bool {
        self.get_lane(lane)
            .probe_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Clear the probe flag (called after probe completes).
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn clear_probe(&self, lane: usize) {
        self.get_lane(lane)
            .probe_in_flight
            .store(false, Ordering::Release);
    }

    /// Transition to Open state with escalated cooldown.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn open_state(&self, lane: usize, now_time: u64, cfg: &BreakerCfg) {
        Self::cell_open(
            self.get_lane(lane).as_ref(),
            now_time,
            cfg,
            None,
            self.max_honored_retry_after_secs,
        );
    }

    /// Transition to Open state with escalated cooldown and optional Retry-After floor.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn open_state_with_retry_after(
        &self,
        lane: usize,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) {
        Self::cell_open(
            self.get_lane(lane).as_ref(),
            now_time,
            cfg,
            retry_after,
            self.max_honored_retry_after_secs,
        );
    }

    /// Transition to Closed state (probe success). Mirrors the production recovery path: close the
    /// cell, then reset its SWRR accumulator (the lock-free generational bump).
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn closed_state(&self, lane: usize, _now_time: u64) {
        let cell = self.get_lane(lane);
        Self::cell_closed(cell.as_ref());
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
pub(crate) fn make_lane_data_with_weight(id: usize, max_permits: usize) -> (LaneData, u32) {
    let lane = LaneData {
        model: format!("model-{}", id),
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

/// Breaker configuration per pool.
#[derive(Debug, Clone)]
pub struct BreakerCfg {
    pub base_cooldown_secs: u64,
    pub max_cooldown_secs: u64,
    pub honor_retry_after: bool,
    pub trip: TripConfig,
    /// Whether a transient failure that did NOT breach the trip threshold still benches the cell
    /// for a cooldown.
    ///
    /// ADR-0002 states the sub-threshold rule as one sentence with two halves: on
    /// `TransientUpstream`, "drive trip evaluation ... and re-arm an exponential cooldown; **fail
    /// over** to the next candidate". The cooldown is the DEPRIORITISATION half of a selection walk
    /// — "prefer a sibling for a while" — and the failover half is what keeps the caller served
    /// while it lasts. On a pool with siblings that is right, and this stays `true` there.
    ///
    /// A DEGENERATE SINGLE-MEMBER CELL HAS NO SIBLING, and on the MCP client leg and the A2A relay
    /// there is no walk at all (`docs/circuit-breaker.md`: "on a live tool call or task submission
    /// no second candidate is tried today — a tripped target is refused, never rerouted"). There,
    /// the identical store means "refuse every caller of this server for the next 15-120s", handed
    /// out after ONE blip and announced as "open after repeated failures" — a sentence the cell's
    /// own `should_trip` had just refused to make true. So those cells set this `false` and refuse
    /// only on a real trip, on the thresholds ADR-0002 and `docs/circuit-breaker.md` publish.
    pub bench_below_trip_threshold: bool,
}

impl Default for BreakerCfg {
    fn default() -> Self {
        Self {
            base_cooldown_secs: 15,
            max_cooldown_secs: 120,
            honor_retry_after: true, // default to honoring Retry-After header
            trip: TripConfig::default(),
            // The LLM plane's pools, which is what every `Default` here builds, DO fail over.
            bench_below_trip_threshold: true,
        }
    }
}

impl From<&crate::config::BreakerCfg> for BreakerCfg {
    /// Resolve the parsed config into the runtime breaker config the FSM evaluates.
    /// `honor_retry_after` has no config knob (always honored), and an absent `trip` block
    /// falls back to the ADR-0002 defaults.
    fn from(c: &crate::config::BreakerCfg) -> Self {
        let trip = c
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
        Self {
            base_cooldown_secs: c.base_cooldown_secs,
            max_cooldown_secs: c.max_cooldown_secs,
            honor_retry_after: true,
            trip,
            // `pools.<pool>.breaker:` is the LLM plane's only breaker surface, and that plane walks
            // its members. The plane cells do not parse config (see `PlaneBreakers::new`).
            bench_below_trip_threshold: true,
        }
    }
}

impl BreakerCfg {
    /// Flatten this RESOLVED runtime breaker cfg into the neutral carrier the LLM plane's
    /// `build_runtime` reconstructs from (money-path Phase 3-4 C). Lossless over every field the FSM
    /// reads. `honor_retry_after`/`bench_below_trip_threshold` are always `true` on the LLM path (see
    /// `From<&config::BreakerCfg>`), carried anyway so a future divergence cannot silently drop.
    pub fn to_llm(&self) -> busbar_substrate::plane_host::LlmBreakerInput {
        busbar_substrate::plane_host::LlmBreakerInput {
            base_cooldown_secs: self.base_cooldown_secs,
            max_cooldown_secs: self.max_cooldown_secs,
            honor_retry_after: self.honor_retry_after,
            bench_below_trip_threshold: self.bench_below_trip_threshold,
            trip: busbar_substrate::plane_host::LlmTripInput {
                mode: match self.trip.mode {
                    TripMode::ErrorRate => busbar_substrate::plane_host::LlmTripMode::ErrorRate,
                    TripMode::Consecutive => busbar_substrate::plane_host::LlmTripMode::Consecutive,
                },
                window_s: self.trip.window_s,
                threshold: self.trip.threshold,
                min_requests: self.trip.min_requests,
                consecutive_n: self.trip.consecutive_n,
            },
        }
    }

    /// Reconstruct the runtime breaker cfg from the neutral carrier — the inverse of [`to_llm`], called
    /// IN-PLANE by the LLM plane's `build_runtime` (the allowed plane→core edge; the plane names only
    /// this pub constructor and the neutral input type, never a private `BreakerCfg`/`TripConfig` field).
    ///
    /// [`to_llm`]: Self::to_llm
    pub fn from_llm(i: &busbar_substrate::plane_host::LlmBreakerInput) -> Self {
        Self {
            base_cooldown_secs: i.base_cooldown_secs,
            max_cooldown_secs: i.max_cooldown_secs,
            honor_retry_after: i.honor_retry_after,
            bench_below_trip_threshold: i.bench_below_trip_threshold,
            trip: TripConfig {
                mode: match i.trip.mode {
                    busbar_substrate::plane_host::LlmTripMode::ErrorRate => TripMode::ErrorRate,
                    busbar_substrate::plane_host::LlmTripMode::Consecutive => TripMode::Consecutive,
                },
                window_s: i.trip.window_s,
                threshold: i.trip.threshold,
                min_requests: i.trip.min_requests,
                consecutive_n: i.trip.consecutive_n,
            },
        }
    }
}

/// Trip configuration mode.
#[derive(Debug, Clone)]
pub enum TripMode {
    ErrorRate,
    Consecutive,
}

/// Trip configuration parameters (ADR-0002 defaults).
#[derive(Debug, Clone)]
pub struct TripConfig {
    pub mode: TripMode,
    pub window_s: u64,
    pub threshold: f64,
    pub min_requests: usize,
    pub consecutive_n: u32, // For consecutive mode
}

/// The window (seconds) the `Signal::CandidateErrorRate` catalog entry reads the
/// breaker's existing outcome window over — matches [`TripConfig::default`]'s own `window_s` so
/// the projected error rate reads over the same horizon the default breaker trip mode does.
pub(crate) const DEFAULT_ERROR_RATE_WINDOW_S: u64 = 30;

impl Default for TripConfig {
    fn default() -> Self {
        Self {
            mode: TripMode::ErrorRate,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            consecutive_n: 3, // 3 consecutive errors
        }
    }
}

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

    /// Mutating admission check used on the dispatch path (sticky-affinity preference + the single
    /// lane SWRR selection returns): an expired-Open lane transitions to HalfOpen and the caller
    /// CAS-acquires the single-flight probe. Only ever called for a lane about to receive a request.
    // Reached only via `usable`/`usable_in`/`acquire_for_dispatch_in`, all of which are now test-only
    // after `pick_among` moved to `try_admit` (which calls `cell_acquire_breaker` directly). Retained
    // as the shared mutating-admission body those tested primitives delegate to.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn usable_for(&self, pool: &str, lane: usize, now: u64) -> bool {
        if !self.lane_admissible(lane) {
            return false;
        }
        // Both ADMIT arms (`ReadyNoProbe`, `ProbeWon`) mean "this lane may dispatch"; only `Denied`
        // is not usable. This bool projection is for the test-only `acquire_for_dispatch_in`/`usable_*`
        // callers — the production dispatch paths take the richer `ProbeAdmit` via `try_admit`/
        // `try_admit_breaker` so they can distinguish "won a probe" from a Closed no-op.
        !matches!(
            Self::cell_acquire_breaker(self.cell(pool, lane).as_ref(), now),
            ProbeAdmit::Denied
        )
    }

    /// Side-effect-FREE readiness check (lane-global gates + a non-mutating breaker peek). Shared
    /// body for both `is_ready` (test-gated) and `ready_in` (the non-test `LaneRuntime` trait method,
    /// production-wired via `proxy::decide_policy_order`/`pick_among`), so it is production-live.
    pub(crate) fn ready_for(&self, pool: &str, lane: usize, now: u64) -> bool {
        if !self.lane_admissible(lane) {
            return false;
        }
        cell_ready_breaker(self.cell(pool, lane).as_ref(), now)
    }

    /// Lane-global admission gates shared by both the mutating and read-only checks: a `dead` lane
    /// (administratively down) or an exhausted budget is never admissible regardless of breaker FSM.
    pub(crate) fn lane_admissible(&self, lane: usize) -> bool {
        let ls = self.get_lane(lane);
        if ls.dead.load(Ordering::Relaxed) {
            return false;
        }
        if ls.limited && ls.budget.load(Ordering::Relaxed) <= 0 {
            return false;
        }
        true
    }

    #[cfg_attr(not(test), allow(dead_code))] // reached only via the test-exercised `breaker_state`
    pub(crate) fn breaker_state_for(&self, pool: &str, lane: usize) -> BreakerState {
        if self.get_lane(lane).dead.load(Ordering::Relaxed) {
            return BreakerState::Open { until: u64::MAX };
        }
        Self::cell_breaker_state(self.cell(pool, lane).as_ref())
    }

    pub(crate) fn cooldown_remaining_for(&self, pool: &str, lane: usize, now: u64) -> u64 {
        self.cell(pool, lane)
            .cooldown_until()
            .load(Ordering::Acquire)
            .saturating_sub(now)
    }

    /// Lane-global readiness for `/healthz` and `/stats`: true iff the lane is admissible (not dead /
    /// in budget) AND at least one breaker cell that production ACTUALLY routes through would admit a
    /// request right now. Production traffic routes through NAMED pools, whose per-pool cells trip
    /// independently; the lane-default (pool `""`) cell is the `LaneState` itself, which starts
    /// `ST_CLOSED`/`cooldown=0` and is written ONLY by direct/ad-hoc routes — pool-routed traffic
    /// never touches it. So when a lane has per-pool cells, the default cell is (almost) always
    /// "ready" and must NOT short-circuit the verdict: a lane whose every per-pool cell is tripped
    /// Open is NOT serviceable for pool traffic even though its untouched default cell reads ready.
    /// Therefore: if the lane HAS per-pool cells, readiness is purely whether ANY per-pool cell would
    /// admit (the default cell is ignored — it does not reflect pool routing). Only a lane with NO
    /// per-pool cells (direct/ad-hoc-only) falls back to the default cell. Side-effect-free (uses the
    /// non-mutating `cell_ready_breaker`, never the probe-stealing `usable`).
    pub(crate) fn lane_usable_any_cell(&self, lane: usize, now: u64) -> bool {
        if !self.lane_admissible(lane) {
            return false;
        }
        let cells = read_recover(&self.pool_cells);
        match cells.get(&lane) {
            // Lane belongs to one or more pools: readiness reflects ONLY the per-pool cells that
            // pool-routed traffic actually dispatches through. Do NOT short-circuit on the
            // always-Closed default cell.
            Some(per_lane) if !per_lane.is_empty() => per_lane
                .iter()
                .any(|(_, cell)| cell_ready_breaker(cell.as_ref(), now)),
            // Direct/ad-hoc-only lane (no per-pool cells): the default cell IS the routed cell.
            _ => cell_ready_breaker(self.get_lane(lane).as_ref(), now),
        }
    }

    /// Worst-case remaining cooldown across the default cell and every per-pool cell for the lane.
    /// `/stats` must surface the lane's most-tripped state, not the default cell's (which never moves
    /// for pool-routed traffic — see `lane_usable_any_cell`).
    pub(crate) fn lane_max_cooldown_remaining(&self, lane: usize, now: u64) -> u64 {
        let mut worst = self
            .get_lane(lane)
            .cooldown_until
            .load(Ordering::Acquire)
            .saturating_sub(now);
        let cells = read_recover(&self.pool_cells);
        for (_, cell) in cells.get(&lane).into_iter().flatten() {
            worst = worst.max(
                cell.cooldown_until()
                    .load(Ordering::Acquire)
                    .saturating_sub(now),
            );
        }
        worst
    }

    /// Worst-case consecutive-failure streak across the default cell and every per-pool cell for the
    /// lane (the lane-global health signal for `/stats`; the default cell's streak stays 0 for
    /// pool-routed traffic — see `lane_usable_any_cell`).
    pub(crate) fn lane_max_streak(&self, lane: usize) -> u32 {
        let mut worst = self.get_lane(lane).streak.load(Ordering::Relaxed);
        let cells = read_recover(&self.pool_cells);
        for (_, cell) in cells.get(&lane).into_iter().flatten() {
            worst = worst.max(cell.streak().load(Ordering::Relaxed));
        }
        worst
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
        if self.get_lane(lane).dead.load(Ordering::Relaxed) {
            return false; // administratively down — ignore
        }
        let tripped = Self::cell_record_failure(
            self.cell(pool, lane).as_ref(),
            now_time,
            cfg,
            retry_after,
            self.max_honored_retry_after_secs,
        );
        // Bump the lane-GLOBAL error counter as well — but ONLY for a NAMED pool. `cell_record_failure`
        // bumps the cell's own `err()`; for a named pool that is the per-pool `BreakerCell.err` (a
        // per-pool diagnostic, distinct from `LaneState.err`), so the `/stats` `LaneState.err` snapshot
        // would otherwise stay permanently 0 for any lane reached exclusively via named pools
        // (production dispatch always passes the real pool name). For the DEFAULT cell (`pool == ""`),
        // however, `cell("", lane)` IS the `LaneState` itself, so `cell_record_failure` already bumped
        // `LaneState.err` via `c.err()`; bumping it again here double-counted every failure recorded on
        // the bare/default-cell path (degraded forward, direct/ad-hoc routes), inflating the public
        // `/stats` `err` metric 2x. Guard on a non-empty pool so the default cell is counted exactly
        // once. Still mirrors how `record_success_for` keeps the success/error counters symmetric (it
        // bumps `LaneState.ok` separately because `cell_record_success` does NOT touch `err()`/`ok()`).
        if !pool.is_empty() {
            self.get_lane(lane).err.fetch_add(1, Ordering::Relaxed);
        }
        // Genuine Closed→Open trip: bump the lane's MONOTONIC trip counter + stamp the epoch, at
        // the same seam that mints BREAKER_TRIPS_TOTAL — one logical trip, counted once.
        if tripped {
            let ls = self.get_lane(lane);
            ls.trips.fetch_add(1, Ordering::Relaxed);
            ls.last_trip_at.store(now_time, Ordering::Relaxed);
        }
        tripped
    }

    pub(crate) fn record_success_for(&self, pool: &str, lane: usize) {
        let ls = self.get_lane(lane);
        if ls.dead.load(Ordering::Relaxed) {
            // Dead lane: count the success for observability, don't touch the breaker.
            ls.ok.add();
            return;
        }
        let cell = self.cell(pool, lane);
        let recovered = Self::cell_record_success(cell.as_ref(), Self::now_secs());
        // The HalfOpen→Closed recovery re-admits this cell to selection; zero its stale SWRR
        // accumulator under the pool's shard lock (NOT inside the transition-locked close above) so
        // the reset serializes against any concurrent selection for this pool and keeps the pool's
        // `Σ current_weight == 0` invariant exact. The transition lock is already released here, so
        // the shard lock is taken un-nested.
        if recovered {
            self.reset_swrr_for(pool, cell.as_ref());
        }
        ls.ok.add();
    }

    // Production callers: the test-only `record_hard_down`/`record_hard_down_in` trait wrappers, and
    // `store::planes::PlaneBreakers::record_signal` — the non-LLM planes' hard-down is PER CELL by
    // design (their degenerate cells share one lane index, so the all-cells primitive would trip
    // every other tool server and agent).
    // With BOTH planes compiled out `PlaneBreakers` is vestigial, leaving only the test-only
    // wrappers, so this reads dead in a non-test both-off build alone.
    #[allow(dead_code)]
    pub(crate) fn record_hard_down_for(&self, pool: &str, lane: usize, reason: &str) {
        let ls = self.get_lane(lane);
        // Hard-down is RECOVERABLE — long sticky cooldown + Open, recovered via the half-open
        // probe. We do NOT set `dead` (that would block recovery). Per (pool, lane): only the
        // routing pool's view is tripped; other pools discover the bad upstream independently.
        *lock_recover(&ls.dead_reason) = reason.to_string();
        diag_warn!(
            LANE_HARD_DOWN,
            model = %ls.model,
            reason,
            cooldown_secs = self.hard_down_cooldown_secs,
            "lane hard-down; sticky cooldown (recovers via half-open probe)"
        );
        let cell = self.cell(pool, lane);
        // Take the cell's transition lock so this trip's (Open + sticky cooldown) pair lands
        // atomically with respect to a racing recovery (`cell_closed`) or probe acquisition — without
        // it the separate `cooldown_until`/`breaker_state` stores could interleave with a concurrent
        // success-recovery and leave the cell Open with a cleared/short cooldown (sticky cooldown
        // dropped) or Closed with the stale sticky cooldown.
        let _tx = lock_recover(cell.transition_lock());
        let now_secs = Self::now_secs();
        // Same bool `record_hard_down_all_cells` captures (:1936): a genuine Closed->Open trip,
        // gating the trip-counter bump below so a persistently-dead lane's recovery-probe cycle
        // doesn't inflate it once per cycle.
        let was_closed = cell.breaker_state().load(Ordering::Acquire) == ST_CLOSED;
        cell.cooldown_until().store(
            now_secs.saturating_add(self.hard_down_cooldown_secs),
            Ordering::Release,
        );
        cell.breaker_state().store(ST_OPEN, Ordering::Release);
        // Release the single-flight probe back to Open — mirrors `cell_open`. A hard-down can be
        // classified while the cell is HalfOpen with a probe in flight (a recovering lane's half-open
        // probe returns a billing/auth/hard-quota error). Without clearing this, the cell goes Open
        // with `probe_in_flight == true`; after the (30 min) cooldown expires the cell transitions
        // Open→HalfOpen but the probe CAS (false→true) fails forever, benching the lane permanently
        // even after the operator fixes the credential/billing. Clearing it keeps hard-down RECOVERABLE.
        cell.probe_in_flight().store(false, Ordering::Release);
        // Same seam `record_failure_for` bumps at (:1524-1528) — one logical trip, counted once.
        if was_closed {
            ls.trips.fetch_add(1, Ordering::Relaxed);
            ls.last_trip_at.store(now_secs, Ordering::Relaxed);
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
        let mut healthy: Vec<(usize, Arc<dyn BreakerCellAccess>, i64)> =
            Vec::with_capacity(candidates.len());
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
            if cell_ready_breaker(cell.as_ref(), now) {
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

// Test-only helpers: release code records outcomes via the cell-core fns; these give the unit
// tests a lane-indexed handle to seed the default cell's outcome window directly.
#[cfg(any(test, feature = "test-support"))]
impl HealthState {
    /// Record an error outcome in the sliding window with explicit time.
    pub(crate) fn record_outcome_error_with_time(&self, lane: usize, now_time: u64) {
        let ls = self.get_lane(lane);

        // Add to sliding window
        let mut window = lock_recover(&ls.outcome_window);
        window.push(now_time, true);

        ls.err.fetch_add(1, Ordering::Relaxed);
    }

    /// Record success outcome with explicit time.
    pub(crate) fn record_outcome_success_with_time(&self, lane: usize, now_time: u64) {
        let ls = self.get_lane(lane);

        // Reset streak on success (for the FSM to know we recovered)
        ls.streak.store(0, Ordering::Release);

        // Add to sliding window
        let mut window = lock_recover(&ls.outcome_window);
        window.push(now_time, false);

        ls.ok.add();
    }

    /// Drive the recovery-close gate (`cell_closed_if_recoverable`) directly against a named cell with
    /// an EXPLICIT `observed_cooldown`. This lets a regression test reproduce the TOCTOU
    /// deterministically: pass the (smaller) cooldown a probe would have observed, after a concurrent
    /// hard-down has already re-armed the live cell to a stricter cooldown — exactly the interleaving
    /// where the old unconditional close clobbered the hard-down. Returns whether the cell was closed.
    pub(crate) fn recover_close_if_recoverable(
        &self,
        pool: &str,
        lane: usize,
        now: u64,
        observed: u64,
    ) -> bool {
        Self::cell_closed_if_recoverable(self.cell(pool, lane).as_ref(), now, observed)
    }

    /// Read a cell's raw `cooldown_until` (no `now` subtraction), for race-regression assertions.
    pub(crate) fn cell_cooldown_until(&self, pool: &str, lane: usize) -> u64 {
        self.cell(pool, lane)
            .cooldown_until()
            .load(Ordering::Acquire)
    }

    /// Park a named cell HalfOpen with the single-flight probe acquired and a STALE SWRR accumulator —
    /// the precondition under which a recorded success drives a HalfOpen→Closed recovery whose reset
    /// the caller is responsible for. Test-only setup for the SWRR-reset regression.
    pub(crate) fn arm_half_open_stale_swrr(
        &self,
        pool: &str,
        lane: usize,
        cooldown: u64,
        stale_weight: i64,
    ) {
        let c = self.cell(pool, lane);
        c.swrr().force(stale_weight);
        c.cooldown_until().store(cooldown, Ordering::Relaxed);
        c.breaker_state().store(ST_HALF_OPEN, Ordering::Relaxed);
        c.probe_in_flight().store(true, Ordering::Relaxed);
    }

    /// Read a cell's whole SWRR accumulator (live stripes summed), for the invariant assertion.
    pub(crate) fn cell_current_weight(&self, pool: &str, lane: usize) -> i64 {
        self.cell(pool, lane).swrr().sum()
    }
}
