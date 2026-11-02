// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

const PROBE_RETRY_FLOOR_MS: u64 = 250;

pub const SHED_RETRY_FLOOR_MS: u64 = 1000;

pub const AT_CAPACITY_RECOVERY_FLOOR_MS: u64 = 2_000;

/// Why a lane cannot accept a request right now — the ONE taxonomy every consumer speaks: selection
/// (exclude), least_bad (rank), `Retry-After` (hint), `/stats` + `/metrics` (render), queue (wait).
/// Add a future reason (e.g. `RateLimited { until }`) in ONE place and every consumer inherits it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// Administratively down. Does not self-recover (until config change).
    Dead,
    /// Lifetime request budget (`max_requests`) spent. Does not self-recover.
    BudgetExhausted,
    /// Circuit breaker Open (or a Closed cell still inside a pending soft cooldown). `until` is EXACT
    /// (epoch secs) — recovery time is known, not estimated.
    BreakerOpen { until: u64 },
    /// Lost the HalfOpen single-flight probe race to a peer. Transient; the peer's probe resolves the
    /// cell within one request. Recovery is "next tick", carried as [`PROBE_RETRY_FLOOR_MS`].
    ProbeInFlight,
    /// All concurrency permits held. `drain_hint_ms` is an ESTIMATE, NOT exact —
    /// capacity has no scheduled recovery the way a breaker does. `None` when there is no basis to
    /// estimate, in which case `recovery_hint_ms` falls back to [`AT_CAPACITY_RECOVERY_FLOOR_MS`].
    AtCapacity { drain_hint_ms: Option<u64> },
    /// Inbound backpressure shed this request before lane selection (`limits.max_inbound_concurrent`).
    #[cfg_attr(not(test), allow(dead_code))]
    Shedding,
}

impl Unavailable {
    pub fn recovery_hint_ms(&self, now: u64) -> Option<u64> {
        match self {
            Unavailable::Dead | Unavailable::BudgetExhausted => None,
            Unavailable::BreakerOpen { until } => {
                Some(until.saturating_sub(now).saturating_mul(1000))
            }
            Unavailable::ProbeInFlight => Some(PROBE_RETRY_FLOOR_MS),

            Unavailable::AtCapacity { drain_hint_ms } => {
                Some(drain_hint_ms.unwrap_or(AT_CAPACITY_RECOVERY_FLOOR_MS))
            }
            Unavailable::Shedding => Some(SHED_RETRY_FLOOR_MS),
        }
    }

    pub fn variant_name(&self) -> &'static str {
        match self {
            Unavailable::Dead => "dead",
            Unavailable::BudgetExhausted => "budget_exhausted",
            Unavailable::BreakerOpen { .. } => "breaker_open",
            Unavailable::ProbeInFlight => "probe_in_flight",
            Unavailable::AtCapacity { .. } => "at_capacity",
            Unavailable::Shedding => "shedding",
        }
    }
}

/// Breaker state for a lane per ADR-0002.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    Closed,
    Open { until: u64 },
    HalfOpen,
}

pub fn now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub const FNV1A_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

pub const FNV1A_PRIME: u64 = 0x0000_0100_0000_01b3;

pub fn fnv1a_u64(s: &str) -> u64 {
    let mut hash = FNV1A_OFFSET_BASIS;
    for &byte in s.as_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV1A_PRIME);
    }
    hash
}

#[must_use]
pub enum Permit {
    Bounded(#[allow(dead_code)] tokio::sync::OwnedSemaphorePermit),
    Unbounded,
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
    pub consecutive_n: u32,
}

impl Default for TripConfig {
    fn default() -> Self {
        Self {
            mode: TripMode::ErrorRate,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            consecutive_n: 3,
        }
    }
}

/// Breaker configuration per pool.
#[derive(Debug, Clone)]
pub struct BreakerCfg {
    pub base_cooldown_secs: u64,
    pub max_cooldown_secs: u64,
    pub honor_retry_after: bool,
    pub trip: TripConfig,
    /// Whether a transient failure that did NOT breach the trip threshold still benches the cell
    /// for a cooldown. See ADR-0002 / `docs/circuit-breaker.md`: `true` on a walked (LLM) pool with
    /// siblings, `false` on a degenerate single-member cell (MCP client leg / A2A relay) that would
    /// otherwise refuse every caller after one blip.
    pub bench_below_trip_threshold: bool,
}

impl Default for BreakerCfg {
    fn default() -> Self {
        Self {
            base_cooldown_secs: 15,
            max_cooldown_secs: 120,
            honor_retry_after: true,
            trip: TripConfig::default(),

            bench_below_trip_threshold: true,
        }
    }
}

pub struct Admit {
    pub permit: Permit,
    pub probe_epoch: Option<u64>,
}

/// Snapshot of lane stats for /stats endpoint.
#[derive(Debug, Clone)]
pub struct LaneSnapshot {
    /// The member the lane serves: the config entry's name, as the routing table keys it.
    pub member: String,
    /// The route the lane dials: the destination entry the member is bound to.
    pub route: String,
    pub max_concurrent: usize,
    pub inflight: i64,
    pub free_slots: usize,
    /// Available concurrency permits for a BOUNDED lane (`Some(n)`); `None` for an unbounded lane
    /// (`max_concurrent` omitted — nothing is counted). Distinct from `free_slots` only in that it
    /// makes "unbounded" explicit rather than reporting an effectively-infinite number: a saturated
    /// lane must be externally distinguishable — `Some(0)` — from an idle or unbounded one.
    pub available: Option<usize>,
    /// True iff this lane is BOUNDED and has zero available permits — i.e. at its `max_concurrent`
    /// limit. Post the at-capacity-exhaustion fix, such a lane sheds/spills rather than queueing, so
    /// this flag is the external signal that a pool is oversubscribed (not merely slow). This is the
    /// CAPACITY axis, deliberately kept INDEPENDENT of `availability`/`breaker_state`: a lane can
    /// be both breaker-Open AND at-capacity, and an operator must see both facts to understand why an
    /// Open lane's breaker never recovers (its recovery probe needs a dispatch it can never win).
    pub at_capacity: bool,
    /// Lane-GLOBAL availability over the shared [`Unavailable`] taxonomy: the SAME
    /// classification `classify`/routing speaks, aggregated across the cells production routes through.
    /// `Ok(())` = the lane would admit; `Err(_)` carries the reason (and its `recovery_hint_ms`). This
    /// is the ONE source `/stats` and (per-pool) `/metrics` render from, so observability cannot drift
    /// from behaviour. Breaker-first: an Open-and-at-capacity lane classifies `BreakerOpen`, while the
    /// orthogonal `at_capacity`/`breaker_state` fields still expose each axis independently.
    pub availability: Result<(), Unavailable>,
    /// Lane-GLOBAL aggregate breaker FSM state (best-case across the routed cells, matching `usable`),
    /// surfaced as its own field so the BREAKER axis is legible independently of `availability` and
    /// `at_capacity`. An expired-Open cell still reports `Open` here even though it would win a
    /// recovery probe (so `availability` may read `at_capacity` while this reads `open`) — that pairing
    /// is exactly the Open+AtCapacity operators need to see.
    pub breaker_state: BreakerState,
    pub ok: u64,
    pub err: u64,
    pub client_fault: u64,
    pub usable: bool,
    pub dead: bool,
    pub dead_reason: String,
    pub cooldown_remaining_s: u64,
    pub streak: u32,
    pub budget: i64,
    /// Monotonic Closed→Open trip count + the most recent trip's epoch (0 = never) — the
    /// poll-safe "did a trip happen since I last looked" signal.
    pub trips: u64,
    pub last_trip_at: u64,
}

/// One lane's PORTABLE health state, keyed by its STABLE IDENTITY (member + route) instead of
/// its array position. This is the carrier that lets learned reliability state survive the
/// two events that invalidate positional indexing: a config APPLY that changes the lane set (the
/// new store is built with surviving lanes'
/// snapshots restored), or serialized for restart. Ephemeral
/// state is not carried: semaphores /
/// an in-flight probe records into the OLD store snapshot it was dispatched under), SWRR fairness
/// counters (positional by nature; reset is harmless), and the rolling outcome windows (strictly
/// time-windowed — they refill within seconds and carrying them would import stale samples).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LaneHealthSnapshot {
    /// The member the lane serves ([`LaneSnapshot::member`]).
    pub member: String,
    /// The route the lane dials ([`LaneSnapshot::route`]).
    pub route: String,
    /// Remaining lifetime request budget (`-1` = unlimited).
    pub budget: i64,
    /// Default-cell breaker: FSM state, cooldown deadline (unix secs), consecutive-error streak.
    pub breaker_state: u64,
    pub cooldown_until: u64,
    pub streak: u32,
    /// Lane-global hard-down latch + reason.
    pub dead: bool,
    pub dead_reason: String,
    /// Lifetime counters (feed /stats continuity).
    pub ok: u64,
    pub err: u64,
    pub client_fault: u64,
    /// Latency EWMA (raw f64 bits; 0 = no sample).
    pub latency_ewma_bits: u64,
    /// Monotonic Closed→Open trip count + last-trip epoch (0 = never) — learned reliability, so it
    /// carries across apply/restart like ok/err. `serde(default)` reads pre-1.3 persisted snapshots.
    #[serde(default)]
    pub trips: u64,
    #[serde(default)]
    pub last_trip_at: u64,
    /// Per-(pool) breaker cells for this lane.
    pub cells: Vec<PoolCellHealthSnapshot>,
}

/// One per-pool breaker cell's portable state (the FSM triple; windows/probe/SWRR stay ephemeral).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PoolCellHealthSnapshot {
    pub pool: String,
    pub breaker_state: u64,
    pub cooldown_until: u64,
    pub streak: u32,
    pub err: u64,
}

pub trait LaneRuntime: Send + Sync + 'static {
    #[cfg(test)]
    fn usable(&self, lane: usize, now: u64) -> bool {
        self.usable_in("", lane, now)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn usable_in(&self, pool: &str, lane: usize, now: u64) -> bool;

    #[cfg(any(test, feature = "test-support"))]
    fn is_ready(&self, lane: usize, now: u64) -> bool {
        self.ready_in("", lane, now)
    }

    fn is_ready_any_cell(&self, lane: usize, now: u64) -> bool;

    fn ready_in(&self, pool: &str, lane: usize, now: u64) -> bool;

    fn breaker_state_snapshot_in(&self, pool: &str, lane: usize) -> BreakerState;

    fn error_rate_in(&self, pool: &str, lane: usize, now: u64) -> Option<f64>;

    fn available_permits(&self, lane: usize) -> usize;

    fn lane_budget_remaining(&self, lane: usize) -> Option<i64>;

    fn lane_admissible(&self, lane: usize) -> bool;

    fn lane_latency_ms(&self, lane: usize) -> Option<f64>;

    fn record_latency_in(&self, pool: &str, lane: usize, latency_ms: f64);

    #[cfg_attr(not(test), allow(dead_code))]
    fn acquire_for_dispatch_in(&self, pool: &str, lane: usize, now: u64) -> bool;

    fn classify(&self, pool: &str, lane: usize, now: u64) -> Result<(), Unavailable>;

    fn try_admit(&self, pool: &str, lane: usize, now: u64) -> Result<Admit, Unavailable>;

    fn lane_semaphore(&self, lane: usize) -> Option<std::sync::Arc<tokio::sync::Semaphore>>;

    fn try_admit_breaker(
        &self,
        pool: &str,
        lane: usize,
        now: u64,
    ) -> Result<Option<u64>, Unavailable>;

    #[cfg_attr(not(test), allow(dead_code))]
    fn release_probe_in(&self, pool: &str, lane: usize);

    #[cfg_attr(not(test), allow(dead_code))]
    fn probe_epoch_in(&self, pool: &str, lane: usize) -> u64;

    fn release_probe_owned_in(&self, pool: &str, lane: usize, owned_epoch: u64);

    #[cfg(any(test, feature = "test-support"))]
    fn breaker_state(&self, lane: usize) -> BreakerState {
        self.breaker_state_in("", lane)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn breaker_state_in(&self, pool: &str, lane: usize) -> BreakerState;

    #[cfg(any(test, feature = "test-support"))]
    fn force_open_in(&self, pool: &str, lane: usize, cooldown_until: u64);

    #[cfg(any(test, feature = "test-support"))]
    fn cooldown_remaining(&self, lane: usize, now: u64) -> u64 {
        self.cooldown_remaining_in("", lane, now)
    }
    fn cooldown_remaining_in(&self, pool: &str, lane: usize, now: u64) -> u64;

    fn lane_needs_probe(&self, lane: usize, now: u64) -> bool;

    #[cfg(any(test, feature = "test-support"))]
    fn record_success(&self, lane: usize) {
        self.record_success_in("", lane, super::HealthState::now_secs());
    }

    fn record_success_in(&self, pool: &str, lane: usize, now: u64);

    fn record_probe_success_all_cells(&self, lane: usize, now: u64);
    fn record_client_fault(&self, lane: usize);

    #[cfg(test)]
    fn record_transient(
        &self,
        lane: usize,
        what: &str,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool {
        self.record_transient_in("", lane, what, cfg, retry_after)
    }
    fn record_transient_in(
        &self,
        pool: &str,
        lane: usize,
        what: &str,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool;

    fn record_transient_in_at(
        &self,
        pool: &str,
        lane: usize,
        now: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool;
    #[cfg(test)]
    fn record_rate_limit(
        &self,
        lane: usize,
        now: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool {
        self.record_rate_limit_in("", lane, now, cfg, retry_after)
    }
    fn record_rate_limit_in(
        &self,
        pool: &str,
        lane: usize,
        now: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
    ) -> bool;

    #[cfg(any(test, feature = "test-support"))]
    fn record_hard_down(&self, lane: usize, reason: &str);

    fn record_hard_down_all_cells(&self, lane: usize, reason: &str, now: u64) -> bool;

    fn recover_lane(&self, lane: usize, now: u64);

    fn record_probe_failure_all_cells(
        &self,
        lane: usize,
        what: &str,
        resolve_cfg: &dyn Fn(&str) -> BreakerCfg,
        retry_after: Option<u64>,
        now: u64,
    );

    fn try_acquire(&self, lane: usize) -> Option<Permit>;

    #[must_use]
    fn spend_budget(&self, lane: usize) -> bool;

    fn refund_budget(&self, lane: usize);

    fn snapshot(&self, lane: usize, now: u64) -> LaneSnapshot;

    fn export_health(&self) -> Vec<LaneHealthSnapshot>;

    fn breaker_unit(&self) -> std::sync::Arc<busbar_kernel_breaker::BreakerUnit>;
}
