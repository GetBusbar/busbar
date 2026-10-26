// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S OWN ROUTE-TABLE INPUTS: every resolved lane and pool, flattened from the resolved
//! `RootCfg` into neutral rows that
//! [`ConfigTables::of`](super::route_tables::ConfigTables::of) builds the driver's route tables from.
//! They carry only what the route tables, the boot banner and the telemetry label bank read.

/// Active health-probe mode — a neutral mirror of `busbar_kernel::config::HealthMode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum HealthModeInput {
    /// No active probing (`none`).
    #[default]
    None,
    /// Re-probe only tripped lanes (`dead`).
    Dead,
    /// Probe every lane (`active`).
    Active,
}

/// ONE resolved lane (one per model), flattened to the scalars the route tables and the boot banner read.
#[derive(Clone, Debug)]
pub struct LaneInput {
    /// The model name (config key) — the lane's stable identity and `by_model` key.
    pub model: String,
    /// The provider name this lane routes through.
    pub provider: String,
    /// The provider's upstream base URL, already trailing-slash-trimmed, its userinfo stripped.
    pub base_url: String,
    /// The realized concurrency cap (`Semaphore::MAX_PERMITS` for an omitted / unbounded cap).
    pub max_concurrent: usize,
}

/// ONE pool member: the resolved lane index and the member weight.
#[derive(Clone, Debug)]
pub struct PoolMemberInput {
    /// The resolved lane index (into the build's lane rows, `lanes[i]` is lane `i`).
    pub lane_idx: usize,
    /// The member weight (config `PoolMember.weight`, default 1).
    pub weight: u32,
}

/// A pool's `on_exhausted:` policy — a neutral mirror of `busbar_kernel::config::OnExhausted`.
#[derive(Clone, Debug, Default)]
pub enum OnExhaustedInput {
    /// `503` + Retry-After (the default).
    #[default]
    Status503,
    /// Route to the named fallback pool.
    FallbackPool(String),
    /// Send to the least-bad (soonest-cooldown) Open member.
    LeastBad,
    /// Wait up to `max_ms` for a permit, else fall through to 503.
    Queue {
        /// The queue wait ceiling in milliseconds.
        max_ms: u64,
    },
}

/// A pool's breaker trip mode — a neutral mirror of `busbar_kernel::store::TripMode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TripModeInput {
    /// Trip on the error RATE over the window (the ADR-0002 default).
    #[default]
    ErrorRate,
    /// Trip on N consecutive failures.
    Consecutive,
}

/// A pool's resolved breaker TRIP parameters — a neutral mirror of `busbar_kernel::store::TripConfig`.
#[derive(Clone, Debug)]
pub struct TripInput {
    /// The trip mode.
    pub mode: TripModeInput,
    /// The outcome window in seconds.
    pub window_s: u64,
    /// The error-rate trip threshold (`ErrorRate` mode).
    pub threshold: f64,
    /// The minimum request count before the rate can trip.
    pub min_requests: usize,
    /// The consecutive-failure count that trips (`Consecutive` mode).
    pub consecutive_n: u32,
}

/// A pool's RESOLVED breaker config — a neutral mirror of the runtime `busbar_kernel::store::BreakerCfg`
/// (the config `pools.<pool>.breaker:` block already lowered core-side via `BreakerCfg::from`, then
/// flattened here, so the row names no core type). `None` on `PoolInput` ⇒ the pool uses the ADR-0002 defaults.
#[derive(Clone, Debug)]
pub struct BreakerInput {
    /// Base cooldown after a trip (seconds).
    pub base_cooldown_secs: u64,
    /// Cooldown ceiling for the exponential backoff (seconds).
    pub max_cooldown_secs: u64,
    /// Whether an upstream `Retry-After` is honored as the cooldown floor.
    pub honor_retry_after: bool,
    /// Whether a sub-trip-threshold transient still benches the cell for a cooldown.
    pub bench_below_trip_threshold: bool,
    /// The resolved trip parameters (the config `trip:` block, or the ADR-0002 defaults).
    pub trip: TripInput,
}

/// ONE pool, flattened to neutral scalars. Its routing POLICY / gates / rewrites are NOT here — those
/// stay resolved-and-read core-side behind `App::resolve_pool_*`.
#[derive(Clone, Debug)]
pub struct PoolInput {
    /// The pool name.
    pub name: String,
    /// The pool's members, in config order.
    pub members: Vec<PoolMemberInput>,
    /// The pool's `on_exhausted:` policy.
    pub on_exhausted: OnExhaustedInput,
    /// The pool's resolved `breaker:` override (`None` ⇒ ADR-0002 defaults).
    pub breaker: Option<BreakerInput>,
}
