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
}
