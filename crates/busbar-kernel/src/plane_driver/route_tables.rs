// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROUTE TABLES' READ VIEW — the pools, members and lanes the route step walks, projected for
//! the cold readers that report them: the `/metrics` lane-state scrape, `/stats`, the admin pool
//! listing and the boot-time telemetry label bank.
//!
//! The tables are the kernel's own: `pools`, their members, `on_exhausted` and
//! `upstream_credentials` are reserved core-owned keys (BUSBAR-1.6.0.md §4, l.552-554), and the
//! route step is the kernel's walk over them (Part 3 §12, l.2577). [`ConfigTables`] is the view over
//! one resolved generation; [`EMPTY_VIEW`] is the view a configuration with no tables reads (zero
//! pools, zero lanes), so every reader answers empty rather than panicking.
//!
//! ## What this is NOT
//!
//! This is the COLD read seam, reached at most once per scrape or listing call and free to allocate
//! its projections. It is not the route walk itself.

/// A read-only projection of ONE lane's identity, borrowed from the lane table for the duration of a
/// scrape or listing read: protocol-neutral scalars only.
pub struct LaneView<'a> {
    /// The lane's configured model name — the value the `/metrics` `lane` label and the counter sites
    /// carry, so a gauge and its counters PromQL-join.
    pub model: &'a str,
    /// The lane's provider name.
    pub provider: &'a str,
    /// The lane's upstream base URL.
    pub base_url: &'a str,
}

/// THE READ SEAM over the route tables. Every accessor returns a neutral projection, so the
/// `/metrics`, `/stats`, admin and telemetry readers name no routing type. Cold paths only; the
/// projections allocate.
pub trait EngineTablesView {
    /// The pool label space paired with each pool's member lane indices — one entry per configured
    /// pool. Drives the `/metrics` per-pool lane-state loop, the `/v1/models` visible-pool filter, and
    /// the telemetry engine-label bank.
    fn pools(&self) -> Vec<(&str, Vec<usize>)>;

    /// WHETHER `pool` IS A CONFIGURED POOL — one probe, no projection.
    ///
    /// The odd one out on this trait, and deliberately so. Everything else here is a cold
    /// scrape/discovery read that may allocate; this is the membership question a REQUEST asks, and
    /// it is stated separately because the only way to ask it through [`Self::pools`] is to build
    /// the whole projection — a `Vec` of pools plus a `Vec` per pool — and walk it. That is the
    /// scrape path's price paid on the request path, and it scales with the size of the deployment
    /// for a yes/no. It is the exact counterpart of [`Self::model_index`], which has always been the
    /// one-probe form of the same question for the direct-model half.
    fn pool_exists(&self, pool: &str) -> bool;

    /// The direct-model index: every `(model name, lane index)` reachable without a pool.
    fn model_indices(&self) -> Vec<(&str, usize)>;

    /// The lane index a direct model routes to, if the model is configured.
    fn model_index(&self, model: &str) -> Option<usize>;

    /// A neutral view of the lane at `idx`, or `None` when the index is out of range.
    fn lane_view(&self, idx: usize) -> Option<LaneView<'_>>;

    /// The total number of configured lanes — the upper bound the staying `/stats` and telemetry
    /// readers iterate `0..lane_count()` over (each index then read through [`Self::lane_view`] /
    /// the neutral store cell). Zero for the empty view.
    fn lane_count(&self) -> usize;

    /// The `(lane index, member weight)` pairs of `pool`'s members, in config order — the NEUTRAL
    /// projection the core-resident admin pool listing (`GET /admin/pools[/{name}][?detail]`) renders
    /// each member's weight and (via [`Self::lane_view`]) lane name from. Empty for an unknown pool.
    /// Cold admin path; allocates.
    fn pool_members(&self, pool: &str) -> Vec<(usize, u32)>;

    /// The live `on_exhausted: queue` park depth for `pool` (0 when the pool never queues).
    fn queued_depth(&self, pool: &str) -> u64;

    /// The FALLBACK-POOL target `pool` fails over to on exhaustion, if its `on_exhausted:` policy is
    /// `fallback_pool:<name>` — else `None` (every other policy, `503`/`least_bad`/`queue`, stays
    /// within the pool and introduces no new pool name; an unconfigured pool defaults to `503`). Read
    /// by the ingress ACL walk (`fallback_pools_authorized`) to re-enforce a key's `allowed_pools`
    /// against every reachable fallback pool.
    fn on_exhausted_fallback(&self, pool: &str) -> Option<String>;

    /// The ALL-POOLS upstream-credential DEFAULT (`Own` vs `Passthrough`), a kernel-owned key the
    /// pool-less readers (`auth::open_door` keys-in-chain guard, the admin upstream-credentials
    /// render) consult. The empty view returns the type's default.
    fn upstream_creds(&self) -> busbar_contract::config::UpstreamCreds;
}

/// THE EMPTY VIEW: an [`EngineTablesView`] with zero pools and zero lanes, read when a generation
/// carries no tables, so every reader sees empty tables rather than panicking.
pub struct EmptyEngineTablesView;

/// The process-lifetime [`EmptyEngineTablesView`] singleton the read seam falls back to.
pub static EMPTY_VIEW: EmptyEngineTablesView = EmptyEngineTablesView;

impl EngineTablesView for EmptyEngineTablesView {
    fn pools(&self) -> Vec<(&str, Vec<usize>)> {
        Vec::new()
    }
    fn pool_exists(&self, _pool: &str) -> bool {
        false
    }
    fn model_indices(&self) -> Vec<(&str, usize)> {
        Vec::new()
    }
    fn model_index(&self, _model: &str) -> Option<usize> {
        None
    }
    fn lane_view(&self, _idx: usize) -> Option<LaneView<'_>> {
        None
    }
    fn lane_count(&self) -> usize {
        0
    }
    fn pool_members(&self, _pool: &str) -> Vec<(usize, u32)> {
        Vec::new()
    }
    fn queued_depth(&self, _pool: &str) -> u64 {
        0
    }
    fn on_exhausted_fallback(&self, _pool: &str) -> Option<String> {
        None
    }
    fn upstream_creds(&self) -> busbar_contract::config::UpstreamCreds {
        busbar_contract::config::UpstreamCreds::default()
    }
}

/// THE KERNEL'S OWN TABLES VIEW over the pools and lanes it resolved: the lanes in the lane table's
/// order (the order the lane store and the telemetry bank are indexed by), the direct-lane index,
/// each pool's members and its fallback pool, and the all-pools upstream-credential default. `/stats`,
/// the `/metrics` lane families and the admin pool listing read the same tables the route walk
/// walks. The live `on_exhausted: queue` depth is the one the walk reports
/// ([`set_pool_queued_depth`]).
#[derive(Debug, Default)]
pub struct ConfigTables {
    lanes: Vec<(String, String, String)>,
    by_model: std::collections::HashMap<String, usize>,
    pools: std::collections::HashMap<String, Vec<(usize, u32)>>,
    fallbacks: std::collections::HashMap<String, String>,
    upstream_credentials: busbar_contract::config::UpstreamCreds,
}

impl ConfigTables {
    /// The tables of one resolved configuration generation.
    #[must_use]
    pub fn of(
        lanes: &[crate::plane_driver::route_input::LaneInput],
        pools: &[crate::plane_driver::route_input::PoolInput],
        by_model: &std::collections::HashMap<String, usize>,
        upstream_credentials: busbar_contract::config::UpstreamCreds,
    ) -> Self {
        ConfigTables {
            lanes: lanes
                .iter()
                .map(|l| (l.model.clone(), l.provider.clone(), l.base_url.clone()))
                .collect(),
            by_model: by_model.clone(),
            pools: pools
                .iter()
                .map(|p| {
                    (
                        p.name.clone(),
                        p.members.iter().map(|m| (m.lane_idx, m.weight)).collect(),
                    )
                })
                .collect(),
            fallbacks: pools
                .iter()
                .filter_map(|p| match &p.on_exhausted {
                    crate::plane_driver::route_input::OnExhaustedInput::FallbackPool(to) => {
                        Some((p.name.clone(), to.clone()))
                    }
                    _ => None,
                })
                .collect(),
            upstream_credentials,
        }
    }
}

/// The live `on_exhausted: queue` depth of each pool, as the walk reports it.
static QUEUED: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<String, u64>>> =
    std::sync::LazyLock::new(Default::default);

/// Record `pool`'s live wait-terminal depth (the walk's balanced park/leave count).
pub fn set_pool_queued_depth(pool: &str, depth: u64) {
    QUEUED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(pool.to_string(), depth);
}

impl EngineTablesView for ConfigTables {
    fn pools(&self) -> Vec<(&str, Vec<usize>)> {
        self.pools
            .iter()
            .map(|(name, members)| (name.as_str(), members.iter().map(|(i, _)| *i).collect()))
            .collect()
    }
    fn pool_exists(&self, pool: &str) -> bool {
        self.pools.contains_key(pool)
    }
    fn model_indices(&self) -> Vec<(&str, usize)> {
        self.by_model
            .iter()
            .map(|(m, &idx)| (m.as_str(), idx))
            .collect()
    }
    fn model_index(&self, model: &str) -> Option<usize> {
        self.by_model.get(model).copied()
    }
    fn lane_view(&self, idx: usize) -> Option<LaneView<'_>> {
        self.lanes
            .get(idx)
            .map(|(model, provider, base_url)| LaneView {
                model,
                provider,
                base_url,
            })
    }
    fn lane_count(&self) -> usize {
        self.lanes.len()
    }
    fn pool_members(&self, pool: &str) -> Vec<(usize, u32)> {
        self.pools.get(pool).cloned().unwrap_or_default()
    }
    fn queued_depth(&self, pool: &str) -> u64 {
        QUEUED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(pool)
            .copied()
            .unwrap_or(0)
    }
    fn on_exhausted_fallback(&self, pool: &str) -> Option<String> {
        self.fallbacks.get(pool).cloned()
    }
    fn upstream_creds(&self) -> busbar_contract::config::UpstreamCreds {
        self.upstream_credentials
    }
}

#[cfg(test)]
#[path = "tests/route_tables_tests.rs"]
mod route_tables_tests;
