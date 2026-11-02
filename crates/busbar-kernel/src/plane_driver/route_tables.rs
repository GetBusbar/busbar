// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub struct LaneView<'a> {
    pub model: &'a str,

    pub provider: &'a str,

    pub base_url: &'a str,
}

pub trait EngineTablesView {
    fn pools(&self) -> Vec<(&str, Vec<usize>)>;

    fn pool_exists(&self, pool: &str) -> bool;

    fn model_indices(&self) -> Vec<(&str, usize)>;

    fn model_index(&self, model: &str) -> Option<usize>;

    fn lane_view(&self, idx: usize) -> Option<LaneView<'_>>;

    fn lane_count(&self) -> usize;

    fn pool_members(&self, pool: &str) -> Vec<(usize, u32)>;

    fn queued_depth(&self, pool: &str) -> u64;

    fn on_exhausted_fallback(&self, pool: &str) -> Option<String>;

    fn upstream_creds(&self) -> busbar_contract::config::UpstreamCreds;
}

pub struct EmptyEngineTablesView;

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

static QUEUED: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<String, u64>>> =
    std::sync::LazyLock::new(Default::default);

pub fn set_pool_queued_depth(pool: &str, depth: u64) {
    QUEUED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(pool.to_string(), depth);
}

pub fn change_pool_queued_depth(pool: &str, delta: i64) {
    let mut queued = QUEUED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let depth = queued.entry(pool.to_string()).or_default();
    *depth = depth.saturating_add_signed(delta);
    if *depth == 0 {
        queued.remove(pool);
    }
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
