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

    /// Whether the deployment configures the LLM plane (any provider or model). A deployment without
    /// it serves no lanes, so lanes do not count against its health.
    fn llm_configured(&self) -> bool {
        true
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
    pub(crate) lanes: Vec<(String, String, String)>,
    pub(crate) by_model: foldhash::HashMap<String, usize>,
    pub(crate) pools: foldhash::HashMap<String, Vec<(usize, u32)>>,
    pub(crate) fallbacks: foldhash::HashMap<String, String>,
    /// True only when the deployment configures no provider and no model. Defaults to false, so a
    /// table built without that fact counts the LLM plane as configured (health refuses, never opens).
    pub(crate) no_llm: bool,
    pub(crate) upstream_credentials: busbar_contract::config::UpstreamCreds,
}

/// The live `on_exhausted: queue` depth per pool. A pool's slot, once created, stays (at depth 0 when
/// drained), so a pool name is copied in once for the process, never per queued request.
static QUEUED: std::sync::LazyLock<std::sync::Mutex<foldhash::HashMap<String, u64>>> =
    std::sync::LazyLock::new(Default::default);

fn with_queued_depth(pool: &str, change: impl FnOnce(&mut u64)) {
    let mut queued = QUEUED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(depth) = queued.get_mut(pool) {
        change(depth);
        return;
    }
    let mut depth = 0;
    change(&mut depth);
    crate::cold::first_queued_depth(&mut queued, pool, depth);
}

pub fn set_pool_queued_depth(pool: &str, depth: u64) {
    with_queued_depth(pool, |d| *d = depth);
}

pub fn change_pool_queued_depth(pool: &str, delta: i64) {
    with_queued_depth(pool, |d| *d = d.saturating_add_signed(delta));
}

/// The live queue depth of `pool` (`0` before its first queued request).
pub(crate) fn queued_depth_of(pool: &str) -> u64 {
    QUEUED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(pool)
        .copied()
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "tests/route_tables_tests.rs"]
mod route_tables_tests;
