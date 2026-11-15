// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `plane_driver::route_tables`'s off-path code: the kernel's own tables view, built once per
//! generation, and its [`EngineTablesView`] projection, read by the cold scrape and discovery paths
//! (`/stats`, `/metrics`, `/v1/models`, the admin pool listing) at most once per read.

use crate::plane_driver::route_tables::{ConfigTables, EngineTablesView, LaneView};

impl ConfigTables {
    #[must_use]
    pub fn of<'m>(
        lanes: &[crate::plane_driver::route_input::LaneInput],
        pools: &[crate::plane_driver::route_input::PoolInput],
        by_model: impl IntoIterator<Item = (&'m String, &'m usize)>,
        upstream_credentials: busbar_contract::config::UpstreamCreds,
        llm_configured: bool,
    ) -> Self {
        ConfigTables {
            lanes: lanes
                .iter()
                .map(|l| (l.model.clone(), l.provider.clone(), l.base_url.clone()))
                .collect(),
            by_model: by_model
                .into_iter()
                .map(|(model, &idx)| (model.clone(), idx))
                .collect(),
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
            no_llm: !llm_configured,
        }
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
        crate::plane_driver::route_tables::queued_depth_of(pool)
    }
    fn on_exhausted_fallback(&self, pool: &str) -> Option<String> {
        self.fallbacks.get(pool).cloned()
    }
    fn upstream_creds(&self) -> busbar_contract::config::UpstreamCreds {
        self.upstream_credentials
    }
    fn llm_configured(&self) -> bool {
        !self.no_llm
    }
}
