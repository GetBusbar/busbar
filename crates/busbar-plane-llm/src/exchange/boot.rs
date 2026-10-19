// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BOOT LINES (u26, coordinator ruling (a)): the three lines v1.5.5 printed for the generation's
//! models and pools (`crates/busbar/src/main.rs:2886`, `:3042`, `:3046` at v1.5.5), built by the
//! plane from the routing it publishes and the provider base URLs the kernel hands at open
//! (`ProviderFacts.base_url`: the trailing `/` trimmed, the `user:pass@` stripped, by the kernel).
//!
//! ```text
//!   model <model> via <provider> (<base_url>) max <n|unbounded>[ → upstream <u>]
//! busbar: <N> models, <M> pools
//!   pool /<pool> = [<m1>, <m2>] aggregate <sum>
//! ```
//!
//! Models print in name order (v1.5.5 sorted them); pools in name order (v1.5.5 iterated a
//! `HashMap`, so any one order is its order). A pool's aggregate is the sum of its members' caps,
//! an unbounded member counted as v1.5.5's `Semaphore::MAX_PERMITS`, summed as v1.5.5's release
//! build summed (wrapping).

use std::collections::BTreeMap;

use busbar_contract::abi::plane::FACT_CONCURRENCY_CAP;
use busbar_contract::abi::sdk::publish::{RouteEntrySpec, RouteMemberSpec};

use super::shaping::sections;

/// v1.5.5's stand-in for an unbounded lane's cap: `tokio::sync::Semaphore::MAX_PERMITS`,
/// `usize::MAX >> 3` on the 64-bit targets busbar ships.
pub const UNBOUNDED_CAP: u64 = u64::MAX >> 3;

fn cap(m: &RouteMemberSpec) -> Option<u64> {
    m.facts
        .iter()
        .find(|(f, _)| *f == FACT_CONCURRENCY_CAP)
        .map(|(_, v)| *v)
}

/// The boot lines of one generation's `routing`, each without its line break; `base_urls` is each
/// provider's display URL by provider name (absent = printed empty, as an empty `base_url` was).
#[must_use]
pub fn lines(routing: &[RouteEntrySpec], base_urls: &BTreeMap<String, String>) -> Vec<String> {
    let models: Vec<&RouteMemberSpec> = routing
        .iter()
        .filter(|e| e.section == sections::MODELS)
        .filter_map(|e| e.members.first())
        .collect();
    let pools: Vec<&RouteEntrySpec> = routing
        .iter()
        .filter(|e| e.section == sections::POOLS)
        .collect();
    let mut out = Vec::with_capacity(1 + models.len() + pools.len());
    for m in &models {
        let max = cap(m).map_or_else(|| "unbounded".to_string(), |n| n.to_string());
        let upstream = if m.upstream.is_empty() {
            String::new()
        } else {
            format!(" → upstream {}", m.upstream)
        };
        out.push(format!(
            "  model {} via {} ({}) max {max}{upstream}",
            m.lane,
            m.provider,
            base_urls.get(&m.provider).map_or("", String::as_str),
        ));
    }
    out.push(format!(
        "busbar: {} models, {} pools",
        models.len(),
        pools.len()
    ));
    for p in &pools {
        let aggregate = p.members.iter().fold(0u64, |sum, m| {
            sum.wrapping_add(cap(m).unwrap_or(UNBOUNDED_CAP))
        });
        out.push(format!(
            "  pool /{} = [{}] aggregate {aggregate}",
            p.entry,
            p.members
                .iter()
                .map(|m| m.lane.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }
    out
}
