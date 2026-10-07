// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel's own tables view over the `pools:`/`models:` sections it resolved: the read seam's
//! answer when no plane contributes a runtime, so it must project exactly what the sections say.

use std::collections::HashMap;

use super::{ConfigTables, EngineTablesView};
use crate::plane_host::{AuthStyleInput, LaneInput, OnExhaustedInput, PoolInput, PoolMemberInput};

fn lane(model: &str, provider: &str) -> LaneInput {
    LaneInput {
        model: model.to_string(),
        provider: provider.to_string(),
        protocol: "widget".to_string(),
        base_url: format!("https://{provider}.invalid"),
        path: None,
        path_base: None,
        organization: None,
        project: None,
        upstream_model: None,
        api_key: busbar_contract::redacted::Redacted::new(String::new()),
        auth_style: AuthStyleInput::Default,
        scope: None,
        token_url: None,
        subject: None,
        error_map: HashMap::new(),
        health: None,
        allow_metadata_hosts: Vec::new(),
        context_max: None,
        lane_default_max_tokens: None,
        attempt_timeout_ms: None,
        reasoning: false,
        prompt_caching: false,
        lane_caps: Default::default(),
        max_concurrent: 1,
        limited: false,
        budget: -1,
    }
}

fn member(model: &str, lane_idx: usize, weight: u32) -> PoolMemberInput {
    PoolMemberInput {
        model: model.to_string(),
        lane_idx,
        weight,
        reasoning: None,
        attempt_timeout_ms: None,
        tier: None,
        cost_per_mtok: None,
        tags: Vec::new(),
    }
}

fn pool(name: &str, members: Vec<PoolMemberInput>, on_exhausted: OnExhaustedInput) -> PoolInput {
    PoolInput {
        name: name.to_string(),
        members,
        failover: None,
        affinity: None,
        on_exhausted,
        upstream_credentials: None,
        breaker: None,
    }
}

#[test]
fn the_tables_project_the_resolved_sections_in_lane_order() {
    let lanes = vec![lane("m-a", "pa"), lane("m-b", "pb")];
    let pools = vec![
        pool(
            "primary",
            vec![member("m-a", 0, 3), member("m-b", 1, 1)],
            OnExhaustedInput::FallbackPool("spare".to_string()),
        ),
        pool(
            "spare",
            vec![member("m-b", 1, 1)],
            OnExhaustedInput::default(),
        ),
    ];
    let by_model: HashMap<String, usize> = [("m-a".to_string(), 0), ("m-b".to_string(), 1)].into();
    let t = ConfigTables::of(
        &lanes,
        &pools,
        &by_model,
        busbar_contract::config::UpstreamCreds::Passthrough,
    );
    assert_eq!(t.lane_count(), 2);
    let b = t.lane_view(1).expect("lane 1");
    assert_eq!(
        (b.model, b.provider, b.base_url),
        ("m-b", "pb", "https://pb.invalid")
    );
    assert!(t.lane_view(2).is_none());
    assert_eq!(t.model_index("m-a"), Some(0));
    assert!(t.pool_exists("primary") && !t.pool_exists("m-a"));
    assert_eq!(t.pool_members("primary"), vec![(0, 3), (1, 1)]);
    assert_eq!(t.on_exhausted_fallback("primary").as_deref(), Some("spare"));
    assert_eq!(t.on_exhausted_fallback("spare"), None);
    assert_eq!(
        t.upstream_creds(),
        busbar_contract::config::UpstreamCreds::Passthrough
    );
    let mut pools_seen: Vec<(&str, Vec<usize>)> = t.pools();
    pools_seen.sort();
    assert_eq!(
        pools_seen,
        vec![("primary", vec![0, 1]), ("spare", vec![1])]
    );
}

#[test]
fn the_queue_depth_is_the_one_the_walk_reports() {
    let t = ConfigTables::default();
    assert_eq!(t.queued_depth("config-tables-q"), 0);
    super::set_pool_queued_depth("config-tables-q", 2);
    assert_eq!(t.queued_depth("config-tables-q"), 2);
    super::set_pool_queued_depth("config-tables-q", 0);
    assert_eq!(t.queued_depth("config-tables-q"), 0);
}

// ── THE VIEW IS THE KERNEL'S ────────────────────────────────────────────────────────────────────

/// Tables a plane's runtime would answer: one lane, `sentinel`, nothing like the configuration.
struct PlaneOwnTables;

impl EngineTablesView for PlaneOwnTables {
    fn pools(&self) -> Vec<(&str, Vec<usize>)> {
        vec![("sentinel-pool", vec![0])]
    }
    fn pool_exists(&self, pool: &str) -> bool {
        pool == "sentinel-pool"
    }
    fn model_indices(&self) -> Vec<(&str, usize)> {
        vec![("sentinel", 0)]
    }
    fn model_index(&self, model: &str) -> Option<usize> {
        (model == "sentinel").then_some(0)
    }
    fn lane_view(&self, idx: usize) -> Option<super::LaneView<'_>> {
        (idx == 0).then_some(super::LaneView {
            model: "sentinel",
            provider: "sentinel",
            base_url: "http://sentinel.invalid",
        })
    }
    fn lane_count(&self) -> usize {
        1
    }
    fn pool_members(&self, _pool: &str) -> Vec<(usize, u32)> {
        vec![(0, 1)]
    }
    fn queued_depth(&self, _pool: &str) -> u64 {
        0
    }
    fn on_exhausted_fallback(&self, _pool: &str) -> Option<String> {
        None
    }
    fn upstream_creds(&self) -> busbar_contract::config::UpstreamCreds {
        busbar_contract::config::UpstreamCreds::Passthrough
    }
}

static PLANE_OWN_TABLES: PlaneOwnTables = PlaneOwnTables;

/// A fallback plane that contributes a runtime slot AND states a view of it.
static PLANE_WITH_A_VIEW: crate::plane::registry::PlaneDecl = crate::plane::registry::PlaneDecl {
    declaration: crate::plane::registry::PlaneDeclaration {
        key: "route-tables-plane-with-a-view",
        ..crate::test_support::NEUTRAL_FALLBACK.declaration
    },
    build_runtime: Some(|_, _| std::sync::Arc::new(())),
    viewer: Some(|_| &PLANE_OWN_TABLES),
    ..crate::test_support::NEUTRAL_FALLBACK
};

/// ROUTE IS THE KERNEL'S (spec Part 3, the outbound table, step 1: "KERNEL | route (pool walk, member,
/// breaker)"): the routing tables every core reader and a door plane's member lanes read are the ones
/// the kernel built from the sections it resolved, even when the fallback plane contributes a runtime
/// and states its own view of it. RED: the view was the plane's, read through its runtime slot, so the
/// configured model `m-real` was invisible and a plane's `sentinel` stood in its place.
#[test]
fn the_tables_are_the_kernels_whatever_a_plane_states() {
    let _registry = crate::plane::registry::TestRegistryIsolation::seeded(&[&PLANE_WITH_A_VIEW]);
    let app = crate::test_support::TestApp::new()
        .lane(crate::test_support::LaneSpec::new(
            "m-real",
            crate::proto::PROTO_OPENAI,
            "http://m-real.invalid",
        ))
        .pool("pool-real", &[(0, 2)])
        .build();
    let view = app.engine_tables_view();
    assert_eq!(view.lane_count(), 1);
    assert_eq!(view.model_index("m-real"), Some(0), "the configured model");
    assert_eq!(view.model_index("sentinel"), None, "never the plane's");
    assert_eq!(
        view.lane_view(0).map(|l| (l.model, l.base_url)),
        Some(("m-real", "http://m-real.invalid"))
    );
    assert!(view.pool_exists("pool-real") && !view.pool_exists("sentinel-pool"));
    assert_eq!(view.pool_members("pool-real"), vec![(0, 2)]);
}
