// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-PLANE `config_validate::validate_unified_pool_names` AGREEMENT TESTS, relocated here from
//! `src/config_validate/tests/tests.rs` (the A6/HostCtx dev-dependency-cycle cleanup): each builds a
//! REAL `busbar_mcp::mcp::config::ToolsCfg` and hands it to core's own validator through
//! `RootCfg::tool_defs` (`Box<dyn PlaneCfg>`), which only type-checks with ONE `busbar_kernel` in the
//! graph — see `plane_integration.rs`'s header for the full rationale, and `config_cross_plane.rs`'s
//! header for the twin move out of `src/config/tests/tests.rs`.
//!
//! `validate_unified_pool_names` was widened from private to `pub` (in `busbar_kernel::config_validate`)
//! for exactly this move — the test still drives the real function directly, not the aggregate
//! `validate`/`validate_with_unset` entry point (one of these three tests asserts `errors.is_empty()`,
//! so routing through the full validator risked an unrelated rule firing on the shared minimal fixture).

use busbar_kernel::config::{self, RootCfg};
use busbar_kernel::config_validate::validate_unified_pool_names;
use busbar_kernel::failover::CandidatePoolCfg;
use std::collections::HashMap;

/// Byte-identical to `src/config_validate/tests/tests.rs::make_root_cfg` (kept private/local there
/// too — this is the one copy an integration test needs).
fn make_root_cfg(
    providers: HashMap<String, config::ProviderCfg>,
    models: HashMap<String, config::ModelCfg>,
    pools: HashMap<String, config::PoolCfg>,
) -> RootCfg {
    config::RootCfg {
        tool_defs: busbar_kernel::plane::config::ToolsSection::default().0,
        agent_defs: busbar_kernel::plane::config::AgentsSection::default().0,
        tool_pools: Default::default(),
        agent_pools: Default::default(),
        plane_sections: Default::default(),
        listen: config::DEFAULT_LISTEN_ADDR.into(),
        endpoint_resources: Default::default(),
        oauth_as: None,
        public_url: None,
        tls: None,
        admin_listen: config::DEFAULT_ADMIN_LISTEN_ADDR.to_string(),
        admin_tls: None,
        auth: None,
        providers,
        models,
        pools,
        upstream_credentials: busbar_kernel::auth::UpstreamCreds::Own,
        hooks: HashMap::new(),
        admin_auth: vec!["admin-tokens".to_string()],
        groups: std::collections::BTreeMap::new(),
        rate_card: None,
        per_request_fee: 0,
        plane_fees: Default::default(),
        store: None,
        secrets: std::collections::BTreeMap::new(),
        global_hooks: Vec::new(),
        blocked_metadata_hosts: Vec::new(),
        allow_metadata_hosts: Vec::new(),
        allow_all_metadata: false,
        limits: config::LimitsResolved::default(),
        export: Default::default(),
        identity_providers: Default::default(),
        export_defs: Default::default(),
    }
}

/// Byte-identical to `src/config_validate/tests/tests.rs::make_model_unbounded`.
fn make_model_unbounded(provider: &str) -> config::ModelCfg {
    config::ModelCfg {
        reasoning: None,
        prompt_caching: None,
        max_requests: -1,
        provider: provider.into(),
        max_concurrent: None,
        default_max_tokens: None,
        upstream_model: None,
        attempt_timeout_ms: None,
    }
}

/// A minimal `tools:` registry holding one server id, for the collision tests below — byte-identical
/// to `src/config_validate/tests/tests.rs::tools_with`.
fn tools_with(id: &str) -> busbar_mcp::mcp::config::ToolsCfg {
    let mut td = busbar_mcp::mcp::config::ToolsCfg::default();
    td.servers.insert(
        id.to_string(),
        serde_yaml::from_str("{url: 'https://x.example/mcp', pin: {mechanism: unpinned}}")
            .expect("a minimal server"),
    );
    td
}

/// A name defined in TWO nouns makes a bare member ambiguous — the router could not tell which plane
/// `shared` belongs to. Refused so kind inference stays name-only.
#[test]
fn a_name_defined_in_two_nouns_is_refused() {
    let mut models = HashMap::new();
    models.insert("shared".to_string(), make_model_unbounded("prov"));
    let mut cfg = make_root_cfg(HashMap::new(), models, HashMap::new());
    cfg.tool_defs = Box::new(tools_with("shared"));

    let mut errors = Vec::new();
    validate_unified_pool_names(&cfg, &mut errors);
    assert!(
        errors.iter().any(|e| e.contains("`shared`")
            && e.contains("`models:`")
            && e.contains("`tools:`")
            && e.contains("at most ONE noun")),
        "the collision names the two nouns: {errors:?}"
    );
}

/// A pool name that collides with a registration on the plane it routes to would alias that
/// registration's breaker cell. Refused, cross-checked against every noun (the map is not kind-scoped).
#[test]
fn a_pool_named_like_a_tools_registration_is_refused() {
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.tool_defs = Box::new(tools_with("search"));
    cfg.tool_pools.insert(
        "search".to_string(),
        CandidatePoolCfg {
            members: vec!["search-eu".into(), "search-us".into()],
            repeatable: Vec::new(),
        },
    );

    let mut errors = Vec::new();
    validate_unified_pool_names(&cfg, &mut errors);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("pool name 'search'") && e.contains("`tools:` registration")),
        "a pool sharing a registration name is refused: {errors:?}"
    );
}

/// The clean case: distinct names across every noun and pool, no collision — zero errors.
#[test]
fn distinct_names_across_nouns_and_pools_pass() {
    let mut models = HashMap::new();
    models.insert("gpt".to_string(), make_model_unbounded("prov"));
    let mut cfg = make_root_cfg(HashMap::new(), models, HashMap::new());
    cfg.tool_defs = Box::new(tools_with("fs-server"));

    let mut errors = Vec::new();
    validate_unified_pool_names(&cfg, &mut errors);
    assert!(errors.is_empty(), "no collisions: {errors:?}");
}
