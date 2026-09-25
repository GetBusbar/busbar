// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-PLANE `config::resolve` AGREEMENT TESTS, relocated here from `src/config/tests/tests.rs`
//! (the A6/HostCtx dev-dependency-cycle cleanup): each of these calls a REAL plane crate's function
//! or constructs a REAL plane crate's config type and hands it to core's OWN `resolve`/
//! `merge_provider_fallback`, so the busbar_kernel type on both sides of the call must be the SAME
//! instance — which only an integration-test target gives (busbar_kernel links as an ordinary
//! dependency, the same instance the plane crates link), never a `#[cfg(test)]` unit module in
//! `src/`, which Cargo's dev-dependency back-edge (busbar-kernel dev-depends on busbar-llm/-mcp,
//! which normal-depend on busbar-kernel) compiles as a SECOND, distinct `busbar_kernel` instance.
//! See `plane_integration.rs`'s header for the same rationale, first written there.
//!
//! `merge_provider_fallback` (in `busbar_kernel::config`) and `validate_unified_pool_names` (in
//! `busbar_kernel::config_validate`, used by `config_validate_cross_plane.rs`) were widened from
//! private to `pub` for exactly this move — nothing about the tests themselves changed; they still
//! drive the real functions directly, not a shim.

use busbar_kernel::config::{
    merge_provider_fallback, resolve, AdvancedCfg, ConfigMgmtCfg, DeployCfg, HealthDefaultsCfg,
    LimitsCfg, PoolCfg, ProviderDef, ProviderDeploy, RoutingCfg, SecretRef,
    DEFAULT_ADMIN_LISTEN_ADDR, DEFAULT_LISTEN_ADDR,
};
use std::collections::HashMap;

/// Register the real MCP/A2A planes in the process registry, idempotent (first-wins) — needed
/// because `resolve()` refuses a non-default `tools:`/`agents:` section as "compiled without the
/// plane that owns it" unless that plane is actually registered. `src/config/tests/tests.rs` got
/// this for free from the removed `TEST_BUILTIN_PLANE_DECLS`; here it is explicit, per-test.
fn register_planes() {
    busbar_mcp::testkit::install_test_seams();
    busbar_a2a::testkit::install_test_seams();
}

/// A minimal ProviderDef for resolve() tests — byte-identical to the fixture this test used before
/// the move (`src/config/tests/tests.rs::provider_def`).
fn provider_def(protocol: &str, base_url: &str) -> ProviderDef {
    ProviderDef {
        protocol: protocol.to_string(),
        base_url: base_url.to_string(),
        error_map: HashMap::new(),
        health: None,
        path: None,
        path_base: None,
        token_url: None,
        scope: None,
        subject: None,
        auth: None,
        allow_metadata_hosts: Vec::new(),
        max_output_key: None,
        anthropic_adaptive_thinking: None,
        native_structured_output: None,
        model_capabilities: Vec::new(),
    }
}

/// A minimal ProviderDeploy whose credential is `{ env: <var> }` — byte-identical to
/// `src/config/tests/tests.rs::provider_deploy`.
fn provider_deploy(env_var: &str) -> ProviderDeploy {
    ProviderDeploy {
        api_key: SecretRef::env(env_var),
        protocol: None,
        base_url: None,
        error_map: None,
        path: None,
        path_base: None,
        token_url: None,
        scope: None,
        subject: None,
        auth: None,
        allow_metadata_hosts: None,
        max_output_key: None,
        anthropic_adaptive_thinking: None,
        native_structured_output: None,
        model_capabilities: None,
        health: None,
    }
}

/// An all-default DeployCfg for struct-literal resolve() tests (DeployCfg has no Default because
/// providers/models are required in YAML) — byte-identical to `src/config/tests/tests.rs::base_deploy`.
fn base_deploy() -> DeployCfg {
    DeployCfg {
        tools: Default::default(),
        agents: Default::default(),
        streams: Default::default(),
        decisions: Default::default(),
        listen: DEFAULT_LISTEN_ADDR.into(),
        endpoint: Default::default(),
        oauth_as: None,
        public_url: None,
        tls: None,
        admin_listen: DEFAULT_ADMIN_LISTEN_ADDR.into(),
        admin_tls: None,
        admin_require_mtls: true,
        config: ConfigMgmtCfg::default(),
        providers_file: None,
        auth: None,
        identity_providers: Default::default(),
        providers: HashMap::new(),
        models: HashMap::new(),
        pools: Default::default(),
        hooks: Default::default(),
        groups: Default::default(),
        rate_card: None,
        per_request_fee: 0,
        plane_rate_cards: Default::default(),
        plane_fees: Default::default(),
        plane_raw: Default::default(),
        store: None,
        secrets: Default::default(),
        advanced: AdvancedCfg::default(),
        plugins: Default::default(),
        security: None,
        limits: LimitsCfg::default(),
        export: Default::default(),
        health: HealthDefaultsCfg::default(),
        routing: RoutingCfg::default(),
    }
}

/// THE HOOK-PATH / FALLBACK-PATH EQUIVALENCE (1.6.0 pools stage-B). `resolve`'s provider merge runs
/// through `PlaneDecl::resolve_provider` when the LLM plane is installed (the shipped default) and
/// through core's own `merge_provider_fallback` when no plane implements the hook. This test proves
/// the two produce the IDENTICAL `ProviderCfg` for the same inputs, so an llm-plane-absent build's
/// merge is byte-identical to the shipped one — the guarantee `merge_provider_fallback`'s doc claims.
#[test]
fn resolve_provider_hook_and_core_fallback_agree() {
    let mut def = provider_def("anthropic", "https://api.z.ai/api/model-1");
    def.error_map
        .insert("1113".to_string(), "billing".to_string());
    def.error_map
        .insert("1302".to_string(), "rate_limit".to_string());
    let deploy_cfg = provider_deploy("ZAI_KEY");

    let hook = busbar_llm::PLANE_HOOKS
        .resolve_provider
        .expect("the LLM plane declares `resolve_provider`");
    let via_hook = hook(&def, &deploy_cfg);
    let via_fallback = merge_provider_fallback(&def, &deploy_cfg);

    assert_eq!(via_hook.protocol, via_fallback.protocol);
    assert_eq!(via_hook.base_url, via_fallback.base_url);
    assert_eq!(via_hook.api_key.env_var(), via_fallback.api_key.env_var());
    assert_eq!(via_hook.error_map, via_fallback.error_map);
    assert_eq!(via_hook.health.is_some(), via_fallback.health.is_some());
    assert_eq!(via_hook.path, via_fallback.path);
    assert_eq!(via_hook.path_base, via_fallback.path_base);
    assert_eq!(via_hook.token_url, via_fallback.token_url);
    assert_eq!(via_hook.scope, via_fallback.scope);
    assert_eq!(via_hook.subject, via_fallback.subject);
    assert_eq!(via_hook.auth, via_fallback.auth);
    assert_eq!(
        via_hook.allow_metadata_hosts,
        via_fallback.allow_metadata_hosts
    );
}

/// THE PUBLISHED-NAME COLLISION IS A `resolve` ERROR, which is what makes it a `--validate` error.
///
/// `busbar --validate`, boot, the admin config-apply rebuild and the admin dry-run validate endpoint
/// all reach `resolve`, and none of them reaches `mcp::config::validate_published_names` any other
/// way. If the check were wired only into the `ToolsCfg` `Deserialize` it would never see a server
/// the admin API applied, and a config that validated would not be the config that boots. So the
/// wiring itself is the thing under test here, not the rule.
#[test]
fn resolve_refuses_a_publish_as_collision_so_validate_and_boot_agree() {
    register_planes();
    // The SUBTLE collision — an override against a namespaced default nobody typed — because it is
    // the one that survives a partial implementation of the rule.
    let tools: busbar_mcp::mcp::config::ToolsCfg = serde_yaml::from_str(
        r#"
foo:
  url: "https://foo/"
  pin: { mechanism: unpinned }
  tools_allow: { bar: {} }
other:
  url: "https://other/"
  pin: { mechanism: unpinned }
  tools_allow: { anything: { publish_as: foo_bar } }
"#,
    )
    .expect("both servers are individually valid");

    let mut deploy = base_deploy();
    deploy.tools = busbar_kernel::plane::config::ToolsSection(Box::new(tools));
    let errors = resolve(&deploy, &HashMap::new())
        .expect_err("resolve must refuse a config whose published names are not unique");
    assert!(
        errors.iter().any(|e| e.contains("published as `foo_bar`")),
        "{errors:?}"
    );

    // GREEN, same shape, one name changed: the refusal is about the collision and nothing else.
    let ok: busbar_mcp::mcp::config::ToolsCfg = serde_yaml::from_str(
        r#"
foo:
  url: "https://foo/"
  pin: { mechanism: unpinned }
  tools_allow: { bar: {} }
other:
  url: "https://other/"
  pin: { mechanism: unpinned }
  tools_allow: { anything: { publish_as: other_name } }
"#,
    )
    .unwrap();
    let mut deploy = base_deploy();
    deploy.tools = busbar_kernel::plane::config::ToolsSection(Box::new(ok));
    resolve(&deploy, &HashMap::new()).expect("distinct published names must resolve");
}

/// A member naming nothing is an operator believing a request has somewhere to go when it does not.
/// 1.6.0: the pool lives in the ONE neutral `pools:` map; kind is INFERRED from the resolvable
/// member (`search-eu` → a `tools:` server), so the dangling `search-us` is named against `tools:`.
#[test]
fn a_tool_pool_member_that_names_no_server_is_refused() {
    register_planes();
    let mut deploy = base_deploy();
    let mut tools = busbar_mcp::mcp::config::ToolsCfg::default();
    tools.servers.insert(
        "search-eu".to_string(),
        serde_yaml::from_str("{url: 'https://eu.example/mcp', pin: {mechanism: unpinned}}")
            .expect("a minimal server"),
    );
    deploy.tools = busbar_kernel::plane::config::ToolsSection(Box::new(tools));
    deploy.pools.pools.insert(
        "search".to_string(),
        serde_yaml::from_str::<PoolCfg>("{members: [search-eu, search-us]}")
            .expect("a bare-name pool"),
    );
    let errs = resolve(&deploy, &HashMap::new()).expect_err("a dangling member must refuse boot");
    assert!(
        errs.iter()
            .any(|e| e.contains("search-us") && e.contains("`tools:`")),
        "the message names the missing entry and the section it belongs in: {errs:?}"
    );
}

/// KIND IS INFERRED, SO A POOL MUST BE HOMOGENEOUS: a pool whose members span two nouns cannot be
/// assigned a single plane and is refused with the homogeneity error.
#[test]
fn a_pool_may_not_straddle_two_planes() {
    register_planes();
    let mut deploy = base_deploy();
    let mut agents = busbar_a2a::a2a::config::AgentsCfg::default();
    agents.agents.insert(
        "planner".to_string(),
        serde_yaml::from_str("{url: 'https://a.example/card', pin: {mechanism: unpinned}}")
            .expect("a minimal agent"),
    );
    deploy.agents = busbar_kernel::plane::config::AgentsSection(Box::new(agents));
    let mut tools = busbar_mcp::mcp::config::ToolsCfg::default();
    tools.servers.insert(
        "search-eu".to_string(),
        serde_yaml::from_str("{url: 'https://eu.example/mcp', pin: {mechanism: unpinned}}")
            .expect("a minimal server"),
    );
    deploy.tools = busbar_kernel::plane::config::ToolsSection(Box::new(tools));
    deploy.pools.pools.insert(
        "mixed".to_string(),
        serde_yaml::from_str::<PoolCfg>("{members: [planner, search-eu]}")
            .expect("a bare-name pool"),
    );
    let errs =
        resolve(&deploy, &HashMap::new()).expect_err("a cross-plane member must refuse boot");
    assert!(
        errs.iter()
            .any(|e| e.contains("more than one plane") && e.contains("same kind")),
        "the message says the pool's members are not all one kind: {errs:?}"
    );
}

/// A one-member pool changes nothing, so writing one is a mistake and is named as one.
#[test]
fn a_failover_pool_needs_two_members() {
    register_planes();
    let mut deploy = base_deploy();
    let mut agents = busbar_a2a::a2a::config::AgentsCfg::default();
    agents.agents.insert(
        "only-one".to_string(),
        serde_yaml::from_str("{url: 'https://a.example/card', pin: {mechanism: unpinned}}")
            .expect("a minimal agent"),
    );
    deploy.agents = busbar_kernel::plane::config::AgentsSection(Box::new(agents));
    deploy.pools.pools.insert(
        "planner".to_string(),
        serde_yaml::from_str::<PoolCfg>("{members: [only-one]}").expect("a bare-name pool"),
    );
    let errs = resolve(&deploy, &HashMap::new()).expect_err("a one-member pool must refuse boot");
    assert!(
        errs.iter().any(|e| e.contains("at least TWO members")),
        "{errs:?}"
    );
}
