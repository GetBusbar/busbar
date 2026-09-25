// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-PLANE `config::resolve` AGREEMENT TESTS, relocated here from `src/config/tests/tests.rs`:
//! each drives core's OWN `resolve` / `merge_provider_fallback` against the REAL planes this binary
//! links (the test-linked table, `tests/linked/mod.rs`), so the busbar_kernel instance on both sides
//! of the call is the one the planes link — which only an integration-test target gives. The
//! configuration is CONFIG-DRIVEN: a YAML document parsed through the kernel's own entry point, so
//! the sections are lifted by whichever registered plane declares them and this file names no plane
//! crate and no plane type.

mod linked;

use busbar_kernel::config::{
    deploy_from_yaml_str, merge_provider_fallback, resolve, DeployCfg, ProviderDef, ProviderDeploy,
    SecretRef,
};
use std::collections::HashMap;

/// Register every test-linked plane in the process registry, idempotent (first-wins) — needed
/// because the kernel lifts a `tools:`/`agents:` section only when a registered plane declares it.
fn register_planes() {
    linked::install();
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

/// A DeployCfg parsed from `sections` through the kernel's own config entry point
/// (`deploy_from_yaml_str`, the boot path's lift), after the linked planes are installed — so a
/// section is lifted exactly when a registered plane declares it, as in a shipped binary. Empty
/// `providers:`/`models:` stand in for the required keys this file's refusals do not concern.
fn deploy_yaml(sections: &str) -> DeployCfg {
    register_planes();
    let text = format!("providers: {{}}\nmodels: {{}}\n{sections}");
    deploy_from_yaml_str(&text).unwrap_or_else(|e| panic!("the test config parses: {e}\n{text}"))
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

    // Every linked plane that implements the hook, read back from the registry — at least one (the
    // shipped fallback plane does), each proven equal to core's fallback.
    let hooks: Vec<_> = linked::planes()
        .iter()
        .filter_map(|d| d.resolve_provider.map(|h| (d.key, h)))
        .collect();
    assert!(
        !hooks.is_empty(),
        "a test-linked plane declares `resolve_provider`"
    );
    let via_fallback = merge_provider_fallback(&def, &deploy_cfg);
    for (key, hook) in hooks {
        let via_hook = hook(&def, &deploy_cfg);
        assert_eq!(via_hook.protocol, via_fallback.protocol, "{key}");
        assert_eq!(via_hook.base_url, via_fallback.base_url, "{key}");
        assert_eq!(
            via_hook.api_key.env_var(),
            via_fallback.api_key.env_var(),
            "{key}"
        );
        assert_eq!(via_hook.error_map, via_fallback.error_map, "{key}");
        assert_eq!(
            via_hook.health.is_some(),
            via_fallback.health.is_some(),
            "{key}"
        );
        assert_eq!(via_hook.path, via_fallback.path, "{key}");
        assert_eq!(via_hook.path_base, via_fallback.path_base, "{key}");
        assert_eq!(via_hook.token_url, via_fallback.token_url, "{key}");
        assert_eq!(via_hook.scope, via_fallback.scope, "{key}");
        assert_eq!(via_hook.subject, via_fallback.subject, "{key}");
        assert_eq!(via_hook.auth, via_fallback.auth, "{key}");
        assert_eq!(
            via_hook.allow_metadata_hosts, via_fallback.allow_metadata_hosts,
            "{key}"
        );
    }
}

#[test]
fn resolve_refuses_a_publish_as_collision_so_validate_and_boot_agree() {
    register_planes();
    // The SUBTLE collision — an override against a namespaced default nobody typed — because it is
    // the one that survives a partial implementation of the rule.
    let deploy = deploy_yaml(
        r#"
tools:
  foo:
    url: "https://foo/"
    pin: { mechanism: unpinned }
    tools_allow: { bar: {} }
  other:
    url: "https://other/"
    pin: { mechanism: unpinned }
    tools_allow: { anything: { publish_as: foo_bar } }
"#,
    );
    let errors = resolve(&deploy, &HashMap::new())
        .expect_err("resolve must refuse a config whose published names are not unique");
    assert!(
        errors.iter().any(|e| e.contains("published as `foo_bar`")),
        "{errors:?}"
    );

    // GREEN, same shape, one name changed: the refusal is about the collision and nothing else.
    let deploy = deploy_yaml(
        r#"
tools:
  foo:
    url: "https://foo/"
    pin: { mechanism: unpinned }
    tools_allow: { bar: {} }
  other:
    url: "https://other/"
    pin: { mechanism: unpinned }
    tools_allow: { anything: { publish_as: other_name } }
"#,
    );
    resolve(&deploy, &HashMap::new()).expect("distinct published names must resolve");
}

/// A member naming nothing is an operator believing a request has somewhere to go when it does not.
/// 1.6.0: the pool lives in the ONE neutral `pools:` map; kind is INFERRED from the resolvable
/// member (`search-eu` → a `tools:` server), so the dangling `search-us` is named against `tools:`.
#[test]
fn a_tool_pool_member_that_names_no_server_is_refused() {
    register_planes();
    let deploy = deploy_yaml(
        r#"
tools:
  search-eu: { url: "https://eu.example/t", pin: { mechanism: unpinned } }
pools:
  search:
    members: [search-eu, search-us]
"#,
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
    let deploy = deploy_yaml(
        r#"
agents:
  planner: { url: "https://a.example/card", pin: { mechanism: unpinned } }
tools:
  search-eu: { url: "https://eu.example/t", pin: { mechanism: unpinned } }
pools:
  mixed:
    members: [planner, search-eu]
"#,
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
    let deploy = deploy_yaml(
        r#"
agents:
  only-one: { url: "https://a.example/card", pin: { mechanism: unpinned } }
pools:
  planner:
    members: [only-one]
"#,
    );
    let errs = resolve(&deploy, &HashMap::new()).expect_err("a one-member pool must refuse boot");
    assert!(
        errs.iter().any(|e| e.contains("at least TWO members")),
        "{errs:?}"
    );
}
