// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-PLANE MIGRATE→RESOLVE TESTS, relocated here from `src/config/tests/migrate_tests.rs` (the
//! "fix the 85" pass after the A6/HostCtx dev-dependency-cycle cleanup): the fixture below configures
//! a real `tools:`/`agents:` block and then asserts on `cfg.tool_pools`/`cfg.agent_pools`, which only
//! exist once the REAL `busbar_mcp`/`busbar_a2a` failover planes actually claim those sections —
//! `resolve()` refuses a `tools:`/`agents:` section as "compiled without the plane that owns it"
//! unless the owning plane is registered, and a neutral fake plane cannot stand in for what these
//! assertions read back. That only type-checks with ONE `busbar_kernel` in the graph, which is
//! exactly what an integration-test target gives. See `plane_integration.rs`'s header for the same
//! rationale, first written there.

mod linked;

use busbar_kernel::config::migrate::migrate_config;
use busbar_kernel::config::{deploy_from_yaml_str, resolve, DeployCfg, ProviderDef};

/// Register the real llm/mcp/a2a planes in the process registry, idempotent (first-wins).
fn register_planes() {
    linked::install();
}

/// END-TO-END, 1.6.0: a COMPLETE 1.5.x-shaped config that uses EVERY deprecated spelling at once —
/// a hook written with the retired `plugin:` key AND the retired single-stage `at:` key, a model pool
/// with rich weighted members (still the 1.6.0 grammar, carried through unchanged), and the
/// unreleased `tool_pools:`/`agent_pools:` sections — runs through `busbar --migrate-config` and the
/// output (a) parses into the 1.6.0 `DeployCfg`, (b) `config::resolve` + `config_validate::validate`
/// clean, and (c) contains NONE of the deprecated spellings. This migrate→validate round-trip on a
/// full config is the only thing that proves the migrator is comprehensive: a code read of what it
/// "thinks" it handles is not enough.
#[test]
fn end_to_end_a_full_legacy_config_migrates_validates_and_drops_every_deprecated_spelling() {
    register_planes();
    let raw = r#"
listen: "0.0.0.0:8080"
providers:
  acme:
    api_key: { env: BUSBAR_T_E2E_ACME }
models:
  fast-a:
    provider: acme
  fast-b:
    provider: acme
hooks:
  audit:
    kind: gate
    plugin: audit-hook
    at: request
tools:
  search-eu:
    url: "https://eu.example/t"
    pin: { mechanism: unpinned }
  search-us:
    url: "https://us.example/t"
    pin: { mechanism: unpinned }
agents:
  planner-eu:
    url: "https://a1.example/card"
    pin: { mechanism: unpinned }
  planner-us:
    url: "https://a2.example/card"
    pin: { mechanism: unpinned }
pools:
  fast:
    members:
      - { model: fast-a, weight: 3 }
      - { model: fast-b }
    hooks: [audit]
tool_pools:
  search:
    members: [search-eu, search-us]
agent_pools:
  planner:
    members: [planner-eu, planner-us]
"#;

    let out = migrate_config(raw).expect("the full legacy config migrates");

    // (c) NONE of the deprecated spellings survive anywhere in the migrated document.
    for needle in ["plugin:", "at: ", "tool_pools:", "agent_pools:"] {
        assert!(
            !out.yaml.contains(needle),
            "the migrated config still contains the deprecated spelling `{needle}`:\n{}",
            out.yaml
        );
    }
    // The hook keys were rewritten to their 1.6.0 spelling.
    assert!(
        out.yaml.contains("module: audit-hook"),
        "`plugin: audit-hook` must become `module: audit-hook`:\n{}",
        out.yaml
    );
    assert!(
        out.yaml.contains("phase:"),
        "the single-stage `at: request` must become a `phase:` list:\n{}",
        out.yaml
    );

    // (a) It parses into the 1.6.0 DeployCfg (deny_unknown_fields is the real gate: a surviving
    // `plugin:`/`at:`/tool_pools would fail HERE; the rich pool members are valid 1.6.0 grammar).
    let deploy: DeployCfg = deploy_from_yaml_str(&out.yaml).unwrap_or_else(|e| {
        panic!(
            "migrated config must boot-parse on 1.6.0: {e}\n{}",
            out.yaml
        )
    });

    // (b) It resolves and validates clean on 1.6.0.
    let defs: std::collections::HashMap<String, ProviderDef> = serde_yaml::from_str(
        "acme:\n  protocol: anthropic\n  base_url: https://api.acme.example\n",
    )
    .expect("provider defs parse");
    let cfg = resolve(&deploy, &defs)
        .unwrap_or_else(|e| panic!("migrated config must resolve on 1.6.0: {e:?}"));
    busbar_kernel::config_validate::validate(&cfg)
        .unwrap_or_else(|e| panic!("migrated config must validate clean on 1.6.0: {e:?}"));

    // The tool/agent pools folded into the ONE neutral `pools:` map and resolve by INFERRED kind:
    // `search` (tool members) onto the tool-kind pool map, `planner` (agent members) onto the
    // agent-kind pool map, and the model pool `fast` onto the model-kind pool map.
    assert!(
        cfg.tool_pools.contains_key("search"),
        "the folded tool pool resolves onto the `tools:` plane's failover map: {:?}",
        cfg.tool_pools.keys().collect::<Vec<_>>()
    );
    assert!(
        cfg.agent_pools.contains_key("planner"),
        "the folded agent pool resolves onto the `agents:` plane's failover map: {:?}",
        cfg.agent_pools.keys().collect::<Vec<_>>()
    );
    assert!(
        cfg.pools.contains_key("fast"),
        "the model pool resolves onto the model plane"
    );
}
