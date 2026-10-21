// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-PLANE MIGRATE→RESOLVE TESTS, relocated here from `src/config/tests/migrate_tests.rs` (the
//! "fix the 85" pass after the A6/HostCtx dev-dependency-cycle cleanup): the fixture below configures
//! a real `tools:`/`agents:` block and then asserts on `cfg.plane_pools`, which only
//! exist once a registered plane actually claims each section — `resolve()` refuses a
//! `tools:`/`agents:` section as "compiled without the plane that owns it" unless the owning plane
//! is registered. `tools:` is a linked plane's; `agents:` is the roster's DOOR row (a
//! `door:` row of the test-linked list: the plane's own door, its registry row folded from its
//! Statement by the kernel's door fold as the composition root folds it), so the section is
//! parsed, judged and pooled by the kernel's production code for a door. That only type-checks with ONE `busbar_kernel` in the graph, which is
//! exactly what an integration-test target gives. See `plane_integration.rs`'s header for the same
//! rationale, first written there.

mod linked;

use busbar_kernel::config::migrate::migrate_config;
use busbar_kernel::config::{deploy_from_yaml_str, resolve, DeployCfg, ProviderDef};

/// Register the roster (the linked planes and the door row) in the process registry, idempotent
/// (first-wins).
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

    let out = migrate_config(
        raw,
        &busbar_kernel::preflight::RootInstall::STAND_IN,
        busbar_kernel::config::Legacy::stand_in(),
    )
    .expect("the full legacy config migrates");

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

    // The tool/agent pools moved under their verbs (`tools.pools`, `agents.pools`) and resolve
    // onto those planes' failover maps; the model pool `fast` stays on the model plane.
    let pools_of = |section: &str| cfg.plane_pools.get(section).cloned().unwrap_or_default();
    assert!(
        pools_of("tools").contains_key("search"),
        "the moved tool pool resolves onto the `tools:` plane's failover map: {:?}",
        cfg.plane_pools
    );
    assert!(
        pools_of("agents").contains_key("planner"),
        "the moved agent pool resolves onto the `agents:` plane's failover map: {:?}",
        cfg.plane_pools
    );
    assert!(
        cfg.pools.contains_key("fast"),
        "the model pool resolves onto the model plane"
    );
}

/// A POOL UNDER A PLANE'S VERB REFUSES EVERY FIELD ITS PLANE DOES NOT HONOUR (Q128 arch u28 HIGH,
/// coordinator ruling: a field the path does not honour is refused, naming it). A plane's pool is
/// the reserved `pools` sub-key of its own section and carries `members:` by bare name and
/// `repeatable:`; each other family below used to be dropped without a word by the old projection
/// of a top-level pool onto a plane, so a gate the operator wrote on such a pool never fired. One RED
/// per field family, on pools of `tools:` entries and of `agents:` entries alike, and a control: the
/// carried fields alone resolve. No 1.5.5 config reaches this path: v1.5.5's deployment grammar
/// (crates/busbar/src/config/mod.rs:2573, `deny_unknown_fields`) has no plane sections.
#[test]
fn a_plane_pool_refuses_each_field_its_plane_does_not_honour() {
    register_planes();
    let base = r#"
providers: {}
models: {}
hooks:
  audit:
    kind: gate
    module: audit-hook
    phase: [request]
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
"#;
    let defs: std::collections::HashMap<String, ProviderDef> = std::collections::HashMap::new();
    let resolve_pool = |section: &str, members: &str, extra: &str| {
        let mut doc: serde_yaml::Value = serde_yaml::from_str(base).expect("the base parses");
        let pool: serde_yaml::Value =
            serde_yaml::from_str(&format!("members: {members}\n{extra}")).expect("the pool parses");
        doc[section]["pools"] = serde_yaml::from_str("{}").unwrap();
        doc[section]["pools"]["p"] = pool;
        let raw = serde_yaml::to_string(&doc).expect("the config renders");
        let deploy: DeployCfg =
            deploy_from_yaml_str(&raw).unwrap_or_else(|e| panic!("the config parses: {e}\n{raw}"));
        resolve(&deploy, &defs)
            .map(|_| ())
            .map_err(|e| format!("{e:?}"))
    };
    for (section, members) in [
        ("tools", "[search-eu, search-us]"),
        ("agents", "[planner-eu, planner-us]"),
    ] {
        // The control: what the plane honours resolves.
        resolve_pool(section, members, "repeatable: [read]\n")
            .unwrap_or_else(|e| panic!("a carried field is refused for {members}: {e}"));
        for (extra, named) in [
            ("hooks: [audit]\n", "hooks"),
            ("failover: { max_hops: 2 }\n", "failover"),
            ("on_exhausted: reject\n", "on_exhausted"),
            ("affinity: { mode: session }\n", "affinity"),
            (
                "upstream_credentials: passthrough\n",
                "upstream_credentials",
            ),
            ("weights: { x: 3 }\n", "weights"),
            ("tier: large\n", "tier"),
            ("attempt_timeout_ms: 500\n", "attempt_timeout_ms"),
        ] {
            let refused = resolve_pool(section, members, extra);
            assert!(
                refused
                    .as_ref()
                    .is_err_and(|e| e.contains(&format!("{section}.pools"))
                        && e.contains(&format!("unknown field `{named}`"))),
                "a {section} pool must refuse `{named}:`, naming it: {refused:?}"
            );
        }
        let rich = members
            .replace("[", "[{ model: ")
            .replacen(", ", ", weight: 3 }, ", 1);
        let refused = resolve_pool(section, &rich, "");
        assert!(
            refused
                .as_ref()
                .is_err_and(|e| e.contains(&format!("{section}.pools"))),
            "a {section} pool must refuse a member's own keys: {refused:?}"
        );
    }
}
