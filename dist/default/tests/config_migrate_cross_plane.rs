// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod linked;

mod migration {
    include!(concat!(env!("OUT_DIR"), "/migration_table.rs"));
}

use busbar_contract::yaml::{self, prelude::*};
use busbar_kernel::config::{deploy_from_yaml_str, resolve, DeployCfg, ProviderDef};
use busbar_migrations::config::migrate::migrate_config;

fn register_planes() {
    busbar_kernel::config::declared_vocabulary::install(migration::MIGRATION_ROWS);
    linked::install();
}

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
  pools:
    search:
      members: [search-eu, search-us]
agents:
  planner-eu:
    url: "https://a1.example/card"
    pin: { mechanism: unpinned }
  planner-us:
    url: "https://a2.example/card"
    pin: { mechanism: unpinned }
  pools:
    planner:
      members: [planner-eu, planner-us]
pools:
  fast:
    members:
      - { model: fast-a, weight: 3 }
      - { model: fast-b }
    hooks: [audit]
"#;

    let out = migrate_config(raw).expect("the full legacy config migrates");

    for needle in ["plugin:", "at: "] {
        assert!(
            !out.yaml.contains(needle),
            "the migrated config still contains the deprecated spelling `{needle}`:\n{}",
            out.yaml
        );
    }

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

    let deploy: DeployCfg = deploy_from_yaml_str(&out.yaml, &live_grammar()).unwrap_or_else(|e| {
        panic!(
            "migrated config must boot-parse on 1.6.0: {e}\n{}",
            out.yaml
        )
    });

    let defs: std::collections::HashMap<String, ProviderDef> =
        yaml::from_str("acme:\n  protocol: anthropic\n  base_url: https://api.acme.example\n")
            .expect("provider defs parse");
    let cfg = resolve(&deploy, &defs)
        .unwrap_or_else(|e| panic!("migrated config must resolve on 1.6.0: {e:?}"));
    busbar_kernel::config_validate::validate(&cfg)
        .unwrap_or_else(|e| panic!("migrated config must validate clean on 1.6.0: {e:?}"));

    let pools_of = |section: &str| cfg.plane_pools.get(section).cloned().unwrap_or_default();
    assert!(
        pools_of("tools").contains_key("search"),
        "the tool pool resolves onto the `tools:` plane's failover map: {:?}",
        cfg.plane_pools
    );
    assert!(
        pools_of("agents").contains_key("planner"),
        "the agent pool resolves onto the `agents:` plane's failover map: {:?}",
        cfg.plane_pools
    );
    assert!(
        cfg.pools.contains_key("fast"),
        "the model pool resolves onto the model plane"
    );
}

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
        let mut doc: Value = yaml::from_str(base).expect("the base parses");
        let pool: Value =
            yaml::from_str(&format!("members: {members}\n{extra}")).expect("the pool parses");
        *doc.at_mut(section).at_mut("pools") = yaml::from_str("{}").unwrap();
        *doc.at_mut(section).at_mut("pools").at_mut("p") = pool;
        let raw = yaml::to_string(&doc).expect("the config renders");
        let deploy: DeployCfg = deploy_from_yaml_str(&raw, &live_grammar())
            .unwrap_or_else(|e| panic!("the config parses: {e}\n{raw}"));
        resolve(&deploy, &defs)
            .map(|_| ())
            .map_err(|e| format!("{e:?}"))
    };
    for (section, members) in [
        ("tools", "[search-eu, search-us]"),
        ("agents", "[planner-eu, planner-us]"),
    ] {
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

#[test]
fn unreleased_tool_and_agent_pool_keys_are_left_for_admission_to_refuse() {
    register_planes();
    for (key, raw) in [
        (
            "tool_pools",
            "providers: {}\nmodels: {}\ntool_pools:\n  MIGRATION_PRIVATE_SENTINEL:\n    members: [a]\n",
        ),
        (
            "agent_pools",
            "providers: {}\nmodels: {}\nagent_pools:\n  MIGRATION_PRIVATE_SENTINEL:\n    members: [a]\n",
        ),
    ] {
        let out = migrate_config(raw).expect("the config still parses as YAML");
        assert!(
            out.yaml.contains(&format!("{key}:")),
            "`{key}:` was never written by a released Busbar, so it is not rewritten:\n{}",
            out.yaml
        );
        assert!(
            !out.changes.iter().any(|line| line.contains(key)),
            "no rewrite is reported for `{key}`: {:?}",
            out.changes
        );
        let error = deploy_from_yaml_str(&out.yaml, &live_grammar())
            .err()
            .unwrap_or_else(|| panic!("`{key}:` must be refused at admission"))
            .to_string();
        assert!(error.contains(key), "the refusal names `{key}`: {error}");
        assert!(
            !error.contains("MIGRATION_PRIVATE_SENTINEL"),
            "the refusal never echoes authored values: {error}"
        );
    }
}

/// The grammar these fixtures read under: the words the installed secret axis declares (this
/// distribution's linked secret modules), passed explicitly.
fn live_grammar() -> busbar_kernel::config::Grammar {
    busbar_kernel::config::Grammar::new(
        busbar_kernel::config::secret::live_axis()
            .map(busbar_contract::secret::SecretAxis::sugars)
            .unwrap_or_default(),
        Default::default(),
        Vec::new(),
    )
}
