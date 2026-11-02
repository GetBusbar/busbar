// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::config::migrate::*;

fn migrate_to_value(raw: &str) -> (MigrateOutput, serde_yaml::Value) {
    let out = migrate_config(raw).expect("migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).expect("output is valid YAML");
    (out, doc)
}

fn dig<'a>(doc: &'a serde_yaml::Value, path: &[&str]) -> Option<&'a serde_yaml::Value> {
    let mut cur = doc;
    for k in path {
        cur = cur.as_mapping()?.get(serde_yaml::Value::from(*k))?;
    }
    Some(cur)
}

fn webhooks(defs: &busbar_kernel::config::ExportDefs) -> usize {
    defs.values()
        .filter(|d| d.module.trim() == "request-log-webhook")
        .count()
}

fn built_ins(defs: &busbar_kernel::config::ExportDefs) -> busbar_kernel::config::ExportDefs {
    defs.iter()
        .filter(|(_, d)| d.module.trim() != "request-log-webhook")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

#[test]
fn migrate_keeps_explicit_empty_admin_chain_distinct_from_absence() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    for auth in ["null", "{}"] {
        let (_, doc) = migrate_to_value(&format!("auth: {auth}\nadmin_auth: []\n"));
        assert!(dig(&doc, &["auth", "admin_auth"])
            .unwrap()
            .as_sequence()
            .unwrap()
            .is_empty());
    }
    let (_, doc) = migrate_to_value("auth: {}\n");
    assert!(dig(&doc, &["auth", "admin_auth"]).is_none());
}

#[test]
fn migrate_preserves_admin_values_when_auth_cannot_accept_them() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    for raw in [
        "auth: opaque\nadmin_auth: [test-idp-double]\n",
        "auth: { admin_auth: opaque }\nadmin_auth: [test-idp-double]\n",
        "auth: opaque\ngovernance: { admin_token: '${ADMIN_TOKEN}' }\n",
        "auth: { admin_auth: opaque }\ngovernance: { admin_token: '${ADMIN_TOKEN}' }\n",
    ] {
        let original: serde_yaml::Value = serde_yaml::from_str(raw).unwrap();
        let (out, doc) = migrate_to_value(raw);
        for (key, value) in original.as_mapping().unwrap() {
            assert_eq!(doc.as_mapping().unwrap().get(key), Some(value));
        }
        assert!(!out.todos.is_empty());
        assert!(!out
            .changes
            .iter()
            .any(|s| s.contains("governance.admin_token")));
    }
}

#[test]
fn migrate_preserves_unrecognized_pool_sections_and_destinations() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    for raw in [
        "tool_pools: [unread]\n",
        "agent_pools: opaque\n",
        "tool_pools: [MIGRATION_PRIVATE_SENTINEL]\n",
        "agent_pools: MIGRATION_PRIVATE_SENTINEL\n",
        "auth: { upstream_credentials: caller }\npools: [unread]\n",
        "global_hooks: [screen]\npools: [unread]\n",
        "hooks: { screen: { socket: /tmp/screen, global: true } }\npools: opaque\n",
        "global_hooks: [screen]\npools: { hooks: opaque }\n",
        "hooks: { screen: { socket: /tmp/screen, global: true } }\npools: { hooks: opaque }\n",
        "tool_pools: { x: { members: [a] } }\ntools: opaque\n",
        "tool_pools: { x: { members: [a] } }\ntools: { pools: opaque }\n",
        "agent_pools: { x: { members: [a] } }\nagents: opaque\n",
        "agent_pools: { x: { members: [a] } }\nagents: { pools: opaque }\n",
    ] {
        let original: serde_yaml::Value = serde_yaml::from_str(raw).unwrap();
        let (out, doc) = migrate_to_value(raw);
        for (key, value) in original.as_mapping().unwrap() {
            assert_eq!(
                doc.as_mapping().unwrap().get(key),
                Some(value),
                "{}",
                out.yaml
            );
        }
        assert!(!out.todos.is_empty());
        assert!(!out
            .changes
            .iter()
            .chain(&out.todos)
            .chain(&out.warnings)
            .any(|line| line.contains("MIGRATION_PRIVATE_SENTINEL")));
    }
}

#[test]
fn migrate_preserves_unrecognized_role_entries_and_budget_groups() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    for role in ["opaque", "{ rpm_limit: 3, future_cap: 7 }"] {
        let raw = format!("auth: {{ chain: [test-idp-double] }}\ngroup_map: {{ staff: {role} }}\n");
        let original: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();
        let (out, doc) = migrate_to_value(&raw);
        assert_eq!(dig(&doc, &["group_map"]), dig(&original, &["group_map"]));
        assert!(out.todos.iter().any(|t| t.contains("group_map")));
        assert!(dig(&doc, &["auth", "role_bindings", "test-idp-double", "staff"]).is_none());
    }
    for group in ["opaque", "{ max_budget_cents: 3, future_cap: 7 }"] {
        let raw = format!("governance: {{ budget_groups: {{ staff: {group} }} }}\n");
        let original: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();
        let (out, doc) = migrate_to_value(&raw);
        assert_eq!(dig(&doc, &["governance"]), dig(&original, &["governance"]));
        assert!(out.todos.iter().any(|t| t.contains("budget_groups")));
        assert!(dig(&doc, &["groups"]).is_none());
    }
}

#[test]
fn migrate_preserves_non_string_export_keys() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = "export:\n  7: { module: unknown-sink, settings: { keep: original } }\n";
    let original: serde_yaml::Value = serde_yaml::from_str(raw).unwrap();
    let (out, doc) = migrate_to_value(raw);
    assert_eq!(dig(&doc, &["export"]), dig(&original, &["export"]));
    assert!(out.todos.iter().any(|t| t.contains("export")));
}

#[test]
fn migrate_optional_null_auth_preserves_top_level_admin_chain() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let (_, doc) = migrate_to_value(
        "auth: null\nadmin_auth: [test-idp-double]\nproviders: {}\nmodels: {}\npools: {}\n",
    );
    assert_eq!(
        dig(&doc, &["auth", "admin_auth"]).and_then(|v| v.as_sequence()),
        Some(&vec![serde_yaml::Value::from("test-idp-double")])
    );
    assert!(dig(&doc, &["admin_auth"]).is_none());
    let (_, again) = migrate_to_value(&serde_yaml::to_string(&doc).unwrap());
    assert_eq!(doc, again);
}

#[test]
fn migrate_optional_null_auth_preserves_governance_admin_token() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let op = busbar_kernel::config::operator_provider();
    for top_chain in [String::new(), format!("admin_auth: [{op}]\n")] {
        let raw = format!(
            "auth: null\n{top_chain}governance:\n  admin_token: ${{MIGRATION_ADMIN_TOKEN}}\n\
             providers: {{}}\nmodels: {{}}\npools: {{}}\n"
        );
        let (_, doc) = migrate_to_value(&raw);
        assert_eq!(
            dig(&doc, &["auth", "admin_auth"]).and_then(|v| v.as_sequence()),
            Some(&vec![serde_yaml::Value::from(op)])
        );
        assert_eq!(
            dig(&doc, &["identity-providers", op, "token", "env"]).and_then(|v| v.as_str()),
            Some("MIGRATION_ADMIN_TOKEN")
        );
        assert!(dig(&doc, &["governance"]).is_none());
        let (_, again) = migrate_to_value(&serde_yaml::to_string(&doc).unwrap());
        assert_eq!(doc, again);
    }
}

#[test]
fn migrate_identity_providers_preserves_conflicting_typed_fields() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let op = busbar_kernel::config::operator_provider();
    for (key, module, data, admin) in [
        ("max_admin_scope", "test-idp-double", "read-only", "full"),
        ("max_admin_scope", "test-idp-double", "full", "read-only"),
        ("token", op, "{ env: DATA_TOKEN }", "{ env: ADMIN_TOKEN }"),
    ] {
        let raw = format!(
            "auth:\n  chain: [{{ {module}: {{ {key}: {data}, settings: {{}} }} }}]\n\
             \x20 admin_auth: [{{ {module}: {{ {key}: {admin}, settings: {{}} }} }}]\n\
             providers: {{}}\nmodels: {{}}\npools: {{}}\n"
        );
        let (out, doc) = migrate_to_value(&raw);
        let original: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();
        let admin_name = format!("{module}-admin");
        for (chain, name) in [("chain", module), ("admin_auth", admin_name.as_str())] {
            let original_entry = &dig(&original, &["auth", chain])
                .unwrap()
                .as_sequence()
                .unwrap()[0];
            assert_eq!(
                dig(&doc, &["auth", chain]).and_then(|v| v.as_sequence()),
                Some(&vec![serde_yaml::Value::from(name)])
            );
            assert_eq!(
                dig(&doc, &["identity-providers", name, key]),
                dig(original_entry, &[module, key])
            );
            assert_eq!(
                dig(&doc, &["identity-providers", name, "settings"]),
                dig(original_entry, &[module, "settings"])
            );
        }
        assert!(out.todos.iter().any(|t| t.contains(&admin_name)));
        assert!(!out.todos.iter().any(|t| t.contains("ADMIN_TOKEN")));
        let (_, again) = migrate_to_value(&serde_yaml::to_string(&doc).unwrap());
        assert_eq!(doc, again);
    }
}

#[test]
fn migrate_identity_providers_still_deduplicates_equal_and_complementary_fields() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let op = busbar_kernel::config::operator_provider();
    for admin in [
        "max_admin_scope: full, token: { env: SHARED_TOKEN }",
        "max_admin_scope: full",
    ] {
        let raw = format!(
            "auth:\n  chain: [{{ {op}: {{ token: {{ env: SHARED_TOKEN }} }} }}]\n\
             \x20 admin_auth: [{{ {op}: {{ {admin} }} }}]\n\
             providers: {{}}\nmodels: {{}}\npools: {{}}\n"
        );
        let (_, doc) = migrate_to_value(&raw);
        assert_eq!(
            dig(&doc, &["auth", "admin_auth"]).and_then(|v| v.as_sequence()),
            Some(&vec![serde_yaml::Value::from(op)])
        );
        assert_eq!(
            dig(&doc, &["identity-providers", op, "token", "env"]).and_then(|v| v.as_str()),
            Some("SHARED_TOKEN")
        );
        assert_eq!(
            dig(&doc, &["identity-providers", op, "max_admin_scope"]).and_then(|v| v.as_str()),
            Some("full")
        );
        assert!(dig(&doc, &["identity-providers", &format!("{op}-admin")]).is_none());
    }
}

#[test]
fn migrate_on_exhausted_all_arms_round_trip() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = r#"
providers: {}
models: {}
pools:
  primary:
    members: [ { target: a } ]
    on_exhausted: { action: "fallback_pool:overflow" }   # the exact user case
  overflow:
    members: [ { target: b } ]
    on_exhausted: { action: least_bad }
  strict:
    members: [ { target: c } ]
    on_exhausted: { action: reject }
  legacy503:
    members: [ { target: d } ]
    on_exhausted: { action: status_503 }
  nameless:
    members: [ { target: e } ]
    on_exhausted: { action: "fallback_pool:" }            # no pool named -> TODO, safe reject
  bogus:
    members: [ { target: f } ]
    on_exhausted: { action: explode }                     # unknown -> TODO, safe reject
"#;
    let (out, doc) = migrate_to_value(raw);

    assert_eq!(
        dig(&doc, &["pools", "primary", "on_exhausted", "fallback_pool"]).and_then(|v| v.as_str()),
        Some("overflow"),
        "fallback_pool:<name> must become the structured 1.5.0 form"
    );

    assert_eq!(
        dig(&doc, &["pools", "overflow", "on_exhausted"]).and_then(|v| v.as_str()),
        Some("least_bad")
    );
    assert_eq!(
        dig(&doc, &["pools", "strict", "on_exhausted"]).and_then(|v| v.as_str()),
        Some("reject")
    );

    assert_eq!(
        dig(&doc, &["pools", "legacy503", "on_exhausted"]).and_then(|v| v.as_str()),
        Some("reject")
    );

    for pool in [
        "primary",
        "overflow",
        "strict",
        "legacy503",
        "nameless",
        "bogus",
    ] {
        assert!(
            dig(&doc, &["pools", pool, "on_exhausted", "action"]).is_none(),
            "pool {pool} still carries the 1.4.x on_exhausted.action wrapper"
        );
    }

    assert!(
        out.todos.iter().any(|t| t.contains("nameless")),
        "an empty fallback_pool must raise a TODO: {:?}",
        out.todos
    );
    assert!(
        out.todos.iter().any(|t| t.contains("bogus")),
        "an unknown action must raise a TODO: {:?}",
        out.todos
    );

    assert!(
        busbar_kernel::config::deploy_from_yaml_str(&out.yaml).is_ok(),
        "on_exhausted-bearing config must boot-parse: {:?}",
        busbar_kernel::config::deploy_from_yaml_str(&out.yaml).err()
    );
}

#[test]
fn migrate_real_14x_top_level_auth_surfaces() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = r#"
auth:
  chain: [tokens, test-idp-double]
  upstream_credentials: own
  client_tokens: [ "${BUSBAR_CLIENT_TOKEN}" ]
  modules:
    test-idp-double:
      allowed_groups: [growth]
      max_admin_scope: full
admin_auth: [admin-tokens]
group_map:
  growth-eng:
    allowed_pools: [fast]
    rpm_limit: 120
providers: {}
models: {}
pools: {}
"#;
    let (out, doc) = migrate_to_value(raw);

    let chain = dig(&doc, &["auth", "chain"])
        .unwrap()
        .as_sequence()
        .unwrap();
    assert_eq!(chain[0].as_str(), Some("keys"), "tokens -> keys");
    assert_eq!(
        chain[1].as_str(),
        Some("test-idp-double"),
        "a 1.5.3 chain is a list of bare PROVIDER NAMES"
    );
    assert_eq!(
        dig(&doc, &["identity-providers", "test-idp-double", "max_admin_scope"])
            .and_then(|v| v.as_str()),
        Some("full"),
        "auth.modules.test-idp-double.max_admin_scope must fold onto the identity-providers DEFINITION"
    );

    assert_eq!(
        dig(
            &doc,
            &[
                "auth",
                "role_bindings",
                "test-idp-double",
                "growth-eng",
                "allowed_pools"
            ]
        )
        .and_then(|v| v.as_sequence())
        .map(|s| s.len()),
        Some(1),
        "top-level group_map must migrate to auth.role_bindings.<module>"
    );

    assert!(
        dig(&doc, &["auth", "admin_auth"])
            .and_then(|v| v.as_sequence())
            .is_some(),
        "top-level admin_auth must move under auth"
    );

    for k in ["group_map", "admin_auth", "modules"] {
        assert!(
            doc.as_mapping()
                .unwrap()
                .get(serde_yaml::Value::from(k))
                .is_none(),
            "top-level `{k}` must be gone after migration"
        );
    }

    assert!(
        out.todos.iter().any(|t| t.contains("allowed_groups")),
        "dropping auth.modules.*.allowed_groups must raise a TODO: {:?}",
        out.todos
    );

    assert!(
        busbar_kernel::config::deploy_from_yaml_str(&out.yaml).is_ok(),
        "real top-level 1.4.x auth surfaces must migrate to a bootable config: {:?}",
        busbar_kernel::config::deploy_from_yaml_str(&out.yaml).err()
    );
}

#[test]
fn migrate_global_hooks_names_resolve_and_dedup() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = r#"
providers: {}
models: {}
pools: {}
hooks:
  audit-tap:
    kind: tap
    webhook: "https://sidecar.internal/audit"
    global: true
global_hooks: [audit-tap]
"#;
    let (out, doc) = migrate_to_value(raw);

    assert!(
        dig(&doc, &["global_hooks"]).is_none(),
        "the removed top-level global_hooks: must not survive"
    );
    let all = dig(&doc, &["pools", "hooks"]).unwrap();
    let all = all.as_sequence().unwrap();
    assert_eq!(
        all.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>(),
        ["audit-tap"],
        "the doubly-named global hook is a single BARE all-pools reference: {all:?}"
    );

    assert_eq!(
        dig(&doc, &["hooks", "audit-tap", "module"]).and_then(|v| v.as_str()),
        Some("webhook"),
        "the registry name became a named hook definition"
    );
    assert!(
        busbar_kernel::config::deploy_from_yaml_str(&out.yaml).is_ok(),
        "global_hooks must migrate to a bootable config: {:?}",
        busbar_kernel::config::deploy_from_yaml_str(&out.yaml).err()
    );
}

#[test]
fn migrate_price_per_1k_synthesizes_rate_card() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = r#"
governance:
  price_per_1k_tokens_cents: 5
providers: {}
models:
  m1: { provider: p }
  m2: { provider: p }
pools: {}
"#;
    let out = migrate_config(raw).expect("migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).unwrap();
    let card = doc
        .as_mapping()
        .unwrap()
        .get(serde_yaml::Value::from("rate_card"))
        .and_then(|v| v.as_mapping())
        .expect("rate_card synthesized");
    for m in ["m1", "m2"] {
        let entry = card
            .get(serde_yaml::Value::from(m))
            .and_then(|v| v.as_mapping())
            .unwrap();
        assert_eq!(
            entry
                .get(serde_yaml::Value::from("input_utok"))
                .and_then(|v| v.as_f64()),
            Some(50.0),
            "5 cents/1k = 50 micro-units/token"
        );
    }
    assert!(
        out.todos.iter().any(|t| t.contains("rate_card")),
        "the uniform synthesis is flagged for review"
    );
}

#[test]
fn migrate_pool_policy_without_hooks_block() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = r#"
providers: {}
models: {}
pools:
  fast:
    members: [ { target: widget, weight: 1 } ]
    policy: cheapest
"#;
    let out = migrate_config(raw).expect("migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).unwrap();
    let hooks = doc
        .as_mapping()
        .and_then(|m| m.get(serde_yaml::Value::from("pools")))
        .and_then(|v| v.as_mapping())
        .and_then(|m| m.get(serde_yaml::Value::from("fast")))
        .and_then(|v| v.as_mapping())
        .and_then(|m| m.get(serde_yaml::Value::from("hooks")))
        .and_then(|v| v.as_sequence())
        .expect("policy became a hooks list");
    assert_eq!(hooks[0].as_str(), Some("cheapest"));

    assert!(
        busbar_kernel::config::deploy_from_yaml_str(&out.yaml).is_ok(),
        "policy-only pool must migrate to a bootable config"
    );
}

#[test]
fn migrate_auth_mode_arms() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let out = migrate_config("auth:\n  mode: passthrough\nproviders: {}\nmodels: {}\npools: {}\n")
        .unwrap();
    assert!(out.yaml.contains("upstream_credentials: passthrough"));

    let out =
        migrate_config("auth:\n  mode: token\nproviders: {}\nmodels: {}\npools: {}\n").unwrap();
    assert!(out.yaml.contains("- keys"));
    assert!(
        out.todos.iter().any(|t| t.contains("signed key")),
        "static-token removal must surface the key re-mint TODO: {:?}",
        out.todos
    );
}

#[test]
fn migrate_group_map_without_module_flags_placeholder() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = r#"
auth:
  group_map:
    r1: { allowed_pools: [fast] }
providers: {}
models: {}
pools: {}
"#;
    let out = migrate_config(raw).unwrap();
    assert!(out.yaml.contains("<module>"));
    assert!(out
        .todos
        .iter()
        .any(|t| t.contains("replace the '<module>' placeholder")));
}

#[test]
fn migrate_group_map_survives_a_non_mapping_auth() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = r#"
auth: null
group_map:
  growth-eng:
    allowed_pools: [fast]
providers: {}
models: {}
pools: {}
"#;
    let out = migrate_config(raw).unwrap();

    assert!(
        out.yaml.contains("group_map") || out.yaml.contains("role_bindings"),
        "group_map data must not silently vanish from the migrated document:\n{}",
        out.yaml
    );
    assert!(
        out.todos.iter().any(|t| t.contains("group_map"))
            || out.warnings.iter().any(|w| w.contains("group_map")),
        "a non-mapping `auth:` losing group_map must surface a loud TODO/warning, got \
         todos={:?} warnings={:?}",
        out.todos,
        out.warnings
    );
}

#[test]
fn migrate_non_mapping_group_map_survives_a_mapping_auth() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = r#"
auth:
  chain: [test-idp-double]
group_map: [foo]
providers: {}
models: {}
pools: {}
"#;
    let out = migrate_config(raw).unwrap();
    assert!(
        out.yaml.contains("group_map"),
        "a non-mapping group_map must not silently vanish from the migrated document:\n{}",
        out.yaml
    );
    assert!(
        out.todos.iter().any(|t| t.contains("group_map"))
            || out.warnings.iter().any(|w| w.contains("group_map")),
        "a non-mapping `group_map:` disappearing must surface a loud TODO/warning, got \
         todos={:?} warnings={:?}",
        out.todos,
        out.warnings
    );

    assert!(
        !out.changes
            .iter()
            .any(|c| c.contains("group_map -> auth.role_bindings")),
        "must not claim a group_map -> role_bindings migration happened when it did not: {:?}",
        out.changes
    );
}

#[test]
fn migrate_dropped_scopes_map_to_full_with_warning() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = r#"
auth:
  chain: ["test-idp-double"]
  modules:
    test-idp-double:
      max_admin_scope: hooks-register
  group_map:
    minter:
      admin_scope: mint
providers:
  vendor-a: { api_key_env: KEY }
models:
  widget: { provider: vendor-a }
pools:
  fast:
    members:
      - { target: widget, weight: 1 }
"#;
    let out = migrate_config(raw).expect("migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).expect("output is valid YAML");
    let auth = doc
        .as_mapping()
        .unwrap()
        .get(serde_yaml::Value::from("auth"))
        .and_then(|v| v.as_mapping())
        .expect("auth mapping");

    let bound_scope = auth
        .get(serde_yaml::Value::from("role_bindings"))
        .and_then(|v| v.as_mapping())
        .and_then(|m| m.get(serde_yaml::Value::from("test-idp-double")))
        .and_then(|v| v.as_mapping())
        .and_then(|m| m.get(serde_yaml::Value::from("minter")))
        .and_then(|v| v.as_mapping())
        .and_then(|m| m.get(serde_yaml::Value::from("admin_scope")))
        .and_then(|v| v.as_str());
    assert_eq!(
        bound_scope,
        Some("full"),
        "the retired `mint` admin_scope must be rewritten to `full`; got {bound_scope:?}"
    );

    let oidc_cap = dig(
        &doc,
        &["identity-providers", "test-idp-double", "max_admin_scope"],
    )
    .and_then(|v| v.as_str());
    assert_eq!(
        oidc_cap,
        Some("full"),
        "the retired `hooks-register` max_admin_scope must be rewritten to `full`; got {oidc_cap:?}"
    );
    let chain = auth
        .get(serde_yaml::Value::from("chain"))
        .and_then(|v| v.as_sequence())
        .expect("chain sequence");
    assert!(
        chain.iter().any(|e| e.as_str() == Some("test-idp-double")),
        "the chain references the provider by BARE NAME: {chain:?}"
    );

    assert!(
        out.warnings.iter().any(|w| w.contains("mint -> full")),
        "a warning must name the mint -> full rewrite; got {:?}",
        out.warnings
    );
    assert!(
        out.warnings
            .iter()
            .any(|w| w.contains("hooks-register -> full")),
        "a warning must name the hooks-register -> full rewrite; got {:?}",
        out.warnings
    );
}

#[test]
fn migrate_emit_server_timing_moves_to_advanced_response_headers() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = r#"
providers: {}
models: {}
advanced:
  rate_sweep_interval: 64
observability:
  emit_server_timing: true
  otlp_endpoint: "http://otel:4318/v1/traces"
"#;
    let (out, doc) = migrate_to_value(raw);

    assert!(
        dig(&doc, &["observability"]).is_none(),
        "the whole observability block must not survive migration: {doc:?}"
    );

    assert_eq!(
        dig(&doc, &["advanced", "response_headers", "server_timing"]).and_then(|v| v.as_bool()),
        Some(true)
    );

    assert_eq!(
        dig(&doc, &["advanced", "rate_sweep_interval"]).and_then(|v| v.as_u64()),
        Some(64)
    );

    assert_eq!(
        dig(&doc, &["export", "traces", "settings", "url"]).and_then(|v| v.as_str()),
        Some("http://otel:4318/v1/traces")
    );
    assert!(
        out.changes
            .iter()
            .any(|c| c.contains("emit_server_timing -> advanced.response_headers.server_timing")),
        "a change entry must name the rename; got {:?}",
        out.changes
    );

    let deploy: Result<busbar_kernel::config::DeployCfg, _> =
        busbar_kernel::config::deploy_from_yaml_str(&out.yaml);
    assert!(
        deploy.is_ok(),
        "migrated config must boot-parse: {:?}",
        deploy.err().map(|e| e.to_string())
    );
}

#[test]
fn migrate_hook_stage_at_values_are_renamed() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = r#"
providers: {}
models: {}
pools:
  primary:
    members: [ { model: a } ]
    hooks:
      - { module: webhook, settings: { url: "https://s/route" }, kind: tap, at: route }
      - { module: webhook, settings: { url: "https://s/attempt" }, kind: tap, at: attempt }
global_hooks:
  - { module: webhook, settings: { url: "https://s/done" }, kind: tap, at: completion }
"#;
    let (out, doc) = migrate_to_value(raw);

    let defs = dig(&doc, &["hooks"]).unwrap();
    let defs = defs.as_mapping().unwrap();
    let phase_for = |url_suffix: &str| -> Option<String> {
        defs.iter().find_map(|(_, d)| {
            let d = d.as_mapping()?;
            let url = d
                .get(serde_yaml::Value::from("settings"))?
                .as_mapping()?
                .get(serde_yaml::Value::from("url"))?
                .as_str()?;
            if !url.ends_with(url_suffix) {
                return None;
            }
            let phase = d.get(serde_yaml::Value::from("phase"))?.as_sequence()?;
            phase.first()?.as_str().map(str::to_string)
        })
    };
    assert_eq!(
        phase_for("/route").as_deref(),
        Some("candidate"),
        "`at: route` must migrate to `phase: [candidate]`"
    );
    assert_eq!(
        phase_for("/attempt").as_deref(),
        Some("routing"),
        "`at: attempt` must migrate to `phase: [routing]`"
    );
    assert_eq!(
        phase_for("/done").as_deref(),
        Some("response"),
        "`at: completion` must migrate to `phase: [response]`"
    );

    let pool_hooks = dig(&doc, &["pools", "primary", "hooks"])
        .unwrap()
        .as_sequence()
        .unwrap();
    assert!(
        pool_hooks.iter().all(|v| v.as_str().is_some()),
        "pool hooks are bare names now: {pool_hooks:?}"
    );
    assert!(
        dig(&doc, &["pools", "hooks"])
            .and_then(|v| v.as_sequence().cloned())
            .is_some_and(|s| !s.is_empty()),
        "the global instance became a reserved pools.hooks attach"
    );

    let deploy: Result<busbar_kernel::config::DeployCfg, _> =
        busbar_kernel::config::deploy_from_yaml_str(&out.yaml);
    assert!(
        deploy.is_ok(),
        "migrated config must boot-parse: {:?}",
        deploy.err().map(|e| e.to_string())
    );
}

#[test]
fn migrate_emit_server_timing_absent_is_a_no_op() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = "providers: {}\nmodels: {}\n";
    let (out, doc) = migrate_to_value(raw);
    assert!(
        dig(&doc, &["advanced"]).is_none(),
        "no advanced: block should be synthesized: {doc:?}"
    );
    assert!(
        !out.changes.iter().any(|c| c.contains("response_headers")),
        "no change entry expected when the old key was absent; got {:?}",
        out.changes
    );
}

#[test]
fn migrate_observability_export_rewrites_old_to_new() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = r#"
observability:
  otlp_url: "https://otel.example.com/v1/traces"
  request_log_webhook_url: "https://logs.example.com/busbar"
  max_inflight_webhook_deliveries: 32
  webhook_delivery_timeout_secs: 5
metrics:
  buffer_seconds: 90
  key_gauge_limit: 1500
providers: {}
models: {}
pools: {}
"#;
    let (out, doc) = migrate_to_value(raw);

    assert_eq!(
        dig(&doc, &["export", "req-log", "module"]).and_then(|v| v.as_str()),
        Some("request-log-webhook"),
    );
    assert_eq!(
        dig(&doc, &["export", "req-log", "settings", "url"]).and_then(|v| v.as_str()),
        Some("https://logs.example.com/busbar"),
    );
    assert_eq!(
        dig(
            &doc,
            &["export", "req-log", "settings", "max_inflight_deliveries"]
        )
        .and_then(|v| v.as_u64()),
        Some(32),
    );
    assert_eq!(
        dig(
            &doc,
            &["export", "req-log", "settings", "delivery_timeout_secs"]
        )
        .and_then(|v| v.as_u64()),
        Some(5),
    );

    assert_eq!(
        dig(&doc, &["export", "metrics", "module"]).and_then(|v| v.as_str()),
        Some("prometheus"),
    );
    assert_eq!(
        dig(&doc, &["export", "metrics", "settings", "buffer_seconds"]).and_then(|v| v.as_u64()),
        Some(90),
    );
    assert_eq!(
        dig(&doc, &["export", "metrics", "settings", "key_gauge_limit"]).and_then(|v| v.as_u64()),
        Some(1500),
    );

    assert_eq!(
        dig(&doc, &["export", "traces", "module"]).and_then(|v| v.as_str()),
        Some("otlp"),
    );
    assert_eq!(
        dig(&doc, &["export", "traces", "settings", "url"]).and_then(|v| v.as_str()),
        Some("https://otel.example.com/v1/traces"),
    );
    assert!(
        dig(&doc, &["observability"]).is_none(),
        "the whole observability block must be gone after migration"
    );
    assert!(
        dig(&doc, &["metrics"]).is_none(),
        "the retired top-level metrics block must be removed"
    );
    assert!(
        out.changes
            .iter()
            .any(|c| c.contains("request-log-webhook"))
            && out.changes.iter().any(|c| c.contains("prometheus"))
            && out.changes.iter().any(|c| c.contains("otlp")),
        "the change ledger names all three rewrites; got {:?}",
        out.changes
    );

    let migrated_yaml = serde_yaml::to_string(&doc).unwrap();
    let deploy: busbar_kernel::config::DeployCfg =
        busbar_kernel::config::deploy_from_yaml_str(&migrated_yaml)
            .expect("the migrated config must boot-parse");
    let mut errs = Vec::new();
    let export = busbar_kernel::config::resolve_export(&built_ins(&deploy.export), &mut errs);
    assert!(errs.is_empty(), "{errs:?}");
    assert_eq!(webhooks(&deploy.export), 1);
    assert!(export.recorder.is_some() && export.plugins.iter().any(|p| p.def.module == "otlp"));

    let (out2, doc2) = migrate_to_value(&migrated_yaml);
    assert!(
        !out2
            .changes
            .iter()
            .any(|c| c.contains("request-log-webhook")
                || c.contains("prometheus")
                || c.contains("otlp")),
        "a second migrate is a no-op for the export rewrite; got {:?}",
        out2.changes
    );
    assert_eq!(doc, doc2, "the migration is a fixed point after one run");
}

#[test]
fn migrate_never_drops_a_malformed_auth_block() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    for (shape, raw_auth) in [
        ("null", "auth:\n"),
        ("sequence", "auth: []\n"),
        ("scalar", "auth: tokens\n"),
    ] {
        let raw = format!("{raw_auth}providers: {{}}\nmodels: {{}}\npools: {{}}\n");
        let (out, doc) = migrate_to_value(&raw);
        let kept = dig(&doc, &["auth"]).unwrap_or_else(|| {
            panic!(
                "a malformed `auth:` ({shape}) was DROPPED by the migration:\n{}",
                out.yaml
            )
        });
        let original: serde_yaml::Value = serde_yaml::from_str(raw_auth).unwrap();
        assert_eq!(
            Some(kept),
            original
                .as_mapping()
                .and_then(|m| m.get(serde_yaml::Value::from("auth"))),
            "a malformed `auth:` ({shape}) must be carried through EXACTLY as written"
        );
        assert!(
            out.todos.iter().any(|t| t.starts_with("auth:")),
            "a malformed `auth:` ({shape}) must be NAMED in the todos, never silently passed \
             through; got {:?}",
            out.todos
        );
    }
}

#[test]
fn migrate_never_drops_a_malformed_identity_providers_block() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw =
        "auth:\n  chain: [{ test-idp-double: { settings: { issuer: https://a.example.com } } }]\n\
               identity-providers: 7\nproviders: {}\nmodels: {}\npools: {}\n";
    let (out, doc) = migrate_to_value(raw);
    assert_eq!(
        dig(&doc, &["identity-providers"]).and_then(|v| v.as_u64()),
        Some(7),
        "a malformed `identity-providers:` must be carried through EXACTLY as written:\n{}",
        out.yaml
    );
    assert!(
        dig(&doc, &["auth", "chain"]).is_some(),
        "the `auth:` block this pass removed first must be restored on the early return:\n{}",
        out.yaml
    );
    assert!(
        out.todos
            .iter()
            .any(|t| t.starts_with("identity-providers:")),
        "the untouched malformed block must be named in the todos; got {:?}",
        out.todos
    );
}

#[test]
fn migrate_records_the_deletion_of_a_malformed_retired_block() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = "observability:\nmetrics: []\nproviders: {}\nmodels: {}\npools: {}\n";
    let (out, doc) = migrate_to_value(raw);
    assert!(
        dig(&doc, &["observability"]).is_none() && dig(&doc, &["metrics"]).is_none(),
        "both blocks are RETIRED in 1.5.3 and must still be deleted:\n{}",
        out.yaml
    );
    assert!(
        out.changes
            .iter()
            .any(|c| c.starts_with("observability: block removed")),
        "the observability deletion must be RECORDED in the ledger; got {:?}",
        out.changes
    );
    assert!(
        out.changes
            .iter()
            .any(|c| c.starts_with("metrics: block removed")),
        "the metrics deletion must be RECORDED in the ledger; got {:?}",
        out.changes
    );
}

#[test]
fn migrate_identity_providers_splits_a_per_plane_settings_conflict() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = "auth:\n  \
                 chain: [{ test-idp-double: { settings: { issuer: https://data.example.com } } }]\n  \
                 admin_auth: [{ test-idp-double: { max_admin_scope: full, settings: { issuer: https://admin.example.com } } }]\n\
               providers: {}\nmodels: {}\npools: {}\n";
    let (out, doc) = migrate_to_value(raw);

    assert_eq!(
        dig(
            &doc,
            &[
                "identity-providers",
                "test-idp-double",
                "settings",
                "issuer"
            ]
        )
        .and_then(|v| v.as_str()),
        Some("https://data.example.com"),
        "the first plane keeps the module-named definition:\n{}",
        out.yaml
    );
    assert_eq!(
        dig(
            &doc,
            &[
                "identity-providers",
                "test-idp-double-admin",
                "settings",
                "issuer"
            ]
        )
        .and_then(|v| v.as_str()),
        Some("https://admin.example.com"),
        "the CONFLICTING second plane must get its OWN definition — its settings must not be \
         dropped:\n{}",
        out.yaml
    );
    assert_eq!(
        dig(
            &doc,
            &["identity-providers", "test-idp-double-admin", "module"]
        )
        .and_then(|v| v.as_str()),
        Some("test-idp-double"),
        "the split definition still names the same backing module"
    );
    assert_eq!(
        dig(&doc, &["auth", "admin_auth"]).and_then(|v| v.as_sequence()),
        Some(&vec![serde_yaml::Value::from("test-idp-double-admin")]),
        "the admin plane must REFERENCE the split definition:\n{}",
        out.yaml
    );
    assert_eq!(
        dig(&doc, &["auth", "chain"]).and_then(|v| v.as_sequence()),
        Some(&vec![serde_yaml::Value::from("test-idp-double")]),
        "the data plane keeps referencing the original definition"
    );
    assert!(
        out.todos
            .iter()
            .any(|t| t.contains("test-idp-double-admin")),
        "a split must be explained in the todos; got {:?}",
        out.todos
    );

    let same = "auth:\n  \
                  chain: [{ test-idp-double: { settings: { issuer: https://one.example.com } } }]\n  \
                  admin_auth: [{ test-idp-double: { settings: { issuer: https://one.example.com } } }, { tokens: {} }]\n\
                providers: {}\nmodels: {}\npools: {}\n";
    let (_, doc) = migrate_to_value(same);
    let defs = dig(&doc, &["identity-providers"])
        .and_then(|v| v.as_mapping())
        .expect("definitions");
    assert!(
        defs.contains_key(serde_yaml::Value::from("test-idp-double"))
            && !defs.contains_key(serde_yaml::Value::from("test-idp-double-admin")),
        "identical per-plane settings must still DEDUPE to one definition: {defs:?}"
    );
    assert_eq!(
        dig(&doc, &["auth", "admin_auth"]).and_then(|v| v.as_sequence()),
        Some(&vec![
            serde_yaml::Value::from("test-idp-double"),
            serde_yaml::Value::from("tokens")
        ]),
        "both planes reference the ONE deduped definition"
    );
}

#[test]
fn unmappable_budget_period_never_silently_becomes_the_all_time_window() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = "\
governance:
  enabled: true
  budget_groups:
    weekly-team: { max_budget_cents: 700000, budget_period: weekly }
    hourly-team: { max_budget_cents: 1000, budget_period: hourly }
    burst-team: { max_budget_cents: 500, budget_period: fortnightly }
    forever-team: { max_budget_cents: 900, budget_period: total }
providers: {}
models: {}
pools: {}
";
    let (out, doc) = migrate_to_value(raw);
    let per = |group: &str| -> String {
        dig(&doc, &["groups", group, "limits"])
            .and_then(|v| v.as_sequence())
            .and_then(|s| s.first())
            .and_then(|l| l.as_mapping())
            .and_then(|m| m.get(serde_yaml::Value::from("per")))
            .and_then(|v| v.as_str())
            .unwrap_or("<missing>")
            .to_string()
    };

    assert_eq!(per("hourly-team"), "hour", "hourly -> the `hour` window");

    let weekly = per("weekly-team");
    assert_ne!(
        weekly, "total",
        "a recurring weekly cap must NEVER become the all-time window (it never rolls, so the cap \
         becomes a lifetime cap)"
    );
    assert!(
        out.todos
            .iter()
            .any(|t| t.contains("weekly") && t.contains(&weekly)),
        "an approximated window must be LOUD — a todo naming the period AND the window it was \
         mapped to; got {:?}",
        out.todos
    );

    let burst = per("burst-team");
    assert_ne!(
        burst, "total",
        "an unrecognized period must not become total"
    );
    assert!(
        out.todos
            .iter()
            .any(|t| t.contains("fortnightly") && t.contains(&burst)),
        "an unrecognized period must be named in the todos; got {:?}",
        out.todos
    );

    assert_eq!(per("forever-team"), "total");
    assert!(
        !out.todos.iter().any(|t| t.contains("forever-team")),
        "an exact mapping must not push a todo; got {:?}",
        out.todos
    );
}

#[test]
fn a_yearly_budget_period_is_rescaled_never_loosened_onto_the_month_window() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = "\
governance:
  enabled: true
  budget_groups:
    annual-team: { max_budget_cents: 1200000, budget_period: yearly }
    annual-alias: { max_budget_cents: 1200000, budget_period: annually }
    tiny-annual: { max_budget_cents: 6, budget_period: year }
    weekly-team: { max_budget_cents: 700000, budget_period: weekly }
providers: {}
models: {}
pools: {}
";
    let (out, doc) = migrate_to_value(raw);
    let limit = |group: &str| -> serde_yaml::Mapping {
        dig(&doc, &["groups", group, "limits"])
            .and_then(|v| v.as_sequence())
            .and_then(|s| s.first())
            .and_then(|l| l.as_mapping())
            .cloned()
            .unwrap_or_default()
    };
    let field = |group: &str, key: &str| -> serde_yaml::Value {
        limit(group)
            .get(serde_yaml::Value::from(key))
            .cloned()
            .unwrap_or(serde_yaml::Value::Null)
    };

    for group in ["annual-team", "annual-alias"] {
        assert_eq!(
            field(group, "per"),
            serde_yaml::Value::from("month"),
            "{group}: yearly lands on the longest rolling window"
        );
        assert_eq!(
            field(group, "budget"),
            serde_yaml::Value::from(100000u64),
            "{group}: 1_200_000/year must become 100_000/month, NOT 1_200_000/month — carrying \
             the amount over unchanged is a 12x cap increase the operator never wrote"
        );
    }

    assert_eq!(
        field("tiny-annual", "budget"),
        serde_yaml::Value::from(1u64),
        "6/year floors to 1/month — tighter than exact, and never the `budget: 0` that would make \
         the migrated config refuse to boot"
    );

    assert_eq!(
        field("weekly-team", "per"),
        serde_yaml::Value::from("month")
    );
    assert_eq!(
        field("weekly-team", "budget"),
        serde_yaml::Value::from(700000u64),
        "weekly -> month is already fail-CLOSED; rescaling it would loosen the cap"
    );

    let todo = out
        .todos
        .iter()
        .find(|t| t.contains("groups.annual-team"))
        .unwrap_or_else(|| panic!("no todo for the approximated annual cap: {:?}", out.todos));
    assert!(
        todo.contains("yearly") && todo.contains("month") && todo.contains("DIVIDED BY 12"),
        "the todo must name the period, the window AND the rescale it applied; got {todo:?}"
    );
}

#[test]
fn quarterly_and_biannual_budget_periods_are_rescaled_never_loosened_onto_the_month_window() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = "\
governance:
  enabled: true
  budget_groups:
    quarter-team: { max_budget_cents: 900000, budget_period: quarterly }
    biannual-team: { max_budget_cents: 600000, budget_period: biannually }
    semiannual-team: { max_budget_cents: 600000, budget_period: semiannual }
providers: {}
models: {}
pools: {}
";
    let (out, doc) = migrate_to_value(raw);
    let field = |group: &str, key: &str| -> serde_yaml::Value {
        dig(&doc, &["groups", group, "limits"])
            .and_then(|v| v.as_sequence())
            .and_then(|s| s.first())
            .and_then(|l| l.as_mapping())
            .and_then(|m| m.get(serde_yaml::Value::from(key)))
            .cloned()
            .unwrap_or(serde_yaml::Value::Null)
    };

    assert_eq!(
        field("quarter-team", "per"),
        serde_yaml::Value::from("month")
    );
    assert_eq!(
        field("quarter-team", "budget"),
        serde_yaml::Value::from(300000u64),
        "900_000/quarter must become 300_000/month; carrying it unchanged loosens the cap 3x"
    );

    for group in ["biannual-team", "semiannual-team"] {
        assert_eq!(field(group, "per"), serde_yaml::Value::from("month"));
        assert_eq!(
            field(group, "budget"),
            serde_yaml::Value::from(100000u64),
            "{group}: 600_000/half-year must become 100_000/month; unchanged loosens the cap 6x"
        );
    }

    let per_month = |group: &str| field(group, "budget").as_u64().unwrap();
    assert!(per_month("quarter-team") <= 900000 / 3);
    assert!(per_month("biannual-team") <= 600000 / 6);

    let todo_for = |needle: &str| {
        out.todos
            .iter()
            .find(|t| t.contains(needle))
            .unwrap_or_else(|| panic!("no todo for {needle}: {:?}", out.todos))
            .clone()
    };
    assert!(
        todo_for("quarter-team").contains("quarterly")
            && todo_for("quarter-team").contains("month")
            && todo_for("quarter-team").contains("DIVIDED BY 3"),
        "quarterly todo must name the period, window and /3 rescale; got {:?}",
        todo_for("quarter-team")
    );
    assert!(
        todo_for("biannual-team").contains("DIVIDED BY 6"),
        "biannual todo must name the /6 rescale; got {:?}",
        todo_for("biannual-team")
    );
}

#[test]
fn a_wrong_shaped_key_is_never_taken_and_discarded() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = "\
hooks: some-hook-name
global_hooks: audit-tap
providers: {}
models: {}
pools:
  frontier:
    hooks: baa-gate
    members: []
";
    let (out, doc) = migrate_to_value(raw);

    assert_eq!(
        dig(&doc, &["pools", "frontier", "hooks"]).and_then(|v| v.as_str()),
        Some("baa-gate"),
        "a scalar `pools.frontier.hooks:` must be left EXACTLY as written, never dropped — an \
         absent `hooks:` is a legal default, so --validate would then PASS with the gate gone. \
         Migrated document:\n{}",
        out.yaml
    );

    assert_eq!(
        dig(&doc, &["hooks"]).and_then(|v| v.as_str()),
        Some("some-hook-name"),
        "a non-mapping top-level `hooks:` must survive; got:\n{}",
        out.yaml
    );
    assert_eq!(
        dig(&doc, &["global_hooks"]).and_then(|v| v.as_str()),
        Some("audit-tap"),
        "a non-sequence `global_hooks:` must survive; got:\n{}",
        out.yaml
    );

    for key in ["pools.frontier.hooks", "hooks", "global_hooks"] {
        assert!(
            out.todos.iter().any(|t| t.starts_with(&format!("{key}:"))),
            "`{key}` was preserved but not reported; every malformed-shape key must push a todo. \
             todos: {:?}",
            out.todos
        );
    }
}

#[test]
fn a_wrong_shaped_store_block_is_never_taken_and_discarded() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = "store: acme-kv\nproviders: {}\nmodels: {}\npools: {}\n";
    let (out, doc) = migrate_to_value(raw);
    assert_eq!(
        dig(&doc, &["store"]).and_then(|v| v.as_str()),
        Some("acme-kv"),
        "a scalar `store:` must be left EXACTLY as written, never dropped; migrated:\n{}",
        out.yaml
    );
    assert!(
        out.todos.iter().any(|t| t.starts_with("store:")),
        "the malformed `store:` was preserved but not reported; todos: {:?}",
        out.todos
    );
}

#[test]
fn migrate_export_adds_the_explicit_streams_projection() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = "\
export:
  metrics:
    module: prometheus
    settings:
      buffer_seconds: 60
  req-log:
    module: request-log-webhook
    settings:
      url: https://sink.example.com/l
  tail:
    module: request-log-file
    settings:
      path: /var/log/busbar.jsonl
  traces:
    module: otlp
    settings:
      url: http://localhost:4318/v1/traces
";
    let (out, doc) = migrate_to_value(raw);
    for (name, stream) in [
        ("metrics", "metrics"),
        ("req-log", "logs"),
        ("tail", "logs"),
        ("traces", "traces"),
    ] {
        let got = dig(&doc, &["export", name, "streams"])
            .unwrap_or_else(|| panic!("export.{name}.streams was not written"));
        assert_eq!(
            got,
            &serde_yaml::from_str::<serde_yaml::Value>(&format!("[{stream}]")).unwrap(),
            "export.{name}.streams"
        );
        assert!(
            out.changes
                .iter()
                .any(|c| c.contains(&format!("export.{name}")) && c.contains("streams")),
            "the ledger must name export.{name}'s new projection; got {:?}",
            out.changes
        );
    }

    let names: Vec<String> = dig(&doc, &["export"])
        .unwrap()
        .as_mapping()
        .unwrap()
        .keys()
        .map(|k| k.as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, vec!["metrics", "req-log", "tail", "traces"]);

    let migrated_yaml = serde_yaml::to_string(&doc).unwrap();
    let defs: busbar_kernel::config::ExportDefs =
        serde_yaml::from_value(dig(&doc, &["export"]).unwrap().clone())
            .expect("the migrated export block must parse");
    let mut errs = Vec::new();
    let export = busbar_kernel::config::resolve_export(&built_ins(&defs), &mut errs);
    assert!(errs.is_empty(), "{errs:?}");

    assert_eq!(webhooks(&defs), 1);
    let _ = export;

    let (out2, doc2) = migrate_to_value(&migrated_yaml);
    assert!(
        !out2.changes.iter().any(|c| c.contains("streams")),
        "re-migrating must be a no-op; got {:?}",
        out2.changes
    );
    assert_eq!(
        doc2, doc,
        "the migrated tree must be stable under re-migration"
    );
}

#[test]
fn migrate_export_leaves_a_malformed_instance_alone_with_a_todo() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = "export:\n  broken: null\n  ok:\n    module: request-log-file\n    settings:\n      path: /tmp/x.jsonl\n";
    let (out, doc) = migrate_to_value(raw);
    assert!(
        dig(&doc, &["export", "broken"]).is_some_and(|v| v.is_null()),
        "the malformed instance must survive EXACTLY as written"
    );
    assert!(
        out.todos.iter().any(|t| t.contains("export.broken")),
        "a malformed instance must be flagged; got {:?}",
        out.todos
    );

    assert!(dig(&doc, &["export", "ok", "streams"]).is_some());
}

#[test]
fn migrate_export_flags_an_unknown_module_rather_than_guessing() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = "export:\n  siem:\n    module: some-third-party-sink\n    settings: {}\n";
    let (out, doc) = migrate_to_value(raw);
    assert!(dig(&doc, &["export", "siem", "streams"]).is_none());
    assert!(
        out.todos
            .iter()
            .any(|t| t.contains("export.siem") && t.contains("streams")),
        "an unknown module must be flagged, not guessed; got {:?}",
        out.todos
    );
}

#[test]
fn migrate_export_flags_the_retired_audit_stream() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = "export:\n  soc2:\n    module: request-log-webhook\n    streams: [logs, audit]\n    settings:\n      url: https://siem.example.com/l\n";
    let (out, doc) = migrate_to_value(raw);
    let streams = dig(&doc, &["export", "soc2", "streams"]).unwrap();
    assert_eq!(
        streams,
        &serde_yaml::from_str::<serde_yaml::Value>("[logs, audit]").unwrap(),
        "the operator's declaration must be left EXACTLY as written"
    );
    assert!(
        out.todos
            .iter()
            .any(|t| t.contains("export.soc2") && t.contains("audit")),
        "the retired `audit` stream must be flagged; got {:?}",
        out.todos
    );
}

#[test]
fn migrate_moves_tool_and_agent_pools_under_their_verb() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let tools = busbar_kernel::config::plane_sections::NAMED_MAP_SECTIONS[2];
    let agents = busbar_kernel::config::plane_sections::NAMED_MAP_SECTIONS[3];
    let raw = "providers: {}\nmodels:\n  widget: {}\n  gizmo: {}\npools:\n  fast:\n    members: [widget, gizmo]\n\
               tool_pools:\n  search:\n    members: [search-eu, search-us]\n    repeatable: [find]\n\
               agent_pools:\n  planner:\n    members: [planner-eu, planner-us]\n";
    let (out, doc) = migrate_to_value(raw);
    assert!(
        dig(&doc, &["tool_pools"]).is_none() && dig(&doc, &["agent_pools"]).is_none(),
        "the unreleased sections are gone"
    );
    assert_eq!(
        dig(&doc, &[tools, "pools", "search", "members"]).unwrap(),
        &serde_yaml::from_str::<serde_yaml::Value>("[search-eu, search-us]").unwrap(),
        "the tool pool moved under its verb verbatim"
    );
    assert_eq!(
        dig(&doc, &[tools, "pools", "search", "repeatable"]).unwrap(),
        &serde_yaml::from_str::<serde_yaml::Value>("[find]").unwrap(),
        "the neutral `repeatable:` knob is carried"
    );
    assert!(
        dig(&doc, &[agents, "pools", "planner", "members"]).is_some(),
        "the agent pool moved under its verb too"
    );
    assert!(
        dig(&doc, &["pools", "search"]).is_none() && dig(&doc, &["pools", "fast"]).is_some(),
        "the top-level `pools:` keeps only the model plane's pool"
    );
    assert!(
        out.changes
            .iter()
            .any(|c| c.contains(&format!("tool_pools.search -> {tools}.pools.search")))
            && out
                .changes
                .iter()
                .any(|c| c.contains(&format!("agent_pools.planner -> {agents}.pools.planner"))),
        "the move is announced: {:?}",
        out.changes
    );
    assert!(
        !out.todos.iter().any(|t| t.contains("pools.fast")),
        "a model pool raises no todo: {:?}",
        out.todos
    );
}

#[test]
fn migrate_reports_a_top_level_pool_of_another_plane() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = "providers: {}\nmodels: {}\npools:\n  search:\n    members: [search-eu, search-us]\n";
    let (out, _doc) = migrate_to_value(raw);
    assert!(
        out.todos
            .iter()
            .any(|t| t.contains("pools.search") && t.contains("names no `models:` entry")),
        "the stray pool is reported: {:?}",
        out.todos
    );
}

#[test]
fn migrate_leaves_rich_pool_members_untouched() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = "providers: {}\nmodels: {}\npools:\n  model1:\n    members:\n\
               \x20     - { model: model1-a, weight: 3 }\n\
               \x20     - { model: model1-b, weight: 1 }\n\
               \x20     - { model: model1-eu, tier: large }\n";
    let (out, doc) = migrate_to_value(raw);
    let members = dig(&doc, &["pools", "model1", "members"])
        .unwrap()
        .as_sequence()
        .unwrap();
    assert_eq!(members.len(), 3);
    for m in members {
        assert!(
            m.is_mapping(),
            "every rich member stays a rich member: {m:?}"
        );
    }
    assert_eq!(
        dig(&doc, &["pools", "model1", "members"])
            .and_then(|v| v.as_sequence())
            .and_then(|s| s[0].get("weight"))
            .and_then(|v| v.as_u64()),
        Some(3),
        "the member-level weight is carried in place"
    );
    assert!(
        dig(&doc, &["pools", "model1", "weights"]).is_none(),
        "no pool-level `weights:` map is invented"
    );
    assert!(
        !out.changes
            .iter()
            .any(|c| c.contains("uniform") || c.contains("weights")),
        "no member-shape change is announced: {:?}",
        out.changes
    );
    assert!(
        !out.todos.iter().any(|t| t.contains("capabilities")),
        "no capability todo is raised: {:?}",
        out.todos
    );
}

#[test]
fn migrate_rewrites_a_lingering_at_key_on_a_named_hook_def() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = "providers: {}\nmodels: {}\npools: {}\n\
               hooks:\n  audit:\n    kind: tap\n    module: audit-hook\n    at: response\n";
    let (out, doc) = migrate_to_value(raw);
    assert_eq!(
        dig(&doc, &["hooks", "audit", "phase"]).unwrap(),
        &serde_yaml::from_str::<serde_yaml::Value>("[response]").unwrap(),
        "the single-stage `at:` became a `phase:` list"
    );
    assert!(
        dig(&doc, &["hooks", "audit", "at"]).is_none(),
        "the retired `at:` key is gone"
    );
    assert!(
        busbar_kernel::config::deploy_from_yaml_str(&out.yaml).is_ok(),
        "the rewritten config boot-parses on 1.6.0"
    );
}

#[test]
fn migrate_renames_a_tool_server_refresh_ttl_to_verify_ttl_with_a_warning() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = r#"
tools:
  servers:
    fs:
      url: "https://fs.example.com/rpc"
      pin: { mechanism: cert_spki, key: "sha256:abc" }
      refresh_ttl: "6h"
    docs:
      url: "https://docs.example.com/rpc"
      pin: { mechanism: unpinned }
"#;
    let out = migrate_config(raw).expect("migrates");
    let root: serde_yaml::Value = serde_yaml::from_str(&out.yaml).expect("valid yaml");
    let get = |keys: &[&str]| -> serde_yaml::Value {
        let mut v = root.clone();
        for k in keys {
            v = v
                .get(serde_yaml::Value::from(*k))
                .cloned()
                .unwrap_or(serde_yaml::Value::Null);
        }
        v
    };

    assert!(
        get(&["tools", "servers", "fs", "refresh_ttl"]).is_null(),
        "the old `refresh_ttl` key must be removed: {}",
        out.yaml
    );
    assert_eq!(
        get(&["tools", "servers", "fs", "verify_ttl"]).as_str(),
        Some("6h"),
        "the value is carried over onto `verify_ttl`: {}",
        out.yaml
    );

    assert!(get(&["tools", "servers", "docs", "verify_ttl"]).is_null());

    assert!(
        out.warnings.iter().any(|w| {
            w.contains("tools.servers.fs.refresh_ttl -> verify_ttl") && w.contains("MAX staleness")
        }),
        "the rename must warn about the changed meaning: {:?}",
        out.warnings
    );
}

#[test]
fn migrate_renames_a_flat_tools_entry_refresh_ttl() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = r#"
tools:
  fs:
    url: "https://fs.example.com/rpc"
    pin: { mechanism: cert_spki, key: "sha256:abc" }
    refresh_ttl: "6h"
  docs:
    url: "https://docs.example.com/rpc"
    pin: { mechanism: unpinned }
"#;
    let (out, doc) = migrate_to_value(raw);
    assert!(
        dig(&doc, &["tools", "fs", "refresh_ttl"]).is_none(),
        "the old `refresh_ttl` key must be removed: {}",
        out.yaml
    );
    assert_eq!(
        dig(&doc, &["tools", "fs", "verify_ttl"]).and_then(|v| v.as_str()),
        Some("6h"),
        "the value is carried over onto `verify_ttl`: {}",
        out.yaml
    );
    assert!(
        dig(&doc, &["tools", "docs", "verify_ttl"]).is_none(),
        "an entry that never set it is untouched: {}",
        out.yaml
    );
    assert!(
        out.warnings.iter().any(|w| {
            w.contains("tools.fs.refresh_ttl -> verify_ttl") && w.contains("MAX staleness")
        }),
        "the rename must warn about the changed meaning: {:?}",
        out.warnings
    );
}

#[test]
fn migrate_never_invents_a_keyless_api_key() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = "providers:\n  vendor-a: { api_key_env: VENDOR_A_KEY }\n  local: { base_url: 'http://127.0.0.1:11434' }\n";
    let (_out, doc) = migrate_to_value(raw);
    assert_eq!(
        dig(&doc, &["providers", "vendor-a", "api_key", "env"]).and_then(|v| v.as_str()),
        Some("VENDOR_A_KEY"),
        "a visible api_key_env still converts to the secret reference"
    );
    assert!(
        dig(&doc, &["providers", "local", "api_key"]).is_none(),
        "a provider with no credential to convert gets NO api_key — never a fabricated `none`"
    );
}

#[test]
fn a_keys_chain_without_a_signing_key_gets_the_signing_key_todo() {
    crate::dist_root_install::install();
    crate::root::migration_table::install();
    let raw = "listen: 0.0.0.0:8080\nauth:\n  chain: [keys]\n";
    let out = migrate_config(raw).expect("migrates");
    assert!(
        out.todos
            .iter()
            .any(|t| t.starts_with("auth.signing_key: required")
                && t.contains("--generate-signing-key")),
        "{:?}",
        out.todos
    );
    assert!(
        out.yaml
            .contains("# TODO(migrate): auth.signing_key: required"),
        "{}",
        out.yaml
    );

    let with = "listen: 0.0.0.0:8080\nauth:\n  chain: [keys]\n  signing_key: { env: K }\n";
    let out = migrate_config(with).expect("migrates");
    assert!(
        !out.todos.iter().any(|t| t.starts_with("auth.signing_key")),
        "{:?}",
        out.todos
    );
}
