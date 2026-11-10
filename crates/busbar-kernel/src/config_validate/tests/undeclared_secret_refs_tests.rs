// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde_json::json;

use super::check_declared_paths;

fn check(
    cfg: &crate::config::RootCfg,
    secrets: &[&str],
    references: &[&str],
) -> Result<(), String> {
    check_declared_paths(
        cfg,
        |_| secrets.iter().map(|s| (*s).to_owned()).collect(),
        |_| references.iter().map(|s| (*s).to_owned()).collect(),
    )
}

fn reference(slot: &str) -> serde_json::Value {
    json!({"module": "declared-source", "settings": {"slot": slot}})
}

fn store_with(settings: serde_json::Value) -> crate::config::RootCfg {
    let deploy: crate::config::DeployCfg = serde_yaml::from_str(
        "providers: {}\nstore: {module: fixture-owner}\nauth: {chain: [], admin_auth: []}\n",
    )
    .expect("the kernel-owned config parses");
    let mut cfg = crate::config::resolve(&deploy, &Default::default())
        .expect("the kernel-owned config resolves");
    cfg.store = Some(crate::config::StoreCfg {
        module: "fixture-owner".into(),
        settings: serde_json::from_value(settings).expect("object settings"),
    });
    cfg
}

#[test]
fn a_reference_at_an_undeclared_field_is_refused_naming_field_plugin_and_the_way_out() {
    let cfg = store_with(json!({"credential": reference("first"), "base": reference("second")}));
    let e = check(&cfg, &["credential"], &[]).expect_err("refused");
    assert!(e.contains("store.settings.base"), "names the field: {e}");
    assert!(e.contains("'fixture-owner'"), "names the plugin: {e}");
    assert!(
        e.contains("did not declare it as a secret"),
        "says why: {e}"
    );
    assert!(
        e.contains("write the value itself"),
        "says what to write: {e}"
    );
}

#[test]
fn a_reference_nested_at_any_depth_is_refused() {
    let cfg = store_with(json!({"pool": {"hosts": [{"auth": reference("nested")}]}}));
    let e = check(&cfg, &[], &[]).expect_err("refused");
    assert!(e.contains("store.settings.pool.hosts.0.auth"), "{e}");
}

#[test]
fn references_at_a_declared_exact_path_and_a_declared_wildcard_path_are_accepted() {
    let cfg = store_with(json!({
        "credential": reference("first"),
        "replicas": [{"host": "r1", "password": reference("second")}, {"host": "r2", "password": "lit"}],
        "data": {"literal": reference("ordinary-data")},
        "name": "plain"
    }));
    assert_eq!(
        check(&cfg, &["credential", "replicas.*.password"], &[]),
        Ok(())
    );
}

#[test]
fn identity_provider_reference_fields_require_the_owners_declaration() {
    let mut cfg = store_with(json!({}));
    cfg.identity_providers.insert(
        "login".into(),
        crate::config::IdentityProviderCfg {
            module: "fixture-owner".into(),
            max_admin_scope: None,
            token: None,
            browser_login: None,
            settings: serde_json::from_value(json!({
                "credential": reference("credential"),
                "endpoint": reference("endpoint"),
            }))
            .unwrap(),
        },
    );
    let e = check(&cfg, &["credential"], &[]).expect_err("refused");
    assert!(
        e.contains("identity-providers.login.settings.endpoint"),
        "{e}"
    );
    assert!(e.contains("'fixture-owner'"), "{e}");
    assert_eq!(check(&cfg, &["credential"], &["endpoint"]), Ok(()));
}

#[test]
fn core_fields_are_not_plugin_settings() {
    assert_eq!(check(&store_with(json!({})), &[], &[]), Ok(()));
}

#[test]
fn reference_admission_depends_on_declarations_across_kinds() {
    // The same owner name exercises every declaration, so a name-to-capability table
    // cannot determine these results.
    let mut cfg = store_with(json!({"endpoint": reference("store")}));
    assert_eq!(check(&cfg, &[], &["endpoint"]), Ok(()));
    let e = check(&cfg, &[], &[]).expect_err("missing declaration");
    assert!(e.contains("store.settings.endpoint"), "{e}");
    cfg.hooks.insert(
        "gate".into(),
        serde_json::from_value(json!({
            "kind": "gate", "module": "fixture-owner",
            "settings": {"endpoint": reference("hook")},
        }))
        .unwrap(),
    );
    cfg.export_defs.insert(
        "sink".into(),
        serde_json::from_value(json!({
            "module": "fixture-owner", "settings": {"endpoint": reference("export")},
        }))
        .unwrap(),
    );
    assert_eq!(check(&cfg, &[], &["endpoint"]), Ok(()));
    cfg.store = None;
    let e = check(&cfg, &[], &[]).expect_err("hook declaration missing");
    assert!(e.contains("hooks.gate.settings.endpoint"), "{e}");
    cfg.hooks.clear();
    let e = check(&cfg, &[], &[]).expect_err("export declaration missing");
    assert!(e.contains("sink.settings.endpoint"), "{e}");
}
