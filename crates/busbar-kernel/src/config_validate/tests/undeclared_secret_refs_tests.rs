// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The undeclared-reference refusal `--validate` and boot share (OWNER RULING, CHIP-REVIEW-v4
//! change 2; overturns Q123).

use std::sync::Arc;

use busbar_contract::plugin_rows::PluginRows;
use serde_json::json;

use super::undeclared_secret_refs;

/// A store plugin declaring the exact path `dsn` and the wildcard path `replicas.*.password`, and
/// an auth plugin standing in for busbar-auth-github, declaring only `client_secret`.
fn rows() -> Arc<dyn PluginRows> {
    crate::test_support::rows::Rows::new()
        .with_dropped_secret_slots(
            crate::tests::dropped("acme-store", "acme", "store"),
            &["dsn", "replicas.*.password"],
        )
        .with_dropped_secret_slots(
            crate::tests::dropped("busbar-auth-github", "github", "auth"),
            &["client_secret"],
        )
        .into_rows()
}

fn store_with(settings: serde_json::Value) -> crate::config::RootCfg {
    let mut cfg = crate::test_support::cfg_with_provider_api_key(crate::config::SecretRef::env(
        "PROVIDER_KEY",
    ));
    let serde_json::Value::Object(settings) = settings else {
        panic!("an object");
    };
    cfg.store = Some(crate::config::StoreCfg {
        module: "acme-store".into(),
        settings,
    });
    cfg
}

#[test]
fn a_reference_at_an_undeclared_field_is_refused_naming_field_plugin_and_the_way_out() {
    let cfg = store_with(json!({"dsn": {"env": "PG_DSN"}, "base": {"env": "BASE"}}));
    let e = undeclared_secret_refs(rows().as_ref(), &cfg).expect_err("refused");
    assert!(e.contains("store.settings.base"), "names the field: {e}");
    assert!(e.contains("'acme-store'"), "names the plugin: {e}");
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
    let cfg = store_with(json!({"pool": {"hosts": [{"auth": {"file": "/run/k"}}]}}));
    let e = undeclared_secret_refs(rows().as_ref(), &cfg).expect_err("refused");
    assert!(e.contains("store.settings.pool.hosts.0.auth"), "{e}");
}

#[test]
fn references_at_a_declared_exact_path_and_a_declared_wildcard_path_are_accepted() {
    let cfg = store_with(json!({
        "dsn": {"env": "PG_DSN"},
        "replicas": [{"host": "r1", "password": {"env": "R1"}}, {"host": "r2", "password": "lit"}],
        "data": {"literal": {"env": "HOME"}},
        "name": "plain"
    }));
    assert_eq!(undeclared_secret_refs(rows().as_ref(), &cfg), Ok(()));
}

/// THE Q123 CELL: a GitHub base URL written as a reference was resolved in place by the kernel and
/// logged in (OWNER Q123, 2026-09-30). The plugin declares only `client_secret`, so it is refused.
#[test]
fn q123_a_github_base_written_as_a_reference_is_refused() {
    let mut cfg = store_with(json!({}));
    let serde_json::Value::Object(settings) = json!({
        "client_id": "Iv1.client",
        "client_secret": {"env": "GH_SECRET"},
        "api_base": {"env": "GHE_API"}
    }) else {
        panic!("an object");
    };
    cfg.identity_providers.insert(
        "github".into(),
        crate::config::IdentityProviderCfg {
            module: "github".into(),
            max_admin_scope: None,
            token: None,
            browser_login: None,
            settings,
        },
    );
    let e = undeclared_secret_refs(rows().as_ref(), &cfg).expect_err("refused");
    assert!(
        e.contains("identity-providers.github.settings.api_base"),
        "{e}"
    );
    assert!(e.contains("'github'"), "{e}");
}

/// Core's own typed fields are not plugin settings: the provider's `api_key` reference is not
/// looked at here.
#[test]
fn core_fields_are_not_plugin_settings() {
    assert_eq!(
        undeclared_secret_refs(rows().as_ref(), &store_with(json!({}))),
        Ok(())
    );
}
