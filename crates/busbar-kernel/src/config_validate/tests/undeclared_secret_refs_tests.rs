// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde_json::json;

use super::check_declared_paths;

fn check(cfg: &crate::config::RootCfg) -> Result<(), String> {
    check_declared_paths(
        cfg,
        |module| match module {
            "acme-store" => vec!["dsn".into(), "replicas.*.password".into()],
            "github" => vec!["client_secret".into()],
            _ => Vec::new(),
        },
        |_| Vec::new(),
    )
}

fn store_with(settings: serde_json::Value) -> crate::config::RootCfg {
    let deploy: crate::config::DeployCfg = serde_yaml::from_str(
        "providers: {}\nstore: {module: acme-store}\nauth: {chain: [], admin_auth: []}\n",
    )
    .expect("the kernel-owned config parses");
    let mut cfg = crate::config::resolve(&deploy, &Default::default())
        .expect("the kernel-owned config resolves");
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
    let e = check(&cfg).expect_err("refused");
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
    let e = check(&cfg).expect_err("refused");
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
    assert_eq!(check(&cfg), Ok(()));
}

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
    let e = check(&cfg).expect_err("refused");
    assert!(
        e.contains("identity-providers.github.settings.api_base"),
        "{e}"
    );
    assert!(e.contains("'github'"), "{e}");
}

#[test]
fn core_fields_are_not_plugin_settings() {
    assert_eq!(check(&store_with(json!({}))), Ok(()));
}

#[test]
fn a_reference_at_a_reference_capable_url_is_accepted_and_elsewhere_refused() {
    let check = |cfg: &crate::config::RootCfg| {
        check_declared_paths(
            cfg,
            |_| Vec::new(),
            |module| {
                if [
                    "postgres",
                    "valkey",
                    "mysql",
                    "webrequest",
                    "otlp",
                    "request-log-webhook",
                ]
                .contains(&module)
                {
                    vec!["url".into()]
                } else {
                    Vec::new()
                }
            },
        )
    };
    for store in ["postgres", "valkey", "mysql"] {
        let mut cfg = store_with(json!({"url": {"env": "STORE_URL"}}));
        if let Some(s) = cfg.store.as_mut() {
            s.module = store.into();
        }
        assert_eq!(check(&cfg), Ok(()), "{store}");
        let mut cfg = store_with(json!({"url": "postgres://x", "pool": {"env": "POOL"}}));
        if let Some(s) = cfg.store.as_mut() {
            s.module = store.into();
        }
        let e = check(&cfg).expect_err("refused");
        assert!(e.contains("store.settings.pool"), "{store}: {e}");
    }

    let mut cfg = store_with(json!({}));
    cfg.store = None;
    let hook: crate::config::HookCfg = serde_json::from_value(json!({
        "kind": "gate",
        "module": "webrequest",
        "settings": {"url": {"env": "HOOK_URL"}},
    }))
    .expect("a hook");
    cfg.hooks.insert("gate".into(), hook);
    for (name, module) in [("traces", "otlp"), ("wh", "request-log-webhook")] {
        let def: crate::config::ExportDefCfg = serde_json::from_value(json!({
            "module": module,
            "settings": {"url": {"env": "EXPORT_URL"}},
        }))
        .expect("an export");
        cfg.export_defs.insert(name.into(), def);
    }
    assert_eq!(check(&cfg), Ok(()));
}
