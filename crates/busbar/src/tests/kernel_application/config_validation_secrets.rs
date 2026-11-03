// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The original built-in-secret resolution assertions run through the actual product check.
use busbar_kernel::config;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[test]
fn unreferenced_identity_provider_token_is_not_resolved_by_actual_validate() {
    crate::dist_root_install::install();
    let path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(path).expect("the actual store library reads");
    let directory = plugins::scratch("config-secret-token-coverage");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let mut document = serde_json::json!({
        "listen": "127.0.0.1:8080", "providers": {}, "models": {},
        "identity-providers": {
            "oracle-keys": { "module": "keys", "token": { "env": "BUSBAR_TEST_NEVER_SET_ORACLE_UNUSED_TOKEN" } }
        },
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
    });
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let resolve_builtins = |cfg: &config::RootCfg| -> Result<(), String> {
        busbar_kernel::config_validate::check(
            cfg,
            busbar_kernel::config_validate::Check {
                plugins: &plugin_config,
                unset_env_vars: &[],
                root: &busbar_kernel::config_validate::no_root_rules,
                fetch: None,
                resolve_builtins: true,
            },
        )
        .map(|_| ())
        .map_err(|refusal| match refusal {
            busbar_kernel::config_validate::Refusal::Unresolved(message) => message,
            other => panic!("the actual config must reach built-in secret resolution: {other:?}"),
        })
    };
    let deploy = config::deploy_from_deserializer(document.clone()).expect("the fixture parses");
    let cfg = config::resolve(&deploy, &Default::default()).expect("the fixture resolves");
    resolve_builtins(&cfg).unwrap_or_else(|e| {
        panic!("--validate refused a config boot serves (the unset env var is never read): {e}")
    });

    let op = config::operator_provider();
    assert!(
        !op.is_empty(),
        "the actual root declares its operator credential"
    );
    document["identity-providers"][op] = serde_json::json!({
        "module": op, "token": { "env": "BUSBAR_TEST_NEVER_SET_ADMIN_TOKEN" },
    });
    document["auth"]["admin_auth"] = serde_json::json!([op]);
    let deploy = config::deploy_from_deserializer(document).expect("the referenced fixture parses");
    let cfg =
        config::resolve(&deploy, &Default::default()).expect("the referenced fixture resolves");
    let err = resolve_builtins(&cfg)
        .expect_err("the referenced operator token cannot resolve and must be refused");
    assert!(
        err.starts_with(&format!("auth.admin_auth.{op}.token: "))
            && err.contains("BUSBAR_TEST_NEVER_SET_ADMIN_TOKEN"),
        "the refusal must name the operator token, not the unreferenced definition; got: {err}"
    );
}
