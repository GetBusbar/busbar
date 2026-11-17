// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The 1.5 `token:` form through the actual product check: ADMIN-TOKEN-MIGRATE refuses it.
use busbar_contract::json::JsonValueTrait as _;
use busbar_kernel::config;

use crate::root::test_plugins as plugins;

#[test]
fn a_1_5_token_is_refused_with_the_settings_remedy_by_actual_validate() {
    crate::dist_root_install::install();
    // Bind the linked operator: the config takes the closed default admin chain.
    busbar_kernel::preflight::install_operator(crate::root::auth_bindings::operator_binding(None));
    let path = crate::root::test_plugins::application_store_library();
    let module = crate::root::test_plugins::native_image(&path).name;
    let manifest = crate::root::test_plugins::native_manifest(
        "store",
        &path,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    let library = std::fs::read(path).expect("the actual store library reads");
    let directory = plugins::scratch("config-secret-token-coverage");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage actual store archive");
    let settings = crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    // Every stage a config read passes (parse, resolve, the product check) and the refusal it
    // stopped at; a config that passes them all is a failure of this test.
    let refusal_of = |document: serde_json::Value| -> String {
        let deploy = match config::deploy_from_deserializer(
            document,
            &crate::root::boot::axis_test_grammar(),
        ) {
            Ok(deploy) => deploy,
            Err(refused) => return refused.to_string(),
        };
        let cfg = match config::resolve(&deploy, &Default::default()) {
            Ok(cfg) => cfg,
            Err(refused) => return refused.join("; "),
        };
        match busbar_kernel::config_validate::check(
            &cfg,
            busbar_kernel::config_validate::Check {
                plugins: &plugin_config,
                unset_env_vars: &[],
                root: &busbar_kernel::config_validate::no_root_rules,
                fetch: None,
                resolve_builtins: true,
                secret_axis: busbar_kernel::config::secret::live_axis(),
            },
        ) {
            Ok(_) => panic!("1.6 must refuse the 1.5 `token:` form"),
            Err(refused) => format!("{refused:?}"),
        }
    };
    let op = config::operator_provider();
    assert!(
        !op.is_empty(),
        "the actual root declares its operator credential"
    );

    // ADMIN-TOKEN-MIGRATE: a 1.5 `token:` on a definition that is not the operator credential's
    // is refused, naming the definition; the never-set variable is never read.
    let misplaced = refusal_of(serde_json::json!({
        "listen": "127.0.0.1:8080", "providers": {}, "models": {},
        "identity-providers": {
            "oracle-keys": { "module": "keys", "token": { "env": "BUSBAR_TEST_NEVER_SET_ORACLE_UNUSED_TOKEN" } }
        },
        "auth": { "chain": [] },
        "store": { "module": module, "settings": settings },
    }));
    assert!(
        misplaced.contains("identity-providers.oracle-keys")
            && misplaced.contains(&format!(
                "`token:` is the built-in `{op}` operator credential and is meaningless on \
                 `module: keys`"
            )),
        "the misplaced token is refused by its definition's name; got: {misplaced}"
    );

    // ADMIN-TOKEN-MIGRATE: a 1.5 `token:` on the operator credential is refused with its remedy,
    // the 1.6 `settings: {sha256: ..}` form, before any secret is resolved.
    let mut operator = serde_json::json!({
        "listen": "127.0.0.1:8080", "providers": {}, "models": {},
        "identity-providers": {},
        "auth": { "chain": [] },
        "store": { "module": module, "settings": settings },
    });
    operator["identity-providers"][op] = serde_json::json!({
        "module": op, "token": { "env": "BUSBAR_TEST_NEVER_SET_ADMIN_TOKEN" },
    });
    operator["auth"]["admin_auth"] = serde_json::json!([op]);
    let refused = refusal_of(operator);
    assert!(
        refused.contains(&format!(
            "identity-providers.{op}: `token:` is the 1.5 operator credential"
        )) && refused.contains("Replace `token:` with `settings: {sha256:"),
        "the operator token is refused with the settings remedy; got: {refused}"
    );
    assert!(
        !refused.contains("BUSBAR_TEST_NEVER_SET_ADMIN_TOKEN"),
        "the refusal is the token: remedy, not an unresolved secret; got: {refused}"
    );
}
