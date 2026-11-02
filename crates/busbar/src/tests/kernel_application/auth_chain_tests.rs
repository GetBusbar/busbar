// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[path = "../../../../../dist/default/tests/common/mod.rs"]
mod common;

use busbar_kernel::auth::{AuthMiddleware, ChainVerdict};

const AUDIENCE: &str = "api://auth-ordinary-chain";

fn chain_cfg(modules: &[&str]) -> busbar_kernel::config::AuthCfg {
    let mut cfg = busbar_kernel::config::AuthCfg::default_none();
    cfg.chain = modules
        .iter()
        .map(|module| {
            let mut entry = busbar_kernel::config::AuthChainEntry::bare(*module);
            if *module == "test-groups-module" {
                entry.settings = common::credentials::settings(AUDIENCE);
            }
            entry
        })
        .collect();
    cfg
}

#[test]
fn test_chain_identifies_with_module_and_principal() {
    crate::dist_root_install::install();
    let artifact = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&artifact)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC product exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual OIDC statement is valid")
        .name;
    let directory = common::plugins::scratch(
        "auth-ordinary-chain-test_chain_identifies_with_module_and_principal",
    );
    common::credentials::install_auth_plugin(&directory, &module, "test-groups-module", true);
    let plugins = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let registry = busbar_kernel::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .expect("the actual root admits the signed OIDC product");
    let mw = AuthMiddleware::new(
        &chain_cfg(&["test-groups-module"]),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the real auth chain constructs");
    match mw.run_chain(Some(&common::credentials::token_for(
        "dev",
        &["dev"],
        AUDIENCE,
    ))) {
        ChainVerdict::Identified {
            module, principal, ..
        } => {
            assert_eq!(module, "test-groups-module");
            assert_eq!(principal.id, "oidc:dev");
            assert_eq!(principal.roles, vec!["dev".to_string()]);
        }
        other => panic!("expected Identified, got {other:?}"),
    }
    assert!(mw.validate_token(Some(&common::credentials::token_for(
        "dev",
        &["dev"],
        AUDIENCE
    ))));
    assert!(!mw.is_open());
}

#[test]
fn test_nonempty_chain_fails_closed_on_all_pass() {
    crate::dist_root_install::install();
    let artifact = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&artifact)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC product exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual OIDC statement is valid")
        .name;
    let directory = common::plugins::scratch(
        "auth-ordinary-chain-test_nonempty_chain_fails_closed_on_all_pass",
    );
    common::credentials::install_auth_plugin(&directory, &module, "test-groups-module", true);
    let plugins = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let registry = busbar_kernel::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .expect("the actual root admits the signed OIDC product");
    let mw = AuthMiddleware::new(
        &chain_cfg(&["test-groups-module"]),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the real auth chain constructs");
    assert_eq!(
        mw.run_chain(Some("not-a-recognized-credential")),
        ChainVerdict::Denied,
        "an unrecognized credential must be denied by a configured chain"
    );
    assert_eq!(
        mw.run_chain(None),
        ChainVerdict::Denied,
        "no credential at all must be denied by a configured chain"
    );
    assert!(!mw.validate_token(Some("tok3")));
    assert!(!mw.validate_token(None));
    assert!(!mw.validate_token(Some("")));
}

#[test]
fn test_empty_chain_is_open_front_door() {
    crate::dist_root_install::install();
    let registry =
        busbar_kernel::preflight::linked().expect("the actual root registry is installed");
    let mw = AuthMiddleware::new(
        &busbar_kernel::config::AuthCfg::default_none(),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the real auth chain constructs");
    assert!(mw.is_open());
    assert_eq!(mw.run_chain(None), ChainVerdict::Open);
    assert_eq!(mw.run_chain(Some("anything")), ChainVerdict::Open);
    assert!(mw.validate_token(None));
    assert!(mw.validate_token(Some("anything")));
}

#[test]
fn test_keys_in_chain_sets_flag_not_module() {
    crate::dist_root_install::install();
    let artifact = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&artifact)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC product exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual OIDC statement is valid")
        .name;
    let directory =
        common::plugins::scratch("auth-ordinary-chain-test_keys_in_chain_sets_flag_not_module");
    common::credentials::install_auth_plugin(&directory, &module, "test-groups-module", true);
    let plugins = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let registry = busbar_kernel::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .expect("the actual root admits the signed OIDC product");
    let mw = AuthMiddleware::new(
        &chain_cfg(&["keys"]),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the real auth chain constructs");
    assert!(mw.keys_in_chain, "chain: [keys] must set keys_in_chain");
    assert!(
        mw.chain_names().is_empty(),
        "keys is engine-handled, never a boxed module"
    );

    let mw = AuthMiddleware::new(
        &busbar_kernel::config::AuthCfg::default_none(),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the real auth chain constructs");
    assert!(!mw.keys_in_chain, "an empty chain must not claim keys");

    let mw = AuthMiddleware::new(
        &chain_cfg(&["keys", "test-groups-module"]),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the real auth chain constructs");
    assert!(mw.keys_in_chain);
    assert_eq!(mw.chain_names(), vec![module.clone()]);
    assert!(mw.validate_token(Some(&common::credentials::token_for(
        "dev",
        &["dev"],
        AUDIENCE
    ))));
    assert!(!mw.validate_token(Some("wrong")), "still fail-closed");
}

#[test]
fn test_auth_middleware_debug_redacts_tokens() {
    crate::dist_root_install::install();
    let artifact = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&artifact)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC product exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual OIDC statement is valid")
        .name;
    let directory =
        common::plugins::scratch("auth-ordinary-chain-test_auth_middleware_debug_redacts_tokens");
    common::credentials::install_auth_plugin(&directory, &module, "test-groups-module", true);
    let plugins = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let registry = busbar_kernel::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .expect("the actual root admits the signed OIDC product");
    let cfg = chain_cfg(&["keys", "test-groups-module"]);
    let mw = AuthMiddleware::new(
        &cfg,
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the real auth chain constructs");
    let dbg = format!("{mw:?}");
    assert!(
        dbg.contains("chain_len"),
        "AuthMiddleware Debug should report the chain length: {dbg}"
    );
    assert!(
        dbg.contains("keys_in_chain"),
        "AuthMiddleware Debug should report the keys flag: {dbg}"
    );

    for forbidden in ["token", "secret", "credential"] {
        assert!(
            !dbg.to_ascii_lowercase()
                .replace("keys_in_chain", "")
                .contains(forbidden),
            "AuthMiddleware Debug printed an unexpected field '{forbidden}': {dbg}"
        );
    }
}

#[test]
fn a_keys_only_chain_is_not_an_open_front_door() {
    crate::dist_root_install::install();
    let artifact = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&artifact)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC product exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual OIDC statement is valid")
        .name;
    let directory =
        common::plugins::scratch("auth-ordinary-chain-a_keys_only_chain_is_not_an_open_front_door");
    common::credentials::install_auth_plugin(&directory, &module, "test-groups-module", true);
    let plugins = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let registry = busbar_kernel::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .expect("the actual root admits the signed OIDC product");
    let mw = AuthMiddleware::new(
        &chain_cfg(&["keys"]),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the real auth chain constructs");
    assert!(mw.keys_in_chain, "precondition: keys sets the flag");
    assert!(
        mw.chain_names().is_empty(),
        "precondition: keys installs no boxed module"
    );
    assert!(
        !mw.is_open(),
        "chain: [keys] authenticates, so the front door is CLOSED — reporting it open grants \
         VerbScope::Full to every caller at Root::admin_grant"
    );

    let none = AuthMiddleware::new(
        &busbar_kernel::config::AuthCfg::default_none(),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the real auth chain constructs");
    assert!(none.is_open(), "no module and no keys arm IS the open door");

    let both = AuthMiddleware::new(
        &chain_cfg(&["keys", "test-groups-module"]),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the real auth chain constructs");
    assert!(!both.is_open(), "a boxed module closes the door regardless");
}
