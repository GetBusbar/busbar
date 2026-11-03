// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::auth::AuthMiddleware;
use busbar_kernel::config::{AuthCfg, AuthChainEntry, PluginsCfg};
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

fn chain_with(module: &str, settings: serde_json::Map<String, serde_json::Value>) -> AuthCfg {
    let mut entry = AuthChainEntry::bare(module);
    entry.settings = settings;
    AuthCfg {
        chain: vec![entry],
        ..AuthCfg::default_none()
    }
}

#[test]
fn missing_auth_plugin_is_loud_boot_failure() {
    crate::dist_root_install::install();
    let dir = plugins::scratch("auth-plugin-missing");

    let artifact = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("the freshly built actual Store product is required"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&artifact)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(artifact).expect("the actual Store library reads"),
    );
    std::fs::write(dir.join("store.tar.gz"), archive).expect("stage the unrelated actual Store");
    let plugins = crate::root::test_plugins::trusted_config(&dir);
    let cfg = chain_with("test-idp-double", serde_json::Map::new());

    let err = busbar_kernel::plugins_preflight(
        None,
        Some(&cfg),
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .unwrap_err();
    assert!(
        err.contains("test-idp-double"),
        "names the missing module: {err}"
    );
    assert!(
        err.contains("no plugin matching") && err.contains("is installed in"),
        "explains it is unresolved: {err}"
    );

    assert!(
        err.contains("enabled") && err.contains("plugins.fetch"),
        "gives the two-part enabled?/in-folder? diagnosis: {err}"
    );

    let registry = busbar_kernel::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .expect("the directory builds");
    assert_eq!(
        registry
            .resolve(&module)
            .expect("the unrelated actual Store row is present")
            .kind,
        busbar_contract::abi::mechanism::kind::STORE
    );
    let mw_err = AuthMiddleware::new(
        &cfg,
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .unwrap_err();
    assert!(
        mw_err.contains("test-idp-double"),
        "middleware names it: {mw_err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn auth_plugin_with_plugins_disabled_is_boot_error_naming_the_flag() {
    crate::dist_root_install::install();
    let dir = plugins::scratch("auth-plugin-disabled");
    let plugins = PluginsCfg {
        enabled: false,
        dir: dir.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let cfg = chain_with("test-idp-double", serde_json::Map::new());
    let err = busbar_kernel::plugins_preflight(
        None,
        Some(&cfg),
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .unwrap_err();
    assert!(err.contains("plugins.enabled"), "names the flag: {err}");
    assert!(
        err.contains("test-idp-double"),
        "names the auth module: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn keys_module_is_not_a_plugin_ref() {
    crate::dist_root_install::install();
    let cfg = AuthCfg {
        chain: vec![AuthChainEntry::bare(busbar_kernel::config::KEYS_MODULE)],
        ..AuthCfg::default_none()
    };

    let plugins = PluginsCfg::default();
    let registry = busbar_kernel::plugins_preflight(
        None,
        Some(&cfg),
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .expect("keys needs no plugin");
    let mw = AuthMiddleware::new(
        &cfg,
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("keys chain builds");
    assert!(mw.keys_in_chain, "keys sets the engine flag");
    assert!(mw.chain_names().is_empty(), "keys is not a boxed module");
}
