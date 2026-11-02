// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::appbuild::AcceptAll;
use busbar_kernel::config::overlay::{persist_root, RootSettings};
use std::sync::Arc;
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[test]
fn base_store_bootstrap_and_effective_build_share_the_same_opened_store() {
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("config-recovery");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let mut plugin_config = plugin_config;
    let digest = plugins::sha256(&std::fs::read(directory.join("store.tar.gz")).unwrap());
    plugin_config.fetch = vec![busbar_kernel::config::PluginFetch::Url(
        busbar_kernel::config::UrlFetch {
            url: "https://plugins.invalid/store.tar.gz".into(),
            sha256: Some(digest),
        },
    )];
    let cfg = config;
    let opened = busbar_kernel::appbuild::bootstrap_config_store(&cfg, &plugin_config).unwrap();
    let calls = opened.calls.as_ref().unwrap().clone();
    let backend = busbar_kernel::config::overlay::OverlayStore::new(calls.clone()).unwrap();
    persist_root(
        Some(&backend),
        &RootSettings {
            per_request_fee: Some(23),
            ..Default::default()
        },
    )
    .unwrap();
    let rules: std::sync::Arc<dyn busbar_kernel::appbuild::RootRules> =
        std::sync::Arc::new(AcceptAll);
    let (app, _, _limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        cfg,
        plugin_config,
        Some(backend),
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(opened),
        false,
    )
    .unwrap();
    assert!(std::sync::Arc::ptr_eq(
        &app.governance.unwrap().store_calls().unwrap(),
        &calls
    ));
}

#[test]
fn a_cross_node_sibling_update_and_intervening_get_cannot_authorize_a_stale_app_commit() {
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("config-recovery");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let mut plugin_config = plugin_config;
    let digest = plugins::sha256(&std::fs::read(directory.join("store.tar.gz")).unwrap());
    plugin_config.fetch = vec![busbar_kernel::config::PluginFetch::Url(
        busbar_kernel::config::UrlFetch {
            url: "https://plugins.invalid/store.tar.gz".into(),
            sha256: Some(digest),
        },
    )];
    let opened = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config).unwrap();
    let calls = opened.calls.as_ref().unwrap().clone();
    let backend = busbar_kernel::config::overlay::OverlayStore::new(calls.clone()).unwrap();
    persist_root(Some(&backend), &RootSettings::default()).unwrap();
    let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
        Arc::new(crate::root::door_steps::Rules::default());
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(backend.clone()),
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(opened),
        false,
    )
    .unwrap();
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let handle = busbar_kernel::state::AppHandle::new(Arc::new(app));
    let before = handle.load();
    let other = busbar_kernel::config::overlay::OverlayStore::new(calls).unwrap();
    busbar_kernel::config::overlay::persist_groups(
        Some(&other),
        &std::collections::BTreeMap::from([("remote_security_team".into(), Default::default())]),
        None,
        None,
        &Default::default(),
    )
    .unwrap();

    assert!(backend
        .read_required()
        .unwrap()
        .unwrap()
        .groups
        .contains_key("remote_security_team"));
    assert!(backend.read_bytes().unwrap().is_some());
    let next = std::sync::Arc::new(
        busbar_kernel::governance::group_provision::build_with_group(
            &before,
            "local_candidate",
            Default::default(),
        )
        .unwrap(),
    );
    let persist = busbar_kernel::governance::group_provision::persist_provisioned_group(
        next.clone(),
        "local_candidate".into(),
        "test".into(),
    );
    assert!(handle.commit_and_swap(next, persist).is_err());
    assert!(std::sync::Arc::ptr_eq(&handle.load(), &before));
    let stored = backend.read_required().unwrap().unwrap();
    assert!(stored.groups.contains_key("remote_security_team"));
    assert!(!stored.groups.contains_key("local_candidate"));
}

#[test]
fn bootstrap_opens_the_anchor_before_requiring_modules_whose_pins_it_must_recover() {
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("config-recovery");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let mut plugin_config = plugin_config;
    let digest = plugins::sha256(&std::fs::read(directory.join("store.tar.gz")).unwrap());
    plugin_config.fetch = vec![busbar_kernel::config::PluginFetch::Url(
        busbar_kernel::config::UrlFetch {
            url: "https://plugins.invalid/store.tar.gz".into(),
            sha256: Some(digest),
        },
    )];
    let mut cfg = config;
    cfg.hooks.insert(
        "pinned_hook".into(),
        serde_json::from_value(
            serde_json::json!({"kind":"tap","module":"hook-resolved-after-overlay-pins"}),
        )
        .unwrap(),
    );
    let opened = busbar_kernel::appbuild::bootstrap_config_store(&cfg, &plugin_config).unwrap();
    assert!(opened.calls.is_some());
    assert!(
        busbar_kernel::config_validate::check(
            &cfg,
            busbar_kernel::config_validate::Check {
                plugins: &plugin_config,
                unset_env_vars: &[],
                root: &|_| Ok(()),
                fetch: None,
                resolve_builtins: false
            }
        )
        .is_err(),
        "the complete generation still refuses a module that recovery did not make loadable"
    );
}

#[test]
fn root_recovery_can_run_before_hydration_without_changing_standalone_builds() {
    use busbar_contract::records::{UsageLedger, VirtualKey};
    use std::sync::Arc;

    for recover_first in [false, true] {
        crate::dist_root_install::install();
        let library_path = std::path::PathBuf::from(
            std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
                .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
        );
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual store statement reads")
            .expect("the actual store exports its statement");
        let module = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual store statement is valid")
            .name;
        let mut manifest = plugins::manifest(
            "store",
            &module,
            busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        let library = std::fs::read(library_path).expect("the actual store library reads");
        let directory = plugins::scratch("config-recovery");
        let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
        std::fs::write(directory.join("store.tar.gz"), archive)
            .expect("stage the actual store archive");
        let settings: serde_json::Value = serde_json::from_str(
            &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
        )
        .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
        assert!(
            settings.is_object(),
            "the actual store settings are an object"
        );
        let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
            "providers": {},
            "models": {},
            "auth": { "chain": [], "admin_auth": [] },
            "store": { "module": module, "settings": settings },
            "advanced": { "allow_destinations": ["127.0.0.1"] },
        }))
        .expect("the product deployment parses");
        let config = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the product deployment resolves");
        let plugin_config = busbar_kernel::config::PluginsCfg {
            enabled: true,
            dir: directory.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let mut plugin_config = plugin_config;
        let digest = plugins::sha256(&std::fs::read(directory.join("store.tar.gz")).unwrap());
        plugin_config.fetch = vec![busbar_kernel::config::PluginFetch::Url(
            busbar_kernel::config::UrlFetch {
                url: "https://plugins.invalid/store.tar.gz".into(),
                sha256: Some(digest),
            },
        )];
        let cfg = config;
        let opened = busbar_kernel::appbuild::bootstrap_config_store(&cfg, &plugin_config).unwrap();
        let records = Arc::clone(&opened.records);
        let id = "vk_recovery_boot_order";
        records
            .put_key(&VirtualKey {
                id: id.into(),
                name: "recovery boot ordering".into(),
                generation_hash: format!("binding:{id}:public-generation"),
                enabled: true,
                ..Default::default()
            })
            .unwrap();
        records
            .put_usage(
                id,
                0,
                &UsageLedger {
                    requests: 7,
                    ..Default::default()
                },
            )
            .unwrap();
        let rules: Arc<dyn busbar_kernel::appbuild::RootRules> = Arc::new(AcceptAll);
        let (app, _, _limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            plugin_config,
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(opened),
            recover_first,
        )
        .unwrap();
        records
            .put_usage(
                id,
                0,
                &UsageLedger {
                    requests: 11,
                    ..Default::default()
                },
            )
            .unwrap();
        let gov = app.governance.as_ref().unwrap();
        let now = busbar_kernel::store::now();
        assert_eq!(
            gov.usage_for(&app.cost, id, now).unwrap().unwrap().requests,
            if recover_first { 11 } else { 7 },
            "only the explicit recovery boot postpones its initial Store snapshot"
        );
        if recover_first {
            gov.hydrate_budgets(&app.cost, now).unwrap();
            records
                .put_usage(
                    id,
                    0,
                    &UsageLedger {
                        requests: 13,
                        ..Default::default()
                    },
                )
                .unwrap();
            assert_eq!(
                gov.usage_for(&app.cost, id, now).unwrap().unwrap().requests,
                11,
                "the recovery boot explicitly installs the fresh snapshot before serving"
            );
        }
    }
}
