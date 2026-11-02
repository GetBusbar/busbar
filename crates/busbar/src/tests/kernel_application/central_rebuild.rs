// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[test]
fn a_rebuild_carries_the_session_store_and_defaults_scan_off() {
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
    let directory = plugins::scratch("generation-rebuild");
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
    let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
        Arc::new(crate::root::door_steps::Rules::default());
    let (prior, rotate, limits) = busbar_kernel::build_app_from_config(
        busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the same product deployment resolves"),
        plugin_busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the same product deployment resolves"),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("boot");
    limits.keep().expect("the original limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    assert!(
        !prior.incremental_scan,
        "with BUSBAR_INCREMENTAL_SCAN unset the gate incremental scan must default OFF"
    );
    let (next, rotate, limits) = busbar_kernel::build_app_from_config(
        busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the same product deployment resolves"),
        plugin_busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the same product deployment resolves"),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        Some(&prior),
        &rules,
    )
    .expect("rebuild");
    limits.keep().expect("the rebuilt limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    assert!(
        std::sync::Arc::ptr_eq(&prior.session_store, &next.session_store),
        "an apply must carry the process-lifetime session substrate across the rebuild"
    );
}

#[test]
fn an_apply_carries_the_node_amendment_journal_its_governance_owns() {
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
    let directory = plugins::scratch("generation-rebuild");
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
    let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
        Arc::new(crate::root::door_steps::Rules::default());
    let (prior, rotate, limits) = busbar_kernel::build_app_from_config(
        busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the same product deployment resolves"),
        plugin_busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the same product deployment resolves"),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("boot");
    limits.keep().expect("the original limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let gov = prior
        .governance
        .clone()
        .expect("the boot builds governance");
    assert!(
        std::sync::Arc::ptr_eq(&prior.amendments, gov.amendments()),
        "the boot generation carries the journal its governance owns"
    );
    let (next, rotate, limits) = busbar_kernel::build_app_from_config(
        busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the same product deployment resolves"),
        plugin_busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the same product deployment resolves"),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        Some(&prior),
        &rules,
    )
    .expect("apply");
    limits.keep().expect("the rebuilt limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    assert!(
        std::sync::Arc::ptr_eq(&next.amendments, &prior.amendments),
        "an apply carries the prior generation's journal, never a new one"
    );
    let next_gov = next.governance.clone().expect("the apply keeps governance");
    assert!(
        std::sync::Arc::ptr_eq(&next.amendments, next_gov.amendments()),
        "and it is still the journal governance owns"
    );
}

#[test]
fn a_rejected_config_leaves_no_limits_behind() {
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
    let directory = plugins::scratch("rejected-limits");
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

    const ILLEGAL: usize = 4096;

    const _: () = assert!(ILLEGAL < busbar_kernel::config::REQUEST_BODY_MAX_BYTES_FLOOR);

    let mut cfg = config;
    cfg.limits.request_body_max_bytes = ILLEGAL;

    let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
        Arc::new(crate::root::door_steps::Rules::default());
    let Err(err) = busbar_kernel::build_app_from_config(
        cfg,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    ) else {
        panic!("a below-floor body cap must fail validation")
    };
    assert!(
        err.contains("request_body_max_bytes"),
        "the build failed for the expected reason: {err}"
    );
    assert_ne!(
        busbar_kernel_egress::upstream::max_translate_body_bytes(),
        ILLEGAL,
        "the REJECTED config's limits are installed process-wide — an invalid apply changed the \
         live signed-ingress and cross-protocol translate body caps"
    );
}
