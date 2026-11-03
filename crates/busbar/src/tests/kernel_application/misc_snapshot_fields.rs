// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel as kernel;
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[test]
fn the_actual_builder_wires_the_snapshot_ownership_fields() {
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
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "snapshot-fields-{}",
        kernel::door::op_id().counter()
    ));
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
    let deploy = kernel::config::deploy_from_deserializer(serde_json::json!({
        "public_url": "https://assembly.example",
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules =
        Arc::new(crate::root::door_steps::Rules::default()) as Arc<dyn kernel::appbuild::RootRules>;
    let (app, rotate, limits) = kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the host deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    assert!(Arc::ptr_eq(&app.root_rules, &rules));
    assert_eq!(app.public_url.as_deref(), Some("https://assembly.example"));
    assert_eq!(
        app.config_version, 0,
        "the normally built boot snapshot has version zero"
    );
    let governance = app
        .governance
        .as_ref()
        .expect("the actual Store owns governance");
    assert!(Arc::ptr_eq(&app.amendments, governance.amendments()));
    let counter = app.request_id_counter.clone();
    let journal = app.amendments.clone();
    let cloned = app.clone();
    assert!(Arc::ptr_eq(&cloned.request_id_counter, &counter));
    assert!(Arc::ptr_eq(&cloned.amendments, &journal));
    let before = counter.load(Ordering::Relaxed);
    assert_eq!(cloned.next_request_id(), before);
    assert_eq!(counter.load(Ordering::Relaxed), before.wrapping_add(1));
}
