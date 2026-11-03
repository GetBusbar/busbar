// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use busbar_kernel::plane_driver::EngineHost;

use crate::root::test_plugins as plugins;

static ATTACHED: AtomicUsize = AtomicUsize::new(0);

fn count_attach(host: &Arc<dyn EngineHost>) {
    assert!(Arc::downgrade(host).upgrade().is_some());
    ATTACHED.fetch_add(1, Ordering::SeqCst);
}

#[test]
fn every_swap_re_attaches_the_probers_the_root_bound() {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
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
    let directory = plugins::scratch("app-handle-swap");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the swap deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let handle = busbar_kernel::state::AppHandle::new(Arc::clone(&app));
    let before = ATTACHED.load(Ordering::SeqCst);
    handle.swap(Arc::new((*app).clone()));
    assert_eq!(
        ATTACHED.load(Ordering::SeqCst),
        before,
        "nothing was bound, so nothing ran"
    );

    handle.attach_on_swap(count_attach);
    handle.swap(Arc::new((*app).clone()));
    handle.swap(Arc::new((*app).clone()));
    assert_eq!(
        ATTACHED.load(Ordering::SeqCst),
        before + 2,
        "each swap re-attaches the probers to the generation that replaced theirs"
    );
}
