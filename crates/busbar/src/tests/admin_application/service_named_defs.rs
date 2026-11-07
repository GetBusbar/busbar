// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::root::test_plugins as plugins;
use busbar_contract::persistence::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

struct OverlayReads {
    actual: Arc<dyn PersistenceBackend>,
    fail: AtomicBool,
    started: AtomicBool,
    gate: std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    entered: tokio::sync::Notify,
}
impl PersistenceBackend for OverlayReads {
    fn info(&self) -> BackendInfo {
        self.actual.info()
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.actual.clock(dataset)
    }
    fn commit(&self, candidate: PreparedCandidate) -> Call<'_, Decision> {
        self.actual.commit(candidate)
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        self.actual.scan(request)
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            let head = busbar_kernel::persistence::scoped::migration_address(
                true,
                "busbar.config.overlay",
                "busbar.config.overlay.v1",
                b"head",
            )
            .unwrap();
            if request.addresses.contains(&head) {
                if self.fail.load(Ordering::SeqCst) {
                    return Err(Failure::Unavailable);
                }
                let gate = self.gate.lock().unwrap().take();
                if let Some(gate) = gate {
                    self.started.store(true, Ordering::SeqCst);
                    self.entered.notify_one();
                    tokio::time::timeout(std::time::Duration::from_secs(6), gate)
                        .await
                        .expect("the actual read is released within its bound")
                        .unwrap();
                }
            }
            self.actual.read(request).await
        })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn list_named_defs_reads_the_overlay_off_the_async_worker() {
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
    let directory = plugins::scratch(&format!(
        "admin-service-named-defs-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator_token = directory.join("operator-token");
    let signing_key = directory.join("signing-key");
    std::fs::write(&operator_token, "admintok").unwrap();
    std::fs::write(&signing_key, hex::encode([9u8; 32])).unwrap();
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "groups": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": {"file": signing_key} },
        "identity-providers": {},
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["identity-providers"][operator] =
        serde_json::json!({"module": operator, "token": {"file": operator_token}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let actual = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .await
        .expect("the configured native backend opens");
    let faults = Arc::new(OverlayReads {
        actual,
        fail: AtomicBool::new(false),
        started: AtomicBool::new(false),
        gate: std::sync::Mutex::new(None),
        entered: tokio::sync::Notify::new(),
    });
    let core = crate::root::real_store::core_over(faults.clone()).await;
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(core.clone()),
        false,
    )
    .await
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds the node book and rate history before activation");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let backend = busbar_kernel::config::overlay::OverlayStore::from_core(core)
        .expect("actual Store overlay");
    app.overlay_path = Some(backend.clone());
    let (release, gate) = tokio::sync::oneshot::channel::<()>();
    *faults.gate.lock().unwrap() = Some(gate);
    let (done, finished) = std::sync::mpsc::channel::<()>();
    let watching = faults.clone();
    let watchdog = std::thread::spawn(move || {
        let free = finished
            .recv_timeout(std::time::Duration::from_secs(5))
            .is_ok();
        let _ = release.send(());
        free && watching.started.load(Ordering::SeqCst)
    });
    let waiting = faults.clone();
    let sibling = tokio::spawn(async move {
        waiting.entered.notified().await;
        let _ = done.send(());
    });
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let root = busbar_kernel::config::named_map::NamedMapSection::Export.path_root();
    let response = client
        .get(format!("http://{addr}/api/v1/admin{root}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let page: serde_json::Value = response.json().await.unwrap();
    assert!(page["items"].as_array().unwrap().is_empty(), "{page}");
    assert!(
        watchdog.join().unwrap(),
        "the sibling task progressed while the actual overlay read awaited its native backend"
    );
    sibling.abort();
    let _ = sibling.await;
    server.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn get_named_def_reads_the_overlay_off_the_async_worker() {
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
    let directory = plugins::scratch(&format!(
        "admin-service-named-defs-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator_token = directory.join("operator-token");
    let signing_key = directory.join("signing-key");
    std::fs::write(&operator_token, "admintok").unwrap();
    std::fs::write(&signing_key, hex::encode([9u8; 32])).unwrap();
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "groups": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": {"file": signing_key} },
        "identity-providers": {},
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["identity-providers"][operator] =
        serde_json::json!({"module": operator, "token": {"file": operator_token}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let actual = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .await
        .expect("the configured native backend opens");
    let faults = Arc::new(OverlayReads {
        actual,
        fail: AtomicBool::new(false),
        started: AtomicBool::new(false),
        gate: std::sync::Mutex::new(None),
        entered: tokio::sync::Notify::new(),
    });
    let core = crate::root::real_store::core_over(faults.clone()).await;
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(core.clone()),
        false,
    )
    .await
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds the node book and rate history before activation");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let backend = busbar_kernel::config::overlay::OverlayStore::from_core(core)
        .expect("actual Store overlay");
    app.overlay_path = Some(backend.clone());
    let (release, gate) = tokio::sync::oneshot::channel::<()>();
    *faults.gate.lock().unwrap() = Some(gate);
    let (done, finished) = std::sync::mpsc::channel::<()>();
    let watching = faults.clone();
    let watchdog = std::thread::spawn(move || {
        let free = finished
            .recv_timeout(std::time::Duration::from_secs(5))
            .is_ok();
        let _ = release.send(());
        free && watching.started.load(Ordering::SeqCst)
    });
    let waiting = faults.clone();
    let sibling = tokio::spawn(async move {
        waiting.entered.notified().await;
        let _ = done.send(());
    });
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let root = busbar_kernel::config::named_map::NamedMapSection::Export.path_root();
    let response = client
        .get(format!("http://{addr}/api/v1/admin{root}/absent"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 404);
    let error: serde_json::Value = response.json().await.unwrap();
    assert_eq!(error["error"]["code"], "not_found");
    assert!(
        watchdog.join().unwrap(),
        "the sibling task progressed while the actual overlay read awaited its native backend"
    );
    sibling.abort();
    let _ = sibling.await;
    server.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn named_defs_still_flag_an_unparseable_overlay_entry() {
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
    let directory = plugins::scratch(&format!(
        "admin-service-named-defs-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator_token = directory.join("operator-token");
    let signing_key = directory.join("signing-key");
    std::fs::write(&operator_token, "admintok").unwrap();
    std::fs::write(&signing_key, hex::encode([9u8; 32])).unwrap();
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "groups": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": {"file": signing_key} },
        "identity-providers": {},
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["identity-providers"][operator] =
        serde_json::json!({"module": operator, "token": {"file": operator_token}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let actual = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .await
        .expect("the configured native backend opens");
    let faults = Arc::new(OverlayReads {
        actual,
        fail: AtomicBool::new(false),
        started: AtomicBool::new(false),
        gate: std::sync::Mutex::new(None),
        entered: tokio::sync::Notify::new(),
    });
    let core = crate::root::real_store::core_over(faults.clone()).await;
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(core.clone()),
        false,
    )
    .await
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds the node book and rate history before activation");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let backend = busbar_kernel::config::overlay::OverlayStore::from_core(core)
        .expect("actual Store overlay");
    app.overlay_path = Some(backend.clone());
    busbar_kernel::config::overlay::persist_named_map_async(
        Some(&backend),
        busbar_kernel::config::named_map::NamedMapSection::Export,
        "broken",
        Some(&serde_json::json!({"no_such_field": true})),
    )
    .await
    .expect("the actual Store retains the unparseable definition");
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let root = busbar_kernel::config::named_map::NamedMapSection::Export.path_root();
    let response = client
        .get(format!("http://{addr}/api/v1/admin{root}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let page: serde_json::Value = response.json().await.unwrap();
    let names: Vec<&str> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["broken"], "the unparseable overlay entry is listed");
    let response = client
        .get(format!("http://{addr}/api/v1/admin{root}/broken"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let one: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        one, page["items"][0],
        "the list and the single read give the one flagged view"
    );
    server.abort();
}

#[tokio::test]
async fn named_defs_propagate_store_overlay_read_failures() {
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
    let directory = plugins::scratch(&format!(
        "admin-service-named-defs-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator_token = directory.join("operator-token");
    let signing_key = directory.join("signing-key");
    std::fs::write(&operator_token, "admintok").unwrap();
    std::fs::write(&signing_key, hex::encode([9u8; 32])).unwrap();
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "groups": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": {"file": signing_key} },
        "identity-providers": {},
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["identity-providers"][operator] =
        serde_json::json!({"module": operator, "token": {"file": operator_token}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let actual = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .await
        .expect("the configured native backend opens");
    let faults = Arc::new(OverlayReads {
        actual,
        fail: AtomicBool::new(false),
        started: AtomicBool::new(false),
        gate: std::sync::Mutex::new(None),
        entered: tokio::sync::Notify::new(),
    });
    let core = crate::root::real_store::core_over(faults.clone()).await;
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(core.clone()),
        false,
    )
    .await
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds the node book and rate history before activation");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let backend = busbar_kernel::config::overlay::OverlayStore::from_core(core)
        .expect("actual Store overlay");
    app.overlay_path = Some(backend.clone());
    faults.fail.store(true, Ordering::SeqCst);
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let root = busbar_kernel::config::named_map::NamedMapSection::Export.path_root();
    for suffix in ["", "/absent"] {
        let response = client
            .get(format!("http://{addr}/api/v1/admin{root}{suffix}"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 400);
        let error: serde_json::Value = response.json().await.unwrap();
        assert_eq!(error["error"]["code"], "invalid_request");
    }
    server.abort();
}
