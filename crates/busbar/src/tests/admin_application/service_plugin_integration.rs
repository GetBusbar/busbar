// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::root::test_plugins as plugins;
use base64::Engine as _;
use busbar_kernel::admission::{Admitted, Inventoried, Judged, PluginAdmission, Refusal, Stated};
use busbar_kernel::config::PluginsCfg;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

pub(super) fn trust_document(config: &PluginsCfg) -> serde_json::Value {
    let publishers: Vec<_> = config.trust.publishers.iter().map(|publisher| {
        serde_json::json!({"name": publisher.name, "public_key": publisher.public_key})
    }).collect();
    serde_json::json!({
        "publishers": publishers,
        "allow_unsigned": config.trust.allow_unsigned,
        "allow_third_party": config.trust.allow_third_party,
    })
}

fn fixture_config_document(directory: &Path) -> serde_json::Value {
    let config = crate::root::test_plugins::trusted_config(directory);
    let fetch: Vec<_> = config
        .fetch_targets()
        .expect("fixture archive URLs resolve")
        .iter()
        .map(|target| serde_json::json!({"url": target.url, "sha256": target.sha256}))
        .collect();
    serde_json::json!({
        "enabled": true, "dir": directory,
        "trust": trust_document(&config), "fetch": fetch,
    })
}

struct InventoryReads {
    actual: &'static dyn PluginAdmission,
    scans: AtomicUsize,
    panic: AtomicBool,
    block_publish: AtomicBool,
    gate: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    entered: tokio::sync::Notify,
}
impl PluginAdmission for InventoryReads {
    fn bootstrap_probe_selected(
        &self,
        bytes: &[u8],
        path: &Path,
        urls: &[String],
    ) -> Result<bool, Refusal> {
        self.actual.bootstrap_probe_selected(bytes, path, urls)
    }
    fn is_tarball(&self, file: &str) -> bool {
        self.actual.is_tarball(file)
    }
    fn max_tarball_bytes(&self) -> u64 {
        self.actual.max_tarball_bytes()
    }
    fn restart_default(&self, kind: &str) -> bool {
        self.actual.restart_default(kind)
    }
    fn policy_resolves(&self, cfg: &PluginsCfg) -> Result<(), String> {
        self.actual.policy_resolves(cfg)
    }
    fn inventory(&self, dir: &Path, cfg: &PluginsCfg) -> Result<Vec<Inventoried>, String> {
        self.scans.fetch_add(1, Ordering::SeqCst);
        assert!(
            !self.panic.swap(false, Ordering::SeqCst),
            "the actual inventory worker panics at its fault boundary"
        );
        let gate = self.gate.lock().unwrap().take();
        if let Some(gate) = gate {
            self.entered.notify_one();
            gate.recv_timeout(std::time::Duration::from_secs(12))
                .expect("the actual inventory is released within its bound");
        }
        self.actual.inventory(dir, cfg)
    }
    fn admit_upload(
        &self,
        dir: &Path,
        file: &str,
        bytes: &[u8],
        cfg: &PluginsCfg,
    ) -> Result<Admitted, Refusal> {
        let admitted = self.actual.admit_upload(dir, file, bytes, cfg)?;
        if self.block_publish.swap(false, Ordering::SeqCst) {
            std::fs::remove_dir(dir).expect("the actual admitted directory was empty");
            std::fs::write(dir, b"keep this file")
                .expect("place the bounded filesystem fault after genuine admission");
        }
        Ok(admitted)
    }
    fn inspect(&self, bytes: &[u8], cfg: &PluginsCfg) -> Result<(Stated, Judged), Refusal> {
        self.actual.inspect(bytes, cfg)
    }
    fn rollback_target(
        &self,
        file: &str,
        bytes: &[u8],
        cfg: &PluginsCfg,
    ) -> Result<Stated, Refusal> {
        self.actual.rollback_target(file, bytes, cfg)
    }
}

#[tokio::test]
async fn install_answers_the_admissions_refusals_in_their_classes() {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let store = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid");
    let module = store.name;
    let module_version = store.version;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.version = module_version.clone();
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "admin-service-plugin-policy-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest.clone(),
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), &archive)
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
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
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual configured Store binds rate history before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();

    let before: std::collections::BTreeSet<_> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    let malformed = client.post(format!("http://{addr}/api/v1/admin/plugins")).header("x-admin-token", "admintok").json(&serde_json::json!({"file":"x.tar.gz", "tarball_b64":base64::engine::general_purpose::STANDARD.encode(b"garbage, not a tarball")})).send().await.unwrap();
    assert_eq!(malformed.status().as_u16(), 400);
    let error: serde_json::Value = malformed.json().await.unwrap();
    assert_eq!(error["error"]["code"], "invalid_request");
    assert!(error["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("invalid plugin tarball"));
    let rejected = plugins::seal(manifest, &library);
    let response = client.post(format!("http://{addr}/api/v1/admin/plugins")).header("x-admin-token", "admintok").json(&serde_json::json!({"file":"x.tar.gz", "tarball_b64":base64::engine::general_purpose::STANDARD.encode(&rejected)})).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 409);
    let error: serde_json::Value = response.json().await.unwrap();
    assert_eq!(error["error"]["code"], "conflict");
    assert!(error["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("plugin rejected by the trust policy"));
    let after: std::collections::BTreeSet<_> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(after, before, "refusals publish no archive");

    server.abort();
}

#[tokio::test]
async fn install_catalog_remove_roundtrip() {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let store = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid");
    let module = store.name;
    let module_version = store.version;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.version = module_version.clone();
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "admin-service-plugin-policy-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest.clone(),
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), &archive)
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
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
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual configured Store binds rate history before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    std::fs::remove_file(directory.join("store.tar.gz")).unwrap();
    app.plugins_cfg.trust.allow_unsigned = true;
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();

    let upload_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_BOOTSTRAP_TEST_STORE_PLUGIN").expect(
            "BUSBAR_BOOTSTRAP_TEST_STORE_PLUGIN names the actual distinct SQLite Store cdylib",
        ),
    );
    let upload_statement = busbar_plugin_loader::dispatch::rendering_of_library(&upload_path)
        .expect("the actual upload Store statement reads")
        .expect("the upload Store exports its Statement");
    let upload = busbar_contract::abi::mechanism::rendering::read(&upload_statement)
        .expect("the actual upload Store Statement is valid");
    assert_eq!(
        upload.kind,
        busbar_contract::abi::mechanism::KindCode::Store as u32
    );
    let upload_name = upload.name;
    assert_ne!(
        upload_name, module,
        "publication uses an actual distinct Store rather than a linked copy"
    );
    let library = std::fs::read(upload_path).expect("the actual upload Store library reads");
    manifest = plugins::manifest("store", &upload_name, "acme");
    manifest.version = upload.version;
    manifest.statement = Some(hex::encode(upload_statement));
    let tarball = plugins::seal(manifest, &library);
    let response = client.post(format!("http://{addr}/api/v1/admin/plugins")).header("x-admin-token", "admintok").json(&serde_json::json!({"file":"junk.tar.gz", "tarball_b64":base64::engine::general_purpose::STANDARD.encode(&tarball)})).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 201);
    let view: serde_json::Value = response.json().await.unwrap();
    assert_eq!(view["trust"], "unverified");
    assert_eq!(view["name"], upload_name);
    assert!(directory.join("junk.tar.gz").exists(), "tarball published");
    let response = client
        .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let catalog: serde_json::Value = response.json().await.unwrap();
    let row = catalog["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["loader"] == "dynamic-library")
        .expect("actual dynamic Store in catalog");
    assert_eq!(row["valid"], true);
    assert_eq!(row["name"], upload_name);
    assert_eq!(row["target"], "junk.tar.gz");
    assert_eq!(row["trust"], "unverified");
    let reloaded = client
        .post(format!("http://{addr}/api/v1/admin/plugins/reload"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(reloaded.status().as_u16(), 200);
    let reload: serde_json::Value = reloaded.json().await.unwrap();
    let rows = reload["plugins"].as_array().unwrap();
    assert!(rows.iter().all(|p| p["loader"] == "dynamic-library"));
    assert_eq!(rows.len(), 1);
    let response = client
        .delete(format!("http://{addr}/api/v1/admin/plugins/junk.tar.gz"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert!(!directory.join("junk.tar.gz").exists());
    let missing = client
        .delete(format!("http://{addr}/api/v1/admin/plugins/junk.tar.gz"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);

    server.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn remove_filesystem_failure_is_internal_error() {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let store = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid");
    let module = store.name;
    let module_version = store.version;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.version = module_version.clone();
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "admin-service-plugin-policy-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest.clone(),
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), &archive)
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
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
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual configured Store binds rate history before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();

    use std::os::unix::fs::PermissionsExt;
    struct RestorePermissions(std::path::PathBuf, std::fs::Permissions);
    impl Drop for RestorePermissions {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, self.1.clone());
        }
    }
    let file = directory.join("plugin.tar.gz");
    let probe = directory.join("unlink-probe");
    std::fs::write(&file, b"keep this plugin").unwrap();
    std::fs::write(&probe, b"probe").unwrap();
    let _restore = RestorePermissions(
        directory.clone(),
        std::fs::metadata(&directory).unwrap().permissions(),
    );
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o555)).unwrap();
    match std::fs::remove_file(&probe) {
        Ok(()) => {
            server.abort();
            eprintln!(
                "remove failure regression not exercised: runner bypasses directory mode bits"
            );
            return;
        }
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied),
    }
    assert!(file.is_file(), "the existing-file guard must pass");
    let response = client
        .delete(format!("http://{addr}/api/v1/admin/plugins/plugin.tar.gz"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 500);
    let error: serde_json::Value = response.json().await.unwrap();
    assert_eq!(error["error"]["code"], "internal");
    assert_eq!(std::fs::read(&file).unwrap(), b"keep this plugin");

    server.abort();
}

#[tokio::test]
async fn catalog_repeat_gets_reuse_the_cached_scan() {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let store = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid");
    let module = store.name;
    let module_version = store.version;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.version = module_version.clone();
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "admin-service-plugin-policy-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest.clone(),
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), &archive)
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
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
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual configured Store binds rate history before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let observed = Box::leak(Box::new(InventoryReads {
        actual: app
            .plugin_admission
            .expect("the actual root installs its admission"),
        scans: AtomicUsize::new(0),
        panic: AtomicBool::new(false),
        block_publish: AtomicBool::new(false),
        gate: std::sync::Mutex::new(None),
        entered: tokio::sync::Notify::new(),
    }));
    let observed: &'static InventoryReads = observed;
    app.plugin_admission = Some(observed);
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();

    for _ in 0..5 {
        let response = client
            .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        let view: serde_json::Value = response.json().await.unwrap();
        assert!(view["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == module && p["loader"] == "dynamic-library"));
    }
    assert_eq!(
        observed.scans.load(Ordering::SeqCst),
        1,
        "five unchanged GETs cost exactly one actual inventory scan"
    );
    let upload_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_BOOTSTRAP_TEST_STORE_PLUGIN").expect(
            "BUSBAR_BOOTSTRAP_TEST_STORE_PLUGIN names the actual distinct SQLite Store cdylib",
        ),
    );
    let upload_statement = busbar_plugin_loader::dispatch::rendering_of_library(&upload_path)
        .expect("the actual upload Store statement reads")
        .expect("the upload Store exports its Statement");
    let upload = busbar_contract::abi::mechanism::rendering::read(&upload_statement)
        .expect("the actual upload Store Statement is valid");
    assert_eq!(
        upload.kind,
        busbar_contract::abi::mechanism::KindCode::Store as u32
    );
    let upload_name = upload.name;
    assert_ne!(
        upload_name, module,
        "publication uses an actual distinct Store rather than a linked copy"
    );
    let library = std::fs::read(upload_path).expect("the actual upload Store library reads");
    let mut second = plugins::manifest(
        "store",
        &upload_name,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    second.version = upload.version;
    second.statement = Some(hex::encode(upload_statement));
    let tarball = plugins::signed(&crate::dist_root_install::release_key(), second, &library);
    let installed = client.post(format!("http://{addr}/api/v1/admin/plugins")).header("x-admin-token", "admintok").json(&serde_json::json!({"file":"cache2.tar.gz", "tarball_b64":base64::engine::general_purpose::STANDARD.encode(&tarball)})).send().await.unwrap();
    assert_eq!(installed.status().as_u16(), 201);
    let response = client
        .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    let view: serde_json::Value = response.json().await.unwrap();
    assert!(
        view["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == upload_name),
        "a newly installed plugin appears on the next GET"
    );
    assert_eq!(
        observed.scans.load(Ordering::SeqCst),
        2,
        "a real directory change costs exactly one more scan"
    );

    server.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn catalog_unreadable_dir_does_not_serve_stale_cache() {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let store = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid");
    let module = store.name;
    let module_version = store.version;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.version = module_version.clone();
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "admin-service-plugin-policy-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest.clone(),
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), &archive)
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
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
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual configured Store binds rate history before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let catalog_dir = directory.join("catalog");
    std::fs::create_dir(&catalog_dir).unwrap();
    app.plugins_dir = catalog_dir.clone();
    let observed = Box::leak(Box::new(InventoryReads {
        actual: app
            .plugin_admission
            .expect("the actual root installs its admission"),
        scans: AtomicUsize::new(0),
        panic: AtomicBool::new(false),
        block_publish: AtomicBool::new(false),
        gate: std::sync::Mutex::new(None),
        entered: tokio::sync::Notify::new(),
    }));
    let observed: &'static InventoryReads = observed;
    app.plugin_admission = Some(observed);
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();

    let first = client
        .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    let view: serde_json::Value = first.json().await.unwrap();
    assert!(view["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|p| p["loader"] != "dynamic-library"));
    assert_eq!(
        observed.scans.load(Ordering::SeqCst),
        1,
        "the empty real scan is cached"
    );
    std::fs::remove_dir(&catalog_dir).unwrap();
    std::fs::write(&catalog_dir, b"not a directory").unwrap();
    assert!(std::fs::read_dir(&catalog_dir).is_err());
    let mut errors = Vec::new();
    for _ in 0..2 {
        let response = client
            .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        let view: serde_json::Value = response.json().await.unwrap();
        let row = view["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["loader"] == "dynamic-library")
            .expect("an unreadable real directory surfaces an invalid row");
        assert_eq!(row["valid"], false);
        assert!(row["error"].as_str().unwrap().starts_with("INVALID:"));
        errors.push(row["error"].clone());
    }
    assert_eq!(errors[0], errors[1]);
    assert_eq!(
        observed.scans.load(Ordering::SeqCst),
        3,
        "neither unreadable read serves the empty cached scan"
    );

    server.abort();
}

#[tokio::test]
async fn list_plugins_store_single_flights_concurrent_misses() {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let store = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid");
    let module = store.name;
    let module_version = store.version;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.version = module_version.clone();
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "admin-service-plugin-policy-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest.clone(),
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), &archive)
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
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
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual configured Store binds rate history before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let observed = Box::leak(Box::new(InventoryReads {
        actual: app
            .plugin_admission
            .expect("the actual root installs its admission"),
        scans: AtomicUsize::new(0),
        panic: AtomicBool::new(false),
        block_publish: AtomicBool::new(false),
        gate: std::sync::Mutex::new(None),
        entered: tokio::sync::Notify::new(),
    }));
    let observed: &'static InventoryReads = observed;
    app.plugin_admission = Some(observed);
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();

    let mut requests = Vec::new();
    for _ in 0..10 {
        let client = client.clone();
        requests.push(tokio::spawn(async move {
            let response = client
                .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), 200);
            response.json::<serde_json::Value>().await.unwrap()
        }));
    }
    for request in requests {
        let page = request.await.unwrap();
        assert!(
            page["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["loader"] == "dynamic-library" && p["name"] == module),
            "each of ten concurrent callers sees the actual complete Store catalog"
        );
    }
    assert_eq!(
        observed.scans.load(Ordering::SeqCst),
        1,
        "ten concurrent misses cost exactly one actual inventory"
    );

    server.abort();
}

#[tokio::test]
async fn store_plugin_catalog_async_survives_a_spawn_blocking_panic() {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let store = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid");
    let module = store.name;
    let module_version = store.version;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.version = module_version.clone();
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "admin-service-plugin-policy-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest.clone(),
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), &archive)
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
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
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual configured Store binds rate history before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let observed = Box::leak(Box::new(InventoryReads {
        actual: app
            .plugin_admission
            .expect("the actual root installs its admission"),
        scans: AtomicUsize::new(0),
        panic: AtomicBool::new(false),
        block_publish: AtomicBool::new(false),
        gate: std::sync::Mutex::new(None),
        entered: tokio::sync::Notify::new(),
    }));
    let observed: &'static InventoryReads = observed;
    app.plugin_admission = Some(observed);
    observed.panic.store(true, Ordering::SeqCst);
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();

    let response = client
        .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status().as_u16(),
        200,
        "a panicking blocking scan falls back gracefully"
    );
    let view: serde_json::Value = response.json().await.unwrap();
    let rows = view["items"].as_array().unwrap();
    let stores = busbar_kernel::preflight::root_rows().stores;
    assert_eq!(
        rows.len(),
        stores.len(),
        "fallback contains exactly the actual linked Store rows"
    );
    for (row, store) in rows.iter().zip(stores) {
        assert_eq!(row["name"], store.0);
        assert_eq!(row["loader"], "compiled-in");
    }
    assert_eq!(observed.scans.load(Ordering::SeqCst), 1);

    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn list_plugins_store_scan_does_not_park_the_reactor() {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let store = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid");
    let module = store.name;
    let module_version = store.version;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.version = module_version.clone();
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "admin-service-plugin-policy-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest.clone(),
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), &archive)
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
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
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual configured Store binds rate history before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    for i in 0..2000 {
        std::fs::write(
            directory.join(format!("p{i}.tar.gz")),
            b"a deliberately malformed archive",
        )
        .unwrap();
    }
    let observed = Box::leak(Box::new(InventoryReads {
        actual: app
            .plugin_admission
            .expect("the actual root installs its admission"),
        scans: AtomicUsize::new(0),
        panic: AtomicBool::new(false),
        block_publish: AtomicBool::new(false),
        gate: std::sync::Mutex::new(None),
        entered: tokio::sync::Notify::new(),
    }));
    let observed: &'static InventoryReads = observed;
    app.plugin_admission = Some(observed);
    let (release, blocked) = std::sync::mpsc::channel();
    *observed.gate.lock().unwrap() = Some(blocked);
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();

    let scanner_client = client.clone();
    let scanner = tokio::spawn(async move {
        let response = scanner_client
            .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        response.json::<serde_json::Value>().await.unwrap()
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        observed.entered.notified(),
    )
    .await
    .expect("the actual scan enters on its blocking worker");
    let start = std::time::Instant::now();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let elapsed = start.elapsed();
    release.send(()).unwrap();
    assert!(
        elapsed < std::time::Duration::from_millis(300),
        "a 50ms sibling timer took {elapsed:?} while the real inventory was blocked"
    );
    let page = scanner.await.unwrap();
    assert!(
        page["items"].as_array().unwrap().len() > 2000,
        "the actual inventory returned all rows"
    );

    server.abort();
}

#[tokio::test]
async fn store_plugin_catalog_async_times_out_when_gate_is_held() {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let store = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid");
    let module = store.name;
    let module_version = store.version;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.version = module_version.clone();
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "admin-service-plugin-policy-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest.clone(),
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), &archive)
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
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
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual configured Store binds rate history before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let observed = Box::leak(Box::new(InventoryReads {
        actual: app
            .plugin_admission
            .expect("the actual root installs its admission"),
        scans: AtomicUsize::new(0),
        panic: AtomicBool::new(false),
        block_publish: AtomicBool::new(false),
        gate: std::sync::Mutex::new(None),
        entered: tokio::sync::Notify::new(),
    }));
    let observed: &'static InventoryReads = observed;
    app.plugin_admission = Some(observed);
    let (release, blocked) = std::sync::mpsc::channel();
    *observed.gate.lock().unwrap() = Some(blocked);
    let request_entered = Arc::new(tokio::sync::Notify::new());
    let entering = request_entered.clone();
    let router = busbar_kernel::build_router(Arc::new(app)).layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let entering = entering.clone();
            async move {
                entering.notify_one();
                next.run(request).await
            }
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();

    let first_client = client.clone();
    let first = tokio::spawn(async move {
        first_client
            .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        observed.entered.notified(),
    )
    .await
    .expect("the genuine scan owns the production gate");
    request_entered.notified().await;
    let waiting_client = client.clone();
    let waiting = tokio::spawn(async move {
        waiting_client
            .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        request_entered.notified(),
    )
    .await
    .expect("the second real HTTP handler enters and waits behind the scan");
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(5) + std::time::Duration::from_millis(1))
        .await;
    tokio::time::resume();
    let response = waiting.await.expect("the caller must not panic");
    assert_eq!(
        response.status().as_u16(),
        503,
        "the genuine shared scan gate returns a bounded retryable refusal"
    );
    let error: serde_json::Value = response.json().await.unwrap();
    assert_eq!(error["error"]["code"], "unavailable");
    release.send(()).unwrap();
    assert_eq!(first.await.unwrap().status().as_u16(), 200);

    server.abort();
}

#[tokio::test]
async fn the_store_catalog_heads_with_the_linked_store_rows() {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let store = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid");
    let module = store.name;
    let module_version = store.version;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.version = module_version.clone();
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "admin-service-plugin-policy-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest.clone(),
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), &archive)
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
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
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual configured Store binds rate history before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();

    let response = client
        .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let view: serde_json::Value = response.json().await.unwrap();
    let catalog = view["items"].as_array().unwrap();
    let linked = busbar_kernel::preflight::root_rows().stores;
    assert!(
        !linked.is_empty(),
        "the assembled distribution links a Store row"
    );
    let head: Vec<_> = catalog[..linked.len()]
        .iter()
        .map(|p| {
            (
                p["name"].as_str().unwrap(),
                p["type"].as_str().unwrap(),
                p["loader"].as_str().unwrap(),
                p.get("active").and_then(serde_json::Value::as_bool),
            )
        })
        .collect();
    let want: Vec<_> = linked
        .iter()
        .map(|s| (s.0, "store", "compiled-in", None))
        .collect();
    assert_eq!(head, want);

    server.abort();
}

#[tokio::test]
async fn validate_config_pins_the_scan_to_the_running_plugins_dir() {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let store = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid");
    let module = store.name;
    let module_version = store.version;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.version = module_version.clone();
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "admin-service-plugin-policy-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest.clone(),
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), &archive)
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
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
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual configured Store binds rate history before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let evil_dir = directory.join("evil");
    std::fs::create_dir(&evil_dir).unwrap();
    std::fs::write(evil_dir.join("probe.tar.gz"), b"not a real tarball").unwrap();
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();

    let mut candidate = document;
    candidate["plugins"] = serde_json::json!({"enabled":true, "dir":evil_dir});
    let response = client
        .post(format!("http://{addr}/api/v1/admin/config/validate"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"config":candidate}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let view: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        view["ok"], true,
        "the caller's garbage plugins.dir must not be scanned; errors: {:?}",
        view["errors"]
    );

    server.abort();
}

#[tokio::test]
async fn validate_config_waits_on_the_plugin_scan_gate_and_runs_off_the_reactor() {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let store = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid");
    let module = store.name;
    let module_version = store.version;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.version = module_version.clone();
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "admin-service-plugin-policy-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest.clone(),
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), &archive)
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
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
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual configured Store binds rate history before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let observed = Box::leak(Box::new(InventoryReads {
        actual: app
            .plugin_admission
            .expect("the actual root installs its admission"),
        scans: AtomicUsize::new(0),
        panic: AtomicBool::new(false),
        block_publish: AtomicBool::new(false),
        gate: std::sync::Mutex::new(None),
        entered: tokio::sync::Notify::new(),
    }));
    let observed: &'static InventoryReads = observed;
    app.plugin_admission = Some(observed);
    let (release, blocked) = std::sync::mpsc::channel();
    *observed.gate.lock().unwrap() = Some(blocked);
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();

    let scanner_client = client.clone();
    let scanner = tokio::spawn(async move {
        scanner_client
            .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        observed.entered.notified(),
    )
    .await
    .expect("the genuine scan owns the production gate");
    let validator_client = client.clone();
    let mut candidate = document;
    candidate["plugins"] = fixture_config_document(&directory);
    let validator = tokio::spawn(async move {
        validator_client
            .post(format!("http://{addr}/api/v1/admin/config/validate"))
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"config":candidate}))
            .send()
            .await
            .unwrap()
    });
    let started = std::time::Instant::now();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        started.elapsed() < std::time::Duration::from_millis(300),
        "the reactor remains free while both real calls await the scan"
    );
    assert!(
        !validator.is_finished(),
        "validate must wait behind the actual production plugin scan gate"
    );
    release.send(()).unwrap();
    assert_eq!(scanner.await.unwrap().status().as_u16(), 200);
    let response = validator.await.expect("the caller must not panic");
    assert_eq!(response.status().as_u16(), 200);
    let view: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        view["ok"], true,
        "the verdict is unchanged: {:?}",
        view["errors"]
    );

    server.abort();
}

#[tokio::test]
async fn every_admin_trust_moment_resolves_through_the_snapshots_builder() {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let store = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid");
    let module = store.name;
    let module_version = store.version;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.version = module_version.clone();
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "admin-service-plugin-policy-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest.clone(),
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), &archive)
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
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
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual configured Store binds rate history before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let calls = app
        .governance
        .as_ref()
        .expect("actual governance")
        .store_calls()
        .expect("actual Store calls");
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(calls)
        .expect("the actual Store opens its overlay");
    app.overlay_path = Some(overlay.clone());
    app.plugins_cfg
        .trust
        .publishers
        .push(busbar_kernel::config::PluginPublisher {
            name: "acme".into(),
            public_key: "not-an-ed25519-public-key".into(),
        });
    let refusal = app
        .plugin_admission
        .expect("the actual root admission")
        .policy_resolves(&app.plugins_cfg)
        .expect_err("the actual policy refuses a malformed publisher key");
    let mut no_admission = app.clone();
    no_admission.plugin_admission = None;
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();

    let request = serde_json::json!({"file":"p.tar.gz", "tarball_b64":base64::engine::general_purpose::STANDARD.encode(&archive)});
    for endpoint in ["plugins/inspect", "plugins"] {
        let response = client
            .post(format!("http://{addr}/api/v1/admin/{endpoint}"))
            .header("x-admin-token", "admintok")
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 400);
        let error: serde_json::Value = response.json().await.unwrap();
        assert_eq!(
            error["error"]["message"], refusal,
            "{endpoint} uses the actual snapshot's invalid trust posture"
        );
    }
    let response = client
        .post(format!("http://{addr}/api/v1/admin/plugins/rollback"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"file":"store.tar.gz"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 400);
    let error: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        error["error"]["message"], refusal,
        "rollback resolves through the same actual snapshot policy"
    );
    let response = client
        .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let view: serde_json::Value = response.json().await.unwrap();
    assert!(
        view["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["loader"] == "compiled-in"),
        "unresolvable policy lists linked rows alone"
    );
    let router = busbar_kernel::build_router(Arc::new(no_admission));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let other_addr = listener.local_addr().unwrap();
    let other_server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let response = client.post(format!("http://{other_addr}/api/v1/admin/plugins")).header("x-admin-token", "admintok").json(&serde_json::json!({"file":"plain.tar.gz", "tarball_b64":base64::engine::general_purpose::STANDARD.encode(&archive)})).send().await.unwrap();
    assert_eq!(
        response.status().as_u16(),
        400,
        "filename validation refuses a snapshot without a production admission"
    );
    let error: serde_json::Value = response.json().await.unwrap();
    assert!(error["error"]["message"]
        .as_str()
        .unwrap()
        .contains("no plugin trust policy is installed"));
    other_server.abort();

    server.abort();
}

#[tokio::test]
async fn rollback_reads_the_target_and_merges_pins() {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let store = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid");
    let module = store.name;
    let module_version = store.version;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.version = module_version.clone();
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "admin-service-plugin-policy-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest.clone(),
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), &archive)
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
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
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual configured Store binds rate history before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let publisher_key = plugins::key(67);
    let publisher = busbar_kernel::config::PluginPublisher {
        name: "acme".into(),
        public_key: hex::encode(publisher_key.verifying_key().to_bytes()),
    };
    app.plugins_cfg.trust.publishers.push(publisher);
    document["plugins"] = serde_json::json!({"enabled":true, "dir":directory, "trust":trust_document(&app.plugins_cfg)});
    let config_path = directory.join("config.yaml");
    let providers_path = directory.join("providers.yaml");
    std::fs::write(&config_path, serde_yaml::to_string(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, "{}\n").unwrap();
    app.config_path = Some(config_path);
    app.providers_path = Some(providers_path);
    let calls = app
        .governance
        .as_ref()
        .expect("actual governance")
        .store_calls()
        .expect("actual Store calls");
    let overlay =
        busbar_kernel::config::overlay::OverlayStore::new(calls).expect("actual Store overlay");
    let prior =
        std::collections::BTreeMap::from([("other-plugin".to_string(), "3.0.0".to_string())]);
    busbar_kernel::config::overlay::try_persist_plugin_versions(Some(&overlay), &prior)
        .expect("the prior plugin pin persists in the actual Store");
    app.overlay_path = Some(overlay.clone());
    std::fs::remove_file(directory.join("store.tar.gz")).unwrap();
    manifest.publisher = "acme".into();
    manifest.version = module_version.clone();
    let target = plugins::signed(&publisher_key, manifest.clone(), &library);
    std::fs::write(directory.join("old.tar.gz"), target).unwrap();
    let rejected = plugins::seal(manifest, &library);
    std::fs::write(directory.join("unsigned.tar.gz"), rejected).unwrap();
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();

    let absent = client
        .post(format!("http://{addr}/api/v1/admin/plugins/rollback"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"file":"nope.tar.gz"}))
        .send()
        .await
        .unwrap();
    assert_eq!(absent.status().as_u16(), 404);
    let untrusted = client
        .post(format!("http://{addr}/api/v1/admin/plugins/rollback"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"file":"unsigned.tar.gz"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        untrusted.status().as_u16(),
        409,
        "rollback must never launder an untrusted actual archive"
    );
    std::fs::remove_file(directory.join("unsigned.tar.gz")).unwrap();
    let response = client
        .post(format!("http://{addr}/api/v1/admin/plugins/rollback"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"file":"old.tar.gz"}))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let view: serde_json::Value = response.json().await.unwrap();
    assert_eq!(status, 200, "the actual trusted target rolls back: {view}");
    assert_eq!(view["name"], module);
    assert_eq!(view["version"], module_version);
    let persisted = overlay
        .read_required()
        .expect("the actual overlay reads")
        .expect("the actual overlay exists");
    assert_eq!(
        persisted.plugin_versions.get(&module).map(String::as_str),
        Some(module_version.as_str()),
        "the actual target version is pinned"
    );
    assert_eq!(
        persisted
            .plugin_versions
            .get("other-plugin")
            .map(String::as_str),
        Some("3.0.0"),
        "the prior unrelated pin is preserved"
    );

    server.abort();
}

#[tokio::test]
async fn install_filesystem_failures_are_internal_errors() {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let store = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid");
    let module = store.name;
    let module_version = store.version;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.version = module_version.clone();
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "admin-service-plugin-policy-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest.clone(),
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), &archive)
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
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
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual configured Store binds rate history before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let base_app = app.clone();
    let publish_dir = directory.join("publish");
    std::fs::create_dir(&publish_dir).unwrap();
    std::fs::create_dir(publish_dir.join("plugin.tar.gz")).unwrap();
    app.plugins_dir = publish_dir.clone();
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();

    let upload_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_BOOTSTRAP_TEST_STORE_PLUGIN").expect(
            "BUSBAR_BOOTSTRAP_TEST_STORE_PLUGIN names the actual distinct SQLite Store cdylib",
        ),
    );
    let upload_statement = busbar_plugin_loader::dispatch::rendering_of_library(&upload_path)
        .expect("the actual upload Store statement reads")
        .expect("the upload Store exports its Statement");
    let upload = busbar_contract::abi::mechanism::rendering::read(&upload_statement)
        .expect("the actual upload Store Statement is valid");
    assert_eq!(
        upload.kind,
        busbar_contract::abi::mechanism::KindCode::Store as u32
    );
    let upload_name = upload.name;
    assert_ne!(
        upload_name, module,
        "publication uses an actual distinct Store rather than a linked copy"
    );
    let library = std::fs::read(upload_path).expect("the actual upload Store library reads");
    manifest = plugins::manifest(
        "store",
        &upload_name,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.version = upload.version;
    manifest.statement = Some(hex::encode(upload_statement));
    let tarball = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    let malformed = client.post(format!("http://{addr}/api/v1/admin/plugins")).header("x-admin-token", "admintok").json(&serde_json::json!({"file":"plugin.tar.gz", "tarball_b64":base64::engine::general_purpose::STANDARD.encode(b"not a tarball")})).send().await.unwrap();
    assert_eq!(malformed.status().as_u16(), 400);
    let error: serde_json::Value = malformed.json().await.unwrap();
    assert_eq!(error["error"]["code"], "invalid_request");
    let response = client.post(format!("http://{addr}/api/v1/admin/plugins")).header("x-admin-token", "admintok").json(&serde_json::json!({"file":"plugin.tar.gz", "tarball_b64":base64::engine::general_purpose::STANDARD.encode(&tarball)})).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 500);
    let error: serde_json::Value = response.json().await.unwrap();
    assert_eq!(error["error"]["code"], "internal");
    assert_eq!(error["error"]["message"], "internal error");
    assert!(publish_dir.join("plugin.tar.gz").is_dir());
    assert_eq!(std::fs::read_dir(&publish_dir).unwrap().count(), 1);
    let blocked_dir = directory.join("not-a-directory");
    std::fs::create_dir(&blocked_dir).unwrap();
    let observed = Box::leak(Box::new(InventoryReads {
        actual: base_app
            .plugin_admission
            .expect("the actual root admission"),
        scans: AtomicUsize::new(0),
        panic: AtomicBool::new(false),
        block_publish: AtomicBool::new(false),
        gate: std::sync::Mutex::new(None),
        entered: tokio::sync::Notify::new(),
    }));
    observed.block_publish.store(true, Ordering::SeqCst);
    let mut blocked_app = base_app.clone();
    blocked_app.plugins_dir = blocked_dir.clone();
    blocked_app.plugin_admission = Some(observed);
    let router = busbar_kernel::build_router(Arc::new(blocked_app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let blocked_addr = listener.local_addr().unwrap();
    let blocked_server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let malformed = client.post(format!("http://{blocked_addr}/api/v1/admin/plugins")).header("x-admin-token", "admintok").json(&serde_json::json!({"file":"plugin.tar.gz", "tarball_b64":base64::engine::general_purpose::STANDARD.encode(b"not a tarball")})).send().await.unwrap();
    assert_eq!(
        malformed.status().as_u16(),
        400,
        "malformed input wins before any filesystem publication"
    );
    assert!(
        blocked_dir.is_dir(),
        "a refused real admission does not inject a publication failure"
    );
    let response = client.post(format!("http://{blocked_addr}/api/v1/admin/plugins")).header("x-admin-token", "admintok").json(&serde_json::json!({"file":"plugin.tar.gz", "tarball_b64":base64::engine::general_purpose::STANDARD.encode(&tarball)})).send().await.unwrap();
    assert_eq!(
        response.status().as_u16(),
        500,
        "create_dir_all fails on the actual regular-file path after genuine admission"
    );
    let error: serde_json::Value = response.json().await.unwrap();
    assert_eq!(error["error"]["code"], "internal");
    assert_eq!(error["error"]["message"], "internal error");
    assert_eq!(std::fs::read(&blocked_dir).unwrap(), b"keep this file");
    blocked_server.abort();
    std::fs::remove_file(directory.join("store.tar.gz")).unwrap();
    let router = busbar_kernel::build_router(Arc::new(base_app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let success_server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let response = client.post(format!("http://{addr}/api/v1/admin/plugins")).header("x-admin-token", "admintok").json(&serde_json::json!({"file":"ok.tar.gz", "tarball_b64":base64::engine::general_purpose::STANDARD.encode(&tarball)})).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 201);
    assert_eq!(std::fs::read(directory.join("ok.tar.gz")).unwrap(), tarball);
    let response = client
        .delete(format!("http://{addr}/api/v1/admin/plugins/ok.tar.gz"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let missing = client
        .delete(format!("http://{addr}/api/v1/admin/plugins/ok.tar.gz"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);
    let error: serde_json::Value = missing.json().await.unwrap();
    assert_eq!(error["error"]["code"], "not_found");
    success_server.abort();

    server.abort();
}
