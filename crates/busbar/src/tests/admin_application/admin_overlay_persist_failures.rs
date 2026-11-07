// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::sync::Arc;

use crate::root::test_plugins as plugins;

use busbar_contract::persistence::*;
use std::sync::atomic::{AtomicBool, Ordering};
struct OverlayWriteOutage {
    actual: Arc<dyn PersistenceBackend>,
    armed: AtomicBool,
    failures: std::sync::atomic::AtomicUsize,
}
impl PersistenceBackend for OverlayWriteOutage {
    fn info(&self) -> BackendInfo {
        self.actual.info()
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.actual.clock(dataset)
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        self.actual.read(request)
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        self.actual.scan(request)
    }
    fn commit(&self, candidate: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async move {
            let overlay = candidate.candidate().mutations.iter().any(|mutation| {
                let key = match mutation {
                    Mutation::Put { address, .. } | Mutation::Delete(address) => &address.key,
                    Mutation::DeleteRange { prefix, .. } => prefix,
                };
                key.windows(b"busbar.config.overlay.v1".len())
                    .any(|part| part == b"busbar.config.overlay.v1")
            });
            if overlay && self.armed.load(Ordering::SeqCst) {
                self.failures.fetch_add(1, Ordering::SeqCst);
                return Err(Failure::Refused);
            }
            self.actual.commit(candidate).await
        })
    }
}

#[tokio::test]
async fn test_admin_v1_config_settings_persist_failure_does_not_install_limits() {
    const CHILD: &str = "BUSBAR_ADMIN_PERSIST_8E706DEE46E0";
    const WITNESS: &str = "actual root case test_admin_v1_config_settings_persist_failure_does_not_install_limits completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its exact test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root case"),
        );
        let until = std::time::Instant::now() + std::time::Duration::from_secs(90);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root child failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                std::time::Instant::now() < until,
                "the actual-root child timed out"
            );
            std::thread::park_timeout(std::time::Duration::from_millis(5));
        }
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::dist_root_install::install();
    let store_library = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory = plugins::scratch(
        "test_admin_v1_config_settings_persist_failure_does_not_install_limits-actual-store",
    );
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["plugins"] = crate::root::test_plugins::config_document(
        &crate::root::test_plugins::trusted_config(&directory),
    );
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let dir = directory.clone();
    let upstream_key = directory.join("provider-key");
    std::fs::write(&upstream_key, "unused-upstream-credential")
        .expect("write actual provider input");
    let protocol = busbar_kernel::plane_driver::dispatch::provider_dialects()
        .into_iter()
        .find(|protocol| *protocol == "openai")
        .expect("the actual linked OpenAI provider dialect");
    let definitions = std::collections::HashMap::from([(
        "test-provider".to_string(),
        serde_json::from_value::<busbar_kernel::config::ProviderDef>(serde_json::json!({
            "protocol": protocol, "base_url": "http://127.0.0.1:1/",
        }))
        .expect("actual provider definition"),
    )]);
    document["providers"] = serde_json::json!({"test-provider":{"api_key":{"file":upstream_key}}});
    document["models"] = serde_json::json!({"m0":{"provider":"test-provider","max_concurrent":4}});
    document["pools"] = serde_json::json!({"p":{"members":[{"model":"m0"}]}});
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(
        &providers_path,
        serde_json::to_vec_pretty(&definitions).unwrap(),
    )
    .unwrap();
    std::fs::write(&config_path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &definitions)
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .await
        .expect("the actual Store opens the configuration authority");
    let outage = Arc::new(OverlayWriteOutage {
        actual: anchor,
        armed: AtomicBool::new(false),
        failures: std::sync::atomic::AtomicUsize::new(0),
    });
    let anchor = crate::root::real_store::core_over(outage.clone()).await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path.clone()), Some(providers_path)),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .await
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    assert!(
        app.store.record_hard_down_all_cells(
            0,
            "tripped before configuration change",
            busbar_kernel::store::now()
        ),
        "the actual destination-wide failure trips the configured m0 lane"
    );
    let app = crate::root::real_store::hydrated(Arc::new(app)).await;
    outage.armed.store(true, Ordering::SeqCst);
    let router = busbar_kernel::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let before = busbar_kernel::config::limits::installed();

    let rejected_cap: usize = 7_654_321;
    let put = reqwest::Client::new()
        .put(format!("http://{addr}/api/v1/admin/config/settings"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({ "limits": { "request_body_max_bytes": rejected_cap } }).to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        put.status().as_u16(),
        400,
        "the Store refusal must fail the persist step: {:?}",
        put.text().await
    );

    let after = busbar_kernel::config::limits::installed();
    assert_ne!(
        after.as_ref().map(|l| l.request_body_max_bytes),
        Some(rejected_cap),
        "a persist failure must leave the REJECTED config's limits uninstalled — the response just \
         claimed nothing was changed, and these are process-wide values the old (still-serving) App \
         reads through"
    );
    assert_eq!(
        after.map(|l| l.request_body_max_bytes),
        before.map(|l| l.request_body_max_bytes),
        "the limits installed before the rejected apply are the ones still installed after it"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        outage.failures.load(Ordering::SeqCst) > 0,
        "the rejection must cross the planted real Store overlay write failure"
    );
    let _ = handle.await;
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_config_settings_persist_failure_does_not_rotate_gov_credentials() {
    const CHILD: &str = "BUSBAR_ADMIN_PERSIST_5FD5D7D51822";
    const WITNESS: &str = "actual root case test_admin_v1_config_settings_persist_failure_does_not_rotate_gov_credentials completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its exact test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root case"),
        );
        let until = std::time::Instant::now() + std::time::Duration::from_secs(90);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root child failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                std::time::Instant::now() < until,
                "the actual-root child timed out"
            );
            std::thread::park_timeout(std::time::Duration::from_millis(5));
        }
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::dist_root_install::install();
    let store_library = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory = plugins::scratch(
        "test_admin_v1_config_settings_persist_failure_does_not_rotate_gov_credentials-actual-store",
    );
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let token_path = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&token_path, "admintok-v1").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["plugins"] = crate::root::test_plugins::config_document(
        &crate::root::test_plugins::trusted_config(&directory),
    );
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": token_path },
    });
    let dir = directory.clone();
    let upstream_key = directory.join("provider-key");
    std::fs::write(&upstream_key, "unused-upstream-credential")
        .expect("write actual provider input");
    let protocol = busbar_kernel::plane_driver::dispatch::provider_dialects()
        .into_iter()
        .find(|protocol| *protocol == "openai")
        .expect("the actual linked OpenAI provider dialect");
    let definitions = std::collections::HashMap::from([(
        "test-provider".to_string(),
        serde_json::from_value::<busbar_kernel::config::ProviderDef>(serde_json::json!({
            "protocol": protocol, "base_url": "http://127.0.0.1:1/",
        }))
        .expect("actual provider definition"),
    )]);
    document["providers"] = serde_json::json!({"test-provider":{"api_key":{"file":upstream_key}}});
    document["models"] = serde_json::json!({"m0":{"provider":"test-provider","max_concurrent":4}});
    document["pools"] = serde_json::json!({"p":{"members":[{"model":"m0"}]}});
    let config_path = dir.join("config.json");
    let providers_path = dir.join("providers.json");
    std::fs::write(
        &providers_path,
        serde_json::to_vec_pretty(&definitions).unwrap(),
    )
    .unwrap();
    std::fs::write(&config_path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &definitions)
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .await
        .expect("the actual Store opens the configuration authority");
    let outage = Arc::new(OverlayWriteOutage {
        actual: anchor,
        armed: AtomicBool::new(false),
        failures: std::sync::atomic::AtomicUsize::new(0),
    });
    let anchor = crate::root::real_store::core_over(outage.clone()).await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path.clone()), Some(providers_path)),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .await
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    assert!(
        app.store.record_hard_down_all_cells(
            0,
            "tripped before configuration change",
            busbar_kernel::store::now()
        ),
        "the actual destination-wide failure trips the configured m0 lane"
    );
    let gov = app
        .governance
        .as_ref()
        .expect("actual root governance")
        .clone();
    let before_hash = gov.admin_token_hash();
    let app = crate::root::real_store::hydrated(Arc::new(app)).await;
    outage.armed.store(true, Ordering::SeqCst);
    let router = busbar_kernel::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    std::fs::write(&token_path, "admintok-v2").unwrap();

    let client = reqwest::Client::new();
    let put = client
        .put(format!("http://{addr}/api/v1/admin/config/settings"))
        .header("x-admin-token", "admintok-v1")
        .header("content-type", "application/json")
        .body(serde_json::json!({ "per_request_fee": 42 }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        put.status().as_u16(),
        400,
        "the Store refusal must fail the persist step: {:?}",
        put.text().await
    );

    assert_eq!(
        gov.admin_token_hash(),
        before_hash,
        "a persist failure must leave the shared GovState's admin-token digest untouched — the \
         response just claimed nothing was changed, and this is the process-lifetime object the \
         OLD (still-serving) App snapshot also points at"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        outage.failures.load(Ordering::SeqCst) > 0,
        "the rejection must cross the planted real Store overlay write failure"
    );
    let _ = handle.await;
    println!("{WITNESS}");
}
