// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use axum::http::StatusCode;
use busbar_kernel::config::overlay::OverlayStore;
use std::sync::Arc;
use std::time::{Duration, Instant};
const BASE_FEE: i64 = 0;
const CANDIDATE_BODY_CAP: usize = 5_000_123;
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;
async fn put(addr: std::net::SocketAddr, fee: i64) -> reqwest::Response {
    reqwest::Client::new().put(format!("http://{addr}/api/v1/admin/config/settings"))
        .json(&serde_json::json!({"per_request_fee": fee, "limits": {"request_body_max_bytes": CANDIDATE_BODY_CAP}}))
        .send().await.unwrap()
}
async fn reload(addr: std::net::SocketAddr) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/config/reload"))
        .send()
        .await
        .unwrap()
}
fn stored_fee(backend: &OverlayStore) -> Option<i64> {
    backend
        .read_required()
        .unwrap()
        .and_then(|doc| doc.root)
        .and_then(|root| root.per_request_fee)
}
#[tokio::test]
async fn an_absent_card_and_unchanged_prices_allow_a_successful_settings_handler() {
    const CHILD: &str = "BUSBAR_ADMIN_PRICE_ACTIVATION_CHILD";
    const WITNESS: &str = "actual root overlay refusal assertions completed";
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
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
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
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
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
    let directory = plugins::scratch("admin-store-overlay");
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
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["plugins"] = serde_json::json!({"enabled": true, "dir": directory.to_string_lossy()});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
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
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let dir = directory.clone();
    let config_path = dir.join("config.yaml");
    let providers_path = dir.join("providers.yaml");
    std::fs::write(&config_path, serde_yaml::to_string(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, "{}\n").unwrap();
    app.config_path = Some(config_path.clone());
    app.providers_path = Some(providers_path);
    let calls = app
        .governance
        .as_ref()
        .unwrap()
        .store_calls()
        .expect("actual Store calls");
    crate::root::kernel::ROOT_CARD.keep_in_store(calls.clone(), 103);
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .expect("actual rate history boots");
    let overlay =
        busbar_kernel::config::overlay::OverlayStore::new(calls).expect("actual Store overlay");
    app.overlay_path = Some(overlay.clone());
    let (_data, admin, handle) =
        busbar_kernel::build_split_routers_with_limits(Arc::new(app), 1 << 20, 0, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, admin).await });
    let before = handle.load();
    assert_eq!(put(addr, BASE_FEE).await.status(), StatusCode::OK);
    assert!(!Arc::ptr_eq(&handle.load(), &before));
    assert_eq!(stored_fee(&overlay), Some(BASE_FEE));
    assert_eq!(
        busbar_kernel::config::limits::installed().map(|limits| limits.request_body_max_bytes),
        Some(CANDIDATE_BODY_CAP)
    );
    let next = handle.load();
    assert_eq!(reload(addr).await.status(), StatusCode::OK);
    assert!(!Arc::ptr_eq(&handle.load(), &next));
    server.abort();
    println!("{WITNESS}");
}
