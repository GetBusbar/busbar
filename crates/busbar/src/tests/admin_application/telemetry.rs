// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::root::test_plugins as plugins;
use std::collections::HashSet;
use std::sync::Arc;
const TOKEN: &str = "admintok";

struct Scratch(std::path::PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn isolated() -> bool {
    const CHILD: &str = "BUSBAR_TELEMETRY_ROOT_CHILD";
    if std::env::var_os(CHILD).is_some() {
        return false;
    }
    let name = std::thread::current().name().unwrap().to_owned();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &name, "--nocapture"])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    true
}

async fn application() -> (Arc<busbar_kernel::state::App>, Scratch) {
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
    let directory = plugins::scratch("telemetry-admin-actual-store");
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
    std::fs::write(&signing_key, hex::encode([7u8; 32])).expect("write the test signing input");
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
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .await
        .expect("the actual Store opens the configuration authority");
    let anchor = crate::root::real_store::core_over(anchor).await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
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
    let app = Arc::new(app);
    busbar_kernel::boot::hydrate_all(&app)
        .await
        .expect("the actual Store hydrates");
    (app, Scratch(directory))
}

#[tokio::test]
async fn telemetry_is_an_admin_read_protected_by_the_operator_door() {
    if isolated() {
        return;
    }
    assert_eq!(
        busbar_core_admin::required_scope(busbar_core_admin::KernelVerb::GetTelemetry),
        busbar_core_admin::VerbScope::ReadOnly
    );
    let (app, _scratch) = application().await;
    let router = busbar_core_admin::build_router(app);
    use tower::ServiceExt as _;
    for bearer in [None, Some("wrong")] {
        let request = axum::http::Request::builder().uri("/api/v1/admin/telemetry");
        let request = match bearer {
            Some(token) => request.header("authorization", format!("Bearer {token}")),
            None => request,
        };
        let response = router
            .clone()
            .oneshot(request.body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), 401);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["code"], "unauthorized");
    }
    let response = router
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/admin/telemetry")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        503,
        "authorized request reaches the unavailable source"
    );
}

#[tokio::test]
async fn telemetry_http_route_reads_the_bounded_source_after_admin_authorization() {
    if isolated() {
        return;
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(60));
    let (app, _scratch) = application().await;
    let router = busbar_core_admin::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let url = format!("http://{addr}/api/v1/admin/telemetry");
    for bearer in [None, Some("wrong")] {
        let request = client.get(&url);
        let request = match bearer {
            Some(token) => request.bearer_auth(token),
            None => request,
        };
        let answer = request.send().await.unwrap();
        assert_eq!(answer.status(), 401);
        assert_eq!(
            answer.json::<serde_json::Value>().await.unwrap()["error"]["code"],
            "unauthorized"
        );
    }
    let mut nonce = None;
    let mut uptime = 0;
    for _ in 0..2 {
        let answer = client.get(&url).bearer_auth(TOKEN).send().await.unwrap();
        assert_eq!(answer.status(), 200);
        assert_eq!(answer.headers()["cache-control"], "no-store");
        let bytes = answer.bytes().await.unwrap();
        assert!(bytes.len() <= 65_536);
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(body["identities"].as_array().unwrap().len() <= 32);
        let observed_nonce = body["process_boot_nonce"].as_str().unwrap();
        assert_eq!(observed_nonce.len(), 32);
        assert!(observed_nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        if let Some(prior) = &nonce {
            assert_eq!(prior, observed_nonce);
        }
        nonce = Some(observed_nonce.to_string());
        let next_uptime = body["uptime_since_start_ms"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert!(next_uptime >= uptime);
        uptime = next_uptime;
        assert!(
            body["captured_at_unix_ms"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                > 0
        );
        assert_eq!(body["upper_bounds_ms"].as_array().unwrap().len(), 16);
    }
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn info_process_generation_is_available_without_metrics_and_changes_on_restart() {
    const CHILD: &str = "BUSBAR_TEST_INFO_PROCESS_GENERATION";
    const MARKER: &str = "BUSBAR_INFO_PROCESS_NONCE=";
    if std::env::var_os(CHILD).is_none() {
        let full = concat!(
            module_path!(),
            "::info_process_generation_is_available_without_metrics_and_changes_on_restart"
        );
        let (_, name) = full.split_once("::").unwrap();
        let mut nonces = Vec::new();
        for _ in 0..2 {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", name, "--nocapture"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8(output.stdout).unwrap();
            nonces.push(
                stdout
                    .split_whitespace()
                    .find_map(|word| word.strip_prefix(MARKER))
                    .expect("the real child completed its assertions")
                    .to_string(),
            );
        }
        assert_ne!(
            nonces[0], nonces[1],
            "two actual processes must not reuse their generation"
        );
        return;
    }
    assert!(!busbar_kernel::snapshot::recorder_installed());
    let (app, _scratch) = application().await;
    let (_, router, handle) =
        busbar_core_admin::build_split_routers_with_limits(app, 64 * 1024, 16, false);
    assert!(!busbar_kernel::snapshot::recorder_installed());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let info_url = format!("http://{addr}/api/v1/admin/info");
    let info = client
        .get(&info_url)
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(info.status(), 200);
    let info: serde_json::Value = info.json().await.unwrap();
    let nonce = info["process_boot_nonce"]
        .as_str()
        .expect("native OS randomness is available")
        .to_string();
    assert_eq!(nonce.len(), 32);
    assert!(nonce
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    assert!(
        !busbar_kernel::snapshot::recorder_installed(),
        "info must not enable metrics"
    );
    assert!(busbar_kernel::snapshot::request_snapshot(32).is_none());
    let telemetry_url = format!("http://{addr}/api/v1/admin/telemetry");
    assert_eq!(
        client
            .get(&telemetry_url)
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    let mut next = (*handle.load()).clone();
    next.config_version += 1;
    handle.swap(Arc::new(next)).await;
    let reloaded: serde_json::Value = client
        .get(&info_url)
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(reloaded["process_boot_nonce"], nonce);
    assert_eq!(
        reloaded["config_version"].as_u64().unwrap(),
        info["config_version"].as_u64().unwrap() + 1
    );
    assert!(!busbar_kernel::snapshot::recorder_installed());
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(60));
    let telemetry = client
        .get(&telemetry_url)
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(telemetry.status(), 200);
    let telemetry: serde_json::Value = telemetry.json().await.unwrap();
    assert_eq!(telemetry["process_boot_nonce"], nonce);
    let again: serde_json::Value = client
        .get(&info_url)
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(again["process_boot_nonce"], nonce);
    server.abort();
    let _ = server.await;
    println!("{MARKER}{nonce}");
}
