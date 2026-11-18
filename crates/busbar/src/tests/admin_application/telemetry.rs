// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::json::JsonContainerTrait as _;
use std::collections::HashSet;
use std::sync::Arc;

use busbar_contract::json::{self, JsonValueTrait};
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
    application_with_native_keys(false).await
}

async fn application_with_native_keys(
    native_keys: bool,
) -> (Arc<busbar_kernel::state::App>, Scratch) {
    let (module, directory, settings) =
        crate::distribution::rig::actual_store("telemetry-admin-actual-store");
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([7u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    if native_keys {
        document["auth"]["admin_auth"] = json::json!([operator, "keys"]);
    }
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let crate::root::min3_boot::fixture::Admitted {
        core: anchor,
        rules,
    } = crate::root::min3_boot::fixture::open(&config, &plugin_config, rules.clone())
        .await
        .expect("the actual Store opens the configuration authority")
        .admit()
        .await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        crate::root::test_plugins::plaintext_listeners(config),
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

#[path = "metrics_authorization.rs"]
mod metrics_authorization;

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
    let info = json::parse_value(&info.bytes().await.unwrap()).unwrap();
    let nonce = info["incarnation"]
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
    let mut next = (*handle.load()).clone();
    next.config_version += 1;
    handle.swap(Arc::new(next)).await;
    let reloaded = json::parse_value(
        &client
            .get(&info_url)
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(reloaded["incarnation"], nonce);
    assert!(!busbar_kernel::snapshot::recorder_installed());
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(60));
    let again = json::parse_value(
        &client
            .get(&info_url)
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(again["incarnation"], nonce);
    server.abort();
    let _ = server.await;
    println!("{MARKER}{nonce}");
}

#[tokio::test]
async fn admin_metrics_without_export() {
    if isolated() {
        return;
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(60));
    let (app, _scratch) = application().await;
    let router = busbar_core_admin::build_router(app);
    use tower::ServiceExt as _;
    let get = |accept: Option<&str>, bearer: Option<&str>, path: &str| {
        let mut request = axum::http::Request::builder().uri(path.to_owned());
        if let Some(accept) = accept {
            request = request.header("accept", accept);
        }
        if let Some(token) = bearer {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        request.body(axum::body::Body::empty()).unwrap()
    };
    for path in ["/metrics", "/metrics/hooks"] {
        let response = router.clone().oneshot(get(None, None, path)).await.unwrap();
        assert_eq!(response.status(), 401, "{path} is behind the admin door");
    }

    let response = router
        .clone()
        .oneshot(get(None, Some(TOKEN), "/metrics"))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(response.headers()["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/plain; version=0.0.4"));
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 22)
        .await
        .unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(
        text.contains("# TYPE busbar_build_info gauge\n"),
        "no export plugin is configured and the registry is still on:\n{text}"
    );
    assert!(text.contains(&format!(
        "busbar_build_info{{version=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION")
    )));

    let response = router
        .clone()
        .oneshot(get(
            Some("application/openmetrics-text"),
            Some(TOKEN),
            "/metrics",
        ))
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 22)
        .await
        .unwrap();
    assert!(bytes.ends_with(b"# EOF\n"));

    let response = router
        .oneshot(get(Some("application/json"), Some(TOKEN), "/metrics"))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 22)
        .await
        .unwrap();
    let body = json::parse_value(&bytes).unwrap();
    assert!(body["families"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["name"] == "busbar_build_info" && f["type"] == "gauge"));
}
