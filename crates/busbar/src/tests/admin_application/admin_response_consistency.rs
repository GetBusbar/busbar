// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::root::test_plugins as plugins;

#[tokio::test]
async fn admin_responses_are_private_and_snapshot_consistent() {
    const CHILD: &str = "BUSBAR_ADMIN_RESPONSE_CONTRACTS_CHILD";
    const WITNESS: &str =
        "actual root case admin_responses_are_private_and_snapshot_consistent completed";
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
    let directory = plugins::scratch("admin-response-contracts-actual-store");
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
    let upstream_key = directory.join("provider-key");
    std::fs::write(&upstream_key, "unused-upstream-credential").expect("write provider input");
    let protocol = busbar_kernel::plane_driver::dispatch::provider_dialects()
        .into_iter()
        .find(|protocol| *protocol == "openai")
        .expect("the actual distribution declares its linked OpenAI provider dialect");
    let definitions = std::collections::HashMap::from([(
        "test-provider".to_string(),
        serde_json::from_value::<busbar_kernel::config::ProviderDef>(serde_json::json!({
            "protocol": protocol,
            "base_url": "http://127.0.0.1:1",
        }))
        .expect("the actual provider definition parses"),
    )]);
    document["providers"] = serde_json::json!({
        "test-provider": { "api_key": { "file": upstream_key } },
    });
    document["models"] = serde_json::json!({ "test-model": { "provider": "test-provider" } });
    document["pools"] = serde_json::json!({ "pa": { "members": [{ "model": "test-model" }] } });
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &definitions)
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("the actual Store opens the configuration authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(
        anchor
            .calls
            .as_ref()
            .cloned()
            .expect("the actual Store exposes typed calls"),
    )
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
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(Arc::new(app)));
    let swap_on_capture = Arc::new(AtomicBool::new(false));
    let replace_pending = Arc::new(AtomicBool::new(false));
    let observer: Arc<dyn Fn() + Send + Sync> = {
        let handle = handle.clone();
        let swap_on_capture = swap_on_capture.clone();
        let replace_pending = replace_pending.clone();
        Arc::new(move || {
            if swap_on_capture.swap(false, Ordering::SeqCst) {
                let mut later = (*handle.load()).clone();
                later.config_version += 1;
                if replace_pending.swap(false, Ordering::SeqCst) {
                    busbar_kernel::config::overlay::persist_named_map(
                        later.overlay_path.as_deref(),
                        busbar_kernel::config::named_map::NamedMapSection::Export,
                        "pending-entry",
                        Some(&serde_json::json!({"module":"pending-after", "settings":[]})),
                    )
                    .unwrap();
                }
                if let Some(group) = later.groups_registry.get_mut("snapshot-group") {
                    group.enabled = false;
                }
                handle.swap(Arc::new(later));
            }
        })
    };
    let router = busbar_kernel::router::build_admin_router_on(&handle, 2048, false).layer(
        axum::middleware::from_fn(move |request, next: axum::middleware::Next| {
            let observer = observer.clone();
            async move {
                busbar_core_admin::v1::json::with_response_snapshot_observer(
                    observer,
                    next.run(request),
                )
                .await
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let root = format!("http://{address}/api/v1/admin");

    async fn checked(response: reqwest::Response, status: u16) -> serde_json::Value {
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["content-type"], "application/json");
        response.json().await.unwrap()
    }

    let mint = || {
        client
            .post(format!("{root}/keys"))
            .bearer_auth("admintok")
            .header("idempotency-key", "private-mint")
            .json(&serde_json::json!({"name": "private-key"}))
    };
    let minted = checked(mint().send().await.unwrap(), 201).await;
    assert!(minted["token"]
        .as_str()
        .is_some_and(|token| !token.is_empty()));
    let replayed = checked(mint().send().await.unwrap(), 201).await;
    assert_eq!(replayed, minted);
    let id = minted["id"].as_str().unwrap();
    let rotate = || {
        client
            .post(format!("{root}/keys/{id}/rotate"))
            .bearer_auth("admintok")
            .header("idempotency-key", "private-rotate")
            .json(&serde_json::json!({}))
    };
    let rotated = checked(rotate().send().await.unwrap(), 200).await;
    assert!(rotated["token"]
        .as_str()
        .is_some_and(|token| !token.is_empty()));
    assert_eq!(checked(rotate().send().await.unwrap(), 200).await, rotated);

    for path in ["/keys/%FF", "/hooks/%FF", "/config/versions/%FF"] {
        let body = checked(
            client
                .get(format!("{root}{path}"))
                .bearer_auth("admintok")
                .send()
                .await
                .unwrap(),
            400,
        )
        .await;
        assert_eq!(body["error"]["code"], "invalid_request");
        assert_eq!(body["error"]["message"], "malformed admin request");
    }
    let malformed = checked(
        client
            .post(format!("{root}/groups"))
            .bearer_auth("admintok")
            .json(&serde_json::json!({"name": "g", "config": "PRIVATE_REQUEST_SENTINEL"}))
            .send()
            .await
            .unwrap(),
        400,
    )
    .await;
    assert_eq!(malformed["error"]["code"], "invalid_request");
    assert!(!malformed.to_string().contains("PRIVATE_REQUEST_SENTINEL"));
    let too_large = checked(
        client
            .post(format!("{root}/groups"))
            .bearer_auth("admintok")
            .body("x".repeat(4096))
            .send()
            .await
            .unwrap(),
        413,
    )
    .await;
    assert_eq!(too_large["error"]["code"], "request_too_large");
    let denied = checked(
        client
            .get(format!("{root}/config"))
            .bearer_auth("wrong-token")
            .send()
            .await
            .unwrap(),
        401,
    )
    .await;
    assert_eq!(denied["error"]["code"], "unauthorized");

    // The task-local observer runs after capture but before projection. The real listener sends
    // the old generation even though another publication has already replaced the live handle.
    let before = handle.load().config_version;
    swap_on_capture.store(true, Ordering::SeqCst);
    let response = client
        .get(format!("{root}/config"))
        .bearer_auth("admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["etag"], format!("\"{before}\""));
    let config = checked(response, 200).await;
    assert_eq!(config["version"], before);
    assert_eq!(handle.load().config_version, before + 1);
    assert!(!swap_on_capture.load(Ordering::SeqCst), "capture hook ran");

    // A second generation changes the committed group's value before its mutation echo renders.
    // The echo must remain a successful receipt of the installed value and installed ETag.
    let before = handle.load().config_version;
    swap_on_capture.store(true, Ordering::SeqCst);
    let response = client
        .post(format!("{root}/groups"))
        .bearer_auth("admintok")
        .json(&serde_json::json!({"name": "snapshot-group", "config": {"enabled": true}}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["etag"], format!("\"{}\"", before + 1));
    let installed = checked(response, 201).await;
    assert_eq!(installed["name"], "snapshot-group");
    assert_eq!(installed["enabled"], true);
    assert_eq!(handle.load().config_version, before + 2);
    assert!(!handle.load().groups_registry["snapshot-group"].enabled);
    assert!(!swap_on_capture.load(Ordering::SeqCst));

    // Repeated GETs also retain the captured group definition rather than the later live one.
    for path in ["/groups", "/groups/snapshot-group"] {
        let mut current = (*handle.load()).clone();
        current.config_version += 1;
        current
            .groups_registry
            .get_mut("snapshot-group")
            .unwrap()
            .enabled = true;
        let before = current.config_version;
        handle.swap(Arc::new(current));
        swap_on_capture.store(true, Ordering::SeqCst);
        let response = client
            .get(format!("{root}{path}"))
            .bearer_auth("admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(response.headers()["etag"], format!("\"{before}\""));
        let body = checked(response, 200).await;
        let group = if path == "/groups" {
            body["items"]
                .as_array()
                .unwrap()
                .iter()
                .find(|group| group["name"] == "snapshot-group")
                .unwrap()
        } else {
            &body
        };
        assert_eq!(group["enabled"], true);
        assert!(!handle.load().groups_registry["snapshot-group"].enabled);
        assert!(!swap_on_capture.load(Ordering::SeqCst));
    }
    // Even the malformed desired-overlay fallback is captured before the response projects.
    let section = busbar_kernel::config::named_map::NamedMapSection::Export;
    for item in [false, true] {
        let current = handle.load();
        busbar_kernel::config::overlay::persist_named_map(
            current.overlay_path.as_deref(),
            section,
            "pending-entry",
            Some(&serde_json::json!({"module":"pending-before", "settings":[]})),
        )
        .unwrap();
        let before = current.config_version;
        let path = if item {
            format!("{}/pending-entry", section.path_root())
        } else {
            section.path_root().into_owned()
        };
        replace_pending.store(true, Ordering::SeqCst);
        swap_on_capture.store(true, Ordering::SeqCst);
        let response = client
            .get(format!("{root}{path}"))
            .bearer_auth("admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(response.headers()["etag"], format!("\"{before}\""));
        let body = checked(response, 200).await;
        let entry = if item {
            &body
        } else {
            body["items"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["name"] == "pending-entry")
                .unwrap()
        };
        assert_eq!(entry["module"], "pending-before");
        assert_eq!(handle.load().config_version, before + 1);
        let pending = busbar_kernel::config::overlay::unparseable_named_map_entries(
            handle.load().overlay_path.as_deref(),
            section,
        )
        .unwrap();
        assert_eq!(pending["pending-entry"].raw["module"], "pending-after");
        assert!(!replace_pending.load(Ordering::SeqCst));
    }
    server.abort();
    let _ = server.await;
    println!("{WITNESS}");
}
