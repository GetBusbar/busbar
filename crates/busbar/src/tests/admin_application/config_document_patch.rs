// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Real configured Store and HTTP coverage for the additive document-edit mode.

use crate::root::test_plugins as plugins;
use axum::http::StatusCode;
use busbar_contract::json::{self, JsonValueTrait as _, Value};
use busbar_kernel::config::overlay::OverlayStore;
use std::sync::Arc;
use std::time::{Duration, Instant};

const BASE_CAP: usize = 4_000_123;
const PATCH_CAP: usize = 5_000_123;
const TYPED_CAP: usize = 6_000_123;

fn patch(path: &str, value: Value) -> Value {
    let mut set = json::Map::new();
    set.insert(path, value);
    json::json!({"document_patch": {"set": set, "remove": []}})
}

async fn put(
    client: &reqwest::Client,
    endpoint: &str,
    version: u64,
    body: &Value,
) -> reqwest::Response {
    client
        .put(endpoint)
        .header("If-Match", format!("\"{version}\""))
        .json(body)
        .send()
        .await
        .expect("the actual admin endpoint responds")
}

async fn get(client: &reqwest::Client, endpoint: &str) -> Value {
    let response = client.get(endpoint).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    json::parse_value(&response.bytes().await.unwrap()).unwrap()
}

fn configured_cap(body: &Value) -> usize {
    body["configuration"]["values"]["sections"]["limits"]["request_body_max_bytes"]
        .as_u64()
        .expect("generation readback includes the configured body cap") as usize
}

#[tokio::test]
async fn document_patch_is_durable_conditional_and_preserves_hidden_base_configuration() {
    const CHILD: &str = "BUSBAR_ADMIN_DOCUMENT_PATCH_CHILD";
    const WITNESS: &str = "actual Store document patch assertions completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current().name().unwrap().to_owned();
        // Each actual node retains the production 10/minute Config budget. Split independent
        // refusal scenarios into fresh processes so all assertions run without clock-bound waits.
        for phase in [
            "persistence",
            "locking",
            "sequences",
            "source-drift",
            "source-init-absent",
            "source-init-null",
            "source-root-drift",
        ] {
            let mut child = Child(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", &name, "--nocapture"])
                    .env(CHILD, phase)
                    .env_remove("BUSBAR_WORKER_THREADS")
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .expect("start the isolated actual-root document patch test"),
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
                        "actual-root child failed: {status}: {output}"
                    );
                    assert!(
                        output.contains(WITNESS),
                        "exact child did not complete its assertions"
                    );
                    break;
                }
                assert!(
                    Instant::now() < until,
                    "actual-root document patch child timed out"
                );
                std::thread::park_timeout(Duration::from_millis(5));
            }
        }
        return;
    }

    let phase = std::env::var(CHILD).unwrap();
    assert!([
        "persistence",
        "locking",
        "sequences",
        "source-drift",
        "source-init-absent",
        "source-init-null",
        "source-root-drift"
    ]
    .contains(&phase.as_str()));
    crate::dist_root_install::install();
    let directory = plugins::scratch("admin-document-patch");
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _scratch = Scratch(directory.clone());
    let library_path = plugins::application_store_library();
    let module = crate::root::test_plugins::native_image(&library_path).name;
    let manifest = crate::root::test_plugins::native_manifest(
        "store",
        &library_path,
        plugins::FIXTURE_PUBLISHER,
    );
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(library_path).unwrap(),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).unwrap();
    let signing_key = directory.join("hidden-signing-reference");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).unwrap();
    let plugin_config = plugins::trusted_config(&directory);
    let mut document = serde_json::json!({
        "providers": {}, "models": {},
        "auth": {"chain": [], "admin_auth": [], "signing_key": {"file": signing_key}},
        "store": {"module": module, "settings": plugins::application_store_settings(&directory)},
        "plugins": plugins::config_document(&plugin_config),
        "limits": {"request_body_max_bytes": BASE_CAP},
        "advanced": {},
    });
    if phase == "sequences" || phase.starts_with("source-") {
        let key = directory.join("hidden-provider-key");
        std::fs::write(&key, "unused-provider-key").unwrap();
        document["providers"] = serde_json::json!({"spare": {"api_key": {"file": key}}});
        document["models"] = serde_json::json!({
            "a": {"provider": "spare"}, "b": {"provider": "spare"},
            "c": {"provider": "spare"}, "d": {"provider": "spare"},
        });
        document["pools"] = serde_json::json!({"work": {
            "members": [{"model": "a", "weight": 1}, {"model": "b", "weight": 2, "tags": ["hidden-routing-tag"]}],
            "hooks": ["weighted"],
        }});
    }
    if phase == "source-init-absent" {
        document["pools"]["work"]
            .as_object_mut()
            .unwrap()
            .remove("hooks");
    } else if phase == "source-init-null" {
        document["pools"]["work"]["hooks"] = serde_json::Value::Null;
    }
    let config_path = directory.join("config.yaml");
    let providers_path = directory.join("providers.yaml");
    // JSON text is a YAML subset; avoid serde_json arbitrary_precision's serializer-private
    // Number map when producing the operator file through a different data format.
    let base_bytes = serde_json::to_vec_pretty(&document).unwrap();
    std::fs::write(&config_path, &base_bytes).unwrap();
    let catalog_base = if phase == "sequences" || phase.starts_with("source-") {
        "spare:\n  protocol: openai\n  base_url: http://127.0.0.1:1/\n"
    } else {
        "spare:\n  protocol: openai\n  base_url: https://base.example.com\n"
    };
    std::fs::write(&providers_path, catalog_base).unwrap();
    let mut deploy = busbar_kernel::config::deploy_from_yaml_str(
        std::str::from_utf8(&base_bytes).unwrap(),
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the untouched operator file must independently pass the actual boot reader");
    deploy.document_source_fingerprints = Some(
        busbar_kernel::config::document_patch::SourceFingerprints::from_sources(
            std::str::from_utf8(&base_bytes).unwrap(),
            catalog_base,
        ),
    );
    let defs = busbar_kernel::config::providers::catalog_from_str(
        catalog_base,
        &crate::root::boot::axis_test_grammar(),
    )
    .unwrap();
    let config = busbar_kernel::config::resolve(&deploy, &defs).unwrap();
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let crate::root::min3_boot::fixture::Fixture {
        backend: anchor,
        rules,
    } = crate::root::min3_boot::fixture::open(&config, &plugin_config, rules.clone())
        .await
        .expect("the actual configured Store opens");
    let anchor = crate::root::real_store::core_over(anchor).await;
    let overlay = OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional config persistence");
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay.clone()),
        Default::default(),
        Default::default(),
        (Some(config_path.clone()), Some(providers_path.clone())),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .await
    .expect("the actual root builds the admin application");
    // This fixture models the executable with no explicit CLI/environment catalog override.
    app.providers_override = None;
    busbar_kernel::config::readback::ConfiguredView::capture_documents(&mut app, &deploy, &defs);
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("actual Store rate history boots");
    limits.keep().await.expect("actual boot limits activate");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let app = Arc::new(app);
    busbar_kernel::boot::hydrate_all(&app)
        .await
        .expect("the actual Store hydrates before writes");
    let (_data, admin, handle) =
        busbar_kernel::build_split_routers_with_limits(app, 1 << 20, 0, false);
    // Exercise the response projection through the same synchronous callback seam used by doors.
    if phase == "persistence" {
        handle.on_apply(Box::new(|app| {
            use busbar_kernel::state::activation::RefreshFailure;
            assert_eq!(app.plane_refresh.snapshot().phase, "observing");
            app.plane_refresh.record(
                "held-plane",
                "held-section",
                7,
                Some(RefreshFailure::BootstrapHeld),
            );
            app.plane_refresh.record(
                "failed-plane",
                "failed-section",
                9,
                Some(RefreshFailure::RefreshFailed),
            );
            app.plane_refresh
                .record("installed-plane", "installed-section", 11, None);
        }));
    }
    let boot_snapshot = handle.load();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, admin).await.unwrap() });
    let client = reqwest::Client::new();
    let endpoint = format!("http://{addr}/api/v1/admin/config/settings");
    let before = get(&client, &endpoint).await;
    let initial_version = before["config_version"].as_u64().unwrap();
    assert_eq!(configured_cap(&before), BASE_CAP);
    assert_eq!(before["settings"], json::json!({}));
    assert!(!json::to_string(&before)
        .unwrap()
        .contains("hidden-signing-reference"));

    if phase == "source-init-absent" || phase == "source-init-null" || phase == "source-root-drift"
    {
        document["pools"]["work"]["hooks"] = serde_json::json!(["fastest"]);
        let external = serde_json::to_vec_pretty(&document).unwrap();
        std::fs::write(&config_path, &external).unwrap();
        let stable = handle.load();
        let stable_bytes = overlay.read_bytes_async().await.unwrap();
        let requests = if phase == "source-root-drift" {
            vec![
                patch("/pools/work/hooks", json::json!(["weighted"])),
                patch("/pools/work/hooks", json::Value::new()),
                json::json!({"document_patch": {"remove": ["/pools/work/hooks"]}}),
                patch(
                    "/pools",
                    json::json!({"work": {"members": ["a"], "hooks": ["weighted"]}}),
                ),
                json::json!({"document_patch": {}, "reset_document_paths": ["/pools/work/hooks"]}),
            ]
        } else {
            vec![patch("/pools/work/hooks", json::json!(["weighted"]))]
        };
        for request in requests {
            let response = put(&client, &endpoint, initial_version, &request).await;
            let status = response.status();
            let text = response.text().await.unwrap();
            assert_eq!(
                status,
                StatusCode::CONFLICT,
                "source root drift must refuse {phase}: {text}"
            );
            assert!(Arc::ptr_eq(&stable, &handle.load()));
            assert_eq!(overlay.read_bytes_async().await.unwrap(), stable_bytes);
        }
        let reload = client
            .post(format!("http://{addr}/api/v1/admin/config/reload"))
            .send()
            .await
            .unwrap();
        let status = reload.status();
        let text = reload.text().await.unwrap();
        assert_eq!(status, StatusCode::OK, "source root recovery: {text}");
        let response = put(
            &client,
            &endpoint,
            handle.load().config_version,
            &patch("/pools/work/hooks", json::json!(["weighted"])),
        )
        .await;
        let status = response.status();
        let text = response.text().await.unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "source root write after reload: {text}"
        );
        let loaded = busbar_kernel::load_config_from_disk_with_store(
            &config_path,
            None,
            false,
            busbar_kernel::config::EnvSubst::Strict,
            &*rules,
            handle.load().overlay_path.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            loaded.deploy.pools.pools["work"].members[1].tags,
            vec!["hidden-routing-tag"]
        );
        assert_eq!(std::fs::read(&config_path).unwrap(), external);
        server.abort();
        let _ = server.await;
        println!("{WITNESS}");
        return;
    }

    if phase == "source-drift" {
        // An outside writer can change an authored index without changing the installed ETag.
        // Refuse before mutation against the exact source the candidate would consume.
        document["pools"]["work"]["members"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        let external = serde_json::to_vec_pretty(&document).unwrap();
        std::fs::write(&config_path, &external).unwrap();
        let stable = handle.load();
        let stable_bytes = overlay.read_bytes_async().await.unwrap();
        let response = put(
            &client,
            &endpoint,
            initial_version,
            &patch("/pools/work/members/0/weight", json::json!(19)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let refusal = json::parse_value(&response.bytes().await.unwrap()).unwrap();
        assert!(!refusal.to_string().contains("hidden-routing-tag"));
        assert!(Arc::ptr_eq(&stable, &handle.load()));
        assert_eq!(overlay.read_bytes_async().await.unwrap(), stable_bytes);
        let reload = client
            .post(format!("http://{addr}/api/v1/admin/config/reload"))
            .send()
            .await
            .unwrap();
        let status = reload.status();
        let text = reload.text().await.unwrap();
        assert_eq!(status, StatusCode::OK, "source drift reload: {text}");
        let refreshed = get(&client, &endpoint).await;
        let entries = &refreshed["configuration"]["values"]["sections"]["pools"]["authored"]
            ["definitions"]["work"]["members"]["entries"];
        assert_eq!(entries[0]["model"], "b");
        for weight in [19, 23] {
            let response = put(
                &client,
                &endpoint,
                handle.load().config_version,
                &patch("/pools/work/members/0/weight", json::json!(weight)),
            )
            .await;
            let status = response.status();
            let text = response.text().await.unwrap();
            assert_eq!(
                status,
                StatusCode::OK,
                "unchanged-source repeated edit: {text}"
            );
        }
        let loaded = busbar_kernel::load_config_from_disk_with_store(
            &config_path,
            None,
            false,
            busbar_kernel::config::EnvSubst::Strict,
            &*rules,
            handle.load().overlay_path.clone(),
        )
        .await
        .unwrap();
        assert_eq!(loaded.deploy.pools.pools["work"].members[0].model, "b");
        assert_eq!(loaded.deploy.pools.pools["work"].members[0].weight, 23);
        assert_eq!(
            loaded.deploy.pools.pools["work"].members[0].tags,
            vec!["hidden-routing-tag"]
        );
        assert_eq!(std::fs::read(&config_path).unwrap(), external);
        server.abort();
        let _ = server.await;
        println!("{WITNESS}");
        return;
    }

    if phase == "sequences" {
        let authored = |body: &Value| {
            body["configuration"]["values"]["sections"]["pools"]["authored"]["definitions"]["work"]
                .clone()
        };
        assert_eq!(authored(&before)["members"]["entries"][1]["model"], "b");
        for (request, expected) in [
            (
                patch(
                    "/pools/work/members/-",
                    json::json!({"model": "c", "weight": 3}),
                ),
                vec!["a", "b", "c"],
            ),
            (
                json::json!({"document_patch": {"set": {"/pools/work/members/2/weight": 7, "/pools/work/members/-": {"model": "d"}}}}),
                vec!["a", "b", "c", "d"],
            ),
            (
                json::json!({"document_patch": {"set": {"/pools/work/hooks/0": {"strategy": "fastest"}}, "remove": ["/pools/work/members/0"]}}),
                vec!["b", "c", "d"],
            ),
            (
                patch("/pools/work/members/0/weight", json::json!(9)),
                vec!["b", "c", "d"],
            ),
        ] {
            let response = put(&client, &endpoint, handle.load().config_version, &request).await;
            let status = response.status();
            let etag = response
                .headers()
                .get("etag")
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            let body = json::parse_value(&response.bytes().await.unwrap()).unwrap();
            assert_eq!(status, StatusCode::OK, "sequence response: {body}");
            assert_eq!(
                etag,
                format!("\"{}\"", body["config_version"].as_u64().unwrap())
            );
            assert_eq!(
                body["configuration"]["config_version"],
                body["config_version"]
            );
            let view = authored(&body);
            let entries = view["members"]["entries"].as_array().unwrap();
            assert_eq!(entries.len(), expected.len());
            for (index, (entry, model)) in entries.iter().zip(expected).enumerate() {
                assert_eq!(entry["index"], index);
                assert_eq!(entry["path"], format!("/pools/work/members/{index}"));
                assert_eq!(entry["model"], model);
            }
            assert!(!body.to_string().contains("hidden-routing-tag"));
        }
        let stable = handle.load();
        let stable_bytes = overlay.read_bytes_async().await.unwrap();
        let stale = put(
            &client,
            &endpoint,
            initial_version,
            &patch("/pools/work/members/0/weight", json::json!(12)),
        )
        .await;
        assert_eq!(stale.status(), StatusCode::CONFLICT);
        let invalid = put(
            &client,
            &endpoint,
            stable.config_version,
            &json::json!({"document_patch": {"set": {
                "/pools/work/members/-": {"model": "a"}, "/pools/work/members/99/weight": 13,
            }}}),
        )
        .await;
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        assert!(Arc::ptr_eq(&stable, &handle.load()));
        assert_eq!(overlay.read_bytes_async().await.unwrap(), stable_bytes);
        let reload = client
            .post(format!("http://{addr}/api/v1/admin/config/reload"))
            .send()
            .await
            .unwrap();
        let status = reload.status();
        let text = reload.text().await.unwrap();
        assert_eq!(status, StatusCode::OK, "sequence reload: {text}");
        let current = get(&client, &endpoint).await;
        let view = authored(&current);
        assert_eq!(view["members"]["entries"][0]["model"], "b");
        assert_eq!(view["members"]["entries"][0]["values"]["weight"], 9);
        assert_eq!(view["members"]["entries"][1]["values"]["weight"], 7);
        assert_eq!(
            view["hooks"]["entries"][0]["entry"],
            json::json!({"strategy": "fastest"})
        );
        assert!(!current.to_string().contains("hidden-routing-tag"));
        let loaded = busbar_kernel::load_config_from_disk_with_store(
            &config_path,
            None,
            false,
            busbar_kernel::config::EnvSubst::Strict,
            &*rules,
            handle.load().overlay_path.clone(),
        )
        .await
        .unwrap();
        let members = &loaded.deploy.pools.pools["work"].members;
        assert_eq!(
            members
                .iter()
                .map(|member| member.model.as_str())
                .collect::<Vec<_>>(),
            vec!["b", "c", "d"]
        );
        assert_eq!(members[0].tags, vec!["hidden-routing-tag"]);
        assert_eq!(members[0].weight, 9);
        assert_eq!(members[1].weight, 7);
        assert_eq!(std::fs::read(&config_path).unwrap(), base_bytes);
        server.abort();
        let _ = server.await;
        println!("{WITNESS}");
        return;
    }

    // Exact additive wire form, using the boot schema's path and value.
    let request = json::json!({"document_patch": {
        "set": {"/limits/request_body_max_bytes": 5000123, "/advanced/worker_threads": 3}, "remove": [],
    }, "providers_patch": {"set": {"/spare/base_url": "https://patched.example.com"}}});
    let response = put(&client, &endpoint, initial_version, &request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json::parse_value(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(body["persisted"], true);
    if phase == "persistence" {
        let report = &body["configuration"]["plane_refresh"];
        assert_eq!(report["scope"], "synchronous_plane_refresh");
        assert_eq!(report["phase"], "observed");
        assert_eq!(
            report["planes"],
            json::json!([
                {"plane":"held-plane", "section":"held-section", "generation":7, "outcome":"retained", "failure":"bootstrap_held"},
                {"plane":"failed-plane", "section":"failed-section", "generation":9, "outcome":"retained", "failure":"refresh_failed"},
                {"plane":"installed-plane", "section":"installed-section", "generation":11, "outcome":"installed", "failure":null}
            ])
        );
        assert_eq!(
            body["reload_to_apply"],
            body["configuration"]["reload_to_apply"]
        );
        assert_eq!(
            body["reload_to_apply"],
            json::json!(["/advanced/worker_threads", "held-section"])
        );
        assert_eq!(boot_snapshot.plane_refresh.snapshot().phase, "unobserved");
        let installed = handle.load();
        let cloned = (*installed).clone();
        assert_eq!(cloned.plane_refresh.snapshot().phase, "unobserved");
        assert!(cloned.plane_refresh.snapshot().planes.is_empty());
        assert_eq!(installed.plane_refresh.snapshot().planes.len(), 3);
    }

    assert_eq!(
        body["configuration"]["values"]["sections"]["advanced"]["worker_threads"],
        3
    );
    assert_eq!(body["configuration"]["state"], "restart_pending");
    assert_eq!(
        body["configuration"]["values"]["sections"]["provider_catalog"]["names"],
        json::json!(["spare"])
    );
    assert_eq!(configured_cap(&body), PATCH_CAP);
    assert!(overlay
        .read_required_async()
        .await
        .unwrap()
        .unwrap()
        .document_patch
        .is_some());
    assert_eq!(std::fs::read(&config_path).unwrap(), base_bytes);
    assert_eq!(
        busbar_kernel::config::limits::installed()
            .unwrap()
            .request_body_max_bytes,
        PATCH_CAP
    );
    let after = get(&client, &endpoint).await;
    assert_eq!(configured_cap(&after), PATCH_CAP);
    assert_eq!(
        after["settings"],
        json::json!({}),
        "legacy root overrides remain a separate view"
    );

    // A normal reload replays the Store document layer and leaves an omitted hidden key intact.
    let reload = client
        .post(format!("http://{addr}/api/v1/admin/config/reload"))
        .send()
        .await
        .unwrap();
    let reload_status = reload.status();
    let reload_body = reload.text().await.unwrap();
    assert_eq!(
        reload_status,
        StatusCode::OK,
        "reload response: {reload_body}"
    );
    assert_eq!(configured_cap(&get(&client, &endpoint).await), PATCH_CAP);
    let loaded = busbar_kernel::load_config_from_disk_with_store(
        &config_path,
        Some(&providers_path),
        false,
        busbar_kernel::config::EnvSubst::Strict,
        &*rules,
        handle.load().overlay_path.clone(),
    )
    .await
    .expect("the committed document composes through the normal loader");
    assert_eq!(loaded.deploy.limits.request_body_max_bytes, PATCH_CAP);
    assert_eq!(loaded.deploy.advanced.worker_threads, Some(3));
    assert_eq!(loaded.defs["spare"].base_url, "https://patched.example.com");
    assert_eq!(
        std::fs::read_to_string(&providers_path).unwrap(),
        catalog_base
    );
    let signing = loaded
        .deploy
        .auth
        .as_ref()
        .unwrap()
        .signing_key
        .as_ref()
        .unwrap();
    assert_eq!(
        signing,
        &crate::distribution::config_validation_application::source_path(
            signing_key.to_string_lossy()
        )
    );
    assert!(!json::to_string(&get(&client, &endpoint).await)
        .unwrap()
        .contains("hidden-signing-reference"));

    // Catalog selection follows the effective boot document instead of the old resolved path.
    let alternate_path = directory.join("alternate-providers.yaml");
    std::fs::write(&alternate_path, catalog_base).unwrap();
    let move_catalog = put(
        &client,
        &endpoint,
        handle.load().config_version,
        &json::json!({
            "document_patch": {"set": {"/providers_file": "alternate-providers.yaml"}},
            "reset_providers_paths": ["/spare/base_url"],
        }),
    )
    .await;
    assert_eq!(move_catalog.status(), StatusCode::OK);
    assert_eq!(
        handle.load().providers_path.as_deref(),
        Some(alternate_path.as_path())
    );
    assert!(handle.load().providers_override.is_none());
    let reload = client
        .post(format!("http://{addr}/api/v1/admin/config/reload"))
        .send()
        .await
        .unwrap();
    let reload_status = reload.status();
    let reload_body = reload.text().await.unwrap();
    assert_eq!(
        reload_status,
        StatusCode::OK,
        "reload response: {reload_body}"
    );
    assert_eq!(
        handle.load().providers_path.as_deref(),
        Some(alternate_path.as_path())
    );
    let recovered = busbar_kernel::load_config_from_disk_with_store(
        &config_path,
        None,
        false,
        busbar_kernel::config::EnvSubst::Strict,
        &*rules,
        handle.load().overlay_path.clone(),
    )
    .await
    .unwrap();
    assert_eq!(recovered.providers_path, alternate_path);
    assert_eq!(recovered.defs["spare"].base_url, "https://base.example.com");

    // Stale optimistic concurrency and invalid boot values cannot alter either authority.
    let stable = handle.load();
    let stable_bytes = overlay.read_bytes_async().await.unwrap();
    if phase == "persistence" {
        let stale = put(
            &client,
            &endpoint,
            initial_version,
            &patch("/limits/request_body_max_bytes", json::json!(7_000_123)),
        )
        .await;
        assert_eq!(stale.status(), StatusCode::CONFLICT);
        assert!(Arc::ptr_eq(&stable, &handle.load()));
        assert_eq!(overlay.read_bytes_async().await.unwrap(), stable_bytes);
        for invalid in [
            patch("/limits/request_body_max_bytes", json::json!("invalid-cap")),
            patch("/unknown-config-section", json::json!(true)),
            json::json!({"document_patch": {"set": {"/per_request_fee": 13}},
            "providers_patch": {"remove": ["/spare/protocol"]}}),
        ] {
            let response = put(&client, &endpoint, stable.config_version, &invalid).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert!(Arc::ptr_eq(&stable, &handle.load()));
            assert_eq!(overlay.read_bytes_async().await.unwrap(), stable_bytes);
            assert_eq!(
                busbar_kernel::config::limits::installed()
                    .unwrap()
                    .request_body_max_bytes,
                PATCH_CAP
            );
        }
    } else {
        // Established typed overrides keep precedence; a generic edit must not report a false apply.
        let typed = put(
            &client,
            &endpoint,
            stable.config_version,
            &json::json!({
                "limits": {"request_body_max_bytes": TYPED_CAP},
            }),
        )
        .await;
        assert_eq!(typed.status(), StatusCode::OK);
        assert_eq!(configured_cap(&get(&client, &endpoint).await), TYPED_CAP);
        let typed_generation = handle.load();
        let typed_bytes = overlay.read_bytes_async().await.unwrap();
        let conflict = put(
            &client,
            &endpoint,
            typed_generation.config_version,
            &patch("/limits/request_body_max_bytes", json::json!(8_000_123)),
        )
        .await;
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        assert!(Arc::ptr_eq(&typed_generation, &handle.load()));
        assert_eq!(overlay.read_bytes_async().await.unwrap(), typed_bytes);
        assert_eq!(configured_cap(&get(&client, &endpoint).await), TYPED_CAP);

        // Locking through the shared boot schema removes the writable Store overlay from the next App.
        let lock = put(
            &client,
            &endpoint,
            typed_generation.config_version,
            &patch("/config/locked", json::json!(true)),
        )
        .await;
        assert_eq!(lock.status(), StatusCode::OK);
        let locked = handle.load();
        assert!(locked.overlay_path.is_none());
        let locked_bytes = overlay.read_bytes_async().await.unwrap();
        let refused = put(
            &client,
            &endpoint,
            locked.config_version,
            &patch("/per_request_fee", json::json!(3)),
        )
        .await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert!(Arc::ptr_eq(&locked, &handle.load()));
        assert_eq!(overlay.read_bytes_async().await.unwrap(), locked_bytes);
    }
    assert_eq!(std::fs::read(config_path).unwrap(), base_bytes);
    server.abort();
    let _ = server.await;
    println!("{WITNESS}");
}

/// Run the calling test body once, in a fresh child process (each actual node keeps its own
/// production Config budget and process-wide rate history). Returns `true` in the parent, after
/// the child printed `witness` and exited cleanly; the caller then returns.
pub(super) fn ran_in_child(child: &str, witness: &str) -> bool {
    if std::env::var_os(child).is_some() {
        return false;
    }
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let name = std::thread::current().name().unwrap().to_owned();
    let mut process = Child(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &name, "--nocapture"])
            .env(child, "1")
            .env_remove("BUSBAR_WORKER_THREADS")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("start the isolated actual-root test"),
    );
    let until = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            use std::io::Read;
            let mut output = String::new();
            process
                .0
                .stdout
                .take()
                .unwrap()
                .read_to_string(&mut output)
                .unwrap();
            assert!(
                status.success(),
                "actual-root child failed: {status}: {output}"
            );
            assert!(
                output.contains(witness),
                "exact child did not complete its assertions: {output}"
            );
            return true;
        }
        assert!(Instant::now() < until, "actual-root child timed out");
        std::thread::park_timeout(Duration::from_millis(5));
    }
}

/// One actual admin application whose configured Store reports `durability: Ephemeral`, as the
/// in-memory Store does (BUSBAR-8016). The overlay and the boot Store are that Store.
pub(super) struct EphemeralAdmin {
    pub(super) addr: std::net::SocketAddr,
    pub(super) handle: Arc<busbar_kernel::state::AppHandle>,
    pub(super) overlay: Arc<OverlayStore>,
    pub(super) config_path: std::path::PathBuf,
    pub(super) directory: std::path::PathBuf,
    pub(super) document: serde_json::Value,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for EphemeralAdmin {
    fn drop(&mut self) {
        self.server.abort();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

pub(super) async fn ephemeral_admin(
    tag: &str,
    rules: impl FnOnce(
        Arc<dyn busbar_kernel::appbuild::RootRules>,
    ) -> Arc<dyn busbar_kernel::appbuild::RootRules>,
) -> EphemeralAdmin {
    crate::dist_root_install::install();
    let directory = plugins::scratch(tag);
    let library_path = plugins::application_store_library();
    let module = crate::root::test_plugins::native_image(&library_path).name;
    let manifest = crate::root::test_plugins::native_manifest(
        "store",
        &library_path,
        plugins::FIXTURE_PUBLISHER,
    );
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(library_path).unwrap(),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).unwrap();
    let plugin_config = plugins::trusted_config(&directory);
    let document = serde_json::json!({
        "providers": {}, "models": {},
        "auth": {"chain": [], "admin_auth": []},
        "store": {"module": module, "settings": plugins::application_store_settings(&directory)},
        "plugins": plugins::config_document(&plugin_config),
        "limits": {"request_body_max_bytes": BASE_CAP},
        "advanced": {},
    });
    let config_path = directory.join("config.yaml");
    let providers_path = directory.join("providers.yaml");
    let base_bytes = serde_json::to_vec_pretty(&document).unwrap();
    std::fs::write(&config_path, &base_bytes).unwrap();
    let catalog_base = "spare:\n  protocol: openai\n  base_url: https://base.example.com\n";
    std::fs::write(&providers_path, catalog_base).unwrap();
    let mut deploy = busbar_kernel::config::deploy_from_yaml_str(
        std::str::from_utf8(&base_bytes).unwrap(),
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the operator file passes the actual boot reader");
    deploy.document_source_fingerprints = Some(
        busbar_kernel::config::document_patch::SourceFingerprints::from_sources(
            std::str::from_utf8(&base_bytes).unwrap(),
            catalog_base,
        ),
    );
    let defs = busbar_kernel::config::providers::catalog_from_str(
        catalog_base,
        &crate::root::boot::axis_test_grammar(),
    )
    .unwrap();
    let config = busbar_kernel::config::resolve(&deploy, &defs).unwrap();
    let boot_rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let crate::root::min3_boot::fixture::Fixture {
        backend: opened,
        rules: boot_rules,
    } = crate::root::min3_boot::fixture::open(&config, &plugin_config, boot_rules.clone())
        .await
        .expect("the actual configured Store opens");
    let anchor = crate::root::real_store::core_over(Arc::new(
        crate::root::real_store::EphemeralInfo(opened),
    ))
    .await;
    let overlay = OverlayStore::from_core(anchor.clone())
        .expect("the in-memory Store still carries the config overlay");
    assert_eq!(
        overlay.core_store_handle().unwrap().info().durability,
        busbar_contract::persistence::Durability::Ephemeral
    );
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay.clone()),
        Default::default(),
        Default::default(),
        (Some(config_path.clone()), Some(providers_path)),
        None,
        &boot_rules,
        Some(anchor),
        true,
    )
    .await
    .expect("the actual root builds the admin application on an in-memory Store");
    app.providers_override = None;
    busbar_kernel::config::readback::ConfiguredView::capture_documents(&mut app, &deploy, &defs);
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("actual Store rate history boots");
    limits.keep().await.expect("actual boot limits activate");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    app.root_rules = rules(app.root_rules.clone());
    let app = Arc::new(app);
    busbar_kernel::boot::hydrate_all(&app)
        .await
        .expect("the actual Store hydrates before writes");
    let (_data, admin, handle) =
        busbar_kernel::build_split_routers_with_limits(app, 1 << 20, 0, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, admin).await.unwrap() });
    EphemeralAdmin {
        addr,
        handle,
        overlay,
        config_path,
        directory,
        document,
        server,
    }
}

/// UPG-A30c (F4 guard): an export a config.yaml edit added and a reload installed is reported as
/// restart-pending, but it is not this request's contribution, so a live document edit on an
/// in-memory Store is still admitted.
#[tokio::test]
async fn test_admin_v1_config_document_live_edit_not_blamed_for_config_yaml_export_on_ephemeral_store(
) {
    const CHILD: &str = "BUSBAR_ADMIN_DOCUMENT_EPHEMERAL_EXPORT_CHILD";
    const WITNESS: &str = "ephemeral document export assertions completed";
    if ran_in_child(CHILD, WITNESS) {
        return;
    }
    let fixture = ephemeral_admin("admin-document-ephemeral-export", |rules| rules).await;
    let client = reqwest::Client::new();
    let addr = fixture.addr;
    let endpoint = format!("http://{addr}/api/v1/admin/config/settings");
    let mut document = fixture.document.clone();
    document["export"] = serde_json::json!({"x": {
        "module": "request-log-file",
        "settings": {"path": fixture.directory.join("x.jsonl").to_string_lossy()},
    }});
    std::fs::write(
        &fixture.config_path,
        serde_json::to_vec_pretty(&document).unwrap(),
    )
    .unwrap();
    let reload = client
        .post(format!("http://{addr}/api/v1/admin/config/reload"))
        .send()
        .await
        .unwrap();
    let status = reload.status();
    let text = reload.text().await.unwrap();
    assert_eq!(status, StatusCode::OK, "config.yaml export reload: {text}");
    let response = put(
        &client,
        &endpoint,
        fixture.handle.load().config_version,
        &patch("/limits/request_body_max_bytes", json::json!(1_048_576)),
    )
    .await;
    let status = response.status();
    let body = json::parse_value(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(status, StatusCode::OK, "a live edit is admitted: {body}");
    assert_eq!(body["applied"], json::json!(true), "{body}");
    assert!(
        body["reload_to_apply"]
            .as_array()
            .is_some_and(|paths| paths.contains(&json::json!("export.x"))),
        "the pending config.yaml export is still reported: {body}"
    );
    drop(fixture);
    println!("{WITNESS}");
}

/// The shape `door_steps::Rules` returns for a written, unopened plane section, keyed on a valid
/// live value so a test can make the build report it.
struct PlaneOnMarker {
    inner: Arc<dyn busbar_kernel::appbuild::RootRules>,
}

const PLANE_MARKER: usize = 2_097_152;

impl busbar_kernel::appbuild::RootRules for PlaneOnMarker {
    fn check(&self, cfg: &busbar_kernel::config::RootCfg) -> Result<(), String> {
        self.inner.check(cfg)
    }
    fn check_built(&self, app: &mut busbar_kernel::state::App) -> Result<(), String> {
        self.inner.check_built(app)
    }
    fn mounted_plugin_paths(
        &self,
        app: &busbar_kernel::state::App,
    ) -> Option<std::collections::HashSet<String>> {
        self.inner.mounted_plugin_paths(app)
    }
    fn planes_awaiting_restart(&self, cfg: &busbar_kernel::config::RootCfg) -> Vec<&'static str> {
        if cfg.limits.request_body_max_bytes == PLANE_MARKER {
            vec!["zz-unopened-plane"]
        } else {
            Vec::new()
        }
    }
    fn destinations_applied(&self, destinations: &busbar_kernel::config::Destinations) {
        self.inner.destinations_applied(destinations)
    }
    fn claim_ticket_admission(
        &self,
        identity: &busbar_kernel::host_services::VerifiedTicketIdentity,
    ) -> busbar_kernel::host_services::TicketClaimDisposition {
        self.inner.claim_ticket_admission(identity)
    }
    fn unloaded_plane_refusal(&self, keys: &[&str]) -> Option<String> {
        self.inner.unloaded_plane_refusal(keys)
    }
}

/// UPG-A30c: a write that leaves a door plane awaiting a restart is refused on an in-memory Store,
/// on both the document and the typed form, because the restart that opens the plane erases it.
#[tokio::test]
async fn test_admin_v1_config_settings_unopened_plane_write_refused_on_ephemeral_store() {
    const CHILD: &str = "BUSBAR_ADMIN_SETTINGS_EPHEMERAL_PLANE_CHILD";
    const WITNESS: &str = "ephemeral unopened plane assertions completed";
    if ran_in_child(CHILD, WITNESS) {
        return;
    }
    let fixture = ephemeral_admin("admin-settings-ephemeral-plane", |inner| {
        Arc::new(PlaneOnMarker { inner }) as Arc<dyn busbar_kernel::appbuild::RootRules>
    })
    .await;
    let client = reqwest::Client::new();
    let endpoint = format!("http://{}/api/v1/admin/config/settings", fixture.addr);
    for (form, body) in [
        (
            "document",
            patch("/limits/request_body_max_bytes", json::json!(PLANE_MARKER)),
        ),
        (
            "typed",
            json::json!({"limits": {"request_body_max_bytes": PLANE_MARKER}}),
        ),
    ] {
        let before = fixture.handle.load();
        let response = put(&client, &endpoint, before.config_version, &body).await;
        let status = response.status();
        let refusal = json::parse_value(&response.bytes().await.unwrap()).unwrap();
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "{form}: an unopened plane write on an in-memory Store is refused: {refusal}"
        );
        assert_eq!(refusal["error"]["code"], "conflict", "{form}: {refusal}");
        assert!(
            refusal["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("zz-unopened-plane")),
            "{form}: the refusal names the plane: {refusal}"
        );
        assert!(
            Arc::ptr_eq(&before, &fixture.handle.load()),
            "{form}: no generation installed"
        );
        assert!(
            busbar_kernel::config::overlay::read_async(&fixture.overlay)
                .await
                .is_none_or(|doc| doc.root.is_none() && doc.document_patch.is_none()),
            "{form}: nothing was written to the overlay"
        );
    }
    let response = put(
        &client,
        &endpoint,
        fixture.handle.load().config_version,
        &patch(
            "/limits/request_body_max_bytes",
            json::json!(PLANE_MARKER + 1),
        ),
    )
    .await;
    let status = response.status();
    let body = json::parse_value(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "control: a live edit applies: {body}"
    );
    assert_eq!(body["applied"], json::json!(true), "{body}");
    drop(fixture);
    println!("{WITNESS}");
}
