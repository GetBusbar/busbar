// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The discovered instance edit uses the actual config router and configured CoreStore.

use axum::http::StatusCode;
use serde_json::{json, Value};

async fn describe(fixture: &super::config_document_patch::EphemeralAdmin) -> Value {
    let response = reqwest::get(format!(
        "http://{}/api/v1/admin/kinds/store/instances/store",
        fixture.addr
    ))
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.json().await.unwrap()
}

fn edit(action: &Value, value: u64) -> String {
    json!({"instance_edit": {
        "kind":"store", "id":"store", "target_revision":action["target_revision"],
        "edit":{"set":{"busy_timeout_ms":value},"remove":[]}
    }})
    .to_string()
}

#[tokio::test]
async fn instance_settings_survives_a_cold_sqlite_reopen() {
    const CHILD: &str = "BUSBAR_INSTANCE_SETTINGS_RESTART_CHILD";
    const DIRECTORY: &str = "BUSBAR_INSTANCE_SETTINGS_RESTART_DIRECTORY";
    const WITNESS: &str = "actual SQLite instance setting cold reopen completed";
    let Ok(phase) = std::env::var(CHILD) else {
        struct Directory(std::path::PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let directory = Directory(crate::root::test_plugins::scratch(
            "instance-settings-restart",
        ));
        let name = std::thread::current().name().unwrap().to_owned();
        for phase in ["first", "restart"] {
            let mut process = Child(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", &name, "--nocapture"])
                    .env(CHILD, phase)
                    .env(DIRECTORY, &directory.0)
                    .env_remove("BUSBAR_WORKER_THREADS")
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .expect("start the isolated persistent setting phase"),
            );
            let until = std::time::Instant::now() + std::time::Duration::from_secs(90);
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
                        "cold SQLite {phase} failed: {status}: {output}"
                    );
                    assert!(
                        output.contains(WITNESS),
                        "cold SQLite {phase} did not finish"
                    );
                    break;
                }
                assert!(
                    std::time::Instant::now() < until,
                    "cold SQLite {phase} timed out"
                );
                std::thread::park_timeout(std::time::Duration::from_millis(5));
            }
        }
        return;
    };
    let directory = std::path::PathBuf::from(std::env::var_os(DIRECTORY).unwrap());
    if phase == "first" {
        let mut fixture = super::config_document_patch::durable_admin_in_directory(directory).await;
        // The parent owns the directory even if an assertion fails in either child.
        fixture.retain_files_for_restart();
        let description = describe(&fixture).await;
        let action = &description["actions"][0];
        let client = reqwest::Client::new();
        let endpoint = format!(
            "http://{}{}",
            fixture.addr,
            action["href"].as_str().unwrap()
        );
        let first = client
            .put(&endpoint)
            .header("If-Match", action["etag"].as_str().unwrap())
            .header("Idempotency-Key", "instance-cold-reopen")
            .header("Content-Type", "application/json")
            .body(edit(action, 4321))
            .send()
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let outcome: Value = first.json().await.unwrap();
        assert_eq!(outcome["persisted"], true);
        let installed = fixture.handle.load();
        let stored = fixture.overlay.read_bytes_async().await.unwrap();
        // A fresh key with the old precondition must not change either authority.
        let stale = client
            .put(&endpoint)
            .header("If-Match", action["etag"].as_str().unwrap())
            .header("Idempotency-Key", "instance-cold-stale")
            .header("Content-Type", "application/json")
            .body(edit(action, 9999))
            .send()
            .await
            .unwrap();
        assert_eq!(stale.status(), StatusCode::CONFLICT);
        assert!(std::sync::Arc::ptr_eq(&installed, &fixture.handle.load()));
        assert_eq!(fixture.overlay.read_bytes_async().await.unwrap(), stored);
        std::fs::write(
            fixture.directory.join("committed-overlay.json"),
            stored.unwrap(),
        )
        .unwrap();
    } else {
        assert_eq!(phase, "restart");
        crate::dist_root_install::install();
        let config_path = directory.join("config.yaml");
        let base = std::fs::read_to_string(&config_path).unwrap();
        let deploy = busbar_kernel::config::deploy_from_yaml_str(
            &base,
            &crate::root::boot::axis_test_grammar(),
        )
        .unwrap();
        let catalog = std::fs::read_to_string(directory.join("providers.yaml")).unwrap();
        let defs = busbar_kernel::config::providers::catalog_from_str(
            &catalog,
            &crate::root::boot::axis_test_grammar(),
        )
        .unwrap();
        let config = busbar_kernel::config::resolve(&deploy, &defs).unwrap();
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let plugins = crate::root::test_plugins::trusted_config(&directory);
        let opened = crate::root::min3_boot::fixture::open(&config, &plugins, rules.clone())
            .await
            .expect("a new process opens the same actual SQLite database");
        let (admitted, _serving) = opened.admit_serving().await;
        let core = admitted.core;
        assert_ne!(
            core.info().durability,
            busbar_contract::persistence::Durability::Ephemeral
        );
        let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(core).unwrap();
        assert_eq!(
            overlay.read_bytes_async().await.unwrap().unwrap(),
            std::fs::read(directory.join("committed-overlay.json")).unwrap(),
            "the new process reads the exact durable authority left after the stale refusal"
        );
        let mut loaded = busbar_kernel::load_config_from_disk_with_store(
            &config_path,
            None,
            false,
            busbar_kernel::config::EnvSubst::Strict,
            &*admitted.rules,
            Some(overlay),
        )
        .await
        .unwrap();
        let recovered = loaded.disk_candidate().unwrap();
        let store = recovered.store.unwrap();
        let seal = busbar_kernel::seal::acquire();
        let settings = store.settings.authoring(&seal);
        let settings = serde_json::to_value(settings).unwrap();
        assert_eq!(settings["busy_timeout_ms"], 4321);
        assert_eq!(
            settings["db_path"],
            directory.join("application.sqlite").to_str().unwrap()
        );
        assert_eq!(std::fs::read_to_string(config_path).unwrap(), base);
    }
    println!("{WITNESS}");
}

#[tokio::test]
async fn instance_settings_uses_one_config_transaction_and_retains_exact_replay() {
    const CHILD: &str = "BUSBAR_INSTANCE_SETTINGS_REPLAY_CHILD";
    const WITNESS: &str = "instance settings actual Store replay completed";
    if super::config_document_patch::ran_in_child(CHILD, WITNESS) {
        return;
    }
    let fixture = super::config_document_patch::durable_admin("instance-settings-replay").await;
    let client = reqwest::Client::new();
    let before = fixture.handle.load();
    let description = describe(&fixture).await;
    assert_eq!(description["management"]["available"], true);
    assert_eq!(description["actions"].as_array().unwrap().len(), 1);
    let action = &description["actions"][0];
    assert_eq!(action["operation_id"], "PutConfigSettings");
    assert_eq!(action["verb"], "put_config_settings");
    assert_eq!(action["required_scope"], "full");
    assert_eq!(action["method"], "PUT");
    assert_eq!(action["effect"], "mutation");
    assert_eq!(action["source"]["pointer"], "/store/settings");
    assert_ne!(action["etag"], description["etag"]);
    let openapi: Value = client
        .get(format!("http://{}/api/v1/admin/openapi.json", fixture.addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let operation = &openapi["paths"]["/api/v1/admin/config/settings"]["put"];
    assert_eq!(operation["operationId"], action["operation_id"]);
    assert_eq!(operation["x-busbar-verb"], action["verb"]);
    assert_eq!(
        operation["x-busbar-required-scope"],
        action["required_scope"]
    );
    assert!(
        operation["requestBody"]["content"]["application/json"]["schema"]["oneOf"]
            .as_array()
            .unwrap()
            .contains(&action["input_schema"])
    );
    let endpoint = format!(
        "http://{}{}",
        fixture.addr,
        action["href"].as_str().unwrap()
    );
    let etag = action["etag"].as_str().unwrap();
    let body = edit(action, 4321);

    // Even when the global policy permits unconditional config edits, this mode does not.
    for (index, header) in [None, Some("*"), Some("W/\"anything\"")]
        .into_iter()
        .enumerate()
    {
        let mut request = client
            .put(&endpoint)
            .header("Idempotency-Key", format!("instance-invalid-{index}"))
            .header("Content-Type", "application/json")
            .body(body.clone());
        if let Some(header) = header {
            request = request.header("If-Match", header);
        }
        let response = request.send().await.unwrap();
        assert_eq!(
            response.status(),
            if header.is_none() {
                StatusCode::PRECONDITION_REQUIRED
            } else {
                StatusCode::BAD_REQUEST
            }
        );
        assert!(std::sync::Arc::ptr_eq(&before, &fixture.handle.load()));
    }
    let duplicate = client
        .put(&endpoint)
        .header("If-Match", "\"stale\"")
        .header("If-Match", etag)
        .header("Idempotency-Key", "instance-duplicate-precondition")
        .header("Content-Type", "application/json")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
    let missing_key = client
        .put(&endpoint)
        .header("If-Match", etag)
        .header("Content-Type", "application/json")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(missing_key.status(), StatusCode::BAD_REQUEST);
    assert!(std::sync::Arc::ptr_eq(&before, &fixture.handle.load()));
    let first = client
        .put(&endpoint)
        .header("If-Match", etag)
        .header("Idempotency-Key", "instance-accepted")
        .header("Content-Type", "application/json")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let committed_etag = first.headers()["etag"].clone();
    assert_ne!(committed_etag.to_str().unwrap(), etag);
    let first_bytes = first.bytes().await.unwrap();
    let outcome: Value = serde_json::from_slice(&first_bytes).unwrap();
    assert_eq!(outcome["persisted"], true);
    assert_eq!(outcome["applied"], true);
    assert_eq!(outcome["configuration"]["state"], "restart_pending");
    assert!(outcome["reload_to_apply"]
        .as_array()
        .unwrap()
        .iter()
        .any(|path| { path.as_str().is_some_and(|path| path.starts_with("/store")) }));
    assert!(!String::from_utf8_lossy(&first_bytes).contains("application.sqlite"));
    let installed = fixture.handle.load();
    let doc = fixture
        .overlay
        .read_required_async()
        .await
        .unwrap()
        .unwrap();
    let patch = serde_json::to_value(doc.document_patch.as_ref().unwrap()).unwrap();
    let encoded = patch.to_string();
    assert!(encoded.contains("busy_timeout_ms"));
    assert!(
        !encoded.contains("db_path"),
        "the hidden sibling is never reconstructed"
    );
    assert_eq!(
        std::fs::read(&fixture.config_path).unwrap(),
        serde_json::to_vec_pretty(&fixture.document).unwrap(),
        "the operator source remains intact"
    );

    let replay = client
        .put(&endpoint)
        .header("If-Match", etag)
        .header("Idempotency-Key", "instance-accepted")
        .header("Content-Type", "application/json")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(replay.headers()["etag"], committed_etag);
    assert_eq!(replay.headers()["idempotent-replayed"], "true");
    assert_eq!(replay.bytes().await.unwrap(), first_bytes);
    assert!(std::sync::Arc::ptr_eq(&installed, &fixture.handle.load()));
    let changed = client
        .put(&endpoint)
        .header("If-Match", etag)
        .header("Idempotency-Key", "instance-accepted")
        .header("Content-Type", "application/json")
        .body(edit(action, 4322))
        .send()
        .await
        .unwrap();
    assert_eq!(changed.status(), StatusCode::CONFLICT);
    assert!(std::sync::Arc::ptr_eq(&installed, &fixture.handle.load()));
    let after = describe(&fixture).await;
    assert_ne!(
        after["etag"], description["etag"],
        "the changed action ETag invalidates discovery"
    );
    assert_eq!(
        after["actions"][0]["etag"],
        committed_etag.to_str().unwrap()
    );
    if let Some(path) = std::env::var_os("BUSBAR_INSTANCE_MANAGEMENT_FIXTURE") {
        // The artifact contains the actual producer descriptor and sanitized outcome, no
        // credentials or arbitrary private draft. The submitted setting is this fixed test input.
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&json!({
                "operation":operation,
                "before":description,
                "request":serde_json::from_str::<Value>(&body).unwrap(),
                "response":outcome,
                "response_etag":committed_etag.to_str().unwrap(),
                "after":after
            }))
            .unwrap(),
        )
        .unwrap();
    }
    println!("{WITNESS}");
}

#[tokio::test]
async fn instance_settings_cannot_overwrite_a_higher_priority_typed_overlay() {
    const CHILD: &str = "BUSBAR_INSTANCE_SETTINGS_PRECEDENCE_CHILD";
    const WITNESS: &str = "instance settings precedence refusal completed";
    if super::config_document_patch::ran_in_child(CHILD, WITNESS) {
        return;
    }
    let fixture = super::config_document_patch::durable_admin("instance-settings-precedence").await;
    let client = reqwest::Client::new();
    let endpoint = format!("http://{}/api/v1/admin/config/settings", fixture.addr);
    let before = describe(&fixture).await;
    let typed = client
        .put(&endpoint)
        .header("If-Match", before["actions"][0]["etag"].as_str().unwrap())
        .json(&json!({"store":fixture.document["store"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(typed.status(), StatusCode::OK);
    let description = describe(&fixture).await;
    let action = &description["actions"][0];
    let installed = fixture.handle.load();
    let stored = fixture
        .overlay
        .read_required_async()
        .await
        .unwrap()
        .unwrap();
    assert!(stored.root.as_ref().unwrap().store.is_some());
    let response = client
        .put(&endpoint)
        .header("If-Match", action["etag"].as_str().unwrap())
        .header("Idempotency-Key", "instance-shadowed")
        .header("Content-Type", "application/json")
        .body(edit(action, 4321))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(std::sync::Arc::ptr_eq(&installed, &fixture.handle.load()));
    let after = fixture
        .overlay
        .read_required_async()
        .await
        .unwrap()
        .unwrap();
    assert!(after.document_patch.is_none());
    assert!(after.root.as_ref().unwrap().store.is_some());
    println!("{WITNESS}");
}

#[tokio::test]
async fn instance_settings_refuses_target_confusion_and_source_drift_without_store_change() {
    const CHILD: &str = "BUSBAR_INSTANCE_SETTINGS_SOURCE_CHILD";
    const WITNESS: &str = "instance settings source refusals completed";
    if super::config_document_patch::ran_in_child(CHILD, WITNESS) {
        return;
    }
    let fixture = super::config_document_patch::durable_admin("instance-settings-source").await;
    let client = reqwest::Client::new();
    let description = describe(&fixture).await;
    let action = &description["actions"][0];
    let endpoint = format!("http://{}/api/v1/admin/config/settings", fixture.addr);
    let before = fixture.handle.load();
    for (index, (field, value)) in [
        ("kind", "core"),
        ("id", "other-store"),
        ("target_revision", "invalid-schema-revision"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut body: Value = serde_json::from_str(&edit(action, 4321)).unwrap();
        body["instance_edit"][field] = json!(value);
        let response = client
            .put(&endpoint)
            .header("If-Match", action["etag"].as_str().unwrap())
            .header("Idempotency-Key", format!("instance-target-{index}"))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert!(!response.status().is_success());
        assert!(std::sync::Arc::ptr_eq(&before, &fixture.handle.load()));
    }
    let mut changed = fixture.document.clone();
    changed["store"]["settings"]["busy_timeout_ms"] = json!(9876);
    std::fs::write(&fixture.config_path, serde_json::to_vec(&changed).unwrap()).unwrap();
    let response = client
        .put(&endpoint)
        .header("If-Match", action["etag"].as_str().unwrap())
        .header("Idempotency-Key", "instance-source-drift")
        .header("Content-Type", "application/json")
        .body(edit(action, 4321))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(std::sync::Arc::ptr_eq(&before, &fixture.handle.load()));
    assert!(fixture
        .overlay
        .read_required_async()
        .await
        .unwrap()
        .is_none_or(|doc| doc.document_patch.is_none()));
    println!("{WITNESS}");
}
