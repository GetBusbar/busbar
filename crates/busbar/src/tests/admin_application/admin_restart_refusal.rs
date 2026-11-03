// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::sync::Arc;

use busbar_kernel::audit_ring;

use crate::root::test_plugins as plugins;

#[tokio::test]
async fn test_admin_v1_restart_refuses_when_it_cannot_restart() {
    if std::env::var_os("BUSBAR_ADMIN_RESTART_UNSUPERVISED_PROCESS").is_none() {
        let current = std::thread::current();
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", current.name().expect("test name"), "--nocapture"])
            .env("BUSBAR_ADMIN_RESTART_UNSUPERVISED_PROCESS", "1")
            .env_remove("INVOCATION_ID")
            .env_remove("KUBERNETES_SERVICE_HOST")
            .output()
            .expect("run the restart assertions in an unsupervised process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success()
                && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
            "unsupervised restart assertions failed: {}\n{stdout}\n{stderr}",
            output.status
        );
        return;
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));

    let baseline_seq = busbar_kernel::audit::auditlog::AUDIT_LOG
        .list_filtered(0, 1, None, None)
        .first()
        .map(|e| e.seq)
        .unwrap_or(0);
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
    let directory =
        plugins::scratch("test_admin_v1_restart_refuses_when_it_cannot_restart-actual-store");
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
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _h = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |req: reqwest::RequestBuilder| req.header("x-admin-token", "admintok");
    let url = format!("http://{addr}/api/v1/admin/restart");

    let resp = admin(client.post(&url))
        .header("content-type", "application/json")
        .body(r#"{"confrim": true}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        400,
        "unknown field must not restart"
    );

    let resp = admin(client.post(&url)).send().await.unwrap();
    assert_eq!(
        resp.status().as_u16(),
        409,
        "an unsupervised restart must be refused unless confirmed"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("confirm"),
        "the refusal must tell the operator how to proceed: {body}"
    );

    let resp = admin(client.post(&url))
        .header("content-type", "application/json")
        .body(r#"{"confirm": true}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        409,
        "a process with no shutdown channel cannot restart itself"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    let msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("cannot restart itself"),
        "with `confirm: true` the supervisor gate must be PASSED and the refusal must come from \
         the no-shutdown-channel gate, not the supervisor gate: {body}"
    );
    assert!(
        !msg.contains("confirm"),
        "a confirmed request must never be refused for lack of confirmation: {body}"
    );

    let entries = busbar_kernel::audit::auditlog::AUDIT_LOG.list_filtered(
        0,
        audit_ring::MAX_AUDIT_ENTRIES,
        None,
        None,
    );
    let restarts: Vec<_> = entries
        .iter()
        .filter(|e| e.action == "admin.restart" && e.seq > baseline_seq)
        .collect();
    assert!(
        restarts.len() >= 2,
        "each refusal must be audited, got {restarts:?}"
    );
    assert!(
        restarts
            .iter()
            .all(|e| e.outcome == audit_ring::OUTCOME_REJECTED),
        "a refused restart must never be recorded as applied: {restarts:?}"
    );
}
