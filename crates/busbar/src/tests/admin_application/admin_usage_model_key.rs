// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::root::test_plugins as plugins;

#[tokio::test]
async fn test_admin_v1_usage_meters_by_model_and_key() {
    const CHILD: &str = "BUSBAR_ADMIN_MODEL_USAGE_CHILD";
    const WITNESS: &str = "actual root model usage assertions completed";
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
                    "the actual-root model usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root model usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    let rate = busbar_kernel::config::RateEntryCfg {
        input_utok: 500.0,
        output_utok: 500.0,
        cache_read_utok: 500.0,
        cache_write_utok: 500.0,
        ..Default::default()
    };
    let rate_card: std::collections::BTreeMap<String, busbar_kernel::config::RateEntryCfg> = [
        ("model-1".to_string(), rate.clone()),
        ("model-2".to_string(), rate),
    ]
    .into_iter()
    .collect();
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
    let directory = plugins::scratch("test_admin_v1_usage_meters_by_model_and_key-actual-store");
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
    document["rate_card"] =
        serde_json::to_value(&rate_card).expect("serialize the original token rates");
    document["per_request_fee"] = serde_json::json!(1);
    super::admin_usage_history::complete_usage_fixture(
        &mut document,
        &directory,
        &[("model-1", "vendor-a"), ("model-2", "acme")],
    );
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
        .expect("the actual Store binds the process rate-card history and usage recovery");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let gov = app.governance.as_ref().expect("actual governance").clone();
    let store = gov.store();
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let now = busbar_kernel::store::now();
    let created: serde_json::Value = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name":"team-a"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let minted = store
        .get_key(created["id"].as_str().expect("actual mint id"))
        .unwrap()
        .expect("actual persisted key");
    let minted_secret = created["token"]
        .as_str()
        .expect("actual once-returned token")
        .to_string();
    let usage = busbar_contract::billing::TokenUsage {
        input: 700,
        output: 200,
        cache_read: Some(100),
        cache_creation: None,
        ..Default::default()
    };

    gov.record_metering(&minted.id, "model-1", "vendor-a", Some(&usage), now);
    gov.record_metering(&minted.id, "model-1", "vendor-a", Some(&usage), now);
    gov.record_metering(&minted.id, "model-2", "acme", None, now);
    gov.flush_metering();

    let body: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/usage"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(
        body.get("currency").and_then(|c| c.as_str()),
        Some("USD"),
        "usage response carries currency:USD"
    );
    assert!(body["as_of"].as_u64().unwrap() >= now);
    let (start, end) = (
        body["window"]["start"].as_u64().unwrap(),
        body["window"]["end"].as_u64().unwrap(),
    );
    assert_eq!(end - start, 86_400, "one UTC-day metering bucket");
    assert!((start..end).contains(&now));

    assert_eq!(body["total"]["requests"], 3);
    assert_eq!(body["total"]["tokens_input"], 1400);
    assert_eq!(body["total"]["tokens_output"], 400);
    assert_eq!(body["total"]["tokens_cache_read"], 200);
    assert_eq!(body["total"]["tokens_cache_creation"], 0);
    assert_eq!(body["total"]["spend_micros"], 1_030_000);

    let by_model = body["by_model"].as_array().unwrap();
    assert_eq!(by_model.len(), 2, "{by_model:?}");
    let x = by_model.iter().find(|m| m["model"] == "model-1").unwrap();
    assert_eq!(x["provider"], "vendor-a");
    assert_eq!(x["requests"], 2);
    assert_eq!(x["tokens_input"], 1400);

    assert_eq!(x["spend_micros"], 1_020_000);
    let z = by_model.iter().find(|m| m["model"] == "model-2").unwrap();
    assert_eq!(
        z["requests"], 1,
        "a flat (zero-token) response still counts"
    );
    assert_eq!(
        z["spend_micros"], 10_000,
        "1 req x 1 cent = 10_000 micro-units"
    );

    let by_key = body["by_key"].as_array().unwrap();
    assert_eq!(by_key.len(), 1);
    assert_eq!(by_key[0]["id"], minted.id);
    assert_eq!(by_key[0]["name"], "team-a");
    assert_eq!(by_key[0]["requests"], 3);
    let text = body.to_string();
    assert!(
        !text.contains(&minted_secret),
        "usage must not leak the key secret"
    );

    handle.abort();
    println!("{WITNESS}");
}
