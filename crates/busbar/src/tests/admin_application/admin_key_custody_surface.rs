// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::sync::Arc;

use busbar_contract::json::{self, JsonValueTrait as _};
use busbar_kernel::audit_ring;

#[tokio::test]
async fn test_admin_v1_auth_read_keys_chain_reports_closed() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_A84111105DC5";
    const WITNESS: &str =
        "actual root case test_admin_v1_auth_read_keys_chain_reports_closed completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_admin_v1_auth_read_keys_chain_reports_closed-actual-store",
    );
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
        "auth": { "chain": ["keys"], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = crate::root::boot::store::bootstrap_config_store(
        &config,
        &plugin_config,
        &crate::root::boot::store::Unopened,
    )
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
    let mw = &app.auth;
    assert!(
        !mw.is_open(),
        "the admission predicate stays closed under chain: [keys]"
    );
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let body = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/admin/auth"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(
        body, r#"{"chain":["keys"],"upstream_credentials":"own","open":false}"#,
        "GET /auth must report the effective closed keys chain"
    );
    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_get_single_key() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_547AE3245472";
    const WITNESS: &str = "actual root case test_admin_v1_get_single_key completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) =
        crate::distribution::rig::actual_store("test_admin_v1_get_single_key-actual-store");
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
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = crate::root::boot::store::bootstrap_config_store(
        &config,
        &plugin_config,
        &crate::root::boot::store::Unopened,
    )
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
    let store = app
        .governance
        .as_ref()
        .expect("actual governance")
        .core_store_handle()
        .unwrap();
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let created = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .json(&json::json!({"name":"svc"}))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let created = json::parse_value(&created).unwrap();
    let minted = store
        .identity()
        .get_key(created["id"].as_str().expect("the real mint returns an id"))
        .await
        .expect("the actual Store reads")
        .expect("the actual mint persisted its key");
    let minted_secret = created["token"]
        .as_str()
        .expect("the real mint returns its token once")
        .to_string();
    let resp = client
        .get(format!("http://{addr}/api/v1/admin/keys/{}", minted.id))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let text = resp.text().await.unwrap();
    let body = json::parse_value(text.as_bytes()).unwrap();
    assert_eq!(body["id"], minted.id);
    assert_eq!(body["name"], "svc");
    assert!(
        body.get("generation_hash").is_none(),
        "never expose the hash"
    );
    assert!(
        !text.contains(&minted_secret),
        "never expose the secret on a read"
    );

    let missing = client
        .get(format!("http://{addr}/api/v1/admin/keys/vk_doesnotexist"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);

    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn minting_a_recoverable_credential_without_a_signing_key_is_refused_and_says_what_to_set() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_857B905D7FF9";
    const WITNESS: &str = "actual root case minting_a_recoverable_credential_without_a_signing_key_is_refused_and_says_what_to_set completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store("minting_a_recoverable_credential_without_a_signing_key_is_refused_and_says_what_to_set-actual-store");
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let operator_token = directory.join("operator-token");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator] },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = crate::root::boot::store::bootstrap_config_store(
        &config,
        &plugin_config,
        &crate::root::boot::store::Unopened,
    )
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
    let store = app
        .governance
        .as_ref()
        .expect("actual governance")
        .core_store_handle()
        .unwrap();
    let app = Arc::new(app);
    busbar_kernel::boot::hydrate_all(&app)
        .await
        .expect("the actual root hydrates its audit stream");
    let router = busbar_kernel::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let baseline_seq = busbar_kernel::audit::auditlog::AUDIT_LOG
        .list_filtered(0, 1, None, None)
        .first()
        .map(|e| e.seq)
        .unwrap_or(0);

    let refused = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .json(&json::json!({"name": "no-at-rest", "issue_aws_credential": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status().as_u16(), 409);
    let body = json::parse_value(&refused.bytes().await.unwrap()).unwrap();
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert_eq!(
        message,
        busbar_kernel::governance::at_rest::NO_KEY_REFUSAL,
        "{body}"
    );
    assert!(message.contains("auth.signing_key"), "{body}");
    assert!(
        store.identity().list_keys().await.unwrap().is_empty(),
        "a key was written"
    );
    assert!(store
        .identity()
        .list_credentials_since(0)
        .await
        .unwrap()
        .is_empty());
    assert!(
        busbar_kernel::audit::auditlog::AUDIT_LOG
            .list_filtered(0, audit_ring::MAX_AUDIT_ENTRIES, None, Some("key:-"))
            .into_iter()
            .any(|e| e.seq > baseline_seq
                && e.action == "key.create"
                && e.outcome == audit_ring::OUTCOME_REJECTED),
        "the refusal is audited"
    );

    let plain = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .json(&json::json!({"name": "bearer-only"}))
        .send()
        .await
        .unwrap();
    assert_eq!(plain.status().as_u16(), 201);
    handle.abort();
    println!("{WITNESS}");
}
