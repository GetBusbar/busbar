// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::sync::Arc;

use busbar_contract::json::{self, JsonValueTrait as _};

const X_ADMIN_TOKEN: &str = "x-admin-token";

#[tokio::test]
async fn test_1_5_2_admin_path_bypasses_governance_and_mints() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_D8D9A6536B47";
    const WITNESS: &str =
        "actual root case test_1_5_2_admin_path_bypasses_governance_and_mints completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_1_5_2_admin_path_bypasses_governance_and_mints-actual-store",
    );
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
    let crate::root::min3_boot::fixture::Fixture {
        backend: anchor,
        rules,
    } = crate::root::min3_boot::fixture::open(&config, &plugin_config, rules.clone())
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
    let (_key, _secret) = app
        .governance
        .as_ref()
        .expect("actual governance")
        .mint_signed_async(
            busbar_kernel::governance::NewKeySpec {
                name: "vk".to_string(),
                allowed_pools: Some(vec!["pa".to_string()]),
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            1_000_000_000,
        )
        .await
        .expect("the actual configured signer and Store mint the pre-existing key");
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let r = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header(X_ADMIN_TOKEN, "admintok")
        .header("content-type", "application/json")
        .body(json::json!({"name": "minted-via-admin"}).to_string())
        .send()
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "admin token must authenticate the admin API and mint (got {})",
        r.status()
    );

    let bad = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header(X_ADMIN_TOKEN, "nope")
        .header("content-type", "application/json")
        .body(json::json!({"name": "x"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        bad.status().as_u16(),
        401,
        "a wrong admin token must be rejected"
    );
    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_governance_admin_api() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_4AFD6C880DD7";
    const WITNESS: &str = "actual root case test_governance_admin_api completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) =
        crate::distribution::rig::actual_store("test_governance_admin_api-actual-store");
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
    let (addr, handle, _book) =
        crate::distribution::rig::actual_root(document, &directory, &module).await;
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    let r = client
        .post(format!("{base}/api/v1/admin/keys"))
        .json(&json::json!({"name": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401, "no admin token → unauthorized");

    let r = client
        .post(format!("{base}/api/v1/admin/keys"))
        .bearer_auth("admintok")
        .json(&json::json!({"name": "team-a", "allowed_pools": ["allowedpool"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 201, "admin create → 201");
    let created = json::parse_value(&r.bytes().await.unwrap()).unwrap();
    let id = created["id"].as_str().unwrap().to_string();

    let secret = created["token"].as_str().unwrap().to_string();
    assert!(secret.starts_with("bbk_"), "signed token returned once");
    assert!(
        created.get("generation_hash").is_none(),
        "hash never returned"
    );
    assert!(created.get("secret").is_none(), "no legacy secret in 1.5.0");

    let r = client
        .get(format!("{base}/api/v1/admin/keys"))
        .bearer_auth("admintok")
        .send()
        .await
        .unwrap();
    let listed = json::parse_value(&r.bytes().await.unwrap()).unwrap();
    assert_eq!(listed["items"].as_array().unwrap().len(), 1);
    assert!(listed["items"][0].get("generation_hash").is_none());

    let r = client
        .get(format!("{base}/api/v1/admin/keys/{id}/usage"))
        .bearer_auth("admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);

    let r = client
        .post(format!("{base}/allowedpool/v1/messages"))
        .bearer_auth(&secret)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        404,
        "minted key authenticates + ACL passes"
    );

    let r = client
        .delete(format!("{base}/api/v1/admin/keys/{id}"))
        .bearer_auth("admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 204);
    let r = client
        .get(format!("{base}/api/v1/admin/keys"))
        .bearer_auth("admintok")
        .send()
        .await
        .unwrap();
    let listed = json::parse_value(&r.bytes().await.unwrap()).unwrap();
    assert_eq!(listed["items"].as_array().unwrap().len(), 0, "deleted");

    handle.abort();
    println!("{WITNESS}");
}
