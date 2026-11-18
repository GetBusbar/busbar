// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::json::JsonContainerTrait as _;
use std::collections::HashSet;
use std::sync::Arc;

use busbar_contract::json::{self, JsonValueTrait as _};
use busbar_kernel::governance::NewKeySpec;

#[tokio::test]
async fn test_delete_existing_key_returns_200() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_DB7ED1773FD3";
    const WITNESS: &str = "actual root case test_delete_existing_key_returns_200 completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) =
        crate::distribution::rig::actual_store("test_delete_existing_key_returns_200-actual-store");
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
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
    let (key, _secret) = app
        .governance
        .as_ref()
        .expect("the actual application has governance")
        .mint_signed_async(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            0,
        )
        .await
        .unwrap();
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let resp = client
        .delete(format!("http://{addr}/api/v1/admin/keys/{}", key.id))
        .header("authorization", "Bearer admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        204,
        "existing key deletes with 204 No Content"
    );
    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_delete_missing_key_returns_404() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_C32A2F49886E";
    const WITNESS: &str = "actual root case test_delete_missing_key_returns_404 completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) =
        crate::distribution::rig::actual_store("test_delete_missing_key_returns_404-actual-store");
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
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
    let (addr, handle, _book) =
        crate::distribution::rig::actual_root(document, &directory, &module).await;
    let client = reqwest::Client::new();
    let resp = client
        .delete(format!("http://{addr}/api/v1/admin/keys/vk_does_not_exist"))
        .header("authorization", "Bearer admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        404,
        "deleting a non-existent key must 404, not a spurious 200"
    );
    let body = json::parse_value(&resp.bytes().await.unwrap()).unwrap();
    assert_eq!(body["error"]["message"], "key not found");
    assert_eq!(body["error"]["code"], "not_found");
    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_delete_key_is_not_idempotent_204() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_5B04494322AC";
    const WITNESS: &str = "actual root case test_delete_key_is_not_idempotent_204 completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_delete_key_is_not_idempotent_204-actual-store",
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
    let (key, _secret) = app
        .governance
        .as_ref()
        .expect("the actual application has governance")
        .mint_signed_async(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            0,
        )
        .await
        .unwrap();
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);
    let first = client
        .delete(&url)
        .header("authorization", "Bearer admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(first.status().as_u16(), 204);
    let second = client
        .delete(&url)
        .header("authorization", "Bearer admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(second.status().as_u16(), 404, "second delete must 404");
    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_concurrent_delete_returns_exactly_one_204() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_A0DFD53CBD93";
    const WITNESS: &str =
        "actual root case test_concurrent_delete_returns_exactly_one_204 completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_concurrent_delete_returns_exactly_one_204-actual-store",
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
    let (key, _secret) = app
        .governance
        .as_ref()
        .expect("the actual application has governance")
        .mint_signed_async(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            0,
        )
        .await
        .unwrap();
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let url = url.clone();
        tasks.push(tokio::spawn(async move {
            let client = reqwest::Client::new();
            client
                .delete(&url)
                .header("authorization", "Bearer admintok")
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }));
    }
    let mut ok = 0;
    let mut not_found = 0;
    for t in tasks {
        match t.await.unwrap() {
            204 => ok += 1,
            404 => not_found += 1,
            other => panic!("unexpected status {other} from concurrent delete"),
        }
    }
    assert_eq!(
        ok, 1,
        "exactly one concurrent delete must report a 204 revocation"
    );
    assert_eq!(
        not_found, 7,
        "every losing concurrent delete must report 404"
    );
    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_patch_after_delete_404s_and_does_not_recreate_key() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_6E3B3F7388B5";
    const WITNESS: &str =
        "actual root case test_patch_after_delete_404s_and_does_not_recreate_key completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_patch_after_delete_404s_and_does_not_recreate_key-actual-store",
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
    let (key, _secret) = app
        .governance
        .as_ref()
        .expect("the actual application has governance")
        .mint_signed_async(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            0,
        )
        .await
        .unwrap();
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let key_url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);

    let del = client
        .delete(&key_url)
        .header("authorization", "Bearer admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(del.status().as_u16(), 204, "the key is revoked");

    let patched = client
        .patch(&key_url)
        .header("authorization", "Bearer admintok")
        .json(&json::json!({"enabled": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        patched.status().as_u16(),
        404,
        "PATCH on a deleted key must 404, not resurrect it"
    );

    let usage = client
        .get(format!("{key_url}/usage"))
        .header("authorization", "Bearer admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        usage.status().as_u16(),
        404,
        "the revoked key must remain absent after the PATCH"
    );
    let listed = client
        .get(format!("http://{addr}/api/v1/admin/keys"))
        .header("authorization", "Bearer admintok")
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let listed = json::parse_value(&listed).unwrap();
    assert_eq!(
        listed["items"].as_array().unwrap().len(),
        0,
        "PATCH must not have re-inserted the deleted key: {listed}"
    );
    handle.abort();
    println!("{WITNESS}");
}
