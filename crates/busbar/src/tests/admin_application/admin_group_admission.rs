// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::json::JsonContainerTrait as _;
use std::collections::HashSet;
use std::sync::Arc;

use busbar_contract::json::{self, JsonValueTrait as _};

fn budget_limit(cents: u64) -> busbar_kernel::config::groups::LimitCfg {
    busbar_kernel::config::groups::LimitCfg {
        selected: None,
        metric: busbar_kernel::config::groups::LimitMetric::Budget,
        amount: cents,
        per: Some(busbar_kernel::config::groups::LimitWindow::Month),
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
    }
}

#[tokio::test]
async fn test_patch_key_three_state_group_and_enabled() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_09864D86888C";
    const WITNESS: &str = "actual root case test_patch_key_three_state_group_and_enabled completed";
    isolated!(CHILD, WITNESS);
    let groups = std::collections::BTreeMap::from([(
        "eng".to_string(),
        busbar_kernel::config::GroupCfg {
            parent: None,
            enabled: true,
            limits: vec![busbar_kernel::config::groups::LimitCfg {
                selected: None,
                metric: busbar_kernel::config::groups::LimitMetric::Requests,
                amount: 100,
                per: Some(busbar_kernel::config::groups::LimitWindow::Minute),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
            }],
            ..Default::default()
        },
    )]);

    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_patch_key_three_state_group_and_enabled-actual-store",
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
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    document["groups"] = json::to_value(&groups).expect("the actual group definitions serialize");
    let (addr, handle, _book) =
        crate::distribution::rig::actual_root(document, &directory, &module).await;
    let client = reqwest::Client::new();
    let base = format!("http://{addr}/api/v1/admin/keys");

    let created = client
        .post(&base)
        .header("authorization", "Bearer admintok")
        .json(&json::json!({"name": "k"}))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let created = json::parse_value(&created).unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["enabled"], true, "a fresh key is enabled");
    assert!(created["group"].is_null(), "minted without a group");
    let key_url = format!("{base}/{id}");

    let set = client
        .patch(&key_url)
        .header("authorization", "Bearer admintok")
        .json(&json::json!({"group": "eng"}))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let set = json::parse_value(&set).unwrap();
    assert_eq!(
        set["group"], "eng",
        "rebind surfaces the new binding: {set}"
    );

    let dangling = client
        .patch(&key_url)
        .header("authorization", "Bearer admintok")
        .json(&json::json!({"group": "ghost"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        dangling.status().as_u16(),
        400,
        "a rebind target must exist (mint parity)"
    );

    let cleared = client
        .patch(&key_url)
        .header("authorization", "Bearer admintok")
        .json(&json::json!({"group": null}))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let cleared = json::parse_value(&cleared).unwrap();
    assert!(cleared["group"].is_null(), "null unbinds: {cleared}");
    let toggled = client
        .patch(&key_url)
        .header("authorization", "Bearer admintok")
        .json(&json::json!({"enabled": false}))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let toggled = json::parse_value(&toggled).unwrap();
    assert_eq!(toggled["enabled"], false, "enabled toggles");
    assert!(
        toggled["group"].is_null(),
        "an absent group field leaves the (unbound) binding unchanged"
    );

    for gone in [
        json::json!({"rpm_limit": 5}),
        json::json!({"tpm_limit": 99}),
        json::json!({"max_budget_cents": 123}),
    ] {
        let r = client
            .patch(&key_url)
            .header("authorization", "Bearer admintok")
            .json(&gone)
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status().as_u16(),
            400,
            "a removed cap field must fail loudly: {gone}"
        );
    }

    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_mint_auto_provisions_leaf_from_child_default() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_7B9EAABE3676";
    const WITNESS: &str =
        "actual root case test_mint_auto_provisions_leaf_from_child_default completed";
    isolated!(CHILD, WITNESS);
    let groups = std::collections::BTreeMap::from([
        (
            "acme".to_string(),
            busbar_kernel::config::GroupCfg {
                limits: vec![budget_limit(5_000_000)],
                ..Default::default()
            },
        ),
        (
            "team-payments".to_string(),
            busbar_kernel::config::GroupCfg {
                parent: Some("acme".to_string()),
                limits: vec![budget_limit(2_000_000)],
                child_default: Some(busbar_kernel::config::groups::ChildDefault {
                    limits: vec![budget_limit(2000)],
                }),
                ..Default::default()
            },
        ),
    ]);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_mint_auto_provisions_leaf_from_child_default-actual-store",
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
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    document["groups"] = json::to_value(&groups).expect("the actual group definitions serialize");
    let (addr, handle, _book) =
        crate::distribution::rig::actual_root(document, &directory, &module).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("authorization", "Bearer admintok")
        .json(&json::json!({
            "name": "alice-cli",
            "group": "user:alice",
            "parent": "team-payments"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        201,
        "auto-provision + mint succeeds"
    );
    let body = json::parse_value(&resp.bytes().await.unwrap()).unwrap();
    assert_eq!(body["group"], "user:alice", "key bound to the new leaf");
    assert_eq!(
        body["group_provisioned"], true,
        "the mint reports it created the leaf"
    );

    let leaf = client
        .get(format!("http://{addr}/api/v1/admin/groups/user:alice"))
        .header("authorization", "Bearer admintok")
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let leaf = json::parse_value(&leaf).unwrap();
    assert_eq!(leaf["parent"], "team-payments");
    assert_eq!(leaf["enabled"], true);
    assert_eq!(leaf["limits"][0]["metric"], "budget");
    assert_eq!(
        leaf["limits"][0]["amount"], 2000,
        "leaf carries the nearest-ancestor child_default budget"
    );

    assert!(leaf.get("child_default").is_none());

    let usage = client
        .get(format!(
            "http://{addr}/api/v1/admin/groups/user:alice/usage"
        ))
        .header("authorization", "Bearer admintok")
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let usage = json::parse_value(&usage).unwrap();
    let month_bucket = usage["buckets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["window"] == "month")
        .expect("a month bucket exists for the leaf");
    assert_eq!(
        month_bucket["budget_cap"], 2000,
        "the leaf's budget cap is enforced from the stamped template"
    );

    let resp2 = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("authorization", "Bearer admintok")
        .json(&json::json!({
            "name": "alice-cli-2",
            "group": "user:alice",
            "parent": "team-payments"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status().as_u16(), 201);
    let body2 = json::parse_value(&resp2.bytes().await.unwrap()).unwrap();
    assert_eq!(
        body2["group_provisioned"], false,
        "binding to an existing leaf does not re-provision"
    );

    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_mint_parent_mismatch_is_409() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_B60C0101EFA5";
    const WITNESS: &str = "actual root case test_mint_parent_mismatch_is_409 completed";
    isolated!(CHILD, WITNESS);
    let groups = std::collections::BTreeMap::from([
        (
            "team-a".to_string(),
            busbar_kernel::config::GroupCfg {
                limits: vec![budget_limit(1_000_000)],
                ..Default::default()
            },
        ),
        (
            "team-b".to_string(),
            busbar_kernel::config::GroupCfg {
                limits: vec![budget_limit(1_000_000)],
                ..Default::default()
            },
        ),
        (
            "user:bob".to_string(),
            busbar_kernel::config::GroupCfg {
                parent: Some("team-a".to_string()),
                limits: vec![budget_limit(3000)],
                ..Default::default()
            },
        ),
    ]);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) =
        crate::distribution::rig::actual_store("test_mint_parent_mismatch_is_409-actual-store");
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
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    document["groups"] = json::to_value(&groups).expect("the actual group definitions serialize");
    let (addr, handle, _book) =
        crate::distribution::rig::actual_root(document, &directory, &module).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    let resp = client
        .post(&url)
        .header("authorization", "Bearer admintok")
        .json(&json::json!({"name": "k", "group": "user:bob", "parent": "team-b"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 409, "parent mismatch is a conflict");
    let body = json::parse_value(&resp.bytes().await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("already exists with parent"),
        "the 409 explains the re-home refusal: {body}"
    );

    let ok = client
        .post(&url)
        .header("authorization", "Bearer admintok")
        .json(&json::json!({"name": "k2", "group": "user:bob", "parent": "team-a"}))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status().as_u16(), 201, "matching parent binds");

    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_max_keys_per_principal_cap_trips() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_B3E0DC0AF08C";
    const WITNESS: &str = "actual root case test_max_keys_per_principal_cap_trips completed";
    isolated!(CHILD, WITNESS);
    let groups = std::collections::BTreeMap::from([
        (
            "capped".to_string(),
            busbar_kernel::config::GroupCfg {
                limits: vec![budget_limit(1_000_000)],
                ..Default::default()
            },
        ),
        (
            "other".to_string(),
            busbar_kernel::config::GroupCfg {
                limits: vec![budget_limit(1_000_000)],
                ..Default::default()
            },
        ),
    ]);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_max_keys_per_principal_cap_trips-actual-store",
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
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    document["groups"] = json::to_value(&groups).expect("the actual group definitions serialize");
    document["limits"] = json::json!({"max_keys_per_principal": 2});
    let (addr, handle, _book) =
        crate::distribution::rig::actual_root(document, &directory, &module).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");
    let mint = |name: &str, group: &str| {
        client
            .post(&url)
            .header("authorization", "Bearer admintok")
            .json(&json::json!({"name": name, "group": group}))
            .send()
    };

    assert_eq!(mint("a", "capped").await.unwrap().status().as_u16(), 201);
    assert_eq!(mint("b", "capped").await.unwrap().status().as_u16(), 201);

    let r = mint("c", "capped").await.unwrap();
    assert_eq!(
        r.status().as_u16(),
        409,
        "3rd key into a capped group is a conflict"
    );
    let body = json::parse_value(&r.bytes().await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("max_keys_per_principal"),
        "the 409 names the cap: {body}"
    );

    assert_eq!(mint("d", "other").await.unwrap().status().as_u16(), 201);

    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_idempotency_reservation_frees_on_at_cap_refusal() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_6624966B1C92";
    const WITNESS: &str =
        "actual root case test_admin_v1_idempotency_reservation_frees_on_at_cap_refusal completed";
    isolated!(CHILD, WITNESS);
    let groups = std::collections::BTreeMap::from([(
        "capped".to_string(),
        busbar_kernel::config::GroupCfg {
            limits: vec![budget_limit(1_000_000)],
            ..Default::default()
        },
    )]);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_admin_v1_idempotency_reservation_frees_on_at_cap_refusal-actual-store",
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
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    document["groups"] = json::to_value(&groups).expect("the actual group definitions serialize");
    document["limits"] = json::json!({"max_keys_per_principal": 1});
    let (addr, handle, _book) =
        crate::distribution::rig::actual_root(document, &directory, &module).await;
    let client = reqwest::Client::new();
    let keys_url = format!("http://{addr}/api/v1/admin/keys");

    let filler = client
        .post(&keys_url)
        .header("authorization", "Bearer admintok")
        .json(&json::json!({"name": "filler", "group": "capped"}))
        .send()
        .await
        .unwrap();
    assert_eq!(filler.status().as_u16(), 201);
    let filler_id = json::parse_value(&filler.bytes().await.unwrap()).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let at_cap = client
        .post(&keys_url)
        .header("authorization", "Bearer admintok")
        .header("idempotency-key", "reuse-at-cap")
        .json(&json::json!({"name": "second", "group": "capped"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        at_cap.status().as_u16(),
        409,
        "the reserving mint trips the cap"
    );

    let deleted = client
        .delete(format!("{keys_url}/{filler_id}"))
        .header("authorization", "Bearer admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status().as_u16(), 204);

    let retry = client
        .post(&keys_url)
        .header("authorization", "Bearer admintok")
        .header("idempotency-key", "reuse-at-cap")
        .json(&json::json!({"name": "second", "group": "capped"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        retry.status().as_u16(),
        201,
        "a retry under the same key mints once capacity is free — the AtCap reservation was \
         released, not stuck in-flight: {}",
        retry.text().await.unwrap_or_default()
    );

    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_max_keys_per_principal_atomic_under_concurrent_mint() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_4DA88626C3DB";
    const WITNESS: &str =
        "actual root case test_max_keys_per_principal_atomic_under_concurrent_mint completed";
    isolated!(CHILD, WITNESS);
    let groups = std::collections::BTreeMap::from([(
        "capped".to_string(),
        busbar_kernel::config::GroupCfg {
            limits: vec![budget_limit(1_000_000)],
            ..Default::default()
        },
    )]);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_max_keys_per_principal_atomic_under_concurrent_mint-actual-store",
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
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    document["groups"] = json::to_value(&groups).expect("the actual group definitions serialize");
    document["limits"] = json::json!({"max_keys_per_principal": 3});
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
    let gov = app.governance.as_ref().expect("actual governance").clone();
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");
    let mint = |name: String| {
        let client = client.clone();
        let url = url.clone();
        async move {
            client
                .post(&url)
                .header("authorization", "Bearer admintok")
                .json(&json::json!({"name": name, "group": "capped"}))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };

    assert_eq!(mint("seed-a".to_string()).await, 201);
    assert_eq!(mint("seed-b".to_string()).await, 201);

    let mut set = tokio::task::JoinSet::new();
    for i in 0..6 {
        set.spawn(mint(format!("race-{i}")));
    }
    let mut statuses = Vec::new();
    while let Some(res) = set.join_next().await {
        statuses.push(res.unwrap());
    }
    let created = statuses.iter().filter(|s| **s == 201).count();
    let conflicts = statuses.iter().filter(|s| **s == 409).count();
    assert_eq!(
        created, 1,
        "exactly ONE concurrent mint may fill the last cap slot (got {created} 201s): {statuses:?}"
    );
    assert_eq!(
        conflicts, 5,
        "the other five concurrent mints must 409 at the cap: {statuses:?}"
    );

    let n = gov
        .all_keys_async()
        .await
        .unwrap()
        .iter()
        .filter(|k| k.group.as_deref() == Some("capped"))
        .count();
    assert_eq!(
        n, 3,
        "the group must end at EXACTLY the cap under concurrency, never over it (got {n})"
    );

    handle.abort();
    println!("{WITNESS}");
}

/// SECURITY (v1.6 `key_cap_and_delegation_refusals_are_reachable_declared_and_audited`, PROOF-093-E
/// row 217): every refused mint is audited. A mint past `limits.max_keys_per_principal`, a mint
/// naming a parent other than its group's existing one, and a mint naming a parent with no group
/// each write one `key.create` / `rejected` row for the operator (resource `key:-`: no key was
/// issued), and a rebind of an existing key into an at-cap group writes `key.patch` / `rejected`
/// on that key. Nothing refused is recorded as applied.
#[tokio::test]
async fn key_cap_and_delegation_refusals_are_reachable_declared_and_audited() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_727F6FCE3A24";
    const WITNESS: &str =
        "actual root case key_cap_and_delegation_refusals_are_reachable_declared_and_audited completed";
    isolated!(CHILD, WITNESS);
    let groups = std::collections::BTreeMap::from([
        (
            "capped".to_string(),
            busbar_kernel::config::GroupCfg {
                limits: vec![budget_limit(1_000_000)],
                ..Default::default()
            },
        ),
        (
            "roomy".to_string(),
            busbar_kernel::config::GroupCfg {
                limits: vec![budget_limit(1_000_000)],
                ..Default::default()
            },
        ),
        (
            "user:bob".to_string(),
            busbar_kernel::config::GroupCfg {
                parent: Some("roomy".to_string()),
                limits: vec![budget_limit(3000)],
                ..Default::default()
            },
        ),
    ]);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "key_cap_and_delegation_refusals_are_reachable_declared_and_audited-actual-store",
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
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    document["groups"] = json::to_value(&groups).expect("the actual group definitions serialize");
    document["limits"] = json::json!({"max_keys_per_principal": 2});
    let (addr, handle, _book) =
        crate::distribution::rig::actual_root(document, &directory, &module).await;
    let client = reqwest::Client::new();
    let keys_url = format!("http://{addr}/api/v1/admin/keys");
    let mint = |body: json::Value| {
        client
            .post(&keys_url)
            .header("authorization", "Bearer admintok")
            .json(&body)
            .send()
    };
    let rows = |action: &'static str| {
        let request = client
            .get(format!("http://{addr}/api/v1/admin/audit"))
            .query(&[("action", action)])
            .header("authorization", "Bearer admintok")
            .send();
        async move {
            let r = request.await.unwrap();
            assert_eq!(r.status().as_u16(), 200, "the audit rows are readable");
            json::parse_value(&r.bytes().await.unwrap()).unwrap()["items"]
                .as_array()
                .expect("the audit response has items")
                .clone()
        }
    };
    let rejected = |items: &[json::Value], resource: &str| {
        items
            .iter()
            .filter(|e| e["outcome"] == "rejected" && e["resource"] == resource)
            .count()
    };

    for name in ["a", "b"] {
        let r = mint(json::json!({"name": name, "group": "capped"}))
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 201, "mint {name} under the cap");
    }
    let roamer = mint(json::json!({"name": "roamer", "group": "roomy"}))
        .await
        .unwrap();
    assert_eq!(roamer.status().as_u16(), 201);
    let roamer = json::parse_value(&roamer.bytes().await.unwrap()).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        rejected(&rows("key.create").await, "key:-"),
        0,
        "no refusal yet, so no rejected mint row"
    );

    let refusals = [
        (
            json::json!({"name": "c", "group": "capped"}),
            409,
            "max_keys_per_principal",
        ),
        (
            json::json!({"name": "d", "group": "user:bob", "parent": "capped"}),
            409,
            "already exists with parent",
        ),
        (
            json::json!({"name": "e", "parent": "roomy"}),
            400,
            "`parent` was given without `group`",
        ),
    ];
    for (n, (body, status, names)) in refusals.into_iter().enumerate() {
        let r = mint(body.clone()).await.unwrap();
        assert_eq!(r.status().as_u16(), status, "refused mint {body}");
        let answer = json::parse_value(&r.bytes().await.unwrap()).unwrap();
        assert!(
            answer["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains(names),
            "the refusal names its cause: {answer}"
        );
        let items = rows("key.create").await;
        assert_eq!(
            rejected(&items, "key:-"),
            n + 1,
            "refused mint {body} wrote exactly one rejected key.create row: {items:?}"
        );
    }
    let applied = rows("key.create")
        .await
        .iter()
        .filter(|e| e["outcome"] == "applied")
        .count();
    assert_eq!(applied, 3, "only the three issued keys are recorded applied");

    let r = client
        .patch(format!("{keys_url}/{roamer}"))
        .header("authorization", "Bearer admintok")
        .json(&json::json!({"group": "capped"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 409, "a rebind into an at-cap group");
    let resource = format!("key:{roamer}");
    let items = rows("key.patch").await;
    assert_eq!(
        rejected(&items, &resource),
        1,
        "the refused rebind of {resource} left one rejected key.patch row: {items:?}"
    );

    handle.abort();
    println!("{WITNESS}");
}
