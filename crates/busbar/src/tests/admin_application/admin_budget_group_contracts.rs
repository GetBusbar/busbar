// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::sync::Arc;

use busbar_contract::json::{self, JsonValueTrait as _};
use busbar_kernel::governance::NewKeySpec;

fn budget_limit(cents: u64) -> busbar_kernel::config::groups::LimitCfg {
    busbar_kernel::config::groups::LimitCfg {
        metric: busbar_kernel::config::groups::LimitMetric::Budget,
        amount: cents,
        per: Some(busbar_kernel::config::groups::LimitWindow::Month),
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
    }
}

#[tokio::test]
async fn test_create_key_budget_group_and_labels_roundtrip_and_missing_group_400() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_196DAFDB1E1F";
    const WITNESS: &str = "actual root case test_create_key_budget_group_and_labels_roundtrip_and_missing_group_400 completed";
    isolated!(CHILD, WITNESS);
    let groups = std::collections::BTreeMap::from([(
        "growth".to_string(),
        busbar_kernel::config::GroupCfg {
            parent: None,
            enabled: true,
            limits: vec![busbar_kernel::config::groups::LimitCfg {
                metric: busbar_kernel::config::groups::LimitMetric::Budget,
                amount: 1_000_000,
                per: Some(busbar_kernel::config::groups::LimitWindow::Month),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
            }],
            ..Default::default()
        },
    )]);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_create_key_budget_group_and_labels_roundtrip_and_missing_group_400-actual-store",
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
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    document["groups"] =
        serde_json::to_value(&groups).expect("the original group definitions serialize");
    let (addr, handle, _book) =
        crate::distribution::rig::actual_root(document, &directory, &module).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    let resp = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .json(&json::json!({"name": "k", "group": "ghost"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    let body = json::parse_value(&resp.bytes().await.unwrap()).unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("group 'ghost' does not exist"),
        "the 400 names the missing group: {body}"
    );

    let resp = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .json(&json::json!({
            "name": "grouped",
            "group": "growth",
            "labels": {"team": "growth", "env": "prod"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201, "configured group mints");
    let body = json::parse_value(&resp.bytes().await.unwrap()).unwrap();
    assert_eq!(body["group"], "growth");
    assert_eq!(body["labels"]["env"], "prod");
    let id = body["id"].as_str().unwrap().to_string();

    let list = json::parse_value(
        &client
            .get(&url)
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    let row = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["id"] == id.as_str())
        .expect("minted key listed");
    assert_eq!(row["group"], "growth");
    assert_eq!(row["labels"]["team"], "growth");

    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_patch_no_op_on_an_already_counted_key_is_not_an_admission() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_17A19051983C";
    const WITNESS: &str = "actual root case test_admin_v1_patch_no_op_on_an_already_counted_key_is_not_an_admission completed";
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
        "test_admin_v1_patch_no_op_on_an_already_counted_key_is_not_an_admission-actual-store",
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
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    document["groups"] =
        serde_json::to_value(&groups).expect("the original group definitions serialize");
    document["limits"] = serde_json::json!({"max_keys_per_principal": 1});
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
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(
        &config,
        &plugin_config,
        &busbar_kernel::preflight::Unopened,
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
    let gov = app.governance.as_ref().expect("actual governance").clone();
    let mint = async |name: &str| {
        gov.mint_signed_async(
            NewKeySpec {
                name: name.to_string(),
                allowed_pools: None,
                group: Some("capped".to_string()),
                labels: Default::default(),
                ..Default::default()
            },
            busbar_kernel::store::now() + 86_400,
            busbar_kernel::store::now(),
        )
        .await
        .expect("mint")
        .0
    };
    let a = mint("a").await;
    let _b = mint("b").await;

    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let noop = client
        .patch(format!("http://{addr}/api/v1/admin/keys/{}", a.id))
        .header("x-admin-token", "admintok")
        .json(&json::json!({}))
        .send()
        .await
        .unwrap();
    let status = noop.status().as_u16();
    let body = noop.text().await.unwrap_or_default();
    assert_eq!(
        status, 200,
        "a true no-op PATCH on an already-counted key must not be treated as a NEW admission to \
         its bucket, even though the bucket is now over a since-tightened cap: {body}"
    );

    handle.abort();
    println!("{WITNESS}");
}
