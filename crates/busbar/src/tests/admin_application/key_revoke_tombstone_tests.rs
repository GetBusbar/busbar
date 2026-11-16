// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::sync::Arc;

use busbar_contract::json::{self, JsonValueTrait};
use busbar_kernel::audit_ring;

const X_ADMIN_TOKEN: &str = "x-admin-token";

#[tokio::test]
async fn revoke_on_an_already_tombstoned_key_answers_200_and_audits_applied() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_0FDEBCA26962";
    const WITNESS: &str = "actual root case revoke_on_an_already_tombstoned_key_answers_200_and_audits_applied completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) =
        crate::distribution::rig::actual_store("admin-revoke-tombstone-actual-store");
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
    let app = Arc::new(app);
    busbar_kernel::boot::hydrate_all(&app)
        .await
        .expect("the actual root hydrates the revoke audit stream");
    let router = busbar_kernel::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    let create_resp = client
        .post(&url)
        .header(X_ADMIN_TOKEN, "admintok")
        .json(&json::json!({"name": "tombstone-then-revoke"}))
        .send()
        .await
        .unwrap();
    let create_status = create_resp.status();
    let created = json::parse_value(&create_resp.bytes().await.unwrap()).unwrap();
    let id = created["id"]
        .as_str()
        .unwrap_or_else(|| {
            panic!("create key must return an id (status {create_status}): {created}")
        })
        .to_string();

    let del = client
        .delete(format!("{url}/{id}"))
        .header(X_ADMIN_TOKEN, "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(del.status().as_u16(), 204, "delete must succeed first");

    let before = busbar_kernel::audit::auditlog::AUDIT_LOG
        .list_filtered(0, audit_ring::MAX_AUDIT_ENTRIES, None, None)
        .iter()
        .filter(|e| e.resource == format!("key:{id}") && e.action == "key.revoke")
        .count();

    let revoked = client
        .post(format!("{url}/{id}/revoke"))
        .header(X_ADMIN_TOKEN, "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        revoked.status().as_u16(),
        200,
        "revoke on a tombstoned key must be 200, not 404: {:?}",
        revoked.text().await
    );
    let body = json::parse_value(
        &client
            .post(format!("{url}/{id}/revoke"))
            .header(X_ADMIN_TOKEN, "admintok")
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["revoked"], id.as_str());

    let after = busbar_kernel::audit::auditlog::AUDIT_LOG
        .list_filtered(0, audit_ring::MAX_AUDIT_ENTRIES, None, None)
        .iter()
        .filter(|e| {
            e.resource == format!("key:{id}")
                && e.action == "key.revoke"
                && e.outcome == audit_ring::OUTCOME_APPLIED
        })
        .count();
    assert!(
        after > before,
        "revoking a tombstoned key must write a key.revoke/applied audit row"
    );

    handle.abort();
    println!("{WITNESS}");
}
