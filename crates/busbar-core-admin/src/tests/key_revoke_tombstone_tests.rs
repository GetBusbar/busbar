// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::audit_ring;
use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
use busbar_kernel::governance::GovState;
use busbar_kernel_testkit::test_support::store_double::MemoryStore;
use std::sync::Arc;

const X_ADMIN_TOKEN: &str = "x-admin-token";

#[tokio::test]
async fn revoke_on_an_already_tombstoned_key_answers_200_and_audits_applied() {
    busbar_kernel_testkit::test_support::metrics::init();

    let store = Arc::new(MemoryStore::new());
    let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(store, Some("admintok".to_string()), Some(signer)).unwrap(),
    );
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    let create_resp = client
        .post(&url)
        .header(X_ADMIN_TOKEN, "admintok")
        .json(&serde_json::json!({"name": "tombstone-then-revoke"}))
        .send()
        .await
        .unwrap();
    let create_status = create_resp.status();
    let created: serde_json::Value = create_resp.json().await.unwrap();
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
    let body: serde_json::Value = client
        .post(format!("{url}/{id}/revoke"))
        .header(X_ADMIN_TOKEN, "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
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
}
