// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Binding: `POST /keys/{id}/revoke` is gated on `get_key().is_some()`, not `is_live()` — a key
//! that has ALREADY been deleted (tombstoned) still has a row a store can return, so revoking it
//! answers `200 {"revoked": "<id>"}` and writes a `key.revoke` / `applied` audit row, rather than
//! the 404 a truly nonexistent id gets. Driven end to end through the real router (mint, DELETE,
//! then revoke) so the admin handler under test is the shipped one, not a reimplementation.

use crate::governance::signing::{TokenSigner, DEFAULT_KID};
use crate::governance::{GovState, MemoryStore};
use crate::test_support::TestApp;
use std::sync::Arc;

const X_ADMIN_TOKEN: &str = "x-admin-token";

#[cfg(feature = "auth-admin-tokens")]
#[tokio::test]
async fn revoke_on_an_already_tombstoned_key_answers_200_and_audits_applied() {
    crate::metrics::init();

    let store = Arc::new(MemoryStore::new());
    let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(store, Some("admintok".to_string()), Some(signer)).unwrap(),
    );
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    // Mint a key.
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

    // DELETE it: the row is tombstoned (still readable by id), not erased.
    let del = client
        .delete(format!("{url}/{id}"))
        .header(X_ADMIN_TOKEN, "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(del.status().as_u16(), 204, "delete must succeed first");

    // A unique marker so this test's own audit rows are distinguishable from any other test
    // sharing the process-global AUDIT ring.
    let before = crate::admin::audit::AUDIT
        .export()
        .iter()
        .filter(|e| e.resource == format!("key:{id}") && e.action == "key.revoke")
        .count();

    // Revoking the already-tombstoned key must still answer 200, not 404: the gate is
    // `get_key().is_some()`, and a tombstoned row is still `Some`.
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

    // A `key.revoke` / `applied` audit row landed for this key.
    let after = crate::admin::audit::AUDIT
        .export()
        .iter()
        .filter(|e| {
            e.resource == format!("key:{id}")
                && e.action == "key.revoke"
                && e.outcome == crate::admin::audit::OUTCOME_APPLIED
        })
        .count();
    assert!(
        after > before,
        "revoking a tombstoned key must write a key.revoke/applied audit row"
    );

    handle.abort();
}
