// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde_json::Value;
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

#[tokio::test]
async fn the_browser_device_routes_require_admin_and_public_registration_keeps_its_grant_policy() {
    let (origin, _app) = super::consent_tests::serve(&["read"], true).await;
    let client = reqwest::Client::new();
    for method in [reqwest::Method::GET, reqwest::Method::POST] {
        let response = client
            .request(method, format!("{origin}/device"))
            .form(&[("user_code", "ABCD-EFGH"), ("action", "approve")])
            .send()
            .await
            .unwrap();
        assert!(matches!(response.status().as_u16(), 401 | 403));
        let page = response.text().await.unwrap();
        assert!(!page.contains("csrf_token") && !page.contains("ABCD-EFGH"));
    }
    let response = client
        .post(format!("{origin}/register"))
        .json(&serde_json::json!({
            "redirect_uris": ["https://client.example/cb"],
            "grant_types": [DEVICE_GRANT],
            "token_endpoint_auth_method": "none",
        }))
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_client_error(),
        "public registration cannot enable device grants"
    );
    let registration = client
        .post(format!("{origin}/register"))
        .json(&serde_json::json!({
            "redirect_uris":["https://client.example/cb"],"grant_types":["authorization_code"],
            "token_endpoint_auth_method":"none","scope":"read",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(registration.status(), 201);
    let registration: Value = registration.json().await.unwrap();
    let code_client = registration["client_id"].as_str().unwrap();
    let response = client
        .post(format!("{origin}/device_authorization"))
        .form(&[("client_id", code_client), ("scope", "read")])
        .send()
        .await
        .unwrap();
    assert!(response.status().is_client_error());
    let error: Value = response.json().await.unwrap();
    assert_eq!(
        error["error"], "unauthorized_client",
        "a pre-existing code-only registration does not gain device permission"
    );
}
