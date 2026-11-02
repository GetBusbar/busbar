// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use base64::Engine as _;

use super::is_dpop_bound;
use crate::test_support::TestApp;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn jwt(claims: serde_json::Value) -> String {
    format!(
        "{}.{}.c2ln",
        B64.encode(r#"{"alg":"ES256","typ":"at+jwt"}"#),
        B64.encode(claims.to_string())
    )
}

#[test]
fn only_a_token_carrying_cnf_jkt_is_dpop_bound() {
    assert!(is_dpop_bound(&jwt(
        serde_json::json!({ "sub": "a", "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" } })
    )));
    assert!(!is_dpop_bound(&jwt(serde_json::json!({ "sub": "a" }))));
    assert!(!is_dpop_bound(&jwt(
        serde_json::json!({ "sub": "a", "cnf": { "x5t#S256": "abc" } })
    )));
    assert!(!is_dpop_bound(&jwt(
        serde_json::json!({ "sub": "a", "cnf": { "jkt": 7 } })
    )));
    assert!(!is_dpop_bound("an-opaque-reference-token"));
    assert!(!is_dpop_bound(&format!(
        "{}{}",
        crate::governance::signing::TOKEN_PREFIX,
        "whatever.has.dots"
    )));
}

async fn stats(headers: &[(&str, String)]) -> (u16, String) {
    served(reqwest::Method::GET, "/stats", headers, false).await
}

async fn served(
    method: reqwest::Method,
    path: &str,
    headers: &[(&str, String)],
    authorization_server: bool,
) -> (u16, String) {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let mut app = TestApp::new().idp_chain();
    if authorization_server {
        app = app.oauth_as_plane(std::sync::Arc::new(()));
    }
    let app = app.build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let mut req = reqwest::Client::new().request(method, format!("http://{addr}{path}"));
    for (k, v) in headers {
        req = req.header(*k, v);
    }
    let resp = req.send().await.unwrap();
    let out = (resp.status().as_u16(), resp.text().await.unwrap());
    handle.abort();
    out
}

#[tokio::test]
async fn an_unbound_bearer_is_judged_exactly_as_before() {
    let (status, _) = stats(&[(
        "authorization",
        format!("Bearer {}", jwt(serde_json::json!({ "sub": "a" }))),
    )])
    .await;
    assert_eq!(status, 200, "an unbound JWT bearer is admitted");
    let (status, _) = stats(&[("authorization", "Bearer opaque-token".to_string())]).await;
    assert_eq!(status, 200, "an opaque bearer is admitted");
}

#[tokio::test]
async fn without_an_authorization_server_a_dpop_presentation_is_no_credential() {
    let bound = jwt(serde_json::json!({ "sub": "a", "cnf": { "jkt": "abc" } }));
    let absent = stats(&[]).await;
    let dpop = stats(&[
        ("authorization", format!("DPoP {bound}")),
        ("dpop", "a.b.c".to_string()),
    ])
    .await;
    assert_eq!(absent.0, 401, "the chain requires a credential");
    assert_eq!(
        dpop, absent,
        "the DPoP header is not a credential carrier here"
    );
}

#[tokio::test]
async fn with_an_authorization_server_a_dpop_bound_bearer_is_refused() {
    let bound = jwt(serde_json::json!({ "sub": "a", "cnf": { "jkt": "abc" } }));
    let (status, _) = served(
        reqwest::Method::GET,
        "/stats",
        &[("authorization", format!("Bearer {bound}"))],
        true,
    )
    .await;
    assert_eq!(status, 401);
    let (status, _) = served(
        reqwest::Method::GET,
        "/stats",
        &[("x-api-key", bound)],
        true,
    )
    .await;
    assert_eq!(status, 401, "whichever carrier presents it as a bearer");
}

#[tokio::test]
async fn without_an_authorization_server_a_dpop_bound_bearer_is_admitted_as_1_5_5_did() {
    let bound = jwt(serde_json::json!({ "sub": "a", "cnf": { "jkt": "abc" } }));
    let (status, _) = stats(&[("authorization", format!("Bearer {bound}"))]).await;
    assert_eq!(status, 200);
    let (status, _) = stats(&[("x-api-key", bound)]).await;
    assert_eq!(status, 200, "whichever carrier presents it as a bearer");
}

async fn exchanged(serving_as: bool, headers: &[(&str, String)]) -> (u16, String) {
    served(reqwest::Method::POST, "/auth/token", headers, serving_as).await
}

#[tokio::test]
async fn the_token_exchange_refuses_a_dpop_bound_token_presented_as_a_bearer() {
    let bound = jwt(serde_json::json!({ "sub": "a", "cnf": { "jkt": "abc" } }));
    let (status, body) = exchanged(true, &[("authorization", format!("Bearer {bound}"))]).await;
    assert_eq!(
        (status, body.as_str()),
        (401, r#"{"error":"not authenticated"}"#),
        "a bound token is no bearer at the exchange either"
    );
    let unbound = jwt(serde_json::json!({ "sub": "a" }));
    let (status, _) = exchanged(true, &[("authorization", format!("Bearer {unbound}"))]).await;
    assert_ne!(
        status, 401,
        "an unbound bearer is identified and judged by the grant, as before"
    );
}

#[tokio::test]
async fn without_an_authorization_server_the_exchange_answers_as_1_5_5_did() {
    let bound = jwt(serde_json::json!({ "sub": "a", "cnf": { "jkt": "abc" } }));
    let unbound = jwt(serde_json::json!({ "sub": "a" }));
    let as_bound = exchanged(false, &[("authorization", format!("Bearer {bound}"))]).await;
    let as_unbound = exchanged(false, &[("authorization", format!("Bearer {unbound}"))]).await;
    assert_eq!(as_bound, as_unbound, "the claims move nothing here");
    assert_ne!(
        as_bound.0, 401,
        "an identified caller is never refused as unauthenticated"
    );
    let no_credential = exchanged(false, &[]).await;
    assert_eq!(
        no_credential,
        (401, r#"{"error":"not authenticated"}"#.to_string()),
        "v1.5.5 exchange.rs l.113: no identity, its words"
    );
}
