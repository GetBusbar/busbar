// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RFC 9449 AT THE DOOR, the half this crate can prove without an authorization server: what a
//! bearer that was never DPoP-bound gets (exactly what it got before), what a DPoP presentation gets
//! when no `oauth_as:` plane is configured (exactly what 1.5.5 gave it: the header is not a
//! credential carrier), and that a DPoP-BOUND token presented as a bearer is refused. The proof
//! verification itself runs through the authorization-server seam, so its tests live with the
//! plane (`busbar-core-oauth2`'s `fapi2_tests`).

use base64::Engine as _;

use super::is_dpop_bound;
use crate::test_support::TestApp;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// A JWS-shaped token over `claims`. Never signature-checked here: the test IdP stand-in identifies
/// any non-empty credential, which is the chain a real IdP plugin would stand in.
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

/// `(status, body)` of `GET /stats` with `headers`, on a deployment whose chain identifies any
/// credential and that runs NO authorization server.
async fn stats(headers: &[(&str, String)]) -> (u16, String) {
    crate::snapshot::init();
    let app = TestApp::new().idp_chain().build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let mut req = reqwest::Client::new().get(format!("http://{addr}/stats"));
    for (k, v) in headers {
        req = req.header(*k, v);
    }
    let resp = req.send().await.unwrap();
    let out = (resp.status().as_u16(), resp.text().await.unwrap());
    handle.abort();
    out
}

/// THE BEARER PATH DOES NOT MOVE for a token that was never DPoP-bound: an unbound JWT and an opaque
/// token are admitted exactly as before, and the refusal for a missing credential is the same bytes
/// it was.
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

/// WITH NO AUTHORIZATION SERVER, `Authorization: DPoP` is what it was in 1.5.5: not a credential
/// carrier. The response is byte-identical to the same request carrying no credential at all.
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

/// RFC 9449 s7.1: a DPoP-bound token is not a bearer token. Presented as one it is refused, with
/// the refusal an invalid credential gets.
#[tokio::test]
async fn a_dpop_bound_token_presented_as_a_bearer_is_refused() {
    let bound = jwt(serde_json::json!({ "sub": "a", "cnf": { "jkt": "abc" } }));
    let (status, _) = stats(&[("authorization", format!("Bearer {bound}"))]).await;
    assert_eq!(status, 401);
    let (status, _) = stats(&[("x-api-key", bound)]).await;
    assert_eq!(status, 401, "whichever carrier presents it as a bearer");
}
