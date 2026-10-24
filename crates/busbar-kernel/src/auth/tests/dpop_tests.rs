// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RFC 9449 AT THE DOOR, the half this crate can prove without an authorization server: what a
//! bearer that was never DPoP-bound gets (exactly what it got before), what a DPoP presentation gets
//! when no `oauth_as:` plane is configured (exactly what 1.5.5 gave it: the header is not a
//! credential carrier), and that a DPoP-BOUND token presented as a bearer is refused where an
//! authorization server runs and admitted as 1.5.5 admitted it where none does. The proof
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
    stats_on(headers, false).await
}

/// [`stats`], on a deployment that runs an authorization server when `authorization_server` (an
/// opaque stand-in handle: the door reads only that one is configured before it refuses a bound
/// bearer).
async fn stats_on(headers: &[(&str, String)], authorization_server: bool) -> (u16, String) {
    crate::snapshot::init();
    let mut app = TestApp::new().idp_chain();
    if authorization_server {
        app = app.oauth_as_plane(std::sync::Arc::new(()));
    }
    let app = app.build();
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

/// RFC 9449 s7.1: a DPoP-bound token is not a bearer token, where this deployment runs the
/// authorization server that binds tokens. Presented as one there, it is refused with the refusal
/// an invalid credential gets.
#[tokio::test]
async fn with_an_authorization_server_a_dpop_bound_bearer_is_refused() {
    let bound = jwt(serde_json::json!({ "sub": "a", "cnf": { "jkt": "abc" } }));
    let (status, _) = stats_on(&[("authorization", format!("Bearer {bound}"))], true).await;
    assert_eq!(status, 401);
    let (status, _) = stats_on(&[("x-api-key", bound)], true).await;
    assert_eq!(status, 401, "whichever carrier presents it as a bearer");
}

/// WITH NO AUTHORIZATION SERVER a token carrying `cnf.jkt` is a bearer like any other, exactly as
/// 1.5.5 judged it (THE DESIGN §2 PORT R7/R8: the default is 1.5.5's behaviour). RED: the door
/// refused every bound bearer whatever the config, so an operator IdP token 1.5.5 admitted was a
/// 401 here.
#[tokio::test]
async fn without_an_authorization_server_a_dpop_bound_bearer_is_admitted_as_1_5_5_did() {
    let bound = jwt(serde_json::json!({ "sub": "a", "cnf": { "jkt": "abc" } }));
    let (status, _) = stats(&[("authorization", format!("Bearer {bound}"))]).await;
    assert_eq!(status, 200);
    let (status, _) = stats(&[("x-api-key", bound)]).await;
    assert_eq!(status, 200, "whichever carrier presents it as a bearer");
}

/// `(status, body)` of `POST /auth/token` with `headers`, on the deployment [`stats`] reads, with
/// an authorization server (`oauth_as:`) when `serving_as`.
async fn exchanged(serving_as: bool, headers: &[(&str, String)]) -> (u16, String) {
    crate::snapshot::init();
    let mut app = TestApp::new().idp_chain();
    if serving_as {
        // The bound-bearer refusal reads only that a server runs, never the server itself.
        app = app.oauth_as_plane(std::sync::Arc::new(()));
    }
    let app = app.build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let mut req = reqwest::Client::new().post(format!("http://{addr}/auth/token"));
    for (k, v) in headers {
        req = req.header(*k, v);
    }
    let resp = req.send().await.unwrap();
    let out = (resp.status().as_u16(), resp.text().await.unwrap());
    handle.abort();
    out
}

/// RED (Q128 kernel part 10, MEDIUM): WHERE THIS DEPLOYMENT RUNS ITS OWN AUTHORIZATION SERVER, THE
/// TOKEN EXCHANGE HOLDS THE SENDER CONSTRAINT the data plane holds. `POST /auth/token` runs the
/// chain itself, past the middleware's RFC 9449 judgement, so a DPoP-bound token presented there as
/// a bearer reached the mint and could be swapped for an unbound key. It is refused as an
/// unauthenticated caller now; an unbound bearer still reaches the grant check exactly as before.
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

/// 1.5.5 PARITY (v1.5.5 `crates/busbar/src/auth/exchange.rs`, which reads no DPoP; its refusals at
/// l.113-117): WITH NO AUTHORIZATION SERVER the exchange answers a 1.5.5-shaped request exactly as
/// before, byte for byte, whatever the presented token's claims. A token carrying `cnf.jkt` and the
/// same token's subject without it get the same answer.
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
