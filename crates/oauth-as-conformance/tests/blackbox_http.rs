//! Black-box response-shape conformance against the LIVE AS, including the negative cases:
//! an AS that never rejects anything passes a happy-path suite, so most of this file exists
//! to prove the AS says no, with the RFC-defined error shape, when it must.
//!
//! Every test is `#[ignore]` so that a plain `cargo test --workspace` (no AS running) stays
//! green; `scripts/oauth-conformance.sh` runs them with `--ignored` after starting the AS,
//! and the tests themselves FAIL LOUDLY (see `common::base_url`) if the AS is missing.

mod common;

use common::{
    assert_error_body, endpoint, metadata, no_redirect_client, obtain_auth_code,
    CONFIDENTIAL_CLIENT_ID, PUBLIC_CLIENT_ID, PUBLIC_REDIRECT_URI,
};
use oauth_as_conformance as conf;
use serde_json::Value;

/// RFC 8414: metadata is conformant AND each advertised endpoint actually answers OAuth
/// requests (an advertised endpoint that 404s is a metadata lie).
#[tokio::test]
#[ignore = "black-box: needs the live AS; run via scripts/oauth-conformance.sh"]
async fn metadata_is_conformant_and_advertised_endpoints_exist() {
    let http = no_redirect_client();
    let meta = metadata(&http).await;

    // token_endpoint: a garbage POST must yield an RFC 6749 s5.2 error, never a 404/405.
    let resp = http
        .post(endpoint(&meta, "token_endpoint"))
        .form(&[("junk", "junk")])
        .send()
        .await
        .expect("POST token_endpoint");
    assert_ne!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "advertised token_endpoint 404s"
    );
    assert_error_body(resp, "token_endpoint with no grant_type").await;

    // device_authorization_endpoint: POST without client authentication/identification.
    let resp = http
        .post(endpoint(&meta, "device_authorization_endpoint"))
        .form(&[("junk", "junk")])
        .send()
        .await
        .expect("POST device_authorization_endpoint");
    assert_ne!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "advertised device_authorization_endpoint 404s"
    );
    assert_error_body(resp, "device_authorization_endpoint with no client_id").await;

    // authorization_endpoint: must exist. Without a valid client_id the AS MUST NOT redirect
    // (RFC 6749 s4.1.2.1) and must not 404.
    let resp = http
        .get(endpoint(&meta, "authorization_endpoint"))
        .send()
        .await
        .expect("GET authorization_endpoint");
    assert_ne!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "advertised authorization_endpoint 404s"
    );
    assert!(
        !resp.status().is_redirection(),
        "authorization_endpoint redirected without a validated client_id/redirect_uri \
         (RFC 6749 s4.1.2.1 forbids that)"
    );

    // jwks_uri, when advertised, must serve an RFC 7517 key set.
    if let Some(jwks_uri) = meta.get("jwks_uri").and_then(Value::as_str) {
        let jwks: Value = http
            .get(jwks_uri)
            .send()
            .await
            .expect("GET jwks_uri")
            .json()
            .await
            .expect("jwks_uri must serve JSON (RFC 7517 s5)");
        assert!(
            jwks.get("keys")
                .and_then(Value::as_array)
                .is_some_and(|k| !k.is_empty()),
            "jwks_uri must serve a non-empty \"keys\" array (RFC 7517 s5)"
        );
    }
}

/// RFC 6749 s5.2: an unsupported grant type must be named as such, not merely 400ed.
#[tokio::test]
#[ignore = "black-box: needs the live AS; run via scripts/oauth-conformance.sh"]
async fn token_rejects_unsupported_grant_type() {
    let http = no_redirect_client();
    let meta = metadata(&http).await;
    let resp = http
        .post(endpoint(&meta, "token_endpoint"))
        .form(&[
            ("grant_type", "magic-beans"),
            ("client_id", PUBLIC_CLIENT_ID),
        ])
        .send()
        .await
        .expect("POST token");
    let body = assert_error_body(resp, "unsupported grant_type").await;
    assert_eq!(
        body["error"], "unsupported_grant_type",
        "RFC 6749 s5.2 defines unsupported_grant_type for exactly this case"
    );
}

/// RFC 6749 s5.2: missing grant_type is a malformed request.
#[tokio::test]
#[ignore = "black-box: needs the live AS; run via scripts/oauth-conformance.sh"]
async fn token_rejects_missing_grant_type() {
    let http = no_redirect_client();
    let meta = metadata(&http).await;
    let resp = http
        .post(endpoint(&meta, "token_endpoint"))
        .form(&[("client_id", PUBLIC_CLIENT_ID)])
        .send()
        .await
        .expect("POST token");
    let body = assert_error_body(resp, "missing grant_type").await;
    assert_eq!(
        body["error"], "invalid_request",
        "RFC 6749 s5.2: missing parameter"
    );
}

/// RFC 6749 s5.2: wrong client secret via HTTP Basic MUST yield 401 + WWW-Authenticate and
/// error code invalid_client.
#[tokio::test]
#[ignore = "black-box: needs the live AS; run via scripts/oauth-conformance.sh"]
async fn token_rejects_wrong_client_authentication() {
    let http = no_redirect_client();
    let meta = metadata(&http).await;
    let resp = http
        .post(endpoint(&meta, "token_endpoint"))
        .basic_auth(CONFIDENTIAL_CLIENT_ID, Some("definitely-the-wrong-secret"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "irrelevant"),
            ("redirect_uri", PUBLIC_REDIRECT_URI),
        ])
        .send()
        .await
        .expect("POST token");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "RFC 6749 s5.2: failed Authorization-header client auth MUST be 401"
    );
    assert!(
        resp.headers()
            .contains_key(reqwest::header::WWW_AUTHENTICATE),
        "RFC 6749 s5.2: a 401 for failed Authorization-header auth MUST include \
         WWW-Authenticate"
    );
    let body = assert_error_body(resp, "wrong client secret").await;
    assert_eq!(body["error"], "invalid_client");
}

/// RFC 8628 s3.2 + s3.5: device authorization response shape, then authorization_pending
/// before approval, and invalid_grant for a fabricated device_code.
#[tokio::test]
#[ignore = "black-box: needs the live AS; run via scripts/oauth-conformance.sh"]
async fn device_flow_shape_pending_and_bogus_code() {
    let http = no_redirect_client();
    let meta = metadata(&http).await;
    let device_ep = endpoint(&meta, "device_authorization_endpoint");
    let token_ep = endpoint(&meta, "token_endpoint");

    let resp = http
        .post(&device_ep)
        .form(&[("client_id", PUBLIC_CLIENT_ID)])
        .send()
        .await
        .expect("POST device_authorization");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "RFC 8628 s3.2: success is 200"
    );
    let body: Value = resp
        .json()
        .await
        .expect("device authorization response must be JSON");
    let violations = conf::validate_device_authorization_response(&body);
    assert!(
        violations.is_empty(),
        "RFC 8628 s3.2 violations: {violations:#?}"
    );
    let device_code = body["device_code"].as_str().unwrap().to_string();

    // Poll before approval: MUST be authorization_pending (or slow_down), RFC 8628 s3.5.
    let resp = http
        .post(&token_ep)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code.as_str()),
            ("client_id", PUBLIC_CLIENT_ID),
        ])
        .send()
        .await
        .expect("POST token (device poll)");
    let body = assert_error_body(resp, "device poll before approval").await;
    let code = body["error"].as_str().unwrap_or_default();
    assert!(
        code == "authorization_pending" || code == "slow_down",
        "polling an unapproved device_code must yield authorization_pending or slow_down \
         (RFC 8628 s3.5), got \"{code}\""
    );

    // A fabricated device_code must be invalid_grant (RFC 6749 s5.2 via RFC 8628 s3.5).
    let resp = http
        .post(&token_ep)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", "not-a-real-device-code"),
            ("client_id", PUBLIC_CLIENT_ID),
        ])
        .send()
        .await
        .expect("POST token (bogus device code)");
    let body = assert_error_body(resp, "bogus device_code").await;
    assert_eq!(body["error"], "invalid_grant");
}

/// A device_code is single-use: approve, redeem, then REPLAY the same device_code and require
/// rejection (RFC 8628 s3.5; RFC 6749 s10.5 single-use credentials).
#[tokio::test]
#[ignore = "black-box: needs the live AS; run via scripts/oauth-conformance.sh"]
async fn device_code_cannot_be_replayed() {
    let http = no_redirect_client();
    let meta = metadata(&http).await;
    let token_ep = endpoint(&meta, "token_endpoint");

    let body: Value = http
        .post(endpoint(&meta, "device_authorization_endpoint"))
        .form(&[("client_id", PUBLIC_CLIENT_ID)])
        .send()
        .await
        .expect("POST device_authorization")
        .json()
        .await
        .expect("device authorization JSON");
    let device_code = body["device_code"]
        .as_str()
        .expect("device_code")
        .to_string();
    let user_code = body["user_code"].as_str().expect("user_code").to_string();
    let verification_uri = body["verification_uri"].as_str().expect("verification_uri");

    // Approve (seeded-AS contract: POST user_code form to verification_uri approves).
    let approve = http
        .post(verification_uri)
        .form(&[("user_code", user_code.as_str())])
        .send()
        .await
        .expect("POST verification_uri");
    assert!(
        approve.status().is_success() || approve.status().is_redirection(),
        "seeded AS must accept the user_code approval POST (conformance contract), got {}",
        approve.status()
    );

    let poll = |dc: String| {
        let http = http.clone();
        let token_ep = token_ep.clone();
        async move {
            http.post(&token_ep)
                .form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", dc.as_str()),
                    ("client_id", PUBLIC_CLIENT_ID),
                ])
                .send()
                .await
                .expect("POST token (device poll)")
        }
    };

    // Redeem: poll until success, respecting interval (RFC 8628 s3.5).
    let interval = body["interval"].as_u64().unwrap_or(5);
    let mut token_body = None;
    for _ in 0..12 {
        let resp = poll(device_code.clone()).await;
        if resp.status().is_success() {
            token_body = Some(resp.json::<Value>().await.expect("token response JSON"));
            break;
        }
        let err = assert_error_body(resp, "device poll after approval").await;
        let code = err["error"].as_str().unwrap_or_default().to_string();
        assert!(
            code == "authorization_pending" || code == "slow_down",
            "after approval, poll errors may only be pending/slow_down until issuance, got \
             \"{code}\""
        );
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
    }
    let token_body = token_body.expect("device flow never issued a token after approval");
    let violations = conf::validate_token_response(&token_body);
    assert!(
        violations.is_empty(),
        "RFC 6749 s5.1 violations: {violations:#?}"
    );

    // REPLAY: the same device_code must now be rejected.
    let resp = poll(device_code).await;
    let err = assert_error_body(resp, "replayed device_code").await;
    let code = err["error"].as_str().unwrap_or_default();
    assert!(
        code == "invalid_grant" || code == "expired_token",
        "a redeemed device_code must be single-use (RFC 6749 s10.5), got \"{code}\""
    );
}

/// OAuth 2.1: an authorization request from a public client WITHOUT PKCE must be rejected,
/// never silently granted (OAuth 2.1 draft s4.1.1; RFC 7636 s4.4.1 server behavior).
#[tokio::test]
#[ignore = "black-box: needs the live AS; run via scripts/oauth-conformance.sh"]
async fn authorization_without_pkce_is_rejected() {
    let http = no_redirect_client();
    let meta = metadata(&http).await;
    let url = reqwest::Url::parse_with_params(
        &endpoint(&meta, "authorization_endpoint"),
        &[
            ("response_type", "code"),
            ("client_id", PUBLIC_CLIENT_ID),
            ("redirect_uri", PUBLIC_REDIRECT_URI),
            ("state", "conformance-no-pkce"),
        ],
    )
    .unwrap();
    let resp = http.get(url).send().await.expect("GET authorize");
    if resp.status().is_redirection() {
        let loc = resp.headers()[reqwest::header::LOCATION].to_str().unwrap();
        let redirect = reqwest::Url::parse(loc).expect("Location URL");
        let params: std::collections::HashMap<_, _> = redirect.query_pairs().collect();
        assert!(
            !params.contains_key("code"),
            "AS issued an authorization code to a public client WITHOUT PKCE; OAuth 2.1 \
             forbids this"
        );
        assert_eq!(
            params.get("error").map(AsRef::as_ref),
            Some("invalid_request"),
            "missing code_challenge must be error=invalid_request (RFC 7636 s4.4.1)"
        );
    } else {
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "missing PKCE must be rejected with 400 or an error redirect, got {}",
            resp.status()
        );
    }
}

/// Authorization-code negatives driven manually: wrong verifier is invalid_grant; a good code
/// redeems exactly once and its replay is invalid_grant; the issued access token is a
/// conformant RFC 9068 JWT, signature-verified against the advertised jwks_uri.
#[tokio::test]
#[ignore = "black-box: needs the live AS; run via scripts/oauth-conformance.sh"]
async fn auth_code_pkce_negatives_replay_and_rfc9068_token() {
    let http = no_redirect_client();
    let meta = metadata(&http).await;
    let authz_ep = endpoint(&meta, "authorization_endpoint");
    let token_ep = endpoint(&meta, "token_endpoint");

    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"; // RFC 7636 App B
    let challenge = conf::pkce_s256_challenge(verifier);

    // Code 1: exchange with a WRONG verifier must be invalid_grant (RFC 7636 s4.6).
    let code1 = obtain_auth_code(&http, &authz_ep, &challenge, "conf-state-1").await;
    let resp = http
        .post(&token_ep)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code1.as_str()),
            ("redirect_uri", PUBLIC_REDIRECT_URI),
            ("client_id", PUBLIC_CLIENT_ID),
            (
                "code_verifier",
                "wrong-verifier-wrong-verifier-wrong-verifier-1234",
            ),
        ])
        .send()
        .await
        .expect("POST token (wrong verifier)");
    let body = assert_error_body(resp, "wrong PKCE verifier").await;
    assert_eq!(
        body["error"], "invalid_grant",
        "RFC 7636 s4.6: verifier mismatch"
    );

    // Code 2: correct exchange succeeds with a conformant RFC 6749 s5.1 body.
    let code2 = obtain_auth_code(&http, &authz_ep, &challenge, "conf-state-2").await;
    let resp = http
        .post(&token_ep)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code2.as_str()),
            ("redirect_uri", PUBLIC_REDIRECT_URI),
            ("client_id", PUBLIC_CLIENT_ID),
            ("code_verifier", verifier),
        ])
        .send()
        .await
        .expect("POST token");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let cache_control = resp
        .headers()
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    assert!(
        cache_control.contains("no-store"),
        "RFC 6749 s5.1: token responses MUST include Cache-Control: no-store, got \
         \"{cache_control}\""
    );
    let body: Value = resp.json().await.expect("token response JSON");
    let violations = conf::validate_token_response(&body);
    assert!(
        violations.is_empty(),
        "RFC 6749 s5.1 violations: {violations:#?}"
    );

    // RFC 9068: the access token must be a structurally conformant JWT access token.
    let access_token = body["access_token"].as_str().unwrap();
    let violations = conf::validate_rfc9068_access_token(access_token);
    assert!(
        violations.is_empty(),
        "RFC 9068 violations: {violations:#?}"
    );

    // And its signature must verify against the advertised jwks_uri (RFC 9068 s4).
    let jwks_uri = meta
        .get("jwks_uri")
        .and_then(Value::as_str)
        .expect("an RFC 9068 AS must advertise jwks_uri so RSes can verify tokens");
    let jwks: Value = http
        .get(jwks_uri)
        .send()
        .await
        .expect("GET jwks")
        .json()
        .await
        .expect("jwks");
    conf::verify_jwt_against_jwks(access_token, &jwks)
        .expect("access token signature must verify against the advertised JWKS");

    // REPLAY code 2: must be invalid_grant (RFC 6749 s4.1.2 / s10.5).
    let resp = http
        .post(&token_ep)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code2.as_str()),
            ("redirect_uri", PUBLIC_REDIRECT_URI),
            ("client_id", PUBLIC_CLIENT_ID),
            ("code_verifier", verifier),
        ])
        .send()
        .await
        .expect("POST token (replay)");
    let body = assert_error_body(resp, "replayed authorization code").await;
    assert_eq!(
        body["error"], "invalid_grant",
        "an authorization code is single-use (RFC 6749 s4.1.2); replay must be invalid_grant"
    );
}
