//! THIRD-PARTY CLIENT DRIVE. The `oauth2` crate (ramosbugs/oauth2-rs, pinned exactly at
//! 5.0.0 in Cargo.toml) runs a full device-code flow and a full
//! authorization-code-with-PKCE flow against the AS. That library parses, types, and
//! validates every response itself; this file never hand-validates a token response, so a
//! green here is the INDEPENDENT library's verdict on our AS, not ours.
//!
//! Ignored by default for the same reason as blackbox_http.rs; run via
//! `scripts/oauth-conformance.sh`, which starts the AS and exports OAUTH_AS_BASE_URL.

mod common;

use common::{metadata, no_redirect_client, PUBLIC_CLIENT_ID, PUBLIC_REDIRECT_URI};
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, DeviceAuthorizationUrl, PkceCodeChallenge,
    RedirectUrl, StandardDeviceAuthorizationResponse, TokenResponse as _, TokenUrl,
};
use serde_json::Value;

fn meta_url(meta: &Value, key: &str) -> String {
    meta[key]
        .as_str()
        .unwrap_or_else(|| panic!("metadata missing {key}"))
        .to_string()
}

/// Full RFC 8628 device flow, judged end to end by the oauth2 crate: it validates the
/// device authorization response shape, drives the poll loop, interprets
/// authorization_pending / slow_down itself, and type-checks the final token response.
#[tokio::test]
#[ignore = "black-box: needs the live AS; run via scripts/oauth-conformance.sh"]
async fn third_party_client_completes_device_flow() {
    let http = no_redirect_client();
    let meta = metadata(&http).await;

    let client = BasicClient::new(ClientId::new(PUBLIC_CLIENT_ID.to_string()))
        .set_auth_uri(AuthUrl::new(meta_url(&meta, "authorization_endpoint")).unwrap())
        .set_token_uri(TokenUrl::new(meta_url(&meta, "token_endpoint")).unwrap())
        .set_device_authorization_url(
            DeviceAuthorizationUrl::new(meta_url(&meta, "device_authorization_endpoint")).unwrap(),
        );

    let details: StandardDeviceAuthorizationResponse = client
        .exchange_device_code()
        .request_async(&http)
        .await
        .expect("oauth2 crate rejected the device authorization response as not spec-legal");

    // Approve out of band per the seeded-AS contract: POST user_code to verification_uri.
    let approve = http
        .post(details.verification_uri().as_str())
        .form(&[("user_code", details.user_code().secret().as_str())])
        .send()
        .await
        .expect("POST verification_uri");
    assert!(
        approve.status().is_success() || approve.status().is_redirection(),
        "seeded AS must accept the user_code approval POST, got {}",
        approve.status()
    );

    let token = client
        .exchange_device_access_token(&details)
        .request_async(
            &http,
            &tokio::time::sleep,
            Some(std::time::Duration::from_secs(60)),
        )
        .await
        .expect("oauth2 crate rejected the device token exchange as not spec-legal");
    assert!(
        !token.access_token().secret().is_empty(),
        "third-party client accepted the flow but got an empty access token"
    );
}

/// Full authorization-code + PKCE flow. The oauth2 crate generates the PKCE pair, builds the
/// authorization URL, and validates the token exchange; the harness only plays the browser
/// role (following the seeded AS's auto-approve 302 and delivering the code back).
#[tokio::test]
#[ignore = "black-box: needs the live AS; run via scripts/oauth-conformance.sh"]
async fn third_party_client_completes_auth_code_pkce_flow() {
    let http = no_redirect_client();
    let meta = metadata(&http).await;

    let client = BasicClient::new(ClientId::new(PUBLIC_CLIENT_ID.to_string()))
        .set_auth_uri(AuthUrl::new(meta_url(&meta, "authorization_endpoint")).unwrap())
        .set_token_uri(TokenUrl::new(meta_url(&meta, "token_endpoint")).unwrap())
        .set_redirect_uri(RedirectUrl::new(PUBLIC_REDIRECT_URI.to_string()).unwrap());

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(pkce_challenge)
        .url();

    // Browser role: the seeded AS auto-approves and 302s back to the redirect_uri.
    let resp = http.get(auth_url).send().await.expect("GET authorize");
    assert!(
        resp.status().is_redirection(),
        "seeded AS must auto-approve with a 302 (conformance contract), got {}",
        resp.status()
    );
    let location = resp.headers()[reqwest::header::LOCATION].to_str().unwrap();
    let redirect = reqwest::Url::parse(location).expect("Location URL");
    let mut code = None;
    let mut state = None;
    for (k, v) in redirect.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            _ => {}
        }
    }
    assert_eq!(
        state.as_deref(),
        Some(csrf_state.secret().as_str()),
        "state generated by the third-party client must round-trip unmodified (RFC 6749 s4.1.2)"
    );
    let code = code.expect("authorization response missing code (RFC 6749 s4.1.2)");

    let token = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(&http)
        .await
        .expect("oauth2 crate rejected the token response as not spec-legal");
    assert!(!token.access_token().secret().is_empty());
    assert!(
        token.expires_in().is_some(),
        "token response should carry expires_in (RFC 6749 s5.1 RECOMMENDED; the seeded AS \
         is expected to set it)"
    );
}
