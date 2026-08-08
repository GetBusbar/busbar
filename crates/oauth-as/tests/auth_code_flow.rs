// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Behavioural tests for the RFC 6749 section 4.1 authorization-code grant with mandatory PKCE
//! (RFC 7636, S256 only), on the in-memory store with a manual clock.
//!
//! NOTE ON STANDING: these are the crate's OWN tests (same author as the implementation). The
//! arms-length verdict comes from the separately written black-box conformance harness, which
//! drives this same machinery over HTTP; these tests exist so a regression is named here first,
//! at the unit level, before the black-box gate goes red.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth_as::{
    AuthorizationServer, AuthorizeParams, AuthorizeRejection, Client, ClientAuth, ClientId, Clock,
    ErrorCode, GrantType, MemoryStorage, ScopeSet, ServerConfig, TokenRequest,
};

const REDIRECT_URI: &str = "https://app.example/cb";
// RFC 7636 appendix B.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

#[derive(Clone)]
struct ManualClock(Arc<Mutex<SystemTime>>);

impl ManualClock {
    fn at_epoch() -> Self {
        ManualClock(Arc::new(Mutex::new(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        )))
    }
    fn advance(&self, d: Duration) {
        let mut t = self.0.lock().unwrap();
        *t += d;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }
}

fn web_client() -> Client {
    Client {
        client_id: ClientId::new("web-client"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::AuthorizationCode],
        redirect_uris: vec![REDIRECT_URI.to_string()],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: Some("Test web app".into()),
    }
}

async fn server_with(
    clock: ManualClock,
    clients: Vec<Client>,
) -> AuthorizationServer<MemoryStorage, ManualClock> {
    let cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), clock);
    for c in clients {
        srv.register_client(c).await.unwrap();
    }
    srv
}

fn valid_params() -> AuthorizeParams {
    AuthorizeParams {
        response_type: Some("code".into()),
        client_id: Some("web-client".into()),
        redirect_uri: Some(REDIRECT_URI.into()),
        scope: None,
        state: Some("st-123".into()),
        code_challenge: Some(CHALLENGE.into()),
        code_challenge_method: Some("S256".into()),
    }
}

fn redeem(code: &str, verifier: &str) -> TokenRequest {
    TokenRequest::AuthorizationCode {
        client_id: ClientId::new("web-client"),
        client_secret: None,
        code: code.to_string(),
        redirect_uri: Some(REDIRECT_URI.to_string()),
        code_verifier: Some(verifier.to_string()),
    }
}

fn redirect_error(rej: AuthorizeRejection) -> (String, Option<String>, ErrorCode) {
    match rej {
        AuthorizeRejection::Redirect {
            redirect_uri,
            state,
            error,
        } => (redirect_uri, state, error.error),
        AuthorizeRejection::Unredirectable(e) => {
            panic!("expected a redirect rejection, got unredirectable {e}")
        }
    }
}

#[tokio::test]
async fn happy_path_code_issues_once_and_replay_is_invalid_grant() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![web_client()]).await;

    let grant = srv.authorize(&valid_params(), "user-1").await.unwrap();
    assert_eq!(grant.redirect_uri, REDIRECT_URI);
    assert_eq!(grant.response.state.as_deref(), Some("st-123"));
    let code = grant.response.code.clone();

    let token = srv.token(redeem(&code, VERIFIER)).await.unwrap();
    assert!(!token.access_token.is_empty());
    assert_eq!(token.scope.as_deref(), Some("read"), "client default scope");

    // Single use (RFC 6749 section 4.1.2): the same code again is invalid_grant.
    let err = srv.token(redeem(&code, VERIFIER)).await.unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidGrant);
}

#[tokio::test]
async fn wrong_verifier_is_invalid_grant_and_consumes_the_code() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![web_client()]).await;

    let code = srv
        .authorize(&valid_params(), "user-1")
        .await
        .unwrap()
        .response
        .code;
    let err = srv.token(redeem(&code, &"x".repeat(43))).await.unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidGrant, "RFC 7636 section 4.6");

    // The failed verification consumed the code: the RIGHT verifier now fails too.
    let err = srv.token(redeem(&code, VERIFIER)).await.unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidGrant);
}

#[tokio::test]
async fn missing_or_malformed_verifier_is_invalid_request_and_retryable() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![web_client()]).await;

    let code = srv
        .authorize(&valid_params(), "user-1")
        .await
        .unwrap()
        .response
        .code;

    let mut req = redeem(&code, VERIFIER);
    if let TokenRequest::AuthorizationCode { code_verifier, .. } = &mut req {
        *code_verifier = None;
    }
    let err = srv.token(req).await.unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidRequest);

    let err = srv.token(redeem(&code, "too-short")).await.unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidRequest);

    // Malformed REQUESTS did not burn the code; the correct redemption still works.
    assert!(srv.token(redeem(&code, VERIFIER)).await.is_ok());
}

#[tokio::test]
async fn missing_pkce_is_an_invalid_request_error_redirect() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![web_client()]).await;

    let mut params = valid_params();
    params.code_challenge = None;
    let (uri, state, code) = redirect_error(srv.authorize(&params, "user-1").await.unwrap_err());
    assert_eq!(uri, REDIRECT_URI);
    assert_eq!(state.as_deref(), Some("st-123"));
    assert_eq!(code, ErrorCode::InvalidRequest, "RFC 7636 section 4.4.1");

    // `plain` (explicit or by RFC 7636 section 4.3 default) is not offered.
    let mut params = valid_params();
    params.code_challenge_method = Some("plain".into());
    let (_, _, code) = redirect_error(srv.authorize(&params, "user-1").await.unwrap_err());
    assert_eq!(code, ErrorCode::InvalidRequest);
    let mut params = valid_params();
    params.code_challenge_method = None;
    let (_, _, code) = redirect_error(srv.authorize(&params, "user-1").await.unwrap_err());
    assert_eq!(code, ErrorCode::InvalidRequest);
}

#[tokio::test]
async fn unknown_client_or_bad_redirect_uri_never_redirects() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![web_client()]).await;

    let mut params = valid_params();
    params.client_id = Some("who-is-this".into());
    match srv.authorize(&params, "user-1").await.unwrap_err() {
        AuthorizeRejection::Unredirectable(e) => assert_eq!(e.error, ErrorCode::InvalidRequest),
        other => panic!("unknown client must not redirect (RFC 6749 s4.1.2.1), got {other:?}"),
    }

    let mut params = valid_params();
    params.redirect_uri = Some("https://evil.example/cb".into());
    match srv.authorize(&params, "user-1").await.unwrap_err() {
        AuthorizeRejection::Unredirectable(e) => assert_eq!(e.error, ErrorCode::InvalidRequest),
        other => panic!("unregistered redirect_uri must not redirect, got {other:?}"),
    }
}

#[tokio::test]
async fn redirect_uri_binding_and_wrong_client_are_invalid_grant() {
    let clock = ManualClock::at_epoch();
    let mut other = web_client();
    other.client_id = ClientId::new("other-client");
    other.grant_types = vec![GrantType::AuthorizationCode];
    let srv = server_with(clock.clone(), vec![web_client(), other]).await;

    // redirect_uri presented at authorization must be repeated identically at redemption.
    let code = srv
        .authorize(&valid_params(), "user-1")
        .await
        .unwrap()
        .response
        .code;
    let mut req = redeem(&code, VERIFIER);
    if let TokenRequest::AuthorizationCode { redirect_uri, .. } = &mut req {
        *redirect_uri = Some("https://app.example/other".into());
    }
    let err = srv.token(req).await.unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidGrant, "RFC 6749 section 4.1.3");

    // A code issued to one client presented by another is invalid_grant.
    let code = srv
        .authorize(&valid_params(), "user-1")
        .await
        .unwrap()
        .response
        .code;
    let mut req = redeem(&code, VERIFIER);
    if let TokenRequest::AuthorizationCode { client_id, .. } = &mut req {
        *client_id = ClientId::new("other-client");
    }
    let err = srv.token(req).await.unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidGrant);
}

#[tokio::test]
async fn expired_code_is_invalid_grant() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![web_client()]).await;

    let code = srv
        .authorize(&valid_params(), "user-1")
        .await
        .unwrap()
        .response
        .code;
    clock.advance(Duration::from_secs(61)); // default authorization_code_ttl is 60s
    let err = srv.token(redeem(&code, VERIFIER)).await.unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidGrant);
}

#[tokio::test]
async fn scope_outside_registration_is_an_invalid_scope_redirect() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![web_client()]).await;

    let mut params = valid_params();
    params.scope = Some("read admin".into());
    let (_, _, code) = redirect_error(srv.authorize(&params, "user-1").await.unwrap_err());
    assert_eq!(code, ErrorCode::InvalidScope);
}
