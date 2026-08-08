// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Behavioural tests for the RFC 8628 device authorization grant state machine and the OAuth 2.1
//! refresh rotation, on the in-memory store with a manual clock (no sleeping).

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth_as::{
    AuthorizationServer, Client, ClientAuth, ClientId, Clock, DeviceGrantState, ErrorCode,
    GrantType, MemoryStorage, ScopeSet, ServerConfig, Storage, TokenRequest, TokenType,
};

/// A hand-cranked clock shared between the test and the server under test.
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

fn device_client() -> Client {
    Client {
        client_id: ClientId::new("device-client"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::DeviceCode, GrantType::RefreshToken],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read write admin").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: Some("Test device".into()),
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

fn poll(device_code: &str) -> TokenRequest {
    TokenRequest::DeviceCode {
        client_id: ClientId::new("device-client"),
        client_secret: None,
        device_code: device_code.to_string(),
    }
}

#[tokio::test]
async fn happy_path_pending_then_approved_then_single_use() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![device_client()]).await;

    let scope = ScopeSet::parse("read write").unwrap();
    let auth = srv
        .device_authorization(&ClientId::new("device-client"), None, Some(&scope))
        .await
        .unwrap();

    // Response shape per RFC 8628 section 3.2 and our config defaults.
    assert_eq!(auth.expires_in, 600);
    assert_eq!(auth.interval, 5);
    assert_eq!(auth.verification_uri, "https://as.example/device");
    assert_eq!(
        auth.verification_uri_complete.as_deref(),
        Some(format!("https://as.example/device?user_code={}", auth.user_code).as_str())
    );
    // User code shape: XXXX-XXXX over the section 6.1 example alphabet (20 consonants).
    let (a, b) = auth
        .user_code
        .split_once('-')
        .expect("display form has one hyphen");
    for part in [a, b] {
        assert_eq!(part.len(), 4);
        assert!(
            part.chars().all(|c| "BCDFGHJKLMNPQRSTVWXZ".contains(c)),
            "{}",
            auth.user_code
        );
    }
    assert!(
        auth.device_code.len() >= 43,
        "device code must be high-entropy, got {}",
        auth.device_code
    );

    // Poll before approval: authorization_pending.
    let err = srv.token(poll(&auth.device_code)).await.unwrap_err();
    assert_eq!(err.error, ErrorCode::AuthorizationPending);
    assert_eq!(err.http_status(), 400);

    // The user enters the code sloppily: lowercase, no hyphen, padded. Still found.
    let sloppy = format!(" {} ", auth.user_code.replace('-', "").to_lowercase());
    srv.approve_device(&sloppy, "user-42").await.unwrap();

    // Respect the interval, then redeem.
    clock.advance(Duration::from_secs(5));
    let token = srv.token(poll(&auth.device_code)).await.unwrap();
    assert_eq!(token.token_type, TokenType::Bearer);
    assert_eq!(token.expires_in, 3600);
    assert_eq!(token.scope.as_deref(), Some("read write"));
    let refresh = token
        .refresh_token
        .clone()
        .expect("refresh issued by default");
    assert_ne!(refresh, token.access_token);

    // Introspection sees the token, bound to the approving subject.
    let info = srv
        .introspect(&token.access_token)
        .await
        .unwrap()
        .expect("live token");
    assert_eq!(info.subject.as_deref(), Some("user-42"));
    assert_eq!(info.scope, scope);
    assert_eq!(info.client_id, ClientId::new("device-client"));

    // Single use: the device code is spent.
    clock.advance(Duration::from_secs(5));
    let err = srv.token(poll(&auth.device_code)).await.unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidGrant);
}

#[tokio::test]
async fn omitted_scope_grants_the_client_default() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![device_client()]).await;
    let auth = srv
        .device_authorization(&ClientId::new("device-client"), None, None)
        .await
        .unwrap();
    srv.approve_device(&auth.user_code, "u").await.unwrap();
    clock.advance(Duration::from_secs(5));
    let token = srv.token(poll(&auth.device_code)).await.unwrap();
    assert_eq!(
        token.scope.as_deref(),
        Some("read"),
        "default_scopes applies when the request names none"
    );
}

#[tokio::test]
async fn scope_outside_the_registration_is_invalid_scope() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock, vec![device_client()]).await;
    let scope = ScopeSet::parse("read forbidden").unwrap();
    let err = srv
        .device_authorization(&ClientId::new("device-client"), None, Some(&scope))
        .await
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidScope);
}

#[tokio::test]
async fn polling_too_fast_is_slow_down_and_raises_the_interval_by_five_seconds() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![device_client()]).await;
    let auth = srv
        .device_authorization(&ClientId::new("device-client"), None, None)
        .await
        .unwrap();

    // First poll is never slow_down.
    let err = srv.token(poll(&auth.device_code)).await.unwrap_err();
    assert_eq!(err.error, ErrorCode::AuthorizationPending);

    // Immediate second poll: slow_down, and the required spacing becomes 5 + 5 = 10.
    clock.advance(Duration::from_secs(1));
    let err = srv.token(poll(&auth.device_code)).await.unwrap_err();
    assert_eq!(err.error, ErrorCode::SlowDown);

    // The ORIGINAL interval is no longer enough: 6 seconds later is still too fast.
    clock.advance(Duration::from_secs(6));
    let err = srv.token(poll(&auth.device_code)).await.unwrap_err();
    assert_eq!(
        err.error,
        ErrorCode::SlowDown,
        "old pace after slow_down must still be slow_down"
    );

    // The raised spacing (now 15 after two slow_downs) is honored.
    clock.advance(Duration::from_secs(15));
    let err = srv.token(poll(&auth.device_code)).await.unwrap_err();
    assert_eq!(
        err.error,
        ErrorCode::AuthorizationPending,
        "well-paced poll after backoff"
    );
}

#[tokio::test]
async fn expiry_is_expired_token_once_then_the_code_is_gone() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![device_client()]).await;
    let auth = srv
        .device_authorization(&ClientId::new("device-client"), None, None)
        .await
        .unwrap();

    clock.advance(Duration::from_secs(600));
    let err = srv.token(poll(&auth.device_code)).await.unwrap_err();
    assert_eq!(err.error, ErrorCode::ExpiredToken);

    // The grant was removed; a later poll cannot distinguish it from a code that never existed.
    let err = srv.token(poll(&auth.device_code)).await.unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidGrant);

    // And the user code no longer approves.
    let err = srv.approve_device(&auth.user_code, "u").await.unwrap_err();
    assert!(matches!(
        err,
        oauth_as::server::DeviceApprovalError::UnknownUserCode
    ));
}

#[tokio::test]
async fn denial_is_access_denied_then_the_code_is_gone() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![device_client()]).await;
    let auth = srv
        .device_authorization(&ClientId::new("device-client"), None, None)
        .await
        .unwrap();

    srv.deny_device(&auth.user_code).await.unwrap();
    clock.advance(Duration::from_secs(5));
    let err = srv.token(poll(&auth.device_code)).await.unwrap_err();
    assert_eq!(err.error, ErrorCode::AccessDenied);

    clock.advance(Duration::from_secs(5));
    let err = srv.token(poll(&auth.device_code)).await.unwrap_err();
    assert_eq!(
        err.error,
        ErrorCode::InvalidGrant,
        "a denied grant is consumed by its terminal answer"
    );
}

#[tokio::test]
async fn approval_state_transitions_are_guarded() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![device_client()]).await;
    let auth = srv
        .device_authorization(&ClientId::new("device-client"), None, None)
        .await
        .unwrap();

    let err = srv.approve_device("XXXX-XXXX", "u").await.unwrap_err();
    assert!(matches!(
        err,
        oauth_as::server::DeviceApprovalError::UnknownUserCode
    ));

    srv.approve_device(&auth.user_code, "u").await.unwrap();
    let err = srv
        .approve_device(&auth.user_code, "someone-else")
        .await
        .unwrap_err();
    assert!(
        matches!(err, oauth_as::server::DeviceApprovalError::NotPending),
        "approval is not re-bindable"
    );
    let err = srv.deny_device(&auth.user_code).await.unwrap_err();
    assert!(
        matches!(err, oauth_as::server::DeviceApprovalError::NotPending),
        "a decided grant stays decided"
    );
}

#[tokio::test]
async fn wrong_client_unknown_client_and_bad_secret() {
    let clock = ManualClock::at_epoch();
    let mut confidential = device_client();
    confidential.client_id = ClientId::new("confidential");
    confidential.auth = ClientAuth::ConfidentialSecret {
        secret: "hunter2".into(),
    };
    let srv = server_with(clock.clone(), vec![device_client(), confidential]).await;

    let auth = srv
        .device_authorization(&ClientId::new("device-client"), None, None)
        .await
        .unwrap();
    srv.approve_device(&auth.user_code, "u").await.unwrap();
    clock.advance(Duration::from_secs(5));

    // A different registered client polling someone else's device_code: invalid_grant.
    let err = srv
        .token(TokenRequest::DeviceCode {
            client_id: ClientId::new("confidential"),
            client_secret: Some("hunter2".into()),
            device_code: auth.device_code.clone(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidGrant);

    // An unregistered client: invalid_client, 401.
    let err = srv
        .token(TokenRequest::DeviceCode {
            client_id: ClientId::new("nobody"),
            client_secret: None,
            device_code: auth.device_code.clone(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidClient);
    assert_eq!(err.http_status(), 401);

    // A confidential client with the wrong secret: invalid_client.
    let err = srv
        .token(TokenRequest::DeviceCode {
            client_id: ClientId::new("confidential"),
            client_secret: Some("wrong".into()),
            device_code: auth.device_code.clone(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidClient);

    // The cross-client and bad-auth attempts must not have consumed the grant.
    clock.advance(Duration::from_secs(5));
    let token = srv.token(poll(&auth.device_code)).await.unwrap();
    assert!(!token.access_token.is_empty());
}

#[tokio::test]
async fn client_without_the_device_grant_is_unauthorized_client() {
    let clock = ManualClock::at_epoch();
    let mut no_device = device_client();
    no_device.client_id = ClientId::new("web-only");
    no_device.grant_types = vec![GrantType::AuthorizationCode];
    let srv = server_with(clock, vec![no_device]).await;
    let err = srv
        .device_authorization(&ClientId::new("web-only"), None, None)
        .await
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::UnauthorizedClient);
}

#[tokio::test]
async fn refresh_rotation_is_single_use_with_absolute_lifetime() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![device_client()]).await;
    let auth = srv
        .device_authorization(&ClientId::new("device-client"), None, None)
        .await
        .unwrap();
    srv.approve_device(&auth.user_code, "u").await.unwrap();
    clock.advance(Duration::from_secs(5));
    let first = srv.token(poll(&auth.device_code)).await.unwrap();
    let rt1 = first.refresh_token.unwrap();

    // Redeem: new access token, new refresh token.
    let second = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("device-client"),
            client_secret: None,
            refresh_token: rt1.clone(),
            scope: None,
        })
        .await
        .unwrap();
    let rt2 = second
        .refresh_token
        .clone()
        .expect("rotation issues a replacement");
    assert_ne!(rt2, rt1);
    assert_ne!(second.access_token, first.access_token);
    assert_eq!(
        second.scope.as_deref(),
        Some("read"),
        "scope carries over when not narrowed"
    );

    // The spent token is dead (OAuth 2.1 single-use rotation).
    let err = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("device-client"),
            client_secret: None,
            refresh_token: rt1,
            scope: None,
        })
        .await
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidGrant);

    // Narrowing works; widening is invalid_scope and does NOT burn the presented token.
    let narrowed = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("device-client"),
            client_secret: None,
            refresh_token: rt2,
            scope: Some(ScopeSet::parse("read").unwrap()),
        })
        .await
        .unwrap();
    let rt3 = narrowed.refresh_token.clone().unwrap();
    let err = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("device-client"),
            client_secret: None,
            refresh_token: rt3.clone(),
            scope: Some(ScopeSet::parse("read admin").unwrap()),
        })
        .await
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidScope);
    let again = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("device-client"),
            client_secret: None,
            refresh_token: rt3,
            scope: None,
        })
        .await
        .unwrap();
    assert!(
        again.refresh_token.is_some(),
        "an invalid_scope rejection must not consume the token"
    );
}

#[tokio::test]
async fn introspection_expires_with_the_clock() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![device_client()]).await;
    let auth = srv
        .device_authorization(&ClientId::new("device-client"), None, None)
        .await
        .unwrap();
    srv.approve_device(&auth.user_code, "u").await.unwrap();
    clock.advance(Duration::from_secs(5));
    let token = srv.token(poll(&auth.device_code)).await.unwrap();

    assert!(srv.introspect(&token.access_token).await.unwrap().is_some());
    clock.advance(Duration::from_secs(3600));
    assert!(
        srv.introspect(&token.access_token).await.unwrap().is_none(),
        "expiry is by clock, not deletion"
    );
    assert!(srv.introspect("no-such-token").await.unwrap().is_none());
}

#[tokio::test]
async fn issued_artifacts_are_unique_across_grants() {
    let clock = ManualClock::at_epoch();
    let srv = server_with(clock.clone(), vec![device_client()]).await;
    let a = srv
        .device_authorization(&ClientId::new("device-client"), None, None)
        .await
        .unwrap();
    let b = srv
        .device_authorization(&ClientId::new("device-client"), None, None)
        .await
        .unwrap();
    assert_ne!(a.device_code, b.device_code);
    assert_ne!(a.user_code, b.user_code);

    // Approving one must not touch the other.
    srv.approve_device(&a.user_code, "u").await.unwrap();
    clock.advance(Duration::from_secs(5));
    let err = srv.token(poll(&b.device_code)).await.unwrap_err();
    assert_eq!(err.error, ErrorCode::AuthorizationPending);
    let grant_b = srv
        .store()
        .get_device_grant(&b.device_code)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(grant_b.state, DeviceGrantState::Pending);
}
