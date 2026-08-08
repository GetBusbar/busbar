// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Machine-checkable schema conformance: every body this AS emits is validated with the
//! `jsonschema` crate against JSON Schemas transcribed clause-by-clause from RFC 6749 sections
//! 5.1/5.2 and RFC 8628 sections 3.2/3.5. The validator is independent third-party code; the
//! schemas cite the clause each constraint comes from; and the negative tests at the bottom prove
//! the schemas can actually FAIL (a harness that cannot go red proves nothing).

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonschema::Validator;
use serde_json::{json, Value};

use oauth_as::{
    AuthorizationServer, Client, ClientAuth, ClientId, Clock, ErrorCode, ErrorResponse, GrantType,
    MemoryStorage, ScopeSet, ServerConfig, TokenRequest,
};

#[derive(Clone)]
struct ManualClock(Arc<Mutex<SystemTime>>);
impl ManualClock {
    fn new() -> Self {
        ManualClock(Arc::new(Mutex::new(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        )))
    }
    fn advance(&self, d: Duration) {
        *self.0.lock().unwrap() += d;
    }
}
impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }
}

/// RFC 6749 section 5.1: access_token and token_type REQUIRED; expires_in a number; scope and
/// refresh_token strings. Parameter values are limited to VSCHAR on the wire; token_type is pinned
/// to Bearer because that is the only type this server issues (RFC 6750).
fn token_success_schema() -> Validator {
    jsonschema::validator_for(&json!({
        "type": "object",
        "required": ["access_token", "token_type"],
        "properties": {
            "access_token": { "type": "string", "minLength": 1, "pattern": "^[\\x20-\\x7E]+$" },
            "token_type": { "const": "Bearer" },
            "expires_in": { "type": "integer", "minimum": 1 },
            "refresh_token": { "type": "string", "minLength": 1, "pattern": "^[\\x20-\\x7E]+$" },
            "scope": { "type": "string", "pattern": "^[\\x21\\x23-\\x5B\\x5D-\\x7E]+( [\\x21\\x23-\\x5B\\x5D-\\x7E]+)*$" }
        },
        "additionalProperties": false
    }))
    .unwrap()
}

/// RFC 6749 section 5.2 error object, with the `error` enum extended by the four RFC 8628 section
/// 3.5 device-grant codes. error_description is limited to the RFC's NQSCHAR-ish ASCII set.
fn error_schema() -> Validator {
    jsonschema::validator_for(&json!({
        "type": "object",
        "required": ["error"],
        "properties": {
            "error": { "enum": [
                "invalid_request", "invalid_client", "invalid_grant", "unauthorized_client",
                "unsupported_grant_type", "invalid_scope",
                "authorization_pending", "slow_down", "access_denied", "expired_token"
            ] },
            "error_description": { "type": "string", "pattern": "^[\\x20\\x21\\x23-\\x5B\\x5D-\\x7E]*$" },
            "error_uri": { "type": "string" }
        },
        "additionalProperties": false
    }))
    .unwrap()
}

/// RFC 8628 section 3.2: device_code, user_code, verification_uri, expires_in REQUIRED;
/// verification_uri_complete and interval OPTIONAL.
fn device_authorization_schema() -> Validator {
    jsonschema::validator_for(&json!({
        "type": "object",
        "required": ["device_code", "user_code", "verification_uri", "expires_in"],
        "properties": {
            "device_code": { "type": "string", "minLength": 1 },
            "user_code": { "type": "string", "minLength": 1 },
            "verification_uri": { "type": "string", "format": "uri" },
            "verification_uri_complete": { "type": "string", "format": "uri" },
            "expires_in": { "type": "integer", "minimum": 1 },
            "interval": { "type": "integer", "minimum": 0 }
        },
        "additionalProperties": false
    }))
    .unwrap()
}

fn assert_valid(v: &Validator, body: &Value, what: &str) {
    let errors: Vec<String> = v.iter_errors(body).map(|e| e.to_string()).collect();
    assert!(
        errors.is_empty(),
        "{what} violates the RFC schema: {errors:?}\nbody: {body}"
    );
}

fn client() -> Client {
    Client {
        client_id: ClientId::new("c"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::DeviceCode, GrantType::RefreshToken],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
    }
}

fn poll(device_code: &str) -> TokenRequest {
    TokenRequest::DeviceCode {
        client_id: ClientId::new("c"),
        client_secret: None,
        device_code: device_code.into(),
    }
}

/// Drive a whole device flow and validate EVERY emitted body against the transcribed schemas.
#[tokio::test]
async fn every_emitted_body_matches_the_rfc_schemas() {
    let clock = ManualClock::new();
    let srv = AuthorizationServer::with_clock(
        ServerConfig::new("https://as.example", "https://as.example/device"),
        MemoryStorage::new(),
        clock.clone(),
    );
    srv.register_client(client()).await.unwrap();

    let device_schema = device_authorization_schema();
    let success_schema = token_success_schema();
    let err_schema = error_schema();

    // Device authorization response (RFC 8628 section 3.2).
    let auth = srv
        .device_authorization(&ClientId::new("c"), None, None)
        .await
        .unwrap();
    assert_valid(
        &device_schema,
        &serde_json::to_value(&auth).unwrap(),
        "device authorization response",
    );

    // authorization_pending, then an immediate re-poll for slow_down.
    let pending = srv.token(poll(&auth.device_code)).await.unwrap_err();
    assert_eq!(pending.error, ErrorCode::AuthorizationPending);
    assert_valid(
        &err_schema,
        &serde_json::to_value(&pending).unwrap(),
        "authorization_pending body",
    );
    let slow = srv.token(poll(&auth.device_code)).await.unwrap_err();
    assert_eq!(slow.error, ErrorCode::SlowDown);
    assert_valid(
        &err_schema,
        &serde_json::to_value(&slow).unwrap(),
        "slow_down body",
    );

    // Approval, then the success body (RFC 6749 section 5.1).
    srv.approve_device(&auth.user_code, "subject")
        .await
        .unwrap();
    clock.advance(Duration::from_secs(30));
    let token = srv.token(poll(&auth.device_code)).await.unwrap();
    assert_valid(
        &success_schema,
        &serde_json::to_value(&token).unwrap(),
        "token success body",
    );

    // Spent code: invalid_grant.
    clock.advance(Duration::from_secs(30));
    let spent = srv.token(poll(&auth.device_code)).await.unwrap_err();
    assert_valid(
        &err_schema,
        &serde_json::to_value(&spent).unwrap(),
        "invalid_grant body",
    );

    // Refresh success body.
    let refreshed = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("c"),
            client_secret: None,
            refresh_token: token.refresh_token.clone().unwrap(),
            scope: None,
        })
        .await
        .unwrap();
    assert_valid(
        &success_schema,
        &serde_json::to_value(&refreshed).unwrap(),
        "refresh success body",
    );

    // access_denied and expired_token bodies from fresh grants.
    let auth2 = srv
        .device_authorization(&ClientId::new("c"), None, None)
        .await
        .unwrap();
    srv.deny_device(&auth2.user_code).await.unwrap();
    clock.advance(Duration::from_secs(30));
    let denied = srv.token(poll(&auth2.device_code)).await.unwrap_err();
    assert_eq!(denied.error, ErrorCode::AccessDenied);
    assert_valid(
        &err_schema,
        &serde_json::to_value(&denied).unwrap(),
        "access_denied body",
    );

    let auth3 = srv
        .device_authorization(&ClientId::new("c"), None, None)
        .await
        .unwrap();
    clock.advance(Duration::from_secs(600));
    let expired = srv.token(poll(&auth3.device_code)).await.unwrap_err();
    assert_eq!(expired.error, ErrorCode::ExpiredToken);
    assert_valid(
        &err_schema,
        &serde_json::to_value(&expired).unwrap(),
        "expired_token body",
    );

    // invalid_client and invalid_scope bodies (these carry descriptions; the description charset
    // constraint is part of the schema).
    let bad_client = srv
        .token(TokenRequest::DeviceCode {
            client_id: ClientId::new("ghost"),
            client_secret: None,
            device_code: "x".into(),
        })
        .await
        .unwrap_err();
    assert_valid(
        &err_schema,
        &serde_json::to_value(&bad_client).unwrap(),
        "invalid_client body",
    );
    let bad_scope = srv
        .device_authorization(
            &ClientId::new("c"),
            None,
            Some(&ScopeSet::parse("root").unwrap()),
        )
        .await
        .unwrap_err();
    assert_eq!(bad_scope.error, ErrorCode::InvalidScope);
    assert_valid(
        &err_schema,
        &serde_json::to_value(&bad_scope).unwrap(),
        "invalid_scope body",
    );
}

/// RED-PROOF: the schemas must reject spec-illegal bodies, or the suite above is theater. Each
/// fixture is one deliberate violation of a named clause.
#[test]
fn the_schemas_reject_spec_illegal_bodies() {
    let success = token_success_schema();
    let err = error_schema();
    let device = device_authorization_schema();

    // RFC 6749 section 5.1: access_token is REQUIRED.
    assert!(!success.is_valid(&json!({ "token_type": "Bearer", "expires_in": 60 })));
    // RFC 6750: this server only issues Bearer; a lowercase or foreign type is a defect.
    assert!(!success.is_valid(&json!({ "access_token": "a", "token_type": "bearer" })));
    assert!(!success.is_valid(&json!({ "access_token": "a", "token_type": "MAC" })));
    // expires_in must be a number, not the string some broken servers emit.
    assert!(!success
        .is_valid(&json!({ "access_token": "a", "token_type": "Bearer", "expires_in": "3600" })));

    // RFC 6749 section 5.2 / RFC 8628 section 3.5: `error` must be a registered code.
    assert!(
        !err.is_valid(&json!({ "error": "pending" })),
        "'pending' is not a registered code"
    );
    assert!(
        !err.is_valid(&json!({ "error": "slowdown" })),
        "the registered code is slow_down"
    );
    assert!(!err.is_valid(&json!({ "error_description": "no code at all" })));
    // Non-ASCII in error_description violates the section 5.2 charset.
    assert!(!err
        .is_valid(&json!({ "error": "invalid_request", "error_description": "d\u{e9}sol\u{e9}" })));

    // RFC 8628 section 3.2: user_code and expires_in are REQUIRED.
    assert!(!device.is_valid(&json!({
        "device_code": "d", "verification_uri": "https://x", "expires_in": 600
    })));
    assert!(!device.is_valid(&json!({
        "device_code": "d", "user_code": "U", "verification_uri": "https://x"
    })));
}

/// The ErrorResponse type itself cannot serialize an unregistered code (the enum is closed), so
/// pin the serialized form of each device-grant code against the schema one by one.
#[test]
fn each_device_grant_error_code_serializes_to_a_registered_wire_form() {
    let err_schema = error_schema();
    for code in [
        ErrorCode::AuthorizationPending,
        ErrorCode::SlowDown,
        ErrorCode::AccessDenied,
        ErrorCode::ExpiredToken,
    ] {
        let body = serde_json::to_value(ErrorResponse::new(code)).unwrap();
        assert_valid(&err_schema, &body, "device-grant error body");
    }
}
