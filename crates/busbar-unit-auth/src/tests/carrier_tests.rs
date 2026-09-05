// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The carriers and their precedence, and the redacting debug output.

use super::Headers;
use crate::carrier::{extract_bearer_token, extract_client_token, CallerToken};

#[test]
fn test_extract_bearer_token_valid() {
    assert_eq!(
        extract_bearer_token("Bearer abc123"),
        Some("abc123".to_string())
    );
}

#[test]
fn test_extract_bearer_token_case_insensitive() {
    assert_eq!(
        extract_bearer_token("bEaReR abc123"),
        Some("abc123".to_string())
    );
}

#[test]
fn test_extract_bearer_token_no_bearer() {
    assert_eq!(extract_bearer_token("Basic abc123"), None);
    assert_eq!(extract_bearer_token("Bearer "), None);
}

#[test]
fn test_extract_bearer_token_malformed_no_panic() {
    // A multi-byte character where the scheme belongs must not land mid-character.
    assert_eq!(extract_bearer_token("Béarer x"), None);
    assert_eq!(extract_bearer_token("Bearer"), None);
    assert_eq!(extract_bearer_token(""), None);
    assert_eq!(extract_bearer_token("　"), None);
}

#[test]
fn test_extract_client_token_authorization_bearer() {
    let h = Headers(vec![("authorization", "Bearer tok-a")]);
    assert_eq!(extract_client_token(&h), Some("tok-a".to_string()));
}

#[test]
fn test_extract_client_token_x_api_key() {
    let h = Headers(vec![("x-api-key", "tok-b")]);
    assert_eq!(extract_client_token(&h), Some("tok-b".to_string()));
}

#[test]
fn test_extract_client_token_x_goog_api_key() {
    let h = Headers(vec![("x-goog-api-key", "tok-c")]);
    assert_eq!(extract_client_token(&h), Some("tok-c".to_string()));
}

#[test]
fn test_extract_client_token_precedence_is_authorization_first() {
    let h = Headers(vec![
        ("authorization", "Bearer first"),
        ("x-api-key", "second"),
        ("x-goog-api-key", "third"),
    ]);
    assert_eq!(extract_client_token(&h), Some("first".to_string()));
    let h = Headers(vec![("x-api-key", "second"), ("x-goog-api-key", "third")]);
    assert_eq!(extract_client_token(&h), Some("second".to_string()));
}

#[test]
fn test_extract_client_token_empty_carrier_falls_through() {
    let h = Headers(vec![("x-api-key", ""), ("x-goog-api-key", "third")]);
    assert_eq!(
        extract_client_token(&h),
        Some("third".to_string()),
        "a blank header must not mask a token in a lower-precedence carrier"
    );
}

#[test]
fn test_extract_client_token_none_when_no_carrier() {
    let h = Headers(vec![("content-type", "application/json")]);
    assert_eq!(extract_client_token(&h), None);
}

#[test]
fn test_extract_client_token_non_bearer_authorization_falls_through_to_x_api_key() {
    let h = Headers(vec![
        ("authorization", "AWS4-HMAC-SHA256 Credential=…"),
        ("x-api-key", "tok-b"),
    ]);
    assert_eq!(extract_client_token(&h), Some("tok-b".to_string()));
}

#[test]
fn test_extract_client_token_non_bearer_authorization_falls_through_to_x_goog_api_key() {
    let h = Headers(vec![
        ("authorization", "Basic dXNlcjpwYXNz"),
        ("x-goog-api-key", "tok-c"),
    ]);
    assert_eq!(extract_client_token(&h), Some("tok-c".to_string()));
}

#[test]
fn test_caller_token_debug_redacts_value() {
    let present = format!("{:?}", CallerToken(Some("super-secret".to_string())));
    assert!(
        !present.contains("super-secret"),
        "the token value must never reach a debug rendering: {present}"
    );
    assert!(present.contains("<present>"));
    assert!(format!("{:?}", CallerToken(None)).contains("<absent>"));
}
