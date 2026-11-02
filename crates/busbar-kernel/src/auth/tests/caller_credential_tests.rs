// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn a_cloned_caller_credential_shares_one_zeroising_buffer() {
    let held = CallerCredential::verified("sk-caller-credential");
    let clone = held.clone();
    assert_eq!(
        held.0.as_ptr(),
        clone.0.as_ptr(),
        "a clone shares the one buffer, never a second plaintext copy"
    );
    assert_eq!(clone.text(), "sk-caller-credential");
    assert_eq!(format!("{clone:?}"), "CallerCredential(<present>)");
}

#[test]
fn only_authorization_has_a_public_scheme_word() {
    let consumed = ConsumedCredentials::carrying(&[
        HeaderName::from_static("x-api-key"),
        axum::http::header::AUTHORIZATION,
        HeaderName::from_static("cookie"),
    ]);
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-api-key",
        HeaderValue::from_static("secret-prefix secret-tail"),
    );
    headers.insert(
        "authorization",
        HeaderValue::from_static("Bearer caller-secret"),
    );
    headers.insert(
        "cookie",
        HeaderValue::from_static("session=secret; other=value"),
    );
    assert_eq!(
        ConsumedCredentials::fields_of(Some(&consumed), &headers),
        vec![
            ("x-api-key".to_string(), String::new()),
            ("authorization".to_string(), "Bearer".to_string()),
            ("cookie".to_string(), String::new()),
        ]
    );
    consumed.strip(&mut headers);
    assert!(
        headers.is_empty(),
        "the complete credential fields are still stripped"
    );
}
