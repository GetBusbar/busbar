// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use http::HeaderValue;

#[test]
fn a_cloned_caller_credential_shares_one_zeroising_buffer() {
    let held = CallerCredential::verified("sk-caller-credential");
    let clone = held.clone();
    assert!(
        busbar_contract::SharedSecret::ptr_eq(&held.0, &clone.0),
        "a clone shares the one buffer, never a second plaintext copy"
    );
    assert!(
        busbar_contract::SharedSecret::ptr_eq(&held.0, &clone.lend()),
        "the egress lend is a handle on the same buffer, never a copy"
    );
    assert_eq!(
        clone.0.expose(&crate::seal::lend()).as_slice(),
        b"sk-caller-credential"
    );
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
        ConsumedCredentials::fields_of(Some(&consumed), &headers)
            .into_iter()
            .map(|(name, scheme)| (name.as_str().to_string(), scheme))
            .collect::<Vec<_>>(),
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
