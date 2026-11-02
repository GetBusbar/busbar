// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn an_explicit_call_chain_uses_only_its_supplied_carriers() {
    let mut headers = HeaderMap::new();
    headers.insert("x-c7-credential", HeaderValue::from_static("selected"));
    headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer fallback"));
    let explicit = AuthMiddleware::from_calls_for_test(Vec::new(), &["x-c7-credential"]);
    assert_eq!(
        explicit.extract_client_token(&headers).as_deref(),
        Some("selected")
    );
    let none = AuthMiddleware::from_calls_for_test(Vec::new(), &[]);
    assert_eq!(none.extract_client_token(&headers), None);
    assert!(explicit.chain_names().is_empty());
}
