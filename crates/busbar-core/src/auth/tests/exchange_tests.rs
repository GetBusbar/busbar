// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/auth/exchange.rs`.

use super::*;

/// The headless exchange response is SELF-CONTAINED: it carries `base_url` (= the configured
/// public_url, verbatim) alongside the key so a CI/BYOK caller has everything in one payload.
#[test]
fn exchange_ok_body_includes_base_url_equal_to_public_url() {
    let issued = IssuedKey {
        secret: "sk-busbar-abc".into(),
        key_id: "kid-1".into(),
        group: "eng".into(),
        exp: 1234567890,
    };
    let public_url = "https://busbar.example.com";
    let body = exchange_ok_body(&issued, public_url);
    assert_eq!(body["base_url"], public_url);
    assert_eq!(body["api_key"], "sk-busbar-abc");
    assert_eq!(body["key_id"], "kid-1");
    assert_eq!(body["group"], "eng");
    assert_eq!(body["exp"], 1234567890u64);
    // base_url is verbatim — no /v1 suffix (BYOK clients append their own).
    assert!(!body["base_url"].as_str().unwrap().ends_with("/v1"));
}
