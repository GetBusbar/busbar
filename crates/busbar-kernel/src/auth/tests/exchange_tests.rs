// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn exchange_ok_body_includes_base_url_equal_to_public_url() {
    let issued = IssuedKey {
        secret: busbar_contract::redacted::Secret::new("sk-busbar-abc".to_string()),
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

    assert!(!body["base_url"].as_str().unwrap().ends_with("/v1"));
}
