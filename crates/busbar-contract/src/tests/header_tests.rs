// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-contract/src/header.rs`.

use super::*;

#[test]
fn header_value_rule_rejects_control_bytes_but_a_tab() {
    assert!(is_legal_header_value("normal value"));
    assert!(is_legal_header_value("has\ta\ttab"));
    assert!(!is_legal_header_value("has\ra\rcr"));
    assert!(!is_legal_header_value("has\na\nlf"));
    assert!(!is_legal_header_value("has\0a\0nul"));
    assert!(!is_legal_header_value("has\x7Fa\x7Fdel"));
}

#[test]
fn token_value_joins_the_scheme_word_and_the_credential() {
    assert_eq!(token_value("abc123"), "Bearer abc123");
}
