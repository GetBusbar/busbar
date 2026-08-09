// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/api/src/auth.rs`.

use super::*;

#[test]
fn constant_time_eq_basics() {
    assert!(constant_time_eq("secret", "secret"));
    assert!(!constant_time_eq("short", "longer"));
    assert!(!constant_time_eq("secret1", "secret2"));
}

#[test]
fn sha256_hex_is_lowercase_64() {
    let h = sha256_hex(b"busbar");
    assert_eq!(h.len(), 64);
    assert_eq!(h, h.to_lowercase());
}
