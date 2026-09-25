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

/// KNOWN-ANSWER VECTORS. The shape assertions above -- 64 chars, lower-case -- are satisfied by a
/// `sha256_hex` that hashed the wrong bytes, truncated and padded, or returned a fixed 64-char hex
/// constant; the second one compares the value to a transform of itself. Every admin and plugin
/// credential compare in the tree routes through this function
/// (`crates/auth-admin-tokens/src/lib.rs:46,51`, `crates/auth-static-plugin/src/lib.rs:90`), and
/// until this test nothing anywhere pinned its actual output. The two vectors are FIPS 180-2's,
/// so they are checkable against any independent implementation rather than against ours.
#[test]
fn sha256_hex_matches_the_published_test_vectors() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}
