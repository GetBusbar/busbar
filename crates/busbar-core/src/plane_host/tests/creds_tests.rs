// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/plane_host/creds.rs`.

use super::*;

#[test]
fn mint_then_resolve_returns_plaintext_then_expires() {
    let r = mint(b"tok-abc".to_vec(), 1_000);
    assert_ne!(r, 0, "a live ref is nonzero");
    assert_eq!(
        resolve(r, 999),
        Some(b"tok-abc".to_vec()),
        "before expiry resolves"
    );
    // At/after expiry it fails closed AND drops (cannot be replayed).
    assert_eq!(resolve(r, 1_001), None, "past expiry is refused");
    assert_eq!(
        resolve(r, 999),
        None,
        "the expired mint was dropped, not just skipped"
    );
}

#[test]
fn zero_and_unknown_refs_resolve_to_none() {
    assert_eq!(
        resolve(0, 0),
        None,
        "the reserved 0 ref names no credential"
    );
    assert_eq!(
        resolve(u64::MAX, 0),
        None,
        "an unknown ref resolves to nothing"
    );
}

#[test]
fn distinct_mints_get_distinct_refs() {
    let a = mint(b"a".to_vec(), 10);
    let b = mint(b"b".to_vec(), 10);
    assert_ne!(a, b, "each mint is a fresh opaque ref");
    assert_eq!(resolve(a, 0), Some(b"a".to_vec()));
    assert_eq!(resolve(b, 0), Some(b"b".to_vec()));
}
