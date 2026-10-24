// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-kernel-identity/src/caller_ref.rs`.

use crate::caller_ref::CallerRefKey;

const MATERIAL: &[u8] = b"node signing-key material for the test";

#[test]
fn the_same_principal_gets_the_same_reference_under_the_same_material() {
    let a = CallerRefKey::derive(MATERIAL);
    let b = CallerRefKey::derive(MATERIAL);
    assert_eq!(a.caller_ref("vk-alice"), b.caller_ref("vk-alice"));
    assert_ne!(a.caller_ref("vk-alice"), a.caller_ref("vk-bob"));
    assert_ne!(
        a.caller_ref("vk-alice"),
        CallerRefKey::derive(b"other material").caller_ref("vk-alice"),
        "a reference is bound to the node's key material"
    );
}

#[test]
fn the_reference_never_carries_the_principal() {
    let key = CallerRefKey::derive(MATERIAL);
    let principal = "vk-alice-0123456789";
    let r = key.caller_ref(principal);
    assert_eq!(r.len(), 64);
    assert!(r
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    assert!(!r.contains(principal) && !r.contains("alice"));
    assert_eq!(
        format!("{key:?}"),
        "CallerRefKey(..)",
        "the key never prints"
    );
}

#[test]
fn the_reference_is_hmac_sha256_under_the_hkdf_derived_key() {
    // A pinned value, so a change to the label, the hash or the derivation is a visible break of
    // every reference already handed to a far end.
    let key = CallerRefKey::derive(MATERIAL);
    let pinned = key.caller_ref("vk-alice");
    assert_eq!(
        pinned,
        CallerRefKey::derive(MATERIAL).caller_ref("vk-alice")
    );
    use ring::{hkdf, hmac};
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(MATERIAL);
    let okm = prk
        .expand(&[b"busbar caller-ref v1"], hmac::HMAC_SHA256)
        .expect("expands");
    let k = hmac::Key::from(okm);
    assert_eq!(pinned, hex::encode(hmac::sign(&k, b"vk-alice").as_ref()));
}
