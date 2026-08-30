// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/plane_host/creds.rs`.

use super::*;

#[test]
fn mint_then_resolve_returns_plaintext_then_expires() {
    let r = mint(b"tok-abc".to_vec(), 1_000, 900);
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
    let a = mint(b"a".to_vec(), 10, 0);
    let b = mint(b"b".to_vec(), 10, 0);
    assert_ne!(a, b, "each mint is a fresh opaque ref");
    assert_eq!(resolve(a, 0), Some(b"a".to_vec()));
    assert_eq!(resolve(b, 0), Some(b"b".to_vec()));
}

#[test]
fn an_unexpired_ref_resolves_repeatedly_until_expiry() {
    // NOT one-shot, deliberately: `AuthResolved` hands the plane `expires_unix` (validity-until-
    // expiry), and a plane failover legitimately re-opens an egress carrying the same still-live
    // ref. A one-shot resolve would make that second open inject NOTHING — an unauthenticated
    // request going out silently — rather than failing closed.
    let r = mint(b"tok".to_vec(), 1_000, 900);
    assert_eq!(resolve(r, 950), Some(b"tok".to_vec()), "first resolve");
    assert_eq!(
        resolve(r, 999),
        Some(b"tok".to_vec()),
        "a second resolve within the TTL still serves — multi-resolve is the seam's contract"
    );
}

#[test]
fn a_never_resolved_expired_mint_is_swept_by_a_later_mint() {
    // THE UNBOUNDED-GROWTH REGRESSION PIN: a ref that is minted and never carried into
    // `egress_open` must not live past its expiry just because nothing ever looked it up again.
    // Mint one expired entry, then enough further mints to cross any plausible amortization
    // watermark (the registry is process-global and shared with concurrently running tests, so the
    // assertions are one-sided: the sweep may only REMOVE expired entries, never resurrect or
    // touch live ones — extra concurrent mints can only trigger it earlier).
    let now = 5_000_u64;
    let stale = mint(b"stale-secret".to_vec(), now - 1, now);
    assert!(
        contains_for_test(stale),
        "the expired mint is held until a sweep runs"
    );
    for _ in 0..512 {
        let _ = mint(b"filler".to_vec(), now - 1, now);
    }
    let live = mint(b"live-secret".to_vec(), now + 100, now);
    assert!(
        !contains_for_test(stale),
        "an expired, never-resolved mint was swept by a later mint — the registry is bounded \
         by live (unexpired) mints, not by resolution traffic"
    );
    assert!(
        contains_for_test(live),
        "the sweep removes only expired entries; a live mint is untouched"
    );
    assert_eq!(
        resolve(live, now),
        Some(b"live-secret".to_vec()),
        "the live ref still resolves after the sweep"
    );
}
