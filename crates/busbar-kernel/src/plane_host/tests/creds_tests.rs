// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/plane_host/creds.rs`.

use super::*;
use std::sync::{Mutex, MutexGuard};

/// The registry and `NEXT_REF` are process-global, so `cargo test`'s parallel runner would let these
/// bodies interleave on the ONE shared map. That is not benign here: [`mint`]'s amortized SWEEP
/// evicts every entry expired at the MINTING caller's clock, and these tests deliberately mint under
/// wildly different fake clocks (900, 0, 5_000). A sweep fired by the `now = 5_000` retention test
/// would drop another test's still-live-at-its-own-clock mint, so a concurrent `resolve` sees `None`
/// — the exact intermittent `left == right` / `right: Some(..)` flake. Each test holds this guard for
/// its whole body (serialising them) and calls [`reset_for_test`] at entry, so every body runs
/// against a clean, private global. This is test-only isolation; production `creds.rs` is untouched.
static TEST_GUARD: Mutex<()> = Mutex::new(());

/// Serialise this test against the others and hand it a freshly reset global registry.
fn isolated() -> MutexGuard<'static, ()> {
    let guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    reset_for_test();
    guard
}

/// The destination every legacy test binds to and resolves against — the binding is exercised on its
/// own in [`a_credential_is_bound_to_its_destination_and_a_mismatch_is_refused`].
const DEST: &str = "provider.example";

#[test]
fn mint_then_resolve_returns_plaintext_then_expires() {
    let _guard = isolated();
    let r = mint(b"tok-abc".to_vec(), DEST.to_string(), 1_000, 900);
    assert_ne!(r, 0, "a live ref is nonzero");
    assert_eq!(
        resolve(r, 999, DEST),
        Some(b"tok-abc".to_vec()),
        "before expiry resolves"
    );
    // At/after expiry it fails closed AND drops (cannot be replayed).
    assert_eq!(resolve(r, 1_001, DEST), None, "past expiry is refused");
    assert_eq!(
        resolve(r, 999, DEST),
        None,
        "the expired mint was dropped, not just skipped"
    );
}

#[test]
fn zero_and_unknown_refs_resolve_to_none() {
    let _guard = isolated();
    assert_eq!(
        resolve(0, 0, DEST),
        None,
        "the reserved 0 ref names no credential"
    );
    assert_eq!(
        resolve(u64::MAX, 0, DEST),
        None,
        "an unknown ref resolves to nothing"
    );
}

#[test]
fn distinct_mints_get_distinct_refs() {
    let _guard = isolated();
    let a = mint(b"a".to_vec(), DEST.to_string(), 10, 0);
    let b = mint(b"b".to_vec(), DEST.to_string(), 10, 0);
    assert_ne!(a, b, "each mint is a fresh opaque ref");
    assert_eq!(resolve(a, 0, DEST), Some(b"a".to_vec()));
    assert_eq!(resolve(b, 0, DEST), Some(b"b".to_vec()));
}

/// FFI-F5 (credential confused deputy): a mint is BOUND to the destination the `auth_resolve` caller
/// named, and `resolve` hands back the plaintext ONLY for that destination. A ref paired with a
/// DIFFERENT host resolves to `None` — the secret never travels to a host it was not minted for — and
/// the mismatch is NON-destructive: the ref still resolves for its bound destination afterwards.
#[test]
fn a_credential_is_bound_to_its_destination_and_a_mismatch_is_refused() {
    let _guard = isolated();
    let r = mint(
        b"provider-a-secret".to_vec(),
        "provider-a.example".to_string(),
        1_000,
        0,
    );
    // The confused-deputy attempt: pair provider-A's ref with an attacker-controlled host.
    assert_eq!(
        resolve(r, 0, "attacker.example"),
        None,
        "a credential minted for provider-A must NOT resolve for a different destination"
    );
    // The binding is not consumed by the refused attempt — a legitimate hop to the bound host works.
    assert_eq!(
        resolve(r, 0, "provider-a.example"),
        Some(b"provider-a-secret".to_vec()),
        "the ref still resolves for the destination it was actually bound to"
    );
}

/// FFI-F6 (secret zeroization): the round-trip is unchanged with the stored plaintext wrapped in
/// `Zeroizing` — mint, resolve for the bound destination, and the plaintext comes back byte-identical.
/// The wipe-on-drop is a property of the `Zeroizing<Vec<u8>>` field type; this pins that wrapping it
/// did not change the observable resolve behaviour.
#[test]
fn a_zeroizing_backed_mint_still_round_trips() {
    let _guard = isolated();
    let r = mint(b"wipe-me".to_vec(), DEST.to_string(), 1_000, 0);
    assert_eq!(resolve(r, 0, DEST), Some(b"wipe-me".to_vec()));
}

#[test]
fn an_unexpired_ref_resolves_repeatedly_until_expiry() {
    // NOT one-shot, deliberately: `AuthResolved` hands the plane `expires_unix` (validity-until-
    // expiry), and a plane failover legitimately re-opens an egress carrying the same still-live
    // ref. A one-shot resolve would make that second open inject NOTHING — an unauthenticated
    // request going out silently — rather than failing closed.
    let _guard = isolated();
    let r = mint(b"tok".to_vec(), DEST.to_string(), 1_000, 900);
    assert_eq!(
        resolve(r, 950, DEST),
        Some(b"tok".to_vec()),
        "first resolve"
    );
    assert_eq!(
        resolve(r, 999, DEST),
        Some(b"tok".to_vec()),
        "a second resolve within the TTL still serves — multi-resolve is the seam's contract"
    );
}

#[test]
fn a_never_resolved_expired_mint_is_swept_by_a_later_mint() {
    // THE UNBOUNDED-GROWTH REGRESSION PIN: a ref that is minted and never carried into
    // `egress_open` must not live past its expiry just because nothing ever looked it up again.
    // Mint one expired entry, then enough further mints to cross any plausible amortization
    // watermark. This body runs isolated (guard + reset), so it owns the global registry outright:
    // the sweep may only REMOVE entries expired at this test's clock, never touch the one live mint.
    let _guard = isolated();
    let now = 5_000_u64;
    let stale = mint(b"stale-secret".to_vec(), DEST.to_string(), now - 1, now);
    assert!(
        contains_for_test(stale),
        "the expired mint is held until a sweep runs"
    );
    for _ in 0..512 {
        let _ = mint(b"filler".to_vec(), DEST.to_string(), now - 1, now);
    }
    let live = mint(b"live-secret".to_vec(), DEST.to_string(), now + 100, now);
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
        resolve(live, now, DEST),
        Some(b"live-secret".to_vec()),
        "the live ref still resolves after the sweep"
    );
}
