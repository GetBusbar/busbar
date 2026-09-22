// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/plane_host/identity.rs`.

use super::*;
use std::sync::{Mutex, MutexGuard};

/// The registry is process-global, so parallel test bodies otherwise share it (and, since the
/// bounded-retention fix, share the eviction cap too — one test registering past the cap would
/// evict another's live entries). Every test holds this across its whole body (serialising them)
/// and calls [`reset_for_test`] at entry, so every body runs against clean state.
static TEST_GUARD: Mutex<()> = Mutex::new(());

fn isolated() -> MutexGuard<'static, ()> {
    let guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    reset_for_test();
    guard
}

/// A self-signed client identity (cert + key concatenated as one PEM buffer, the single form
/// `ClientIdentity::from_pem` takes — `reqwest::Identity::from_pem` parity by the R4 corpus),
/// built the way the a2a boot resolver builds one.
fn an_identity() -> crate::egress::engine::ClientIdentity {
    use rcgen::{CertificateParams, KeyPair};
    let kp = KeyPair::generate().expect("a key pair");
    let params = CertificateParams::new(vec!["client.test".to_string()]).expect("params");
    let cert = params.self_signed(&kp).expect("self-signed");
    let mut pem = cert.pem().into_bytes();
    if !pem.ends_with(b"\n") {
        pem.push(b'\n');
    }
    pem.extend_from_slice(kp.serialize_pem().as_bytes());
    crate::egress::engine::ClientIdentity::from_pem(&pem).expect("a usable client identity")
}

#[test]
fn register_then_resolve_returns_the_identity_and_unknown_is_none() {
    let _guard = isolated();
    let r = register(an_identity());
    assert_ne!(r, 0, "a live ref is nonzero");
    assert!(
        resolve(r).is_some(),
        "the registered ref resolves to its identity"
    );
    assert!(
        resolve(0).is_none(),
        "the reserved 0 ref presents no identity"
    );
    assert!(
        resolve(u64::MAX).is_none(),
        "an unknown ref resolves to nothing (fail to no-cert)"
    );
}

#[test]
fn distinct_registrations_get_distinct_refs() {
    let _guard = isolated();
    let a = register(an_identity());
    let b = register(an_identity());
    assert_ne!(a, b, "each registration is a fresh opaque ref");
}

/// UNBOUNDED RETENTION CLOSED: registering past [`MAX_RETAINED_IDENTITIES`] must evict the oldest
/// live entries rather than let the registry grow forever. A fixture identity is cloned rather than
/// freshly generated per registration — the eviction mechanics under test do not depend on the
/// identity's content, only on how many refs the registry retains — so the test stays fast even at
/// several times the cap.
#[test]
fn registering_past_the_cap_evicts_the_oldest_entries_and_bounds_the_registry() {
    let _guard = isolated();
    let identity = an_identity();
    let first = register(identity.clone());
    assert!(resolve(first).is_some(), "the first registration is live");

    // Fill well past the cap.
    let mut last = first;
    for _ in 0..(MAX_RETAINED_IDENTITIES * 3) {
        last = register(identity.clone());
    }

    assert!(
        live_count_for_test() <= MAX_RETAINED_IDENTITIES,
        "the registry must never retain more than MAX_RETAINED_IDENTITIES entries; got {}",
        live_count_for_test()
    );
    assert!(
        resolve(first).is_none(),
        "the earliest registration must have been evicted, not retained forever"
    );
    assert!(
        resolve(last).is_some(),
        "the most recent registration must still resolve"
    );
}

/// The cap is a hard ceiling, not a one-time check: many rounds of registration never push the live
/// count above [`MAX_RETAINED_IDENTITIES`], proving the bound holds across an unbounded run of
/// reloads (a long-lived process hot-reloading its config for weeks), not just the first overflow.
#[test]
fn many_registrations_never_grow_the_registry_past_the_retained_cap() {
    let _guard = isolated();
    let identity = an_identity();
    for _ in 0..(MAX_RETAINED_IDENTITIES * 5) {
        let _ = register(identity.clone());
        assert!(
            live_count_for_test() <= MAX_RETAINED_IDENTITIES,
            "the retained-entry count stays bounded across an unbounded run of registrations"
        );
    }
}
