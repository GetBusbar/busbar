// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-substrate/src/plane_host/identity.rs`.

use super::*;
use std::sync::{Mutex, MutexGuard};

/// The registry is process-global, so parallel test bodies otherwise share it (and, since S28,
/// share the generation-eviction bound too — one test's third generation would evict another's
/// first). Every test holds this across its whole body (serialising them) and calls
/// [`reset_for_test`] at entry, so every body runs against clean state — the same discipline
/// `plane_host::creds`'s tests use for its own process-global map.
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
    let r = register(1, an_identity());
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
    let a = register(1, an_identity());
    let b = register(1, an_identity());
    assert_ne!(a, b, "each registration is a fresh opaque ref");
}

#[test]
fn a_same_generation_reregistration_does_not_grow_the_retained_generation_count() {
    let _guard = isolated();
    let _ = register(1, an_identity());
    let _ = register(1, an_identity());
    let _ = register(1, an_identity());
    assert_eq!(
        generation_count_for_test(),
        1,
        "repeat registrations under one generation are one retained generation, not three"
    );
}

#[test]
fn a_third_generation_evicts_the_oldest_and_its_refs_stop_resolving() {
    let _guard = isolated();
    let gen1 = register(1, an_identity());
    let gen2 = register(2, an_identity());
    assert!(resolve(gen1).is_some(), "generation 1 is still retained");
    assert!(resolve(gen2).is_some(), "generation 2 is still retained");

    // A third distinct generation lands: with MAX_RETAINED_GENERATIONS == 2, generation 1 (the
    // single oldest) is evicted — its entry drops (best-effort zeroizing its key) and its ref
    // fails closed exactly like an unknown ref.
    let gen3 = register(3, an_identity());
    assert!(
        resolve(gen1).is_none(),
        "the oldest generation's ref is evicted, not merely superseded"
    );
    assert!(resolve(gen2).is_some(), "generation 2 survives the evict");
    assert!(resolve(gen3).is_some(), "the newest generation resolves");
    assert_eq!(
        generation_count_for_test(),
        2,
        "the registry never retains more than MAX_RETAINED_GENERATIONS distinct generations"
    );
}

#[test]
fn many_generations_never_grow_the_registry_past_the_retained_cap() {
    let _guard = isolated();
    for generation in 1..=50u64 {
        let _ = register(generation, an_identity());
        let _ = register(generation, an_identity());
        assert!(
            generation_count_for_test() <= 2,
            "the retained-generation count stays bounded across an unbounded run of reloads"
        );
    }
}
