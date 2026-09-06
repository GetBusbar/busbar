// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/plane_host/identity.rs`.

use super::*;

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
    let generation = IdentityGeneration::install();
    let r = generation.register(an_identity());
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
    let generation = IdentityGeneration::install();
    let a = generation.register(an_identity());
    let b = generation.register(an_identity());
    assert_ne!(a, b, "each registration is a fresh opaque ref");
}

/// A RETIRED GENERATION'S REFS RESOLVE TO NOTHING, AND ITS KEYS ARE GONE.
///
/// The whole point of tying a registration to a generation: the apply that lets go of a bundle of
/// client identities lets go of the private keys too. A ref that outlived its generation must not
/// still present a certificate the operator retired — it fails closed, to no certificate at all, and
/// the registry's population goes back to what it was.
#[test]
fn a_retired_generation_stops_resolving_and_leaves_the_registry_where_it_found_it() {
    let (first_ref, second_ref) = {
        let generation = IdentityGeneration::install();
        let first_ref = generation.register(an_identity());
        let second_ref = generation.register(an_identity());
        assert_eq!(
            generation.len(),
            2,
            "both identities are resident while the generation is held"
        );
        assert!(resolve(first_ref).is_some());
        assert!(resolve(second_ref).is_some());
        (first_ref, second_ref)
    };
    assert!(
        resolve(first_ref).is_none() && resolve(second_ref).is_none(),
        "a retired generation's refs present no certificate at all"
    );
}

/// Two generations coexist, and retiring one leaves the other alone — the property that lets one
/// apply release its bundle without pulling the keys out from under the bundle still serving.
#[test]
fn retiring_one_generation_leaves_another_untouched() {
    let kept = IdentityGeneration::install();
    let kept_ref = kept.register(an_identity());
    let discarded_ref = {
        let discarded = IdentityGeneration::install();
        discarded.register(an_identity())
    };
    assert!(
        resolve(discarded_ref).is_none(),
        "the released generation's ref is retired"
    );
    assert!(
        resolve(kept_ref).is_some(),
        "the generation still held keeps presenting its identity"
    );
}
