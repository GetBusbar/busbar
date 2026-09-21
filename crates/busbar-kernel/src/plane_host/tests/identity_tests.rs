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
    let a = register(an_identity());
    let b = register(an_identity());
    assert_ne!(a, b, "each registration is a fresh opaque ref");
}
