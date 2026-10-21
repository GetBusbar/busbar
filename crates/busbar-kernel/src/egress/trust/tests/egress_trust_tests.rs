// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-substrate/src/plane_host/egress_trust.rs` — the HOST-CAPS S3 egress-trust
//! seam as a byte-for-byte pass-through to the `identity`/`trust_anchor`/`spki` primitives.

use super::*;

/// A self-signed client identity, from its parts. `ClientIdentity::from_pem` hands its PEM walk to
/// the installed secure layer; the connector's own outbound identity (`tls::client_identity`, presented
/// over a real handshake) is proven in `busbar-core-connector`'s `tls/client_tests.rs`
/// (`a_client_identity_is_presented_to_a_mutual_peer`).
fn an_identity() -> ClientIdentity {
    use rcgen::{CertificateParams, KeyPair};
    let kp = KeyPair::generate().expect("a key pair");
    let params = CertificateParams::new(vec!["client.test".to_string()]).expect("params");
    let cert = params.self_signed(&kp).expect("self-signed");
    ClientIdentity::from_parts(
        vec![cert.der().to_vec()],
        crate::secure::KeyDer::Pkcs8(kp.serialize_der()),
    )
}

/// A self-signed root certificate, parsed to DER the way the a2a boot resolver parses a
/// `trusting_root` PEM.
fn a_root() -> Vec<u8> {
    use rcgen::{CertificateParams, KeyPair};
    let kp = KeyPair::generate().expect("a key pair");
    let params = CertificateParams::new(vec!["root.test".to_string()]).expect("params");
    let cert = params.self_signed(&kp).expect("self-signed");
    cert.der().to_vec()
}

#[test]
fn client_identity_seam_is_a_pass_through_to_the_registry() {
    let host = PassThroughEgressTrust;
    // A registered identity resolves through the seam exactly as through the free registry.
    let r = host.register_client_identity(an_identity());
    assert_ne!(r, 0, "a live ref is nonzero");
    assert!(
        host.resolve_client_identity(r).is_some(),
        "the seam resolves the ref it just minted"
    );
    // The reserved and unknown refs give the SAME fail-to-no-cert answer the free fn gives.
    assert!(host.resolve_client_identity(0).is_none());
    assert_eq!(
        host.resolve_client_identity(0).is_none(),
        super::identity::resolve(0).is_none(),
        "seam and free fn agree on the reserved ref"
    );
    assert!(host.resolve_client_identity(u64::MAX).is_none());
}

#[test]
fn trust_anchor_seam_is_a_pass_through_to_the_registry() {
    let host = PassThroughEgressTrust;
    let r = host.register_trust_anchor(vec![a_root()]);
    assert_ne!(r, 0, "a live ref is nonzero");
    assert_eq!(
        host.resolve_trust_anchor(r).len(),
        1,
        "the seam resolves the ref it just minted to its one root"
    );
    // Reserved and unknown refs add no extra roots — fail-closed, same as the free fn.
    assert!(host.resolve_trust_anchor(0).is_empty());
    assert!(host.resolve_trust_anchor(u64::MAX).is_empty());
    assert_eq!(
        host.resolve_trust_anchor(u64::MAX).len(),
        super::trust_anchor::resolve(u64::MAX).len(),
        "seam and free fn agree on an unknown ref"
    );
}

#[test]
fn peer_leaf_pin_seam_is_byte_for_byte_the_free_walk() {
    let host = PassThroughEgressTrust;
    let der = a_root();
    // The seam's pin is the SAME string the free DER walk computes — the whole point of the seam
    // being a pass-through and not a second answer to "what is this key's pin".
    assert_eq!(
        host.peer_leaf_pin(der.as_ref()),
        super::spki::pin(der.as_ref()),
        "the seam pins byte-for-byte identically to the free walk"
    );
    assert!(
        host.peer_leaf_pin(der.as_ref())
            .expect("a valid cert pins")
            .starts_with("sha256/"),
        "a real pin is spelled sha256/<base64>"
    );
    // A non-certificate refuses, exactly as the free walk does.
    assert!(host.peer_leaf_pin(b"not-a-cert").is_err());
}

#[test]
fn a_test_binarys_hand_in_is_the_capability_read_back() {
    // A shipped build holds no egress-trust capability; a test binary hands its own in through the
    // test kit and its engine clients read it back. The capability handed in is the pass-through
    // primitives with the test binary's name arm (the fixtures' loopback listed), so the hand-in
    // does not fail closed every other test's loopback dial (the first hand-in stands).
    struct PassThroughListingLoopback;
    impl EgressTrustHost for PassThroughListingLoopback {
        fn judge_name(&self, host: &str, _: u32) -> Result<(), crate::host_services::DestRefusal> {
            crate::egress::fixtures::loopback_literal_listed(host)
        }
    }
    crate::test_support::install_egress_trust(std::sync::Arc::new(PassThroughListingLoopback));
    let installed = egress_trust_host().expect("a capability was handed in");
    let der = a_root();
    assert_eq!(
        installed.peer_leaf_pin(der.as_ref()),
        super::spki::pin(der.as_ref()),
        "the installed capability pins byte-identically to the free walk"
    );
}

/// THE DESTINATION JUDGEMENT ON THE SEAM (ARCHITECT ruling (C)): the pass-through has no guard
/// behind it and refuses every answer (fail closed).
#[test]
fn the_pass_through_seam_fails_closed() {
    let public: std::net::IpAddr = "93.184.216.34".parse().unwrap();
    let refused = PassThroughEgressTrust
        .judge_answer("api.test", &[public], 0)
        .unwrap_err();
    assert_eq!(
        refused.verdict,
        busbar_contract::abi::host::service::DEST_NO_HOST
    );
}
