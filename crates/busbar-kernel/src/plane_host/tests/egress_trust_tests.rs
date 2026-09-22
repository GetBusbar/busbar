// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-substrate/src/plane_host/egress_trust.rs` — the HOST-CAPS S3 egress-trust
//! seam as a byte-for-byte pass-through to the `identity`/`trust_anchor`/`spki` primitives.

use super::*;

/// A self-signed client identity, built the way the a2a boot resolver builds one (cert + key as
/// one PEM buffer, the single form `ClientIdentity::from_pem` takes).
fn an_identity() -> ClientIdentity {
    use rcgen::{CertificateParams, KeyPair};
    let kp = KeyPair::generate().expect("a key pair");
    let params = CertificateParams::new(vec!["client.test".to_string()]).expect("params");
    let cert = params.self_signed(&kp).expect("self-signed");
    let mut pem = cert.pem().into_bytes();
    if !pem.ends_with(b"\n") {
        pem.push(b'\n');
    }
    pem.extend_from_slice(kp.serialize_pem().as_bytes());
    ClientIdentity::from_pem(&pem).expect("a usable client identity")
}

/// A self-signed root certificate, parsed to DER the way the a2a boot resolver parses a
/// `trusting_root` PEM.
fn a_root() -> CertificateDer<'static> {
    use rcgen::{CertificateParams, KeyPair};
    let kp = KeyPair::generate().expect("a key pair");
    let params = CertificateParams::new(vec!["root.test".to_string()]).expect("params");
    let cert = params.self_signed(&kp).expect("self-signed");
    cert.der().clone()
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
        super::super::identity::resolve(0).is_none(),
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
        super::super::trust_anchor::resolve(u64::MAX).len(),
        "seam and free fn agree on an unknown ref"
    );
}

#[test]
fn peer_spki_pin_seam_is_byte_for_byte_the_free_walk() {
    let host = PassThroughEgressTrust;
    let der = a_root();
    // The seam's pin is the SAME string the free DER walk computes — the whole point of the seam
    // being a pass-through and not a second answer to "what is this key's pin".
    assert_eq!(
        host.peer_spki_pin(der.as_ref()),
        super::super::spki::pin(der.as_ref()),
        "the seam pins byte-for-byte identically to the free walk"
    );
    assert!(
        host.peer_spki_pin(der.as_ref())
            .expect("a valid cert pins")
            .starts_with("sha256/"),
        "a real pin is spelled sha256/<base64>"
    );
    // A non-certificate refuses, exactly as the free walk does.
    assert!(host.peer_spki_pin(b"not-a-cert").is_err());
}

#[test]
fn the_composition_root_install_hands_the_installed_capability_back() {
    // Dormant by default: nothing installs the seam on the shipped path. This test installs its
    // own and reads it back, exercising the OnceLock accessor the composition root uses.
    static HOST: PassThroughEgressTrust = PassThroughEgressTrust;
    install_egress_trust_host(&HOST);
    let installed = egress_trust_host().expect("the just-installed capability reads back");
    let der = a_root();
    assert_eq!(
        installed.peer_spki_pin(der.as_ref()),
        super::super::spki::pin(der.as_ref()),
        "the installed capability pins byte-identically to the free walk"
    );
}
