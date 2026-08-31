// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DER WALK, against a certificate somebody else built and a public key somebody else encoded.
//!
//! The hazard in a hand-written ASN.1 walk is landing one element early or one element late and
//! hashing something that is stable, plausible and wrong — a `subject` name hashes to a perfectly
//! good-looking `sha256/…` value, and every assertion written against our own output would agree
//! with it. So the oracle here is never this module: `rcgen` encodes the certificate AND, quite
//! separately, encodes the same key as a bare SubjectPublicKeyInfo. The walk is correct exactly
//! when those two agree.

use super::*;
use base64::Engine as _;
use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use sha2::{Digest, Sha256};

/// A self-signed certificate and, independently, the DER of the very key inside it.
fn cert_and_its_spki() -> (Vec<u8>, Vec<u8>) {
    let kp = KeyPair::generate().expect("a key pair");
    let params = CertificateParams::new(vec!["a2a.vendor.test".to_string()]).expect("params");
    let cert = params.self_signed(&kp).expect("self-signed");
    (cert.der().to_vec(), kp.subject_public_key_info())
}

#[test]
fn the_walk_lands_on_the_subject_public_key_info_and_not_on_the_member_beside_it() {
    let (cert_der, expected_spki) = cert_and_its_spki();
    let found = subject_public_key_info(&cert_der).expect("the SPKI of a well-formed certificate");
    assert_eq!(
        found,
        expected_spki.as_slice(),
        "the walk must produce the SAME bytes the certificate's own key encodes to. A walk that \
         stopped one member early would produce a stable, plausible and completely different value."
    );
}

#[test]
fn the_pin_is_the_sha256_of_those_bytes_in_the_planes_one_digest_spelling() {
    let (cert_der, expected_spki) = cert_and_its_spki();
    let pin = spki_pin(&cert_der).expect("a pin");
    assert_eq!(
        pin,
        format!(
            "sha256/{}",
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&expected_spki))
        ),
        "the pin is the operator-facing value; it must be exactly what `openssl … | openssl dgst \
         -sha256 -binary | base64` prints, or nobody can obtain it out of band"
    );
    assert_eq!(
        pin,
        crate::a2a::card::sha256_tagged(&expected_spki),
        "ONE digest rendering on this plane. A second spelling here is a second value an operator \
         has to know is the same one."
    );
}

#[test]
fn two_certificates_over_the_same_key_pin_identically_and_a_new_key_does_not() {
    // WHY THE PIN IS ON THE KEY AND NOT ON THE CERTIFICATE: a renewal re-issues the certificate
    // and keeps the key. A certificate pin would demand a re-approval every renewal, and a pin an
    // operator clears that often is a pin they clear without reading.
    let kp = KeyPair::generate().expect("key");
    let first = CertificateParams::new(vec!["a2a.vendor.test".to_string()])
        .expect("params")
        .self_signed(&kp)
        .expect("cert");
    let second = CertificateParams::new(vec![
        "a2a.vendor.test".to_string(),
        "other.test".to_string(),
    ])
    .expect("params")
    .self_signed(&kp)
    .expect("cert");
    assert_ne!(
        first.der().to_vec(),
        second.der().to_vec(),
        "the two certificates must genuinely differ, or this test proves nothing"
    );
    assert_eq!(
        spki_pin(first.der()).expect("pin"),
        spki_pin(second.der()).expect("pin"),
        "a renewal keeps the key, so it must keep the pin"
    );

    let (other_cert, _) = cert_and_its_spki();
    assert_ne!(
        spki_pin(first.der()).expect("pin"),
        spki_pin(&other_cert).expect("pin"),
        "a different key must be a different pin, or the pin distinguishes nothing"
    );
}

// ══ NON-DER IS A REFUSAL, NOT A BEST EFFORT ══════════════════════════════════════════════════════

#[test]
fn a_truncated_certificate_refuses_rather_than_hashing_whatever_it_reached() {
    let (cert_der, _) = cert_and_its_spki();
    for cut in [1usize, 2, 8, cert_der.len() / 2, cert_der.len() - 1] {
        assert_eq!(
            spki_pin(&cert_der[..cut]),
            Err(SpkiError::Truncated),
            "{cut} bytes of a certificate is not a certificate"
        );
    }
}

#[test]
fn a_document_that_is_not_a_certificate_refuses_by_tag() {
    // An OCTET STRING where a SEQUENCE belongs. Refused by NAME rather than by falling off the end,
    // so an operator reading the log learns the peer sent something that is not a certificate.
    assert_eq!(
        spki_pin(&[0x04, 0x02, 0xAA, 0xBB]),
        Err(SpkiError::UnexpectedTag {
            want: 0x30,
            got: 0x04
        })
    );
}

#[test]
fn every_ber_length_form_that_gives_one_certificate_a_second_encoding_is_refused() {
    // THE POINT OF THIS TEST. BER admits several spellings of one length. A parser that accepted
    // them would let an upstream re-encode its certificate, produce different bytes for the same
    // key, and — depending on where the re-encoding sat — change or not change the pin. A pin with
    // more than one value for one key is not a pin.
    for (bytes, why) in [
        (vec![0x30u8, 0x80, 0x00, 0x00], "an indefinite length"),
        (
            vec![0x30, 0x82, 0x00, 0x04, 0x30, 0x02, 0x05, 0x00],
            "a length with a leading zero octet",
        ),
        (
            vec![0x30, 0x81, 0x02, 0x30, 0x00],
            "a long-form length that the short form would have carried",
        ),
        (
            vec![0x30, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05],
            "a length wider than four octets",
        ),
    ] {
        assert_eq!(
            spki_pin(&bytes),
            Err(SpkiError::NotDer(why)),
            "{why} must be refused, not tolerated"
        );
    }
}

#[test]
fn a_version_one_certificate_with_no_version_member_is_walked_correctly() {
    // `version` is `[0] EXPLICIT … DEFAULT v1`, so it is ABSENT on a v1 certificate. A walk that
    // skipped it unconditionally would read one member too far on exactly those, and would then
    // pin the `validity` window — a value that changes on every renewal.
    //
    // Built by hand rather than by `rcgen` (which always emits v3): a minimal TBSCertificate with
    // no version member, whose seventh-position element is a recognisable stand-in SPKI.
    let spki: Vec<u8> = vec![0x30, 0x03, 0x02, 0x01, 0x2A];
    let mut tbs: Vec<u8> = Vec::new();
    for member in [
        vec![0x02u8, 0x01, 0x01],     // serialNumber
        vec![0x30, 0x02, 0x05, 0x00], // signature
        vec![0x30, 0x00],             // issuer
        vec![0x30, 0x00],             // validity
        vec![0x30, 0x00],             // subject
    ] {
        tbs.extend_from_slice(&member);
    }
    tbs.extend_from_slice(&spki);

    let mut tbs_element = vec![0x30, u8::try_from(tbs.len()).expect("short form")];
    tbs_element.extend_from_slice(&tbs);
    let mut cert = vec![0x30, u8::try_from(tbs_element.len()).expect("short form")];
    cert.extend_from_slice(&tbs_element);

    assert_eq!(
        subject_public_key_info(&cert).expect("the SPKI"),
        spki.as_slice(),
        "a v1 certificate carries no version member, and the walk must not skip a member that is \
         not there"
    );
}

/// FAITHFULNESS: the HOST spelling of the pin (the neutral [`busbar_substrate::plane_host::spki::pin`] the egress
/// seam hands back in the observed head) is the SAME string as the a2a plane's own [`spki_pin`], byte
/// for byte, over the same certificate DER. This is the whole reason the walk was lifted to one place:
/// a governed hop must be able to return the pin the plane would have computed itself, so the plane's
/// SPKI classification is unchanged whether the hop went through the seam or the plane's own transport.
#[test]
fn the_host_pin_equals_the_plane_pin_byte_for_byte() {
    let (cert_der, _) = cert_and_its_spki();
    let plane = spki_pin(&cert_der).expect("the plane pin");
    let host = busbar_substrate::plane_host::spki::pin(&cert_der).expect("the host pin");
    assert_eq!(
        host.as_bytes(),
        plane.as_bytes(),
        "the host-computed pin must equal the plane-computed pin byte for byte"
    );
}
