// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CRYPTO-SEAM §6 T8: oauth-as's primitives through `FacadeCrypto` answer the published vectors.

use super::*;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn pkce_s256_answers_rfc_7636_appendix_b() {
    let challenge = oauth_as::pkce::code_challenge_s256_with_crypto(
        &FacadeCrypto,
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    );
    assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
}

#[test]
fn hmac_answers_rfc_4231() {
    assert_eq!(
        hex(&FacadeCrypto.hmac_sha256(&[0x0b; 20], b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        hex(&FacadeCrypto.sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn constant_time_equality_and_entropy() {
    assert!(FacadeCrypto.ct_eq(b"abc", b"abc"));
    assert!(!FacadeCrypto.ct_eq(b"abc", b"abd"));
    let (mut a, mut b) = ([0_u8; 32], [0_u8; 32]);
    FacadeCrypto.fill_random(&mut a).unwrap();
    FacadeCrypto.fill_random(&mut b).unwrap();
    assert_ne!(a, b);
    FacadeCrypto.validate().unwrap();
}

#[test]
fn only_es256_and_ps256_have_verifiers() {
    assert!(FacadeCrypto.verifier(JwsAlg::Es256).is_some());
    assert!(FacadeCrypto.verifier(JwsAlg::Ps256).is_some());
    assert!(FacadeCrypto.verifier(JwsAlg::Rs256).is_none());
    assert!(FacadeCrypto.verifier(JwsAlg::EdDsa).is_none());
}
