// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CRYPTO-SEAM §6 T2: the conformance suite against whichever backend is linked.

use busbar_crypto::conformance as c;

#[test]
fn backend_identity_and_self_test() {
    c::backend_const();
}

#[test]
fn hashes_and_audit_link() {
    c::hash();
}

#[test]
fn hmac_known_answers() {
    c::hmac();
}

#[test]
fn kdf_known_answers() {
    c::kdf();
}

#[test]
fn random_draws_differ() {
    c::rng();
}

#[test]
fn aead_and_aes_block_known_answers() {
    c::aead();
}

#[test]
fn signature_known_answers_and_signer_seam() {
    c::signatures();
}

#[test]
fn legacy_known_answers() {
    c::legacy_algs();
}

#[test]
fn tls_handshake_through_the_facade() {
    c::tls_handshake();
}

#[test]
fn software_backend_provides_everything() {
    assert_eq!(busbar_crypto::BACKEND, "software");
    for name in busbar_crypto::alg::ALL {
        assert!(busbar_crypto::supports(name), "{name}");
    }
    assert_eq!(busbar_crypto::link::RECIPE, "busbar.audit.digest.v7");
}
