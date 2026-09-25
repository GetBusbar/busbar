// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-a2a/src/a2a/inbound_jws.rs` — the HOST-CAPS S3 inbound agent-card JWS
//! seam as a byte-for-byte pass-through to `pin::pin_a_signed_card`.

use super::*;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

const STD: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// The operator's out-of-band issuer key, as they paste it: base64 of the RFC 8410 SPKI.
fn key_info_base64(k: &SigningKey) -> String {
    let mut der = jws::ED25519_KEY_INFO_PREFIX.to_vec();
    der.extend_from_slice(k.verifying_key().as_bytes());
    STD.encode(der)
}

fn a_card() -> Value {
    json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "skills": [ { "id": "plan", "name": "Plan", "description": "decompose a goal" } ]
    })
}

fn signed_by(k: &SigningKey) -> Value {
    let mut card = a_card();
    let protected = jws::B64URL.encode(serde_json::to_string(&json!({ "alg": "EdDSA" })).unwrap());
    let payload = jws::B64URL.encode(
        super::super::card::signing_payload(&card)
            .unwrap()
            .as_bytes(),
    );
    let sig = k.sign(format!("{protected}.{payload}").as_bytes());
    card.as_object_mut().unwrap().insert(
        "signatures".to_string(),
        json!([{ "protected": protected, "signature": jws::B64URL.encode(sig.to_bytes()) }]),
    );
    card
}

#[test]
fn the_seam_verifies_a_good_card_byte_identically_to_the_free_function() {
    let k = key(1);
    let card = signed_by(&k);
    let key_pin = key_info_base64(&k);
    let host = PassThroughInboundJws;
    assert_eq!(
        host.verify_signed_card(&card, &key_pin),
        super::super::pin::pin_a_signed_card(&card, &key_pin),
        "the seam's success outcome is byte-for-byte the free function's"
    );
    assert!(
        host.verify_signed_card(&card, &key_pin).is_ok(),
        "a card signed by the pinned issuer verifies through the seam"
    );
}

#[test]
fn the_seam_refuses_a_wrong_key_and_a_malformed_key_exactly_as_the_free_function() {
    let card = signed_by(&key(1));
    let host = PassThroughInboundJws;
    // THE LOOK-ALIKE: signed by a valid but not-pinned key. Same refusal through both paths.
    let wrong = key_info_base64(&key(2));
    assert_eq!(
        host.verify_signed_card(&card, &wrong),
        super::super::pin::pin_a_signed_card(&card, &wrong),
    );
    assert_eq!(
        host.verify_signed_card(&card, &wrong),
        Err(jws::JwsError::NoSignatureVerified),
    );
    // A malformed operator key is refused identically.
    assert_eq!(
        host.verify_signed_card(&card, "not-base64-key-info"),
        super::super::pin::pin_a_signed_card(&card, "not-base64-key-info"),
    );
    assert_eq!(
        host.verify_signed_card(&card, "not-base64-key-info"),
        Err(jws::JwsError::MalformedIssuerKey),
    );
}

#[test]
fn the_composition_root_install_hands_the_installed_capability_back() {
    // Dormant by default: nothing installs the seam on the shipped path. Install one and read it
    // back, exercising the OnceLock accessor the plane composition uses.
    static HOST: PassThroughInboundJws = PassThroughInboundJws;
    install_inbound_card_jws(&HOST);
    let installed = inbound_card_jws().expect("the just-installed capability reads back");
    let k = key(3);
    let card = signed_by(&k);
    let key_pin = key_info_base64(&k);
    assert_eq!(
        installed.verify_signed_card(&card, &key_pin),
        super::super::pin::pin_a_signed_card(&card, &key_pin),
        "the installed capability verifies byte-identically to the free function"
    );
}
