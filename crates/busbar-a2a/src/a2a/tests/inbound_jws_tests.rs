// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-a2a/src/a2a/inbound_jws.rs` — the HOST-CAPS S3 inbound agent-card JWS
//! seam as a byte-for-byte pass-through to `pin::pin_a_signed_card`, and as the ONE verifier
//! `verify_document` reaches (TODO 607).

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
    let mut der = busbar_kernel::trust::signed::KEY_INFO_HEAD.to_vec();
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
    let protected =
        crate::a2a::sign::B64URL.encode(serde_json::to_string(&json!({ "alg": "EdDSA" })).unwrap());
    let payload = crate::a2a::sign::B64URL.encode(
        super::super::card::signing_payload(&card)
            .unwrap()
            .as_bytes(),
    );
    let sig = k.sign(format!("{protected}.{payload}").as_bytes());
    card.as_object_mut().unwrap().insert(
        "signatures".to_string(),
        json!([{ "protected": protected, "signature": crate::a2a::sign::B64URL.encode(sig.to_bytes()) }]),
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
        Err(JwsError::NoSignatureVerified),
    );
    // A malformed operator key is refused identically.
    assert_eq!(
        host.verify_signed_card(&card, "not-base64-key-info"),
        super::super::pin::pin_a_signed_card(&card, "not-base64-key-info"),
    );
    assert_eq!(
        host.verify_signed_card(&card, "not-base64-key-info"),
        Err(JwsError::MalformedIssuerKey),
    );
}

#[test]
fn the_capability_verifies_byte_identically_to_the_free_function() {
    // A read always answers with the ONE capability (never "none"), and it verifies
    // byte-identically to the free function.
    let installed = inbound_card_jws();
    let k = key(3);
    let card = signed_by(&k);
    let key_pin = key_info_base64(&k);
    assert_eq!(
        installed.verify_signed_card(&card, &key_pin),
        super::super::pin::pin_a_signed_card(&card, &key_pin),
        "the installed capability verifies byte-identically to the free function"
    );
}

/// A capability that answers the OPPOSITE of the real verifier: it accepts any card with a sentinel
/// pin and refuses nothing. If `verify_document` consulted anything but the seam, a card the real
/// verifier refuses could not come back verified with this pin.
struct Sentinel;

impl InboundCardJws for Sentinel {
    fn verify_signed_card(
        &self,
        _card: &Value,
        issuer_key_info: &str,
    ) -> Result<CardPin, JwsError> {
        if issuer_key_info == "refuse" {
            return Err(JwsError::NoSignatureVerified);
        }
        Ok(CardPin::JwsIssuerKey {
            issuer_key: "sentinel".to_string(),
            card_fingerprint: "sentinel".to_string(),
        })
    }
}

fn jws_pin(key: &str) -> super::super::config::AgentPinCfg {
    super::super::config::AgentPinCfg {
        mechanism: super::super::config::PinMechanism::JwsIssuerKey,
        key: Some(key.to_string()),
        fingerprint: None,
    }
}

#[test]
fn verify_document_reaches_the_card_signature_only_through_the_seam() {
    use super::super::verify::{verify_document_through, Handshake, VerifyRefusal};
    // An UNSIGNED card, which the real verifier refuses, verifies through a seam that accepts it —
    // and carries the seam's pin, not one computed beside it.
    let unsigned = a_card();
    let verified = verify_document_through(
        &Sentinel,
        &jws_pin(&key_info_base64(&key(4))),
        &unsigned,
        Handshake::default(),
    )
    .expect("the seam's acceptance is the verdict");
    assert_eq!(
        verified.pin,
        CardPin::JwsIssuerKey {
            issuer_key: "sentinel".to_string(),
            card_fingerprint: "sentinel".to_string(),
        }
    );
    // And a GENUINELY signed card the seam refuses is refused, with the seam's refusal.
    let k = key(5);
    assert_eq!(
        verify_document_through(
            &Sentinel,
            &jws_pin("refuse"),
            &signed_by(&k),
            Handshake::default()
        ),
        Err(VerifyRefusal::Jws(JwsError::NoSignatureVerified)),
    );
}

#[test]
fn verify_document_over_the_process_seam_matches_the_free_function() {
    use super::super::verify::{verify_document, Handshake};
    let k = key(6);
    let card = signed_by(&k);
    let key_pin = key_info_base64(&k);
    let pin = super::super::pin::pin_a_signed_card(&card, &key_pin).expect("verifies");
    let verified =
        verify_document(&jws_pin(&key_pin), &card, Handshake::default()).expect("verifies");
    assert_eq!(verified.pin, pin);
}

/// THE ONE-PATH RATCHET: outside its definition and this seam, no production source in the crate
/// calls `pin_a_signed_card`, and the verify driver reads the process seam. A second, direct verifier
/// would be a path a boot flip of the seam silently does not cover.
#[test]
fn the_seam_is_the_only_production_caller_of_the_card_verifier() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).expect("read src dir") {
            let p = e.expect("dir entry").path();
            if p.is_dir() {
                if p.file_name().is_some_and(|n| n == "tests") {
                    continue;
                }
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk(&src, &mut files);
    let mut callers = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f).expect("read source");
        for (i, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            if code.contains("pin_a_signed_card(") && !code.contains("fn pin_a_signed_card(") {
                callers.push(format!("{}:{}", f.display(), i + 1));
            }
        }
    }
    assert!(
        callers.iter().all(|c| c.contains("inbound_jws.rs:")),
        "`pin_a_signed_card` has a production caller outside the inbound-JWS seam: {callers:?}"
    );
    assert_eq!(
        callers.len(),
        1,
        "the seam's pass-through is the one caller: {callers:?}"
    );
    let verify = std::fs::read_to_string(src.join("a2a/verify.rs")).expect("read verify.rs");
    assert!(
        verify.contains("inbound_jws::inbound_card_jws()"),
        "verify_document reads the process inbound-JWS seam"
    );
}
