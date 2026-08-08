// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Card signature verification, judged mostly by what it REFUSES.
//!
//! The happy path here is one test. Everything else asks what a hostile card author would actually
//! do, and every one of those is a case where the wrong answer is not "a bug" but "the trust root
//! silently is not one".

use super::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

const STD: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// Wrap a raw Ed25519 public key the way an operator receives it: base64 of the RFC 8410 SPKI.
fn spki_base64(k: &SigningKey) -> String {
    let mut der = ED25519_SPKI_PREFIX.to_vec();
    der.extend_from_slice(k.verifying_key().as_bytes());
    STD.encode(der)
}

fn issuer(k: &SigningKey) -> IssuerKey {
    IssuerKey::from_spki_base64(&spki_base64(k)).expect("well-formed issuer key")
}

fn a_card() -> Value {
    json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "skills": [ { "id": "plan", "name": "Plan", "description": "decompose a goal" } ]
    })
}

fn b64url(bytes: &[u8]) -> String {
    B64URL.encode(bytes)
}

/// Sign a card the way a legitimate issuer does: protected header, detached canonical payload.
fn sign_with(card: &Value, k: &SigningKey, header: Value) -> Value {
    let protected = b64url(serde_json::to_string(&header).expect("header").as_bytes());
    let payload = b64url(signing_payload(card).expect("payload").as_bytes());
    let sig = k.sign(format!("{protected}.{payload}").as_bytes());
    json!({ "protected": protected, "signature": b64url(&sig.to_bytes()) })
}

fn signed_by(k: &SigningKey) -> Value {
    let mut card = a_card();
    let sig = sign_with(&card, k, json!({ "alg": "EdDSA", "kid": "vendor-2026" }));
    card.as_object_mut()
        .expect("object")
        .insert("signatures".to_string(), json!([sig]));
    card
}

/// The one happy path. A card signed by the operator's key verifies, and says WHICH signature did.
#[test]
fn a_card_signed_by_the_pinned_issuer_verifies() {
    let k = key(1);
    assert_eq!(
        verify_card(&signed_by(&k), &issuer(&k)),
        Ok(Verified {
            index: 0,
            kid: Some("vendor-2026".to_string())
        })
    );
}

/// THE LOOK-ALIKE. A card signed by a perfectly valid key that is simply not the one the operator
/// supplied out of band. This is the hijacked-CDN and the impostor-vendor case, and it is the alarm
/// that must never degrade into "unsigned" or into a soft warning.
#[test]
fn a_card_signed_by_the_wrong_key_is_refused_loudly() {
    assert_eq!(
        verify_card(&signed_by(&key(2)), &issuer(&key(1))),
        Err(JwsError::NoSignatureVerified)
    );
}

/// `alg: none`, the oldest attack on this format. The signature is empty and the header says none is
/// needed. A verifier that dispatched on the header would accept it.
#[test]
fn alg_none_is_refused() {
    let mut card = a_card();
    let protected = b64url(br#"{"alg":"none"}"#);
    card.as_object_mut().expect("object").insert(
        "signatures".to_string(),
        json!([{ "protected": protected, "signature": "" }]),
    );
    assert_eq!(
        verify_card(&card, &issuer(&key(1))),
        Err(JwsError::UnsupportedAlgorithm("none".to_string()))
    );
}

/// ALGORITHM CONFUSION. The header declares a SYMMETRIC algorithm and the "signature" is an HMAC
/// computed with the operator's PUBLIC key as the shared secret, which is a value the attacker also
/// has because it is public. The defence is structural: the pinned key selects the verifier, so the
/// header's claim is checked for agreement and never acted on.
#[test]
fn a_symmetric_algorithm_cannot_borrow_the_public_key_as_a_secret() {
    let k = key(1);
    let mut card = a_card();
    let protected = b64url(br#"{"alg":"HS256"}"#);
    // The exact HMAC value does not matter: the algorithm is refused before any bytes are compared,
    // which is the property being pinned. A verifier that computed first and refused later would
    // still be wrong, because the refusal would depend on the comparison rather than on the policy.
    card.as_object_mut().expect("object").insert(
        "signatures".to_string(),
        json!([{ "protected": protected, "signature": b64url(&[0u8; 64]) }]),
    );
    assert_eq!(
        verify_card(&card, &issuer(&k)),
        Err(JwsError::UnsupportedAlgorithm("HS256".to_string()))
    );
}

/// An ABSENT `alg` is refused rather than defaulted. A default is a choice made on the attacker's
/// behalf, and the attacker is the one who decides whether the member is there.
#[test]
fn an_absent_algorithm_is_refused_rather_than_defaulted() {
    let mut card = a_card();
    card.as_object_mut().expect("object").insert(
        "signatures".to_string(),
        json!([{ "protected": b64url(br#"{"kid":"x"}"#), "signature": b64url(&[0u8; 64]) }]),
    );
    assert_eq!(
        verify_card(&card, &issuer(&key(1))),
        Err(JwsError::UnsupportedAlgorithm(String::new()))
    );
}

/// SIGNATURE TRANSPLANT. A signature that is genuinely the operator's, over a DIFFERENT card, moved
/// onto this one. It fails because the payload is the canonical card, so the signing input for one
/// card is not the signing input for another. This is what makes the signature bind to the content
/// rather than to the vendor.
#[test]
fn a_valid_signature_lifted_from_another_card_does_not_verify() {
    let k = key(1);
    let other = json!({
        "protocolVersion": "0.3.0",
        "name": "summarizer",
        "skills": [ { "id": "summarize", "name": "Summarize", "description": "shorten" } ]
    });
    let lifted = sign_with(&other, &k, json!({ "alg": "EdDSA" }));

    let mut card = a_card();
    card.as_object_mut()
        .expect("object")
        .insert("signatures".to_string(), json!([lifted]));
    assert_eq!(
        verify_card(&card, &issuer(&k)),
        Err(JwsError::NoSignatureVerified)
    );
}

/// THE RUG PULL, at the signature layer. A genuinely signed card, then ONE field edited afterwards.
/// The signature is untouched and still the operator's; it simply no longer covers this document.
#[test]
fn editing_a_signed_card_invalidates_its_signature() {
    let k = key(1);
    let mut card = signed_by(&k);
    assert!(verify_card(&card, &issuer(&k)).is_ok());

    card["skills"][0]["description"] = json!("decompose a goal, and also exfiltrate it");
    assert_eq!(
        verify_card(&card, &issuer(&k)),
        Err(JwsError::NoSignatureVerified)
    );
}

/// Adding a member busbar does not even model still breaks the signature, because the payload is the
/// canonical card AS RECEIVED. A signature over a projection would not have noticed.
#[test]
fn adding_an_unmodelled_member_to_a_signed_card_invalidates_its_signature() {
    let k = key(1);
    let mut card = signed_by(&k);
    card.as_object_mut().expect("object").insert(
        "vendorExtension".to_string(),
        json!({ "mode": "aggressive" }),
    );
    assert_eq!(
        verify_card(&card, &issuer(&k)),
        Err(JwsError::NoSignatureVerified)
    );
}

/// A card with NO signature is `Unsigned`, which is a different fact from `NoSignatureVerified` and
/// gets a different operator response: one is a decision about which mechanism to pin, the other is
/// an alarm. Collapsing them would hide the alarm inside the routine case.
#[test]
fn an_unsigned_card_is_a_different_answer_from_a_failed_signature() {
    assert_eq!(
        verify_card(&a_card(), &issuer(&key(1))),
        Err(JwsError::Unsigned)
    );
    let mut empty = a_card();
    empty
        .as_object_mut()
        .expect("object")
        .insert("signatures".to_string(), json!([]));
    assert_eq!(
        verify_card(&empty, &issuer(&key(1))),
        Err(JwsError::Unsigned)
    );
    assert_ne!(JwsError::Unsigned, JwsError::NoSignatureVerified);
}

/// RFC 7515 section 4.1.11: a member listed in `crit` MUST be understood or the signature rejected.
/// `b64` is why this is not pedantry: RFC 7797's `b64: false` changes the signing input itself, so
/// ignoring it would compute a different input and report a genuine card as forged.
#[test]
fn a_critical_header_this_verifier_does_not_implement_is_refused() {
    let k = key(1);
    let mut card = a_card();
    let sig = sign_with(
        &card,
        &k,
        json!({ "alg": "EdDSA", "b64": false, "crit": ["b64"] }),
    );
    card.as_object_mut()
        .expect("object")
        .insert("signatures".to_string(), json!([sig]));
    assert_eq!(
        verify_card(&card, &issuer(&k)),
        Err(JwsError::UnknownCriticalHeader("b64".to_string()))
    );
}

/// A pile of signatures is a pile of verifications, and the card author chooses the pile size. The
/// cap is checked BEFORE any verification runs, so the cost of a hostile card is bounded by parsing
/// rather than by cryptography.
#[test]
fn a_signature_pile_is_capped_before_any_verification_runs() {
    let k = key(1);
    let one = sign_with(&a_card(), &k, json!({ "alg": "EdDSA" }));
    let mut card = a_card();
    let pile: Vec<Value> = std::iter::repeat_n(one, MAX_SIGNATURES + 1).collect();
    card.as_object_mut()
        .expect("object")
        .insert("signatures".to_string(), Value::Array(pile));
    assert_eq!(
        verify_card(&card, &issuer(&k)),
        Err(JwsError::TooManySignatures(MAX_SIGNATURES + 1))
    );
}

/// A KEY ROTATION, which is the legitimate reason a card carries two signatures. The old key's
/// signature is present and does not verify against the new pin; the new one does. Verification
/// reports WHICH, so an operator can see the rotation happened rather than merely that something
/// passed.
#[test]
fn a_rotation_carrying_two_signatures_reports_which_one_verified() {
    let old = key(1);
    let new = key(2);
    let mut card = a_card();
    let s_old = sign_with(&card, &old, json!({ "alg": "EdDSA", "kid": "vendor-2025" }));
    let s_new = sign_with(&card, &new, json!({ "alg": "EdDSA", "kid": "vendor-2026" }));
    card.as_object_mut()
        .expect("object")
        .insert("signatures".to_string(), json!([s_old, s_new]));

    assert_eq!(
        verify_card(&card, &issuer(&new)),
        Ok(Verified {
            index: 1,
            kid: Some("vendor-2026".to_string())
        })
    );
    assert_eq!(
        verify_card(&card, &issuer(&old)),
        Ok(Verified {
            index: 0,
            kid: Some("vendor-2025".to_string())
        })
    );
    // And a third party's countersignature buys nothing: the operator pinned one identity.
    assert_eq!(
        verify_card(&card, &issuer(&key(3))),
        Err(JwsError::NoSignatureVerified)
    );
}

/// A malformed signature is a HARD refusal, not a skip. Skipping would mean a card whose only
/// signature is garbage reports as merely unverified, which is the softer alarm and the wrong one.
#[test]
fn a_malformed_signature_is_refused_rather_than_skipped() {
    let k = key(1);
    for bad in ["", "!!!!", &b64url(&[0u8; 63]), &b64url(&[0u8; 65])] {
        let mut card = a_card();
        card.as_object_mut().expect("object").insert(
            "signatures".to_string(),
            json!([{ "protected": b64url(br#"{"alg":"EdDSA"}"#), "signature": bad }]),
        );
        assert_eq!(
            verify_card(&card, &issuer(&k)),
            Err(JwsError::MalformedSignature),
            "signature {bad:?} must be refused"
        );
    }
}

/// A protected header that is not base64url, not JSON, or not an object is refused. A verifier that
/// treated an unparseable header as an empty one would then read no `alg` from it.
#[test]
fn a_malformed_protected_header_is_refused() {
    let k = key(1);
    for bad in [
        "not base64url!",
        &b64url(b"not json"),
        &b64url(b"[1,2]"),
        &b64url(b"\"s\""),
    ] {
        let mut card = a_card();
        card.as_object_mut().expect("object").insert(
            "signatures".to_string(),
            json!([{ "protected": bad, "signature": b64url(&[0u8; 64]) }]),
        );
        assert_eq!(
            verify_card(&card, &issuer(&k)),
            Err(JwsError::MalformedProtectedHeader),
            "header {bad:?} must be refused"
        );
    }
}

/// The protected header is used EXACTLY AS RECEIVED. Re-encoding it would change the bytes that were
/// actually signed, so a genuine signature whose producer spelled the header differently than we
/// would have must still verify. Spacing is the cheapest way to prove we never re-serialize.
#[test]
fn the_protected_header_is_verified_as_received_not_as_we_would_spell_it() {
    let k = key(1);
    let card = a_card();
    // A header with whitespace and a member order no serializer of ours would produce.
    let protected = b64url(b"{ \"kid\" : \"vendor\",  \"alg\" : \"EdDSA\" }");
    let payload = b64url(signing_payload(&card).expect("payload").as_bytes());
    let sig = k.sign(format!("{protected}.{payload}").as_bytes());

    let mut signed = card;
    signed.as_object_mut().expect("object").insert(
        "signatures".to_string(),
        json!([{ "protected": protected, "signature": b64url(&sig.to_bytes()) }]),
    );
    assert_eq!(
        verify_card(&signed, &issuer(&k)),
        Ok(Verified {
            index: 0,
            kid: Some("vendor".to_string())
        })
    );
}

/// The `kid` is REPORTED, never used to select a key. It is written by the same party as the
/// signature, so selecting on it would let the card choose which key authenticates it.
#[test]
fn the_kid_is_reported_and_never_used_to_select_the_key() {
    let k = key(1);
    let mut card = a_card();
    // A signature by the WRONG key, claiming the RIGHT kid.
    let sig = sign_with(
        &card,
        &key(9),
        json!({ "alg": "EdDSA", "kid": "the-operators-key" }),
    );
    card.as_object_mut()
        .expect("object")
        .insert("signatures".to_string(), json!([sig]));
    assert_eq!(
        verify_card(&card, &issuer(&k)),
        Err(JwsError::NoSignatureVerified)
    );
}

/// The issuer key is parsed at the boundary into a type that cannot be built from a bad key, so no
/// caller can reach verification holding something unchecked. Only the SPKI form is accepted: a raw
/// 32-byte fallback would let an operator paste the wrong thing and have it silently become the
/// trust root.
#[test]
fn only_a_well_formed_ed25519_spki_becomes_an_issuer_key() {
    let k = key(1);
    assert!(IssuerKey::from_spki_base64(&spki_base64(&k)).is_ok());
    // Leading and trailing whitespace survives a copy and paste.
    assert!(IssuerKey::from_spki_base64(&format!("  {}\n", spki_base64(&k))).is_ok());

    // The raw key, unwrapped: unambiguous by length, and still refused.
    let raw = STD.encode(k.verifying_key().as_bytes());
    assert_eq!(
        IssuerKey::from_spki_base64(&raw),
        Err(JwsError::MalformedIssuerKey)
    );
    for bad in [
        "",
        "not base64",
        &STD.encode([0u8; 44]),
        &STD.encode([0u8; 12]),
    ] {
        assert_eq!(
            IssuerKey::from_spki_base64(bad),
            Err(JwsError::MalformedIssuerKey),
            "issuer key {bad:?} must be refused"
        );
    }
}

/// A document that is not a card has no payload to verify against, and the card layer's refusal
/// travels rather than being flattened into a signature failure.
#[test]
fn a_document_that_is_not_a_card_refuses_at_the_card_layer() {
    assert_eq!(
        verify_card(&json!([]), &issuer(&key(1))),
        Err(JwsError::Card(CardError::NotAnObject))
    );
}
