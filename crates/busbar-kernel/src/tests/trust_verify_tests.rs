// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `trust.verify`: a document's detached signatures judged against the root key the counterparty's
//! declared pin names. The key selects the algorithm; the header only agrees with it; a tampered
//! signature or payload, or a signature by any other key, is never accepted.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{json, Value};

use super::*;
use crate::trust::reverify::Policy;
use crate::trust::section::{DeclaredPin, TrustEntry};

const PAYLOAD: &[u8] = br#"{"name":"peer","version":"1"}"#;

/// The DER head of an Ed25519 SubjectPublicKeyInfo (RFC 8410 section 4).
const KEY_INFO_HEAD: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// The operator's out-of-band form of `k`'s public half: base64 SPKI.
fn key_info(k: &SigningKey) -> String {
    STANDARD.encode([&KEY_INFO_HEAD[..], k.verifying_key().as_bytes()].concat())
}

fn entry(root_key: Option<String>, root: bool) -> TrustEntry {
    TrustEntry {
        pin: Some(DeclaredPin {
            mechanism: "signature-root".into(),
            root,
            peer_key: false,
            key: root_key,
            fingerprint: None,
        }),
        policy: Policy {
            ttl_ms: 0,
            recovery_backoff_ms: 0,
        },
        approved: Default::default(),
    }
}

fn caller(instance: &str) -> Caller {
    Caller {
        instance: Arc::from(instance),
        plugin: Arc::from("plugin"),
        kind: busbar_contract::abi::mechanism::KindCode::Plane,
    }
}

/// An instance declaring `issuer` rooted in key 1, `no-root` with a pin naming no root key, and
/// `bad-root` whose root key is not a key.
fn host() -> KernelServices {
    let s = KernelServices::new();
    s.admit(
        "inst",
        InstanceFacts {
            trust: vec![
                ("issuer".into(), entry(Some(key_info(&key(1))), true)),
                ("no-root".into(), entry(None, false)),
                ("bad-root".into(), entry(Some("not a key".into()), true)),
            ],
            ..InstanceFacts::default()
        },
    )
    .unwrap();
    s
}

/// One signature object over `payload` by `k`, under the header `header`.
fn signature(k: &SigningKey, header: &Value, payload: &[u8]) -> Value {
    let protected = URL_SAFE_NO_PAD.encode(header.to_string());
    let input = format!("{protected}.{}", URL_SAFE_NO_PAD.encode(payload));
    let sig = k.sign(input.as_bytes());
    json!({ "protected": protected, "signature": URL_SAFE_NO_PAD.encode(sig.to_bytes()) })
}

fn eddsa() -> Value {
    json!({ "alg": "EdDSA", "kid": "k1" })
}

fn verify(s: &KernelServices, cp: &str, payload: &[u8], sigs: &Value) -> Stored {
    s.trust_verify(&caller("inst"), cp, payload, sigs.to_string().as_bytes())
}

fn verdict(st: &Stored) -> (Outcome, u64, &[u8]) {
    (st.outcome, st.value, st.bytes.as_slice())
}

/// Ported from the retired agent engine's inbound_jws_tests.rs::the_seam_verifies_a_good_card_byte_identically_to_the_free_function,
/// ::the_capability_verifies_byte_identically_to_the_free_function and
/// ::verify_document_over_the_process_seam_matches_the_free_function: a card's signature is judged
/// on this one path (the door hands its payload and signatures here), so there is no second
/// verifier for it to agree with.
#[test]
fn a_signature_by_the_root_key_verifies() {
    let s = host();
    let sigs = json!([signature(&key(1), &eddsa(), PAYLOAD)]);
    let st = verify(&s, "issuer", PAYLOAD, &sigs);
    assert_eq!(
        verdict(&st),
        (Outcome::Ready, svc::SIGNED_VERIFIED, &b""[..])
    );
    assert!(st.spans.is_empty());
}

/// RED: a TAMPERED SIGNATURE (one bit flipped) is never accepted.
#[test]
fn a_tampered_signature_is_not_by_the_root() {
    let s = host();
    let mut sig = signature(&key(1), &eddsa(), PAYLOAD);
    let mut raw = URL_SAFE_NO_PAD
        .decode(sig["signature"].as_str().unwrap())
        .unwrap();
    raw[10] ^= 0x01;
    sig["signature"] = Value::String(URL_SAFE_NO_PAD.encode(raw));
    let st = verify(&s, "issuer", PAYLOAD, &json!([sig]));
    assert_eq!(
        verdict(&st),
        (Outcome::Ready, svc::SIGNED_NOT_BY_ROOT, &b""[..])
    );
}

/// Ported from the retired agent engine's inbound_jws_tests.rs::the_seam_refuses_a_wrong_key_and_a_malformed_key_exactly_as_the_free_function
/// (its wrong-key half).
///
/// RED: a payload changed after signing, and a signature by another key, are never accepted.
#[test]
fn a_tampered_payload_or_another_key_is_not_by_the_root() {
    let s = host();
    let sigs = json!([signature(&key(1), &eddsa(), PAYLOAD)]);
    let st = verify(&s, "issuer", br#"{"name":"peer","version":"2"}"#, &sigs);
    assert_eq!(st.value, svc::SIGNED_NOT_BY_ROOT);
    let other = json!([signature(&key(2), &eddsa(), PAYLOAD)]);
    assert_eq!(
        verify(&s, "issuer", PAYLOAD, &other).value,
        svc::SIGNED_NOT_BY_ROOT
    );
}

/// A signature by another key beside the root's (a rotation) still verifies; a malformed one
/// anywhere in the list is a hard refusal, never skipped.
#[test]
fn a_second_signature_by_the_root_verifies_and_a_malformed_one_refuses() {
    let s = host();
    let both = json!([
        signature(&key(2), &eddsa(), PAYLOAD),
        signature(&key(1), &eddsa(), PAYLOAD)
    ]);
    assert_eq!(
        verify(&s, "issuer", PAYLOAD, &both).value,
        svc::SIGNED_VERIFIED
    );
    let garbage_first = json!([
        { "protected": URL_SAFE_NO_PAD.encode(eddsa().to_string()), "signature": "AAAA" },
        signature(&key(1), &eddsa(), PAYLOAD)
    ]);
    assert_eq!(
        verify(&s, "issuer", PAYLOAD, &garbage_first).value,
        svc::SIGNED_MALFORMED_SIGNATURE
    );
}

/// The key decides the algorithm: `none`, a symmetric algorithm and a missing `alg` are refused
/// by name, even over a valid Ed25519 signature.
#[test]
fn the_header_algorithm_only_agrees_with_the_key() {
    let s = host();
    for (header, named) in [
        (json!({ "alg": "none" }), &b"none"[..]),
        (json!({ "alg": "HS256" }), &b"HS256"[..]),
        (json!({ "kid": "k1" }), &b""[..]),
    ] {
        let sigs = json!([signature(&key(1), &header, PAYLOAD)]);
        let st = verify(&s, "issuer", PAYLOAD, &sigs);
        assert_eq!(verdict(&st), (Outcome::Ready, svc::SIGNED_ALGORITHM, named));
    }
}

/// RFC 7515 section 4.1.11: a `crit` member is refused by name; an empty or non-string `crit`
/// is a malformed header.
#[test]
fn a_critical_member_is_refused_by_name() {
    let s = host();
    let crit = json!({ "alg": "EdDSA", "crit": ["b64"], "b64": false });
    let st = verify(
        &s,
        "issuer",
        PAYLOAD,
        &json!([signature(&key(1), &crit, PAYLOAD)]),
    );
    assert_eq!(
        verdict(&st),
        (Outcome::Ready, svc::SIGNED_CRITICAL, &b"b64"[..])
    );
    let empty = json!({ "alg": "EdDSA", "crit": [] });
    let st = verify(
        &s,
        "issuer",
        PAYLOAD,
        &json!([signature(&key(1), &empty, PAYLOAD)]),
    );
    assert_eq!(st.value, svc::SIGNED_MALFORMED_HEADER);
}

#[test]
fn no_signature_too_many_and_malformed_parts_each_answer_their_verdict() {
    let s = host();
    let none = s.trust_verify(&caller("inst"), "issuer", PAYLOAD, b"");
    assert_eq!(verdict(&none), (Outcome::Ready, svc::SIGNED_NONE, &b""[..]));
    assert_eq!(
        verify(&s, "issuer", PAYLOAD, &json!([])).value,
        svc::SIGNED_NONE
    );
    let one = signature(&key(1), &eddsa(), PAYLOAD);
    let nine = Value::Array(vec![one; 9]);
    assert_eq!(
        verify(&s, "issuer", PAYLOAD, &nine).value,
        svc::SIGNED_TOO_MANY
    );
    let not_b64 = json!([{ "protected": "!!", "signature": "AAAA" }]);
    assert_eq!(
        verify(&s, "issuer", PAYLOAD, &not_b64).value,
        svc::SIGNED_MALFORMED_HEADER
    );
    let no_protected = json!([{ "signature": "AAAA" }]);
    assert_eq!(
        verify(&s, "issuer", PAYLOAD, &no_protected).value,
        svc::SIGNED_MALFORMED_HEADER
    );
    let short = json!([{
        "protected": URL_SAFE_NO_PAD.encode(eddsa().to_string()),
        "signature": URL_SAFE_NO_PAD.encode([0u8; 63])
    }]);
    assert_eq!(
        verify(&s, "issuer", PAYLOAD, &short).value,
        svc::SIGNED_MALFORMED_SIGNATURE
    );
}

/// Ported from the retired agent engine's inbound_jws_tests.rs::the_seam_refuses_a_wrong_key_and_a_malformed_key_exactly_as_the_free_function
/// (its malformed-key half).
///
/// The root key is checked first: a key that does not read refuses before any signature is read.
#[test]
fn a_root_key_that_is_not_a_key_is_malformed_before_anything_else() {
    let s = host();
    let st = s.trust_verify(&caller("inst"), "bad-root", PAYLOAD, b"");
    assert_eq!(
        verdict(&st),
        (Outcome::Ready, svc::SIGNED_MALFORMED_ROOT, &b""[..])
    );
}

/// Only a declared root verifies: no root key, an undeclared counterparty, an instance never
/// admitted, and signatures that are not JSON are refused.
#[test]
fn only_a_declared_root_key_verifies() {
    let s = host();
    let sigs = json!([signature(&key(1), &eddsa(), PAYLOAD)]).to_string();
    let refused = |inst: &str, cp: &str, sigs: &[u8]| {
        let st = s.trust_verify(&caller(inst), cp, PAYLOAD, sigs);
        (st.outcome, st.error)
    };
    assert_eq!(
        refused("inst", "no-root", sigs.as_bytes()),
        (Outcome::Refused, NO_ROOT_KEY)
    );
    assert_eq!(
        refused("inst", "nobody", sigs.as_bytes()),
        (Outcome::Refused, NOT_A_COUNTERPARTY)
    );
    assert_eq!(
        refused("stranger", "issuer", sigs.as_bytes()),
        (Outcome::Refused, NOT_ADMITTED)
    );
    assert_eq!(
        refused("inst", "issuer", b"[{"),
        (Outcome::Refused, SIGNATURES_NOT_JSON)
    );
}

/// A protected header that is not base64url, not JSON, or not an object is refused: a verifier that
/// treated an unparseable header as an empty one would then read no `alg` from it.
/// Ported from the retired agent engine's jws_tests.rs::a_malformed_protected_header_is_refused.
#[test]
fn a_malformed_protected_header_is_refused() {
    let s = host();
    for bad in [
        "not base64url!".to_string(),
        URL_SAFE_NO_PAD.encode(b"not json"),
        URL_SAFE_NO_PAD.encode(b"[1,2]"),
        URL_SAFE_NO_PAD.encode(b"\"s\""),
    ] {
        let sigs = json!([{ "protected": bad, "signature": URL_SAFE_NO_PAD.encode([0u8; 64]) }]);
        assert_eq!(
            verify(&s, "issuer", PAYLOAD, &sigs).value,
            svc::SIGNED_MALFORMED_HEADER,
            "header {bad:?} must be refused"
        );
    }
}

/// The protected header is used EXACTLY AS RECEIVED. Re-encoding it would change the bytes that
/// were signed, so a genuine signature whose producer spelled the header differently than a
/// serializer here would must still verify.
/// Ported from the retired agent engine's jws_tests.rs::the_protected_header_is_verified_as_received_not_as_we_would_spell_it.
#[test]
fn the_protected_header_is_verified_as_received_not_as_we_would_spell_it() {
    let s = host();
    // Whitespace and a member order no serializer of ours would produce.
    let protected = URL_SAFE_NO_PAD.encode(b"{ \"kid\" : \"vendor\",  \"alg\" : \"EdDSA\" }");
    let input = format!("{protected}.{}", URL_SAFE_NO_PAD.encode(PAYLOAD));
    let sig = key(1).sign(input.as_bytes());
    let sigs = json!([{
        "protected": protected,
        "signature": URL_SAFE_NO_PAD.encode(sig.to_bytes())
    }]);
    assert_eq!(
        verdict(&verify(&s, "issuer", PAYLOAD, &sigs)),
        (Outcome::Ready, svc::SIGNED_VERIFIED, &b""[..])
    );
}

/// The root key is parsed at the boundary: only the base64 SPKI form of an Ed25519 key is a root
/// key. A raw 32-byte key, a wrong prefix and a wrong length are refused, so an operator pasting
/// the wrong thing does not silently get it as the trust root; surrounding whitespace is trimmed.
/// Ported from the retired agent engine's jws_tests.rs::only_a_well_formed_ed25519_key_info_becomes_an_issuer_key.
#[test]
fn only_a_well_formed_ed25519_key_info_becomes_an_issuer_key() {
    use crate::trust::signed::root_key;
    let k = key(1);
    assert!(root_key(&key_info(&k)).is_ok());
    assert!(root_key(&format!("  {}\n", key_info(&k))).is_ok());

    let raw = STANDARD.encode(k.verifying_key().as_bytes());
    assert_eq!(
        root_key(&raw),
        Err((svc::SIGNED_MALFORMED_ROOT, String::new()))
    );
    for bad in [
        String::new(),
        "not base64".to_string(),
        STANDARD.encode([0u8; 44]),
        STANDARD.encode([0u8; 12]),
    ] {
        assert_eq!(
            root_key(&bad),
            Err((svc::SIGNED_MALFORMED_ROOT, String::new())),
            "issuer key {bad:?} must be refused"
        );
    }
}

/// Ported from the retired agent engine's jws_tests.rs::a_rotation_carrying_two_signatures_reports_which_one_verified
/// (its verdict: which of the signatures verified, by index and key id, is no longer reported;
/// `trust.verify` answers a verdict code alone).
///
/// A vendor rotating its key carries two signatures, the outgoing key's and the incoming one's:
/// a counterparty pinned to either verifies, and one pinned to a third party's key does not — the
/// operator pinned one identity, and a countersignature buys nothing.
#[test]
fn a_rotation_carrying_two_signatures_verifies_under_either_pinned_key_and_no_third() {
    let s = pinned(&[
        ("vendor-2025", key_info(&key(1))),
        ("vendor-2026", key_info(&key(2))),
        ("third", key_info(&key(3))),
    ]);
    let both = json!([
        signature(
            &key(1),
            &json!({ "alg": "EdDSA", "kid": "vendor-2025" }),
            PAYLOAD
        ),
        signature(
            &key(2),
            &json!({ "alg": "EdDSA", "kid": "vendor-2026" }),
            PAYLOAD
        ),
    ]);
    for incoming_or_outgoing in ["vendor-2026", "vendor-2025"] {
        assert_eq!(
            verdict(&verify(&s, incoming_or_outgoing, PAYLOAD, &both)),
            (Outcome::Ready, svc::SIGNED_VERIFIED, &b""[..]),
            "{incoming_or_outgoing}"
        );
    }
    assert_eq!(
        verify(&s, "third", PAYLOAD, &both).value,
        svc::SIGNED_NOT_BY_ROOT
    );
}

// ── BUSBAR'S OWN CARD KEY, JUDGED BY THIS VERIFIER ──────────────────────────────────────────────
//
// A card busbar serves is signed through the host `sign` service ([`SignKey`] over
// `GovState::sign_in_domain`) under the subkey the deployment's token secret derives for the
// signing plane's declared domain; a caller pins busbar by that subkey's public half
// (`TokenSigner::card_subkey_key_info_base64`). Nothing below re-implements a signature check:
// every verdict is this verifier's, the one busbar points at every counterparty's signed document.

/// A plane's declared card-signing domain. Any versioned domain derives the same way; the plane
/// that signs cards states its own.
const CARD_DOMAIN: &str = "example-plane/card-signing/v1";

/// An instance declaring each `(counterparty, root key)` of `roots` as a signature root.
fn pinned(roots: &[(&str, String)]) -> KernelServices {
    let s = KernelServices::new();
    s.admit(
        "inst",
        InstanceFacts {
            trust: roots
                .iter()
                .map(|(name, root)| ((*name).into(), entry(Some(root.clone()), true)))
                .collect(),
            ..InstanceFacts::default()
        },
    )
    .unwrap();
    s
}

/// The token signer of the deployment `seed` names.
fn token_signer(seed: u8) -> crate::governance::signing::TokenSigner {
    crate::governance::signing::TokenSigner::from_secret_bytes(
        &[seed; 32],
        crate::governance::signing::DEFAULT_KID,
    )
}

/// The deployment `seed` names: a governance book holding [`token_signer`]`(seed)`.
fn deployment(seed: u8) -> crate::governance::GovState {
    crate::governance::GovState::new_with_signer(
        Arc::new(crate::governance::MemoryStore::new()),
        None,
        Some(token_signer(seed)),
    )
    .expect("a governance book with a signing key")
}

/// The card-issuer key a caller pins the deployment `seed` names by.
fn card_key(seed: u8) -> String {
    token_signer(seed).card_subkey_key_info_base64(CARD_DOMAIN)
}

/// `payload` signed by `deployment` through the `sign` service, as a served card is signed: the
/// key id read with a first signature, then one detached EdDSA signature under a header naming
/// it.
fn busbar_signed(deployment: &crate::governance::GovState, payload: &[u8]) -> Value {
    let (kid, _) = SignKey::sign(deployment, CARD_DOMAIN, b"").expect("a signing key");
    let protected = URL_SAFE_NO_PAD.encode(json!({ "alg": "EdDSA", "kid": kid }).to_string());
    let input = format!("{protected}.{}", URL_SAFE_NO_PAD.encode(payload));
    let (_, sig) = SignKey::sign(deployment, CARD_DOMAIN, input.as_bytes()).expect("signed");
    json!({ "protected": protected, "signature": URL_SAFE_NO_PAD.encode(sig) })
}

/// Ported from the retired agent engine's sign_tests.rs::a_card_signed_by_a_different_busbar_deployment_does_not_verify_here.
///
/// Two deployments, two token secrets, two derived card keys. A caller that pinned one must not
/// accept the other, or the pin identifies "some busbar" rather than "this busbar". The control:
/// this deployment's own card verifies against its own key.
#[test]
fn a_card_signed_by_a_different_busbar_deployment_does_not_verify_here() {
    let s = pinned(&[("ours", card_key(7))]);
    let ours = json!([busbar_signed(&deployment(7), PAYLOAD)]);
    assert_eq!(
        verdict(&verify(&s, "ours", PAYLOAD, &ours)),
        (Outcome::Ready, svc::SIGNED_VERIFIED, &b""[..])
    );
    let theirs = json!([busbar_signed(&deployment(9), PAYLOAD)]);
    assert_eq!(
        verify(&s, "ours", PAYLOAD, &theirs).value,
        svc::SIGNED_NOT_BY_ROOT
    );
}

/// Ported from the retired agent engine's sign_tests.rs::the_card_key_is_not_the_token_key_and_cannot_be_walked_back_to_it.
///
/// A served card is a counterparty's document with busbar's endpoints substituted in; signing it
/// with the credential-minting key would make the card path a signing oracle over
/// upstream-chosen bytes. The published card key is neither the token key nor its secret, and a
/// served card's signature does not verify as the token key's.
#[test]
fn the_card_key_is_not_the_token_key_and_cannot_be_walked_back_to_it() {
    let token = token_signer(7);
    let card_key_pin = STANDARD.decode(card_key(7)).expect("public-key info");
    assert_eq!(&card_key_pin[..12], &KEY_INFO_HEAD[..], "an Ed25519 SPKI");
    assert_ne!(
        &card_key_pin[12..],
        token.verifying_key().as_bytes().as_slice(),
        "THE WHOLE POINT: the card key is not the credential-minting key"
    );
    assert_ne!(
        card_key_pin[12..],
        token.secret_bytes(),
        "and the derived PUBLIC key must not be the token SECRET either"
    );
    let token_key =
        STANDARD.encode([&KEY_INFO_HEAD[..], token.verifying_key().as_bytes()].concat());
    let s = pinned(&[("token-key", token_key)]);
    let card = json!([busbar_signed(&deployment(7), PAYLOAD)]);
    assert_eq!(
        verify(&s, "token-key", PAYLOAD, &card).value,
        svc::SIGNED_NOT_BY_ROOT,
        "a served card's signature is not the token key's"
    );
}

/// Ported from the retired agent engine's sign_tests.rs::rotating_the_token_key_rotates_the_card_key_with_it.
///
/// An operator rotating the signing key is also rotating what external callers pinned: the card
/// key moves with it, and a caller pinned to the key before sees the card after as not signed by
/// its root.
#[test]
fn rotating_the_token_key_rotates_the_card_key_with_it() {
    assert_ne!(card_key(7), card_key(8));
    let s = pinned(&[("before", card_key(7))]);
    let after = json!([busbar_signed(&deployment(8), PAYLOAD)]);
    assert_eq!(
        verify(&s, "before", PAYLOAD, &after).value,
        svc::SIGNED_NOT_BY_ROOT
    );
}
