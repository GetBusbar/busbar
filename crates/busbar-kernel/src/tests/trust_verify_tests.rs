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
