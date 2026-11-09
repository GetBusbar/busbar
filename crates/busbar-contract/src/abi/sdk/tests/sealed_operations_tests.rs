// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{Cred, CredentialPart as Part, Digest, SealedValue};
use zeroize::Zeroizing;

fn credential(bytes: &[u8]) -> Cred {
    Cred::captured(Zeroizing::new(bytes.to_vec()))
}

fn value(bytes: &[u8]) -> SealedValue {
    credential(bytes).sealed_value()
}

#[test]
fn sealed_derivations_match_published_primitive_vectors() {
    let input = value(b"abc");
    for (algorithm, expected) in [
        (Digest::Md5, "900150983cd24fb0d6963f7d28e17f72"),
        (Digest::Sha1, "a9993e364706816aba3e25717850c26c9cd0d89d"),
        (
            Digest::Sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
    ] {
        assert!(input
            .digest(algorithm)
            .hex_lower()
            .verify_eq(expected.as_bytes()));
    }
    // RFC 4231 test case 1.
    assert!(value(&[0x0b; 20])
        .hmac_sha256(&value(b"Hi There"))
        .hex_lower()
        .verify_eq(b"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    assert!(value(b"password")
        .pbkdf2_sha256(b"salt", 1)
        .unwrap()
        .hex_lower()
        .verify_eq(b"120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"));
    assert!(value(b"password")
        .pbkdf2_sha256(b"salt", 2)
        .unwrap()
        .hex_lower()
        .verify_eq(b"ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"));
}

#[test]
fn sealed_composition_preserves_bytes_and_all_inputs_security_requirements() {
    let key = credential(b"secret").require_secure();
    let derived = key.sealed_value();
    let seal = key.field();
    for parts in [
        vec![
            Part::Public(b"["),
            Part::Credential(&key),
            Part::Public(b"]"),
        ],
        vec![Part::Public(b"["), Part::Sealed(&seal), Part::Public(b"]")],
        vec![
            Part::Public(b"["),
            Part::Value(&derived),
            Part::Public(b"]"),
        ],
    ] {
        let result = SealedValue::compose(&parts);
        assert!(result.verify_eq(b"[secret]"));
        assert!(result.secure_required());
    }
    assert!(!SealedValue::compose(&[Part::Public(b"public")]).secure_required());
    assert!(SealedValue::compose(&[]).is_empty());
}

#[test]
fn every_transform_preserves_secure_requirement_including_secondary_inputs() {
    let original = credential(b"a b").require_secure();
    let key = original.sealed_value();
    let plain = value(b"foo");
    for output in [
        key.digest(Digest::Md5),
        key.digest(Digest::Sha1),
        key.digest(Digest::Sha256),
        key.hmac_sha256(&plain),
        plain.hmac_sha256(&key),
        key.pbkdf2_sha256(b"salt", 1).unwrap(),
        key.xor(&plain).unwrap(),
        plain.xor(&key).unwrap(),
        key.xor_repeating(b"mask").unwrap(),
        key.hex_lower(),
        key.base64(),
        original.normalize_ascii_spaces(),
    ] {
        assert!(output.secure_required());
        assert!(output.field().secure_required());
    }
}

#[test]
fn encoding_normalization_and_xor_remain_sealed_and_exact() {
    assert!(value(b"\x00\xff").hex_lower().verify_eq(b"00ff"));
    assert!(value(b"\x00\xff").base64().verify_eq(b"AP8="));
    assert!(credential(b"  alpha   beta \tgamma  ")
        .normalize_ascii_spaces()
        .verify_eq(b"alpha beta \tgamma"));
    assert!(credential(b"   ").normalize_ascii_spaces().is_empty());
    assert!(value(&[1, 2, 3])
        .xor(&value(&[3, 2, 1]))
        .unwrap()
        .verify_eq(&[2, 0, 2]));
    assert!(value(&[1, 2, 3])
        .xor_repeating(&[3, 2])
        .unwrap()
        .verify_eq(&[2, 0, 0]));
    assert!(value(&[1]).xor(&value(&[1, 2])).is_err());
    assert!(value(&[1]).xor_repeating(&[]).is_err());
    assert!(value(b"x").pbkdf2_sha256(b"salt", 0).is_err());
    assert!(value(b"x").pbkdf2_sha256(b"salt", 1_000_001).is_err());
}
