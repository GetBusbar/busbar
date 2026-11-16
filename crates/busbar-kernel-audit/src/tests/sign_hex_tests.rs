// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The key and signature text the audit signer reads and writes: lowercase hex only, pinned before
//! the hand codec moves onto the `hex` crate (DEPENDENCY-LADDER C5).

use crate::sign::{AuditSigningKey, AuditVerifyingKey, KeyError};

const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

#[test]
fn keys_read_and_write_lowercase_hex() {
    let key = AuditSigningKey::from_hex_seed(SEED).expect("the RFC 8032 test 1 seed");
    assert_eq!(key.public_key_hex(), PUBLIC);
    assert_eq!(
        AuditSigningKey::from_hex_seed(&format!(" {SEED}\n"))
            .expect("surrounding whitespace is trimmed")
            .public_key_hex(),
        PUBLIC
    );
    let public = AuditVerifyingKey::from_hex(PUBLIC).expect("the RFC 8032 test 1 key");
    assert_eq!(public.public_key_hex(), PUBLIC);

    let digest = "00".repeat(32);
    let signature = key.sign_digest(&digest);
    assert_eq!(signature.len(), 128);
    assert!(signature
        .bytes()
        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
    assert_eq!(public.verify_digest(&digest, &signature), Ok(()));
    assert_eq!(
        public.verify_digest(&digest, &signature.to_ascii_uppercase()),
        Err(KeyError::MalformedSignature),
        "an uppercase signature is not the spelling"
    );
}

#[test]
fn key_text_that_is_not_lowercase_hex_is_refused_without_detail() {
    let refused = |text: &str| AuditSigningKey::from_hex_seed(text).err();
    assert_eq!(refused(&SEED.to_ascii_uppercase()), Some(KeyError::NotHex));
    assert_eq!(
        refused(&format!("{}A", &SEED[..63])),
        Some(KeyError::NotHex)
    );
    assert_eq!(
        refused(&format!("{}g", &SEED[..63])),
        Some(KeyError::NotHex)
    );
    assert_eq!(
        refused(&format!("+{}", &SEED[..63])),
        Some(KeyError::NotHex)
    );
    assert_eq!(refused(&SEED[..62]), Some(KeyError::WrongLength));
    assert_eq!(refused(&format!("{SEED}00")), Some(KeyError::WrongLength));
    assert_eq!(refused(""), Some(KeyError::WrongLength));
    assert_eq!(
        AuditVerifyingKey::from_hex(&PUBLIC.to_ascii_uppercase()).err(),
        Some(KeyError::NotHex)
    );
}

/// QE: a pinned audit key with no point on edwards25519 (`y = 2`: canonical, not small-order) is
/// refused when it is read, as `NotAKey`, the class it had before Q9b.
#[test]
fn an_off_curve_public_key_is_not_a_key() {
    assert_eq!(
        AuditVerifyingKey::from_hex(
            "0200000000000000000000000000000000000000000000000000000000000000"
        ),
        Err(KeyError::NotAKey)
    );
}
