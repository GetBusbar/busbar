// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The wiped HMAC-SHA256 (`crate::wiped`): the published vectors, agreement with `ring` over every
//! key and message length the derivation can meet, and the derivation keyed through it.

use crate::wiped::hmac_sha256;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// RFC 4231 test cases 1 and 2.
#[test]
fn the_wiped_hmac_reproduces_the_rfc_4231_vectors() {
    assert_eq!(
        hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

/// The wiped HMAC agrees with `ring`'s on every key length up to a block and on messages that
/// cross every padding boundary, so the derivation it keys produces the secrets it always did.
#[test]
fn the_wiped_hmac_agrees_with_ring_across_key_and_message_lengths() {
    let bytes: Vec<u8> = (0..300u32).map(|i| (i * 7 + 3) as u8).collect();
    for key_len in [0, 1, 20, 32, 55, 56, 63, 64] {
        let key = &bytes[..key_len];
        let ring_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
        for msg_len in (0..=200).chain([255, 256, 299]) {
            let msg = &bytes[100..100 + msg_len.min(200)];
            assert_eq!(
                hmac_sha256(key, msg).as_slice(),
                ring::hmac::sign(&ring_key, msg).as_ref(),
                "key {key_len} bytes, message {} bytes",
                msg.len()
            );
        }
    }
}

/// THE SEED-KEYED DERIVATION KEYS THE WIPED HMAC, NOT `ring`'s (Q128 arch u41 #1; THE DESIGN §6
/// l.871, ruling 5): `derived_secret` builds no `ring::hmac::Key`, whose padded key and block
/// states outlive the call unwiped, and its secret is the wiped HMAC of the label under the seed.
///
/// RED before the fix: `derived_secret` keyed `ring::hmac::Key::new` with the seed.
#[test]
fn the_derived_secret_is_keyed_through_the_wiped_hmac() {
    let source = include_str!("../sign.rs");
    let body = source
        .split("pub fn derived_secret")
        .nth(1)
        .and_then(|rest| rest.split("\n    }\n").next())
        .expect("sign.rs defines derived_secret");
    assert!(
        !body.contains("ring::hmac"),
        "derived_secret must not key ring's HMAC with the seed:\n{body}"
    );
    let seed = [9u8; 32];
    let key = crate::sign::AuditSigningKey::from_seed(&seed);
    let label = b"busbar deployment keyset: caller-ref material v1";
    let ring_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &seed);
    assert_eq!(
        key.derived_secret(label).as_slice(),
        ring::hmac::sign(&ring_key, label).as_ref(),
        "the derived secret is the value it always was"
    );
}
