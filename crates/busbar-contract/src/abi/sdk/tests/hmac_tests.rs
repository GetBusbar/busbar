// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one wiped HMAC-SHA256: RFC 4231's known answers, its SHA-256 against the contract's at every
//! padding boundary, and THE DESIGN section 6 rule it exists for, read off the SDK's own sources.

use super::*;

/// RFC 4231's HMAC-SHA-256 vectors: a short key (case 1), a key shorter than the output (case 2),
/// and a key past the block size, hashed first (case 6).
#[test]
fn the_hmac_answers_rfc_4231() {
    assert_eq!(
        hex::encode(&hmac_sha256(&[0x0b; 20], b"Hi There")[..]),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        hex::encode(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")[..]),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    assert_eq!(
        hex::encode(
            &hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )[..]
        ),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

/// The wiped SHA-256 is SHA-256: every message length across the one- and two-block padding
/// boundaries, with and without a whole prefix block, digests as the contract's SHA-256 does.
#[test]
fn the_wiped_sha256_matches_sha256_at_every_padding_boundary() {
    let data: Vec<u8> = (0..=200_u8)
        .map(|b| b.wrapping_mul(31).wrapping_add(7))
        .collect();
    let prefix = [0x5a_u8; BLOCK];
    for n in 0..=data.len() {
        let msg = &data[..n];
        assert_eq!(
            sha256_wiped(None, msg)[..],
            crate::abi::sdk::digest::sha256(msg),
            "length {n}"
        );
        let mut whole = prefix.to_vec();
        whole.extend_from_slice(msg);
        assert_eq!(
            sha256_wiped(Some(&prefix), msg)[..],
            crate::abi::sdk::digest::sha256(&whole),
            "prefix + length {n}"
        );
    }
}
