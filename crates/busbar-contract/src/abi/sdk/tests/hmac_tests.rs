// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Wiped authentication digests against published vectors and the contract's SHA-256 oracle.

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

#[test]
fn hmac_sha1_answers_rfc_2202_with_multipart_messages() {
    let cases: &[(&[u8], &[u8], &str)] = &[
        (
            &[0x0b; 20],
            b"Hi There",
            "b617318655057264e28bc0b6fb378c8ef146be00",
        ),
        (
            b"Jefe",
            b"what do ya want for nothing?",
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
        ),
        (
            &[0xaa; 80],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            "aa4ae5e15272d00e95705637ce8a3b55ed402112",
        ),
    ];
    for &(key, message, expected) in cases {
        let key = Cred::captured(Zeroizing::new(key.to_vec()));
        let digest: Zeroizing<[u8; 20]> = hmac_sha1(&key, &[message]);
        assert_eq!(hex::encode(&digest[..]), expected);
        for split in 0..=message.len() {
            let digest: Zeroizing<[u8; 20]> =
                hmac_sha1(&key, &[&message[..split], b"", &message[split..]]);
            assert_eq!(hex::encode(&digest[..]), expected, "split {split}");
        }
    }
}

#[test]
fn hmac_sha1_accepts_empty_key_and_message() {
    let key = Cred::empty();
    for parts in [&[][..], &[b"".as_slice()][..]] {
        let digest: Zeroizing<[u8; 20]> = hmac_sha1(&key, parts);
        assert_eq!(
            hex::encode(&digest[..]),
            "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"
        );
    }
}

#[test]
fn public_wiped_sha256_answers_fips_vectors() {
    for (message, expected) in [
        (
            b"".as_slice(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc".as_slice(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_slice(),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ] {
        let digest: Zeroizing<[u8; 32]> = sha256(&[message]);
        assert_eq!(hex::encode(&digest[..]), expected);
    }
    let digest: Zeroizing<[u8; 32]> = sha256(&[]);
    assert_eq!(digest[..], crate::abi::sdk::digest::sha256(b""));
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
        for split in [0, msg.len() / 2, msg.len()] {
            let digest: Zeroizing<[u8; 32]> = sha256(&[&msg[..split], b"", &msg[split..]]);
            assert_eq!(
                digest[..],
                crate::abi::sdk::digest::sha256(msg),
                "length {n}, split {split}"
            );
        }
    }
}
