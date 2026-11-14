// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Wiped authentication digests against published vectors and the contract's SHA-256 oracle.

use super::*;

/// RFC 4231's HMAC-SHA-256 vectors: a short key (case 1), a key shorter than the output (case 2),
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

/// The SDK SHA-256 of split parts is SHA-256 of the whole, at every padding boundary.
#[test]
fn the_sdk_sha256_matches_sha256_at_every_padding_boundary() {
    let data: Vec<u8> = (0..=200_u8)
        .map(|b| b.wrapping_mul(31).wrapping_add(7))
        .collect();
    for n in 0..=data.len() {
        let msg = &data[..n];
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

/// Keys exactly one block long are used as-is; one byte more is hashed first (RFC 2104). Values
/// from an independent implementation.
#[test]
fn block_sized_and_one_over_keys_are_split_at_the_block_boundary() {
    let msg = b"block-size key witness";
    let cases: [(usize, &str, &str); 2] = [
        (
            64,
            "19c87957e10d8439278bb991929d316723e9103cb812e446bdee7fac0e1902ab",
            "fa7873e27a2b16cacd63559ab27c89fe82ea5f51",
        ),
        (
            65,
            "40f06f91a6d477fba88304053b37886e1d903c2e078a25e5ddb6a8bde522e93a",
            "0f9b26eae0e456368355be046eda9e4c2910db77",
        ),
    ];
    for (n, sha256, sha1) in cases {
        let key = vec![0xaa_u8; n];
        assert_eq!(
            hex::encode(&hmac_sha256(&key, msg)[..]),
            sha256,
            "sha256, {n}-byte key"
        );
        let cred = Cred::captured(Zeroizing::new(key));
        let d: Zeroizing<[u8; 20]> = hmac_sha1(&cred, &[msg]);
        assert_eq!(hex::encode(&d[..]), sha1, "sha1, {n}-byte key");
    }
}

/// WASTE-AUTH-SECRETS W7: a precomputed key answers exactly the one-shot MACs, for keys around the
/// block boundary and every split of the message into parts (the parts are streamed, not joined).
#[test]
fn precomputed_keys_answer_the_one_shot_macs_over_any_split() {
    let data: Vec<u8> = (0..=150_u8)
        .map(|b| b.wrapping_mul(29).wrapping_add(3))
        .collect();
    for key_len in [0_usize, 1, 20, 63, 64, 65, 131] {
        let key: Vec<u8> = (0..key_len).map(|i| (i as u8) ^ 0xa5).collect();
        let k256 = HmacSha256Key::new(&key);
        let cred = Cred::captured(Zeroizing::new(key.clone()));
        let k1 = HmacSha1Key::new(&cred);
        for n in [0_usize, 1, 55, 56, 63, 64, 65, 119, 120, 128, 150] {
            let msg = &data[..n];
            let want256 = hmac_sha256(&key, msg);
            let want1 = hmac_sha1(&cred, &[msg]);
            assert_eq!(k256.mac(msg)[..], want256[..], "key {key_len}, length {n}");
            for split in [0, n / 3, n / 2, n] {
                let parts: [&[u8]; 4] = [
                    &msg[..split],
                    b"",
                    &msg[split..n / 2.max(split)],
                    &msg[n / 2.max(split)..],
                ];
                assert_eq!(
                    k256.mac_parts(&parts)[..],
                    want256[..],
                    "sha256 key {key_len}, length {n}, split {split}"
                );
                assert_eq!(
                    k1.mac_parts(&parts)[..],
                    want1[..],
                    "sha1 key {key_len}, length {n}, split {split}"
                );
            }
        }
    }
}

/// WASTE-AUTH-SECRETS W7: the key schedule is paid once at construction. A short message under a
/// precomputed key costs two compressions (inner and outer finish), not the four a one-shot MAC
/// costs by re-deriving both pads.
#[test]
fn a_precomputed_key_costs_two_compressions_per_short_mac() {
    let k256 = HmacSha256Key::new(b"whsec-key-bytes");
    let cred = Cred::captured(Zeroizing::new(b"twilio-auth-token".to_vec()));
    let k1 = HmacSha1Key::new(&cred);
    let parts: [&[u8]; 5] = [b"msg_id", b".", b"1700000000", b".", b"{}"];
    for _ in 0..3 {
        let before = compressions();
        let _ = k256.mac_parts(&parts);
        assert_eq!(
            compressions() - before,
            2,
            "sha256: inner + outer finish only"
        );
        let before = compressions();
        let _ = k1.mac_parts(&parts);
        assert_eq!(
            compressions() - before,
            2,
            "sha1: inner + outer finish only"
        );
    }
    let before = compressions();
    let _ = hmac_sha256(b"whsec-key-bytes", b"msg_id.1700000000.{}");
    assert_eq!(
        compressions() - before,
        4,
        "the one-shot MAC derives both pads every call"
    );
}
