// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/api/src/sha256.rs`.
//!
//! Three independent oracles, because a digest that is wrong is wrong silently: the published
//! standards vectors (NIST FIPS 180-4 / CAVP for SHA-256, RFC 4231 for HMAC-SHA-256, AWS's SigV4
//! worked example for the chain the signer runs), and the RustCrypto `sha2`/`hmac` crates — the
//! implementation this one replaces — compared BYTE-FOR-BYTE over a corpus that crosses every block
//! and padding boundary. `sha2`/`hmac` are DEV-dependencies here and nowhere else in this crate.

use super::*;
use hmac::digest::KeyInit as _;
use hmac::Mac as _;
use sha2::Digest as _;

fn hex_of(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

// ── NIST FIPS 180-4 / CAVP known-answer vectors ──────────────────────────────────────────────────

#[test]
fn nist_one_block_message_abc() {
    assert_eq!(
        hex_of(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn nist_empty_message() {
    assert_eq!(
        hex_of(&sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn nist_two_block_message_448_bits() {
    assert_eq!(
        hex_of(&sha256(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn nist_four_block_message_896_bits() {
    assert_eq!(
        hex_of(&sha256(
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
        )),
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
    );
}

#[test]
fn nist_one_million_a_streamed_in_uneven_pieces() {
    // Streamed in a piece size that is coprime with the block, so every partial-buffer path in
    // `update` (fill a started buffer, compress whole blocks, stash a tail) is walked thousands
    // of times before the padding runs.
    let mut h = Sha256::new();
    let piece = [b'a'; 997];
    let mut fed = 0usize;
    while fed < 1_000_000 {
        let take = piece.len().min(1_000_000 - fed);
        h.update(&piece[..take]);
        fed += take;
    }
    assert_eq!(
        hex_of(&h.finalize()),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

// ── RFC 4231 HMAC-SHA-256 test cases ─────────────────────────────────────────────────────────────

#[test]
fn rfc4231_case_1_short_key() {
    assert_eq!(
        hex_of(&hmac_sha256(&[0x0b; 20], b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
}

#[test]
fn rfc4231_case_2_key_shorter_than_digest() {
    assert_eq!(
        hex_of(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

#[test]
fn rfc4231_case_3_combined_key_and_data_over_a_block() {
    assert_eq!(
        hex_of(&hmac_sha256(&[0xaa; 20], &[0xdd; 50])),
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
    );
}

#[test]
fn rfc4231_case_4_twenty_five_byte_key() {
    let key: Vec<u8> = (0x01..=0x19).collect();
    assert_eq!(
        hex_of(&hmac_sha256(&key, &[0xcd; 50])),
        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
    );
}

#[test]
fn rfc4231_case_5_truncated_output_prefix() {
    // The RFC publishes the first 128 bits for this case; the prefix is what is pinned.
    let mac = hex_of(&hmac_sha256(&[0x0c; 20], b"Test With Truncation"));
    assert!(mac.starts_with("a3b6167473100ee06e0c796c2955552b"), "{mac}");
}

#[test]
fn rfc4231_case_6_key_larger_than_block_is_hashed_first() {
    assert_eq!(
        hex_of(&hmac_sha256(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        )),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

#[test]
fn rfc4231_case_7_key_and_data_larger_than_block() {
    assert_eq!(
        hex_of(&hmac_sha256(
            &[0xaa; 131],
            b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
        )),
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
    );
}

// ── AWS SigV4 worked example (GET iam ListUsers, 2015-08-30) ─────────────────────────────────────
//
// The exact inputs the SigV4 signer hashes and chains, so a digest that agreed with
// NIST's strings but disagreed with the signer's would be caught here and not by a 403 from AWS.

const AWS_CANONICAL_REQUEST: &str = "GET\n\
/\n\
Action=ListUsers&Version=2010-05-08\n\
content-type:application/x-www-form-urlencoded; charset=utf-8\n\
host:iam.amazonaws.com\n\
x-amz-date:20150830T123600Z\n\
\n\
content-type;host;x-amz-date\n\
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const AWS_STRING_TO_SIGN: &str = "AWS4-HMAC-SHA256\n\
20150830T123600Z\n\
20150830/us-east-1/iam/aws4_request\n\
f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59";

#[test]
fn aws_sigv4_worked_example_canonical_request_digest() {
    assert_eq!(
        hex_of(&sha256(AWS_CANONICAL_REQUEST.as_bytes())),
        "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
    );
}

#[test]
fn aws_sigv4_worked_example_signing_chain() {
    let k_date = hmac_sha256(b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", b"20150830");
    let k_region = hmac_sha256(&k_date, b"us-east-1");
    let k_service = hmac_sha256(&k_region, b"iam");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    assert_eq!(
        hex_of(&k_signing),
        "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
    );
    assert_eq!(
        hex_of(&hmac_sha256(&k_signing, AWS_STRING_TO_SIGN.as_bytes())),
        "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
    );
}

// ── Byte-for-byte against RustCrypto `sha2` / `hmac` ─────────────────────────────────────────────

/// A deterministic, non-repeating byte stream so no two corpus entries share a prefix pattern the
/// compressor could be accidentally right about.
fn corpus_bytes(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9).wrapping_add(len as u32) | 1;
    (0..len)
        .map(|_| {
            // xorshift32
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 24) as u8
        })
        .collect()
}

/// Every length 0..=320 (five blocks, so single- and multi-block inputs, both padding shapes —
/// the length fitting the last block and needing one more — and every buffered-tail size), plus
/// the exact padding edges around each of the first two blocks.
fn corpus_lengths() -> Vec<usize> {
    let mut lens: Vec<usize> = (0..=320).collect();
    lens.extend([
        55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 1000, 4096, 4097, 65_536,
    ]);
    lens
}

#[test]
fn sha256_matches_rustcrypto_byte_for_byte_over_the_corpus() {
    for len in corpus_lengths() {
        let data = corpus_bytes(len, 7);
        let ours = sha256(&data);
        let theirs = sha2::Sha256::digest(&data);
        assert_eq!(ours[..], theirs[..], "length {len}");
    }
}

#[test]
fn streamed_sha256_matches_one_shot_for_every_split() {
    // Every split point of a three-block message, fed as two pieces: the streaming buffer's
    // fill/compress/stash arms against the one-shot result and against RustCrypto.
    let data = corpus_bytes(200, 11);
    let one_shot = sha256(&data);
    assert_eq!(one_shot[..], sha2::Sha256::digest(&data)[..]);
    for split in 0..=data.len() {
        let mut h = Sha256::new();
        h.update(&data[..split]);
        h.update(&data[split..]);
        assert_eq!(h.finalize(), one_shot, "split at {split}");
    }
}

#[test]
fn hmac_sha256_matches_rustcrypto_byte_for_byte_over_the_corpus() {
    for key_len in [0usize, 1, 4, 20, 32, 63, 64, 65, 131, 300] {
        let key = corpus_bytes(key_len, 3);
        for len in corpus_lengths() {
            let data = corpus_bytes(len, 5);
            let ours = hmac_sha256(&key, &data);
            let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&key)
                .expect("HMAC accepts a key of any length");
            mac.update(&data);
            let theirs = mac.finalize().into_bytes();
            assert_eq!(ours[..], theirs[..], "key {key_len} / data {len}");
        }
    }
}

#[test]
fn sigv4_shaped_inputs_match_rustcrypto() {
    // The two strings the signer hashes, and the four-step chain it runs, against RustCrypto —
    // the implementation those bytes were signed with until this module.
    for s in [AWS_CANONICAL_REQUEST, AWS_STRING_TO_SIGN] {
        assert_eq!(
            sha256(s.as_bytes())[..],
            sha2::Sha256::digest(s.as_bytes())[..]
        );
    }
    let theirs = |key: &[u8], data: &[u8]| -> Vec<u8> {
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).expect("any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    };
    let secret = b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let mut ours = hmac_sha256(secret, b"20150830").to_vec();
    let mut ref_key = theirs(secret, b"20150830");
    for step in [&b"us-east-1"[..], b"iam", b"aws4_request"] {
        ours = hmac_sha256(&ours, step).to_vec();
        ref_key = theirs(&ref_key, step);
        assert_eq!(ours, ref_key);
    }
    assert_eq!(
        hmac_sha256(&ours, AWS_STRING_TO_SIGN.as_bytes())[..],
        theirs(&ref_key, AWS_STRING_TO_SIGN.as_bytes())[..]
    );
}
