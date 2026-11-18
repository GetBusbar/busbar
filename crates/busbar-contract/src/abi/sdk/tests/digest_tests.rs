// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin's digest (`digest.rs`): FIPS 180-2's vectors, the one digest behind `sha256_hex`,

use super::*;

#[test]
fn sha256_answers_the_published_vectors() {
    assert_eq!(
        hex::encode(sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex::encode(sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn sha256_hex_is_this_digest_in_lower_hex() {
    for data in [&b""[..], b"abc", b"a card"] {
        assert_eq!(crate::sha256_hex(data), hex::encode(sha256(data)));
    }
}

/// The tag 1.5.5 wrote for a document fingerprint: `sha256/` and the standard (padded) base64.
#[test]
fn sha256_tagged_is_the_standard_base64_tag() {
    let of = |data: &[u8]| {
        let mut out = String::new();
        sha256_tagged(data, &mut out);
        assert_eq!(out.len(), super::TAGGED_LEN);
        out
    };
    assert_eq!(
        of(b"abc"),
        "sha256/ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    );
    assert_eq!(
        of(b""),
        "sha256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    );
}

/// The stream is the facade's one-shot SHA-256, byte for byte, however its input is split.
#[test]
fn sha256_stream_matches_the_portable_digest_for_every_split() {
    let data: Vec<u8> = (0..5000u32).map(|i| (i * 7 + i / 13) as u8).collect();
    for len in [0usize, 1, 55, 56, 63, 64, 65, 127, 128, 1000, 5000] {
        let want: [u8; 32] = crate::crypto::sha256(&data[..len]);
        assert_eq!(sha256(&data[..len]), want, "one-shot at {len}");
        for split in [0, 1.min(len), len / 3, len / 2, len] {
            let mut hash = Sha256Stream::new();
            hash.update(&data[..split]);
            hash.update(&data[split..len]);
            assert_eq!(hash.finish(), want, "split at {split} of {len}");
        }
    }
}
