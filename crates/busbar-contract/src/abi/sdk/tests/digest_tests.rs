// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin's digest (`digest.rs`): FIPS 180-2's vectors, the one digest behind `sha256_hex`,
//! and its `sha256/<base64>` tag.

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
    assert_eq!(
        sha256_tagged(b"abc"),
        "sha256/ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    );
    assert_eq!(
        sha256_tagged(b""),
        "sha256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    );
}
