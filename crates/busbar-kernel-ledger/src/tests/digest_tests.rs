// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DIGEST IS SHA-256, BYTE FOR BYTE. The ledger's one digest moved from RustCrypto `sha2` to
//! ring (ONE crypto backend = ring). Every checkpoint seal already on disk was taken with the old
//! one, so the new one must produce the same 32 bytes: pinned here against the FIPS 180-2 vectors
//! and against RustCrypto `sha2` computed side by side.

use crate::digest::{sha256, sha256_hex, sha256_of};
use sha2::Digest as _;

const ABC_HEX: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const EMPTY_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[test]
fn sha256_matches_the_fips_vectors() {
    assert_eq!(sha256_hex(b"abc"), ABC_HEX);
    assert_eq!(sha256_hex(b""), EMPTY_HEX);
}

#[test]
fn sha256_matches_rustcrypto_byte_for_byte() {
    for input in [&b""[..], b"abc", &[0u8; 1000], b"busbar/subkey/v1"] {
        let witness: [u8; 32] = sha2::Sha256::digest(input).into();
        assert_eq!(sha256(input), witness);
    }
}

#[test]
fn sha256_of_parts_is_the_digest_of_their_concatenation() {
    assert_eq!(sha256_of(&[b"a", b"", b"bc"]), sha256(b"abc"));
    assert_eq!(sha256_of(&[]), sha256(b""));
}
