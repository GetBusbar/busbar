// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane's hex codec against pinned vectors.

use super::{decode, encode};

#[test]
fn encode_is_lowercase_two_digits_per_byte() {
    assert_eq!(encode(b""), "");
    assert_eq!(encode("x"), "78");
    assert_eq!(encode([0x00u8, 0x0F, 0xA5, 0xFF]), "000fa5ff");
    assert_eq!(encode(b"call_abc"), "63616c6c5f616263");
    let all: Vec<u8> = (0..=255u8).collect();
    let text = encode(&all);
    assert_eq!(text.len(), 512);
    assert!(text.starts_with("000102030405060708090a0b0c0d0e0f10"));
    assert!(text.ends_with("f8f9fafbfcfdfeff"));
}

#[test]
fn decode_inverts_encode_and_accepts_either_case() {
    let all: Vec<u8> = (0..=255u8).collect();
    assert_eq!(decode(encode(&all)), Some(all));
    assert_eq!(decode("000FA5ff"), Some(vec![0x00, 0x0F, 0xA5, 0xFF]));
    assert_eq!(decode(""), Some(Vec::new()));
}

#[test]
fn decode_refuses_an_odd_length_or_a_non_hex_byte() {
    assert_eq!(decode("abc"), None);
    assert_eq!(decode("0g"), None);
    assert_eq!(decode("zz"), None);
    assert_eq!(decode(" 0"), None);
    assert_eq!(decode("-1"), None);
    assert_eq!(decode("é0"), None);
}
