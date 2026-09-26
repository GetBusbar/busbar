// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane's CRC-32 against the pinned CRC-32/ISO-HDLC check vectors.

use super::hash;

#[test]
fn the_standard_check_value() {
    // The catalogue check value of CRC-32/ISO-HDLC: the CRC of the nine ASCII digits.
    assert_eq!(hash(b"123456789"), 0xCBF4_3926);
}

#[test]
fn pinned_vectors() {
    assert_eq!(hash(b""), 0x0000_0000);
    assert_eq!(hash(b"a"), 0xE8B7_BE43);
    assert_eq!(hash(b"abc"), 0x3524_41C2);
    assert_eq!(
        hash(b"The quick brown fox jumps over the lazy dog"),
        0x414F_A339
    );
    assert_eq!(hash(&[0u8; 32]), 0x190A_55AD);
    assert_eq!(hash(&[0xFFu8; 32]), 0xFF6C_AB0B);
}

/// An AWS event-stream prelude: the CRC of the two length fields of a 16-byte, header-less frame
/// (`total_len = 16`, `headers_len = 0`), the smallest frame the framing admits.
#[test]
fn an_event_stream_prelude() {
    let prelude = [0u8, 0, 0, 16, 0, 0, 0, 0];
    assert_eq!(hash(&prelude), 0x05C2_48EB);
}
