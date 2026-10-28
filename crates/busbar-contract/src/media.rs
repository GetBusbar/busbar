// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The base64 codec media payloads cross the JSON/binary boundary with, shared by every plane that
//! carries media. The media carriers themselves are the llm plane's own.

use crate::bounded::SlabBytes;

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 (RFC 4648 section 4, with `=` padding). Audio cells cross the JSON/binary boundary
/// (some upstreams inline audio as base64 in JSON; others return raw bytes), so encode/decode live
/// with the blob types rather than pulling in a `base64` crate.
pub fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// The REVERSE of [`B64_ALPHABET`]: byte → its 6-bit value, `255` for every byte that is not a
/// base64 digit. Built at COMPILE time from the alphabet itself (never hand-typed, so the two cannot
/// drift) rather than rebuilt on entry to every decode.
const B64_REVERSE: [u8; 256] = {
    let mut val = [255u8; 256];
    let mut i = 0;
    while i < B64_ALPHABET.len() {
        val[B64_ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    val
};

/// Decode standard base64 (padding optional; whitespace ignored). Returns `None` on any invalid byte
/// so a malformed upstream payload fails loud rather than silently truncating audio.
pub fn base64_decode(input: &str) -> Option<SlabBytes> {
    let val = &B64_REVERSE;
    let mut bits: u32 = 0;
    let mut nbits = 0u32;
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    // Padding is TERMINAL: `=` ends the encoded data, and only whitespace may follow it. Skipping
    // `=` wherever it appeared let a concatenation of two padded blobs (`QQ==QQ==`) decode as one
    // longer payload, silently accepting a corrupt upstream payload the fail-loud contract exists to
    // reject.
    let mut padded = false;
    for &b in input.as_bytes() {
        if b.is_ascii_whitespace() {
            continue;
        }
        if b == b'=' {
            padded = true;
            continue;
        }
        if padded {
            return None; // encoded data resumed after the padding — malformed
        }
        let v = val[b as usize];
        if v == 255 {
            return None;
        }
        bits = (bits << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    // A well-formed base64 group is 4 chars -> 3 bytes; the only legal remainders leave 0, 2, or 4
    // dangling bits (2- or 3-char tail). A remainder of 6 bits is a single lone trailing char that
    // encodes no whole byte: reject it rather than silently drop it, honoring the fail-loud contract.
    if nbits == 6 {
        return None;
    }
    Some(SlabBytes::from(out))
}

#[cfg(test)]
#[path = "tests/media_tests.rs"]
mod tests;
