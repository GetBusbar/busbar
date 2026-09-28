// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S OWN HEX CODEC (#83a O10: no reviewed-list addition; the need is removed instead): the
//! lowercase hex encoding of a synthesized wire id's bytes (the tool-id remap marker, the cohere uuid,
//! the bedrock request id) and its inverse. Behaviour is the `hex` crate's `encode`/`decode`, which
//! these replace byte for byte: encode writes lowercase; decode accepts either case and refuses an
//! odd length or any non-hex byte. The vectors beside this module pin both directions.

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// The lowercase hex text of `data`, two digits per byte.
#[must_use]
pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
    let bytes = data.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0F)]));
    }
    out
}

/// The bytes `text` spells in hex (either case), or `None` for an odd length or a non-hex byte.
#[must_use]
pub fn decode<T: AsRef<[u8]>>(text: T) -> Option<Vec<u8>> {
    let text = text.as_ref();
    if text.len() % 2 != 0 {
        return None;
    }
    let (pairs, _) = text.as_chunks::<2>();
    pairs
        .iter()
        .map(|&[hi, lo]| Some((nibble(hi)? << 4) | nibble(lo)?))
        .collect()
}

/// One hex digit's value.
fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[path = "tests/hex_tests.rs"]
mod tests;
