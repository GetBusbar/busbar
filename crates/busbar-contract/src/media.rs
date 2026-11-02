// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MEDIA CARRIERS (DECISIONS #83: contract = shapes) — the opaque media payload values a plane

use crate::bounded::SlabBytes;

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 (RFC 4648 section 4, with `=` padding). Audio cells cross the JSON/binary boundary

pub fn base64_encode(input: &[u8]) -> String {
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    base64_encode_into(input, &mut out);

    String::from_utf8(out).expect("base64 output is ASCII")
}

/// [`base64_encode`], APPENDED to a buffer the caller holds: the same bytes, with no allocation when

pub fn base64_encode_into(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[((n >> 18) & 0x3f) as usize]);
        out.push(B64_ALPHABET[((n >> 12) & 0x3f) as usize]);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[((n >> 6) & 0x3f) as usize]
        } else {
            b'='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[(n & 0x3f) as usize]
        } else {
            b'='
        });
    }
}

/// The REVERSE of [`B64_ALPHABET`]: byte → its 6-bit value, `255` for every byte that is not a

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

pub fn base64_decode(input: &str) -> Option<SlabBytes> {
    let val = &B64_REVERSE;
    let mut bits: u32 = 0;
    let mut nbits = 0u32;
    let mut out = Vec::with_capacity(input.len() / 4 * 3);

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
            return None;
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

    if nbits == 6 {
        return None;
    }
    Some(SlabBytes::from(out))
}

/// Audio payload — exactly ONE representation, enforced. `B64` is the lossless common denominator
/// across upstreams; `Bytes` is a raw binary response body.
#[derive(Debug, Clone, PartialEq)]
pub enum MediaPayload {
    Bytes(SlabBytes),
    B64(String),
}

/// Sample parameters for headerless raw PCM (`audio/L16;codec=pcm;rate=24000` and similar codec-only
/// MIME types), where the wire bytes carry no container header. `None` on `MediaBlob.pcm` for
/// self-describing formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcmParams {
    pub sample_rate: u32,
    pub channels: u8,
    pub bit_depth: u8,
}

/// A single audio payload (transcription input / speech output). One representation + its MIME type,
/// plus PCM parameters iff the MIME type is headerless raw PCM.
#[derive(Debug, Clone, PartialEq)]
pub struct MediaBlob {
    pub payload: MediaPayload,
    pub mime_type: String,
    pub pcm: Option<PcmParams>,
}

/// A single generated image. ADDITIVE: `b64` and `url` may BOTH be present and both are
/// kept. `b64` is the common path; `url`/`uri` are additive (some upstreams return a URL, others a
/// bucket URI). The other fields are upstream-specific extras kept for lossless round-trip.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageOutput {
    pub b64: Option<String>,
    pub url: Option<String>,
    pub mime_type: Option<String>,
    pub revised_prompt: Option<String>,
    pub seed: Option<u64>,
    pub finish_reason: Option<String>,
}

#[cfg(test)]
#[path = "tests/media_tests.rs"]
mod tests;
