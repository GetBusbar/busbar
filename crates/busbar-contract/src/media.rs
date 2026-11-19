// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MEDIA CARRIERS (DECISIONS #83: contract = shapes) — the opaque media payload values a plane

use base64::alphabet::STANDARD as STANDARD_ALPHABET;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD};
use base64::engine::DecodePaddingMode;
use base64::Engine as _;

use crate::bounded::SlabBytes;

/// Standard base64 (RFC 4648 section 4, with `=` padding). Audio cells cross the JSON/binary boundary
pub fn base64_encode(input: &[u8]) -> String {
    STANDARD.encode(input)
}

/// [`base64_encode`], APPENDED to a buffer the caller holds: the same bytes, with no allocation when
pub fn base64_encode_into(input: &[u8], out: &mut Vec<u8>) {
    let start = out.len();
    out.resize(start + input.len().div_ceil(3) * 4, 0);
    let written = STANDARD
        .encode_slice(input, &mut out[start..])
        .expect("the buffer holds the padded length");
    out.truncate(start + written);
}

/// The decoder's reading: the standard alphabet, trailing padding already cut, and non-zero trailing
/// bits in the last symbol accepted, as this function always has.
const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &STANDARD_ALPHABET,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone),
);

/// Decode standard base64 (padding optional; whitespace ignored). Returns `None` on any invalid byte
pub fn base64_decode(input: &str) -> Option<SlabBytes> {
    let spaced = input.bytes().any(|b| b.is_ascii_whitespace());
    let compact: std::borrow::Cow<'_, [u8]> = if spaced {
        input
            .bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .collect::<Vec<u8>>()
            .into()
    } else {
        input.as_bytes().into()
    };
    let end = compact
        .iter()
        .rposition(|&b| b != b'=')
        .map_or(0, |i| i + 1);
    LENIENT.decode(&compact[..end]).ok().map(SlabBytes::from)
}

/// A single generated image. ADDITIVE: `b64` and `url` may BOTH be present and both are
/// kept. `b64` is the common path; `url`/`uri` are additive (some upstreams return a URL, others a
/// bucket URI). The other fields are upstream-specific extras kept for lossless round-trip.
#[derive(Clone, Default, PartialEq, Eq)]
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

impl std::fmt::Debug for ImageOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageOutput")
            .field("b64", &self.b64)
            .field("url", &"<redacted>")
            .field("mime_type", &self.mime_type)
            .field("revised_prompt", &self.revised_prompt)
            .field("seed", &self.seed)
            .field("finish_reason", &self.finish_reason)
            .finish()
    }
}
