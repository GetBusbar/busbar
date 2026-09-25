// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IR-18 signature-provenance envelope (architect ruling, IR-INTEGRATE round 3 item 15).
//!
//! A reasoning signature is only valid for the model family that minted it
//! ([`IrSignatureOrigin`]). Inside busbar the IR carries the origin beside the bytes; on the CLIENT
//! wire it has nowhere to live — Responses `encrypted_content`, Gemini `thoughtSignature`,
//! Anthropic/Bedrock `signature` are bare strings. A client that received a Claude signature
//! through a Responses stream sends it back as `encrypted_content`; read as that dialect's own
//! blob, the Anthropic egress then drops it as foreign and Claude thinking continuity breaks.
//!
//! So when a FOREIGN-origin signature is written into a client carrier, it is wrapped in an
//! opaque busbar envelope `bbsig1:<origin>:<base64url(signature)>`, and every reader unwraps it,
//! restoring the original bytes AND their origin. A genuine vendor blob never carries the prefix,
//! so an un-prefixed carrier is read as that vendor's own, exactly as before.

use super::IrSignatureOrigin;

/// The envelope's version prefix. A vendor-minted signature never starts with it.
pub const ENVELOPE_PREFIX: &str = "bbsig1:";

impl IrSignatureOrigin {
    /// The envelope's origin word.
    pub fn as_envelope_word(self) -> &'static str {
        match self {
            IrSignatureOrigin::Anthropic => "anthropic",
            IrSignatureOrigin::Gemini => "gemini",
            IrSignatureOrigin::OpenAi => "openai",
            IrSignatureOrigin::BedrockOther => "bedrock",
        }
    }

    /// Inverse of [`Self::as_envelope_word`]; an unknown word is `None`.
    pub fn from_envelope_word(word: &str) -> Option<Self> {
        match word {
            "anthropic" => Some(IrSignatureOrigin::Anthropic),
            "gemini" => Some(IrSignatureOrigin::Gemini),
            "openai" => Some(IrSignatureOrigin::OpenAi),
            "bedrock" => Some(IrSignatureOrigin::BedrockOther),
            _ => None,
        }
    }
}

/// Wrap `signature` (minted by `origin`) for a carrier that has no provenance field. Idempotent:
/// a value that is already an envelope is returned unchanged, so a pass that runs twice (the
/// buffered prep and then the buffered-to-stream synthesis) never nests envelopes.
pub fn wrap(origin: IrSignatureOrigin, signature: &str) -> String {
    if unwrap(signature).is_some() {
        return signature.to_string();
    }
    format!(
        "{ENVELOPE_PREFIX}{}:{}",
        origin.as_envelope_word(),
        b64url_encode(signature.as_bytes())
    )
}

/// Unwrap an envelope: `Some((origin, original signature))`, or `None` when `carried` is not a
/// well-formed envelope (then it is the carrier dialect's own blob, read as before).
pub fn unwrap(carried: &str) -> Option<(IrSignatureOrigin, String)> {
    let rest = carried.strip_prefix(ENVELOPE_PREFIX)?;
    let (word, payload) = rest.split_once(':')?;
    let origin = IrSignatureOrigin::from_envelope_word(word)?;
    let bytes = b64url_decode(payload)?;
    String::from_utf8(bytes).ok().map(|s| (origin, s))
}

/// READER helper: a signature read off a carrier whose own family is `own`. An envelope yields the
/// original bytes and the origin it recorded; anything else is the carrier family's own blob.
pub fn read_carried(
    carried: String,
    own: Option<IrSignatureOrigin>,
) -> (String, Option<IrSignatureOrigin>) {
    match unwrap(&carried) {
        Some((origin, sig)) => (sig, Some(origin)),
        None => (carried, own),
    }
}

/// [`read_carried`] for an optional carrier: `(None, None)` when no signature was carried.
pub fn read_carried_opt(
    carried: Option<String>,
    own: Option<IrSignatureOrigin>,
) -> (Option<String>, Option<IrSignatureOrigin>) {
    match carried {
        Some(c) => {
            let (sig, origin) = read_carried(c, own);
            (Some(sig), origin)
        }
        None => (None, None),
    }
}

/// CLIENT-WRITER helper: the string to put in a client carrier for a signature minted by `origin`,
/// where `accepts` says which origins the carrier's own family reads as its own. A foreign origin
/// is wrapped; an own or unknown origin (the pre-slot behaviour) is written as is.
pub fn for_client(
    signature: &str,
    origin: Option<IrSignatureOrigin>,
    accepts: impl Fn(IrSignatureOrigin) -> bool,
) -> String {
    match origin {
        Some(o) if !accepts(o) => wrap(o, signature),
        _ => signature.to_string(),
    }
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// RFC 4648 §5 base64url, no padding.
fn b64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        let emit = chunk.len() + 1;
        for i in 0..emit {
            let idx = ((n >> (18 - 6 * i)) & 0x3f) as usize;
            out.push(char::from(B64URL[idx]));
        }
    }
    out
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        B64URL.iter().position(|&x| x == c).map(|p| p as u32)
    }
    let bytes = s.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            n |= val(*c)? << (18 - 6 * i);
        }
        let produced = chunk.len() - 1;
        for i in 0..produced {
            out.push(((n >> (16 - 8 * i)) & 0xff) as u8);
        }
        // Canonical form only: the unused low bits of a short final chunk must be zero.
        let used_bits = 6 * chunk.len();
        let kept_bits = 8 * produced;
        if used_bits > kept_bits {
            let mask = (1u32 << (used_bits - kept_bits)) - 1;
            if (n >> (24 - used_bits)) & mask != 0 {
                return None;
            }
        }
    }
    Some(out)
}
