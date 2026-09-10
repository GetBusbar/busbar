//! G.711 µ-law ↔ PCM16 — implemented from the ITU-T G.711 bias/segment definition, by this crate.
//!
//! `busbar-voice` does not implement this transform: its own `AudioFormat` enum carries only the
//! byte-rate bookkeeping (`bytes_per_ms`) the barge-in truncate arithmetic needs, and its doc
//! comments name the actual sample transcode an unimplemented "seam...armed only when a lane
//! declares it" (`busbar_voice_codec::ir::media`). The `twilio-media-streams` dialect is that lane: Twilio
//! carries 8 kHz G.711 µ-law, and every upstream this plane can dial (OpenAI Realtime, Gemini Live)
//! speaks PCM16. This module is the transform, written independently against the standard, with its
//! own unit tests against known reference values.
//!
//! ## The algorithm
//!
//! µ-law encodes a 14-bit-magnitude linear sample into an 8-bit sign/exponent/mantissa byte: one
//! sign bit, a 3-bit exponent selecting one of eight logarithmic segments, and a 4-bit mantissa
//! giving the position within the segment. The constants below (`BIAS = 0x84`, `CLIP = 8159`) and
//! the segment table are the values the ITU-T G.711 reference algorithm defines; a byte is always
//! bitwise-inverted on the wire (`!ulawbyte`), which is why both directions below start by
//! inverting.
//!
//! Decode uses the closed 8-entry segment-base table directly. Encode searches for the same segment
//! by shifting a probe mask down from the top bit the 14-bit magnitude range can set; this is the
//! same search the reference algorithm performs, written as a loop instead of a literal 256-entry
//! lookup table so the two directions can be read and checked against each other by eye.

/// The bias added to a linear magnitude before segment/mantissa extraction, and subtracted back out
/// on decode. The ITU-T G.711 reference value.
const BIAS: i32 = 0x84;

/// The largest linear magnitude (after removing the sign) a sample is clamped to before encoding.
/// The ITU-T G.711 reference value; every larger magnitude quantizes to this segment's top code.
const CLIP: i32 = 32635;

/// The eight segment base offsets a decoded exponent selects among, from the ITU-T G.711 reference
/// table. `PCM = SEGMENT_BASE[exponent] + (mantissa << (exponent + 3))`, minus the bias, sign-applied.
const SEGMENT_BASE: [i32; 8] = [0, 132, 396, 924, 1980, 4092, 8316, 16764];

/// Decode one µ-law byte to a 16-bit signed linear PCM sample.
///
/// Reference vector: `0xFF` (µ-law "positive zero") decodes to `0`.
#[must_use]
pub fn ulaw_byte_to_pcm16(ulaw_byte: u8) -> i16 {
    let inverted = !ulaw_byte;
    let sign_bit = inverted & 0x80;
    let exponent = usize::from((inverted >> 4) & 0x07);
    let mantissa = i32::from(inverted & 0x0F);
    let magnitude = SEGMENT_BASE[exponent] + (mantissa << (exponent + 3));
    let signed = if sign_bit != 0 { -magnitude } else { magnitude };
    signed.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16
}

/// Encode one 16-bit signed linear PCM sample to a µ-law byte.
///
/// Reference vector: `0` encodes to `0xFF`, the inverse of [`ulaw_byte_to_pcm16`]'s `0xFF → 0`.
#[must_use]
pub fn pcm16_to_ulaw_byte(sample: i16) -> u8 {
    let sign: u8 = if sample < 0 { 0x80 } else { 0x00 };
    let mut magnitude = i32::from(sample).abs();
    if magnitude > CLIP {
        magnitude = CLIP;
    }
    magnitude += BIAS;

    // Find the segment: the largest exponent whose bit (starting at bit 14, the top bit a
    // biased+clipped magnitude can set) is present in the magnitude.
    let mut exponent: i32 = 7;
    let mut probe: i32 = 0x4000;
    while exponent > 0 && (magnitude & probe) == 0 {
        exponent -= 1;
        probe >>= 1;
    }
    let mantissa = (magnitude >> (exponent + 3)) & 0x0F;
    let byte = sign | ((exponent as u8) << 4) | (mantissa as u8);
    !byte
}

/// Decode a whole frame of µ-law bytes into little-endian PCM16 bytes (two bytes per input byte).
#[must_use]
pub fn decode_frame(ulaw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ulaw.len() * 2);
    for &b in ulaw {
        out.extend_from_slice(&ulaw_byte_to_pcm16(b).to_le_bytes());
    }
    out
}

/// Encode a whole frame of little-endian PCM16 bytes into µ-law bytes (one byte per input sample).
///
/// A trailing odd byte (an incomplete final sample) is dropped rather than guessed at.
#[must_use]
pub fn encode_frame(pcm16_le: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(pcm16_le.len() / 2);
    for chunk in pcm16_le.as_chunks::<2>().0 {
        let sample = i16::from_le_bytes(*chunk);
        out.push(pcm16_to_ulaw_byte(sample));
    }
    out
}
