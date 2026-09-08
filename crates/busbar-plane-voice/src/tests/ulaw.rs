//! µ-law ↔ PCM16 tests against known reference values, not just round-trip fuzz.

use crate::ulaw::{decode_frame, encode_frame, pcm16_to_ulaw_byte, ulaw_byte_to_pcm16};

#[test]
fn positive_zero_ulaw_byte_decodes_to_pcm_zero() {
    // The ITU-T G.711 reference: 0xFF is µ-law's "positive zero" code.
    assert_eq!(ulaw_byte_to_pcm16(0xFF), 0);
}

#[test]
fn pcm_zero_encodes_to_the_positive_zero_ulaw_byte() {
    assert_eq!(pcm16_to_ulaw_byte(0), 0xFF);
}

#[test]
fn ulaw_zero_byte_decodes_to_a_large_negative_sample() {
    // 0x00 is µ-law's most-negative code; the ITU-T reference table places it at -32124.
    assert_eq!(ulaw_byte_to_pcm16(0x00), -32124);
}

#[test]
fn the_most_negative_decoded_sample_encodes_back_to_the_ulaw_zero_byte() {
    assert_eq!(pcm16_to_ulaw_byte(-32124), 0x00);
}

#[test]
fn every_ulaw_byte_round_trips_within_the_algorithm_s_own_quantization() {
    // µ-law is lossy by construction (14-bit magnitude compressed to a 4-bit mantissa within a
    // segment), so decode→encode does not reproduce every byte exactly; it reproduces byte VALUES
    // that are already legal µ-law codes for a segment's canonical representative. What must hold
    // for every one of the 256 possible bytes is that decoding it and then re-encoding the result
    // lands on a byte that decodes to the SAME sample the first decode produced — the round trip
    // is stable at the PCM value, which is the property the plane's transcode boundary depends on.
    for byte in 0u8..=255 {
        let sample = ulaw_byte_to_pcm16(byte);
        let re_encoded = pcm16_to_ulaw_byte(sample);
        let re_decoded = ulaw_byte_to_pcm16(re_encoded);
        assert_eq!(
            sample, re_decoded,
            "byte {byte:#04x} decoded to {sample}, round-tripped to a byte decoding to {re_decoded}"
        );
    }
}

/// The ITU-T G.711 `ulaw2linear` expression, written out literally.
///
/// The implementation under test reads its magnitude out of a closed eight-entry table
/// (`SEGMENT_BASE`). This does not: it applies the standard's own arithmetic —
/// `((mantissa << 3) + BIAS) << exponent`, minus the BIAS — so the two agree only if the table
/// really is `132 * (2^e - 1)` for every entry. Shift that table by a segment and this disagrees,
/// which is exactly what the round trip below cannot notice.
fn reference_ulaw_to_pcm16(ulaw_byte: u8) -> i16 {
    const REFERENCE_BIAS: i32 = 0x84;
    let inverted = !ulaw_byte;
    let sign = inverted & 0x80;
    let exponent = i32::from((inverted >> 4) & 0x07);
    let mantissa = i32::from(inverted & 0x0F);
    let magnitude = (((mantissa << 3) + REFERENCE_BIAS) << exponent) - REFERENCE_BIAS;
    let signed = if sign != 0 { -magnitude } else { magnitude };
    signed as i16
}

/// All 256 codes, against the standard's arithmetic rather than against this crate's own.
///
/// The round-trip test below exercises 254 of the 256 codes only through decode → encode → decode
/// against the SAME implementation, so it is a self-consistency check: shift `SEGMENT_BASE` by a
/// segment and it stays green for every byte. This is the conformance half — and µ-law is the one
/// transform in this crate with no upstream to correct it, so a wrong table would be wrong all the
/// way to a caller's ear and to the bill for the seconds it took.
#[test]
fn every_ulaw_code_decodes_to_the_standard_s_own_value() {
    for byte in 0u8..=255 {
        assert_eq!(
            ulaw_byte_to_pcm16(byte),
            reference_ulaw_to_pcm16(byte),
            "code {byte:#04x} does not decode to the ITU-T G.711 value"
        );
    }
}

/// Six published anchors, so the independent reference above is itself anchored.
///
/// Two expressions of the same algorithm agreeing proves they are the same algorithm, not that it is
/// the right one. These are values from the standard's own table, spread across the segments rather
/// than clustered at zero: the two extremes, both zeroes, and the first two codes of the two lowest
/// segments.
#[test]
fn the_published_reference_values_are_what_both_expressions_produce() {
    const ANCHORS: &[(u8, i16)] = &[
        (0x00, -32124),
        (0x80, 32124),
        (0xFF, 0),
        (0x7F, 0),
        (0xF0, 120),
        (0xEF, 132),
    ];
    for &(code, sample) in ANCHORS {
        assert_eq!(
            ulaw_byte_to_pcm16(code),
            sample,
            "code {code:#04x} is {sample} in the G.711 table"
        );
        assert_eq!(reference_ulaw_to_pcm16(code), sample);
    }
}

#[test]
fn frame_helpers_agree_with_the_per_sample_functions() {
    let ulaw = [0xFFu8, 0x00, 0x7F, 0x80];
    let pcm = decode_frame(&ulaw);
    assert_eq!(pcm.len(), ulaw.len() * 2);
    for (i, &byte) in ulaw.iter().enumerate() {
        let sample = i16::from_le_bytes([pcm[i * 2], pcm[i * 2 + 1]]);
        assert_eq!(sample, ulaw_byte_to_pcm16(byte));
    }
    let back = encode_frame(&pcm);
    assert_eq!(back.len(), ulaw.len());
}

#[test]
fn an_odd_trailing_byte_is_dropped_rather_than_guessed_at() {
    let pcm = [0u8, 0, 1]; // one whole sample plus one stray byte
    assert_eq!(encode_frame(&pcm).len(), 1);
}
