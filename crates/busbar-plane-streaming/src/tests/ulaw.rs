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
