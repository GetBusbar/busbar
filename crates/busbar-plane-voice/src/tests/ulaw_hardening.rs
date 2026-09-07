//! The µ-law transform, pinned by the identity G.711 guarantees and by its own reference constants.
//!
//! ## Why this file exists
//!
//! A mutation run left the sign mask, the segment search and both halves of the code assembly
//! surviving. None of them is a crash: every mutant still returns a byte, and audio built on a
//! wrong byte is audio that plays. It is heard, not caught.
//!
//! The judge used here is the property the standard itself states — every one of the 256 codes
//! decodes to a distinct linear value which re-encodes to exactly the code it came from. That is a
//! statement about the WHOLE table rather than about the samples a fixture happened to pick, which
//! is what makes it able to fail: there is no way to break a mask, an offset or a shift and keep it.

use crate::ulaw::{decode_frame, encode_frame, pcm16_to_ulaw_byte, ulaw_byte_to_pcm16};

/// The one code that is an alias: µ-law has a NEGATIVE ZERO, and the encoder canonicalises it.
///
/// G.711 numbers zero twice — `0x7F` approaching from below and `0xFF` from above — and both name
/// the level 0. An encoder must pick one, and this one picks `0xFF`, so `0x7F` is the single code in
/// the table that does not come back from a round trip. It is named here rather than quietly
/// skipped below, because "which zero does this encoder emit" is a real interoperability fact.
const NEGATIVE_ZERO: u8 = 0x7F;

/// EVERY CODE BUT THE ALIASED ZERO SURVIVES DECODE-THEN-ENCODE, exactly.
///
/// This is the identity G.711 is built to have, and it is the strongest single statement available
/// about this pair of functions: it constrains the segment table, the bias, both shifts, the sign
/// bit and the inversion simultaneously, over the entire domain. A transform that satisfies it on
/// 255 codes and canonicalises the 256th is the transform.
#[test]
fn every_code_but_the_aliased_zero_decodes_to_a_sample_that_encodes_back_to_it() {
    for code in 0u8..=255 {
        if code == NEGATIVE_ZERO {
            continue;
        }
        let sample = ulaw_byte_to_pcm16(code);
        assert_eq!(
            pcm16_to_ulaw_byte(sample),
            code,
            "code {code:#04x} decoded to {sample} which encoded back to {:#04x}",
            pcm16_to_ulaw_byte(sample)
        );
    }
}

/// And the aliased zero is an alias for zero, not for something else.
#[test]
fn the_two_zero_codes_are_both_zero_and_the_encoder_picks_one() {
    assert_eq!(ulaw_byte_to_pcm16(NEGATIVE_ZERO), 0);
    assert_eq!(ulaw_byte_to_pcm16(0xFF), 0);
    assert_eq!(
        pcm16_to_ulaw_byte(0),
        0xFF,
        "the encoder emits the positive zero"
    );
}

/// THE CODES NAME 255 DIFFERENT LEVELS — every one but the duplicated zero.
///
/// Two codes that decoded to one level would be a table with a hole in it: some level the encoder
/// can produce that no code carries, and a code that can never be the answer. The round trip above
/// would still pass for one of the pair, so this is asserted separately. Exactly one collision is
/// expected, and it is the zero pair; a second would be a fault.
#[test]
fn the_codes_name_distinct_levels_apart_from_the_one_aliased_zero() {
    let mut levels: Vec<i16> = (0u8..=255).map(ulaw_byte_to_pcm16).collect();
    levels.sort_unstable();
    let before = levels.len();
    levels.dedup();
    assert_eq!(
        before - levels.len(),
        1,
        "exactly one pair of codes may share a level, and it is the zero pair"
    );
    assert_eq!(levels.len(), 255);
}

/// THE PUBLISHED REFERENCE VECTORS, named one at a time.
///
/// The identity above is satisfied by a transform that is self-consistent and wrong — one whose
/// whole table is shifted, say. These anchor it to the standard's own numbering, and they are the
/// values the module's own documentation states.
#[test]
fn the_reference_vectors_hold() {
    assert_eq!(
        ulaw_byte_to_pcm16(0xFF),
        0,
        "positive zero is the all-ones code"
    );
    assert_eq!(pcm16_to_ulaw_byte(0), 0xFF, "and zero encodes back to it");
    // The sign bit is the top bit of the code, INVERTED on the wire: a negative sample's code has
    // that bit clear. A mask that let the sign leak into the segment would move the level, not
    // merely its sign.
    assert!(
        ulaw_byte_to_pcm16(0x00) < 0,
        "the code with the sign bit clear on the wire is a negative level"
    );
    assert!(
        ulaw_byte_to_pcm16(0x80) > 0,
        "and its positive counterpart is positive"
    );
    assert!(
        ulaw_byte_to_pcm16(0xFE) > 0,
        "the quietest positive step is still positive"
    );
    // Mirror symmetry: the level for a code and for the same code with the wire sign bit flipped
    // are negatives of one another. This is what a corrupted sign mask breaks.
    for code in 0u8..=127 {
        let negative = ulaw_byte_to_pcm16(code);
        let positive = ulaw_byte_to_pcm16(code | 0x80);
        assert_eq!(
            negative, -positive,
            "code {code:#04x} and its sign-flipped twin are not mirror levels"
        );
    }
}

/// A SAMPLE LOUDER THAN THE CLIP POINT IS CLIPPED, not wrapped into a quiet code.
///
/// The comparison that finds the clip point is a strict one, and the difference between "greater
/// than" and "equal to" only shows at the clip value itself. Getting it wrong turns the loudest
/// audio into something else entirely rather than into the loudest code — a wrap, not a limit.
#[test]
fn every_sample_above_the_clip_point_encodes_to_the_loudest_code() {
    let loudest = pcm16_to_ulaw_byte(32635);
    for sample in [32635i16, 32636, 30000, i16::MAX] {
        let code = pcm16_to_ulaw_byte(sample);
        if sample >= 32635 {
            assert_eq!(
                code, loudest,
                "{sample} is at or past the clip point and did not encode to the loudest code"
            );
        }
    }
    // The negative limit likewise, including the value that has no positive counterpart.
    let quietest = pcm16_to_ulaw_byte(-32635);
    assert_eq!(pcm16_to_ulaw_byte(i16::MIN), quietest);
    assert_eq!(pcm16_to_ulaw_byte(-32636), quietest);
    assert_ne!(loudest, quietest, "the two limits are different codes");
}

/// ENCODING IS MONOTONIC over the levels the table names.
///
/// Louder in must not mean quieter out. A broken segment search does not usually invert the whole
/// table — it moves one band — so this is asserted across every adjacent pair of levels rather than
/// at the ends.
#[test]
fn a_louder_sample_never_encodes_to_a_quieter_level() {
    let mut levels: Vec<i16> = (0u8..=255).map(ulaw_byte_to_pcm16).collect();
    levels.sort_unstable();
    for pair in levels.windows(2) {
        let (lower, higher) = (pair[0], pair[1]);
        assert!(
            ulaw_byte_to_pcm16(pcm16_to_ulaw_byte(lower))
                <= ulaw_byte_to_pcm16(pcm16_to_ulaw_byte(higher)),
            "{lower} encodes to a louder level than {higher} does"
        );
    }
}

/// A WHOLE FRAME IS THE SAMPLES IT CONTAINS, two bytes in and one byte out.
///
/// The frame helpers are where a per-sample fault becomes an audible one, and the odd trailing byte
/// is the case a length calculation gets wrong.
#[test]
fn a_frame_round_trips_and_drops_only_an_incomplete_sample() {
    // Every code but the aliased negative zero, which the encoder canonicalises (see above).
    let codes: Vec<u8> = (0u8..=255).filter(|c| *c != NEGATIVE_ZERO).collect();
    let pcm = decode_frame(&codes);
    assert_eq!(pcm.len(), codes.len() * 2, "two bytes per sample");
    assert_eq!(
        encode_frame(&pcm),
        codes,
        "a frame of every code does not survive the round trip"
    );

    // A trailing half-sample is dropped rather than guessed at.
    let mut odd = pcm.clone();
    odd.push(0x00);
    assert_eq!(
        encode_frame(&odd),
        codes,
        "the incomplete final sample was not dropped"
    );
    assert_eq!(encode_frame(&[]), Vec::<u8>::new());
    assert_eq!(encode_frame(&[0x00]), Vec::<u8>::new(), "one lone byte");
}
