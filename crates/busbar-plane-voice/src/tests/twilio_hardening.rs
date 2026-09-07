//! The base64 this dialect carries its audio in, pinned against the published vectors.
//!
//! ## Why this file exists
//!
//! This crate writes its own base64 rather than taking a dependency for it, which is a reasonable
//! trade and a stated one. What it did not have was a test that could fail: a mutation run left
//! forty survivors in here — the length estimate, both shifts and both ORs of the encoder, every
//! arm of the alphabet lookup and most of its arithmetic, and the decoder's bit assembly. Audio
//! that came back subtly wrong would not crash anything; it would be heard.
//!
//! The published vectors are the right judge precisely because they are not ours. RFC 4648 fixes
//! seven of them in its test-vector section, and the round trip over every byte and every alphabet
//! character covers the rest of the table. A transform that agrees with the RFC on all seven lengths-mod-3 and inverts
//! itself over the whole byte range is the transform.

use super::{base64_decode, base64_encode, base64_len, base64_sextet, B64_ALPHABET};

/// THE SEVEN PUBLISHED VECTORS, which fix the padding for every length modulo three.
///
/// From the test vectors RFC 4648 publishes. They are the whole point of using a standard: an
/// encoder that agrees
/// with these is interoperable, and one that does not is a private encoding wearing the name.
#[test]
fn the_published_vectors_encode_and_decode_exactly() {
    let vectors: &[(&str, &str)] = &[
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ];
    for (plain, encoded) in vectors {
        assert_eq!(
            base64_encode(plain.as_bytes()),
            *encoded,
            "{plain:?} does not encode as the RFC says"
        );
        assert_eq!(
            base64_decode(encoded).as_deref(),
            Some(plain.as_bytes()),
            "{encoded:?} does not decode as the RFC says"
        );
    }
}

/// THE LENGTH RESERVED IS THE LENGTH WRITTEN, for every remainder.
///
/// The estimate exists to size the buffer in one go. Getting it wrong is not a crash — the vector
/// simply grows — so nothing observable says so, and it drifts. It is asserted against the encoder
/// itself so the two cannot disagree.
#[test]
fn the_length_estimate_is_the_length_the_encoder_writes() {
    for n in 0usize..=48 {
        let data = vec![b'x'; n];
        assert_eq!(
            base64_len(n),
            base64_encode(&data).len(),
            "the estimate for {n} bytes is not what the encoder wrote"
        );
    }
    // And the shape of it, stated directly so a change has to be deliberate.
    assert_eq!(base64_len(0), 0);
    assert_eq!(base64_len(1), 4);
    assert_eq!(base64_len(2), 4);
    assert_eq!(base64_len(3), 4);
    assert_eq!(base64_len(4), 8);
}

/// EVERY CHARACTER OF THE ALPHABET SURVIVES A ROUND TRIP, in its own position.
///
/// The lookup that turns a character back into six bits is a table written as four ranges and two
/// singletons. A missing range, or an offset that is off by the wrong constant, corrupts only the
/// characters in it — and the two singletons, `+` and `/`, appear in roughly one payload in thirty,
/// which is exactly often enough to be a real fault and rare enough that no fixed vector catches it.
#[test]
fn every_alphabet_character_decodes_to_its_own_position() {
    for (position, &character) in B64_ALPHABET.iter().enumerate() {
        assert_eq!(
            base64_sextet(character),
            Some(position as u32),
            "{} is the alphabet's character {position} and did not decode as it",
            character as char
        );
    }
    // The two singletons, named so a deleted arm says which.
    assert_eq!(base64_sextet(b'+'), Some(62));
    assert_eq!(base64_sextet(b'/'), Some(63));
    // And nothing outside the alphabet is a sextet.
    for character in [b'-', b'_', b'=', b' ', b'.', 0x00, 0xff] {
        assert_eq!(
            base64_sextet(character),
            None,
            "{character:#04x} is not in the alphabet and was read as though it were"
        );
    }
}

/// EVERY BYTE VALUE SURVIVES THE ROUND TRIP, at every offset within a group.
///
/// One byte at a time would only ever exercise the first six bits of a group. Running the whole
/// range through at each of the three positions is what puts every byte through every shift.
#[test]
fn every_byte_survives_the_round_trip_at_every_position_in_a_group() {
    for offset in 0..3usize {
        let mut data = vec![0u8; offset];
        data.extend((0u8..=255).collect::<Vec<u8>>());
        let encoded = base64_encode(&data);
        assert_eq!(
            base64_decode(&encoded).as_deref(),
            Some(data.as_slice()),
            "the round trip lost bytes when the group was offset by {offset}"
        );
    }
}

/// The high bits are not silently dropped: a payload of set bits comes back set.
///
/// `0xFF` bytes are the case that separates an OR from an exclusive-OR in the assembly, and
/// silence-versus-loud is precisely what µ-law audio built on top of this sounds like.
#[test]
fn a_payload_of_set_bits_comes_back_set() {
    for len in 1..=6usize {
        let data = vec![0xffu8; len];
        let encoded = base64_encode(&data);
        assert_eq!(
            base64_decode(&encoded).as_deref(),
            Some(data.as_slice()),
            "a run of {len} set bytes did not survive"
        );
        assert!(
            !encoded.contains('A'),
            "all-ones encoded to a run containing the zero character: {encoded}"
        );
    }
    // Alternating bits, which separates a left shift from a right one.
    let data = [0xaau8, 0x55, 0xaa, 0x55];
    assert_eq!(
        base64_decode(&base64_encode(&data)).as_deref(),
        Some(&data[..])
    );
}

/// A character outside the alphabet is REFUSED, not read as some other character.
#[test]
fn a_payload_outside_the_alphabet_is_refused() {
    assert_eq!(base64_decode("Zm9v!"), None);
    assert_eq!(base64_decode("Zm9-"), None);
    // Padding and whitespace are skipped rather than refused, which is what lets a wrapped
    // payload decode.
    assert_eq!(base64_decode("Zm9v\n").as_deref(), Some(&b"foo"[..]));
    assert_eq!(base64_decode("Zg==").as_deref(), Some(&b"f"[..]));
}

/// A group with only one character in it carries no whole byte, and is refused rather than guessed.
#[test]
fn a_group_of_one_character_is_refused() {
    assert_eq!(base64_decode("Zm9vZ"), None, "a trailing lone sextet");
}
