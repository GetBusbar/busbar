// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `media.rs`.

use super::*;

#[test]
fn base64_roundtrip_and_rfc4648_vectors() {
    // RFC 4648 section 10 test vectors — encode must match, decode must invert.
    for (raw, enc) in [
        (&b""[..], ""),
        (b"f", "Zg=="),
        (b"fo", "Zm8="),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg=="),
        (b"fooba", "Zm9vYmE="),
        (b"foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(base64_encode(raw), enc, "encode {raw:?}");
        assert_eq!(base64_decode(enc).as_deref(), Some(raw), "decode {enc:?}");
        // Padding is optional on the decode side.
        assert_eq!(
            base64_decode(enc.trim_end_matches('=')).as_deref(),
            Some(raw),
            "decode unpadded {enc:?}"
        );
    }
}

#[test]
fn base64_decode_fails_loud_on_malformed() {
    // A lone trailing char encodes 6 bits — no whole byte. The decoder MUST reject it, not
    // silently drop the partial group (the bug the fail-loud contract exists to prevent).
    assert_eq!(base64_decode("A"), None, "single dangling char");
    assert_eq!(
        base64_decode("Zm9vA"),
        None,
        "lone dangling char after a full group"
    );
    // Any non-alphabet byte is rejected.
    assert_eq!(base64_decode("Zm9v!"), None, "invalid symbol");
    assert_eq!(base64_decode("Zg=$"), None, "invalid symbol mid-pad");
    // Valid 2- and 3-char remainders (4 and 2 leftover bits) still decode.
    assert_eq!(base64_decode("Zg").as_deref(), Some(&b"f"[..]));
    assert_eq!(base64_decode("Zm8").as_deref(), Some(&b"fo"[..]));
    // Interior whitespace is ignored (providers wrap long base64).
    assert_eq!(base64_decode("Zm9v\nYmFy").as_deref(), Some(&b"foobar"[..]));
}

/// Padding is TERMINAL: `=` ends the encoded data. Skipping `=` wherever it appeared meant two
/// concatenated padded blobs decoded as one longer payload instead of failing loud.
#[test]
fn base64_decode_treats_padding_as_terminal() {
    assert_eq!(base64_decode("QQ==").as_deref(), Some(&b"A"[..]));
    assert_eq!(
        base64_decode("QQ==QQ=="),
        None,
        "encoded data must not resume after the padding"
    );
    assert_eq!(
        base64_decode("QQ=Q"),
        None,
        "a single interior pad byte too"
    );
    // Whitespace after the padding is still fine (providers wrap and newline-terminate).
    assert_eq!(base64_decode("QQ==\n").as_deref(), Some(&b"A"[..]));
}

#[test]
fn image_output_is_additive_b64_and_url_coexist() {
    let img = ImageOutput {
        b64: Some("iVBORw0KGgo=".into()),
        url: Some("https://example/img.png".into()),
        ..Default::default()
    };
    // BOTH PRESENT IS A SHAPE THIS TYPE CAN HOLD, and the construction above compiling is the whole
    // of that proof — a one-of (an enum, or a single field) could not have been written. Restating
    // `img.b64.is_some() && img.url.is_some()` after building it with both was an assertion on the
    // fixture's own literal: it could not fail, whatever `ImageOutput` did.
    //
    // The two fields are independent storage, not two spellings of one slot: an output carrying only
    // the URL is a DIFFERENT value from one carrying only the inline payload, and both differ from
    // the one carrying both. A single-slot representation would collapse at least two of the three.
    let b64_only = ImageOutput {
        b64: img.b64.clone(),
        ..Default::default()
    };
    let url_only = ImageOutput {
        url: img.url.clone(),
        ..Default::default()
    };
    assert_ne!(b64_only, url_only);
    assert_ne!(img, b64_only);
    assert_ne!(img, url_only);
}

/// The compile-time reverse table must be exactly what the per-call loop it replaced would have
/// built: same 6-bit value for every base64 digit, `255` (reject) for every other byte. A hoisted
/// table that drifted from the alphabet would decode payloads wrongly rather than loudly.
#[test]
fn base64_reverse_table_matches_the_alphabet_it_is_built_from() {
    let mut expected = [255u8; 256];
    for (i, &c) in B64_ALPHABET.iter().enumerate() {
        expected[c as usize] = i as u8;
    }
    assert_eq!(
        B64_REVERSE, expected,
        "the base64 reverse table must be the exact inverse of B64_ALPHABET"
    );
}

#[test]
fn base64_encode_into_appends_rfc4648_vectors() {
    for (raw, enc) in [
        (&b""[..], ""),
        (b"f", "Zg=="),
        (b"fo", "Zm8="),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg=="),
        (b"fooba", "Zm9vYmE="),
        (b"foobar", "Zm9vYmFy"),
    ] {
        let mut out = b"prefix:".to_vec();
        base64_encode_into(raw, &mut out);
        assert_eq!(out, [&b"prefix:"[..], enc.as_bytes()].concat(), "encode {raw:?}");
        assert_eq!(base64_encode(raw), enc, "base64_encode {raw:?}");
    }
}

#[test]
fn base64_encode_into_reuses_capacity_without_reallocating() {
    let mut out = Vec::with_capacity(64);
    let ptr = out.as_ptr();
    for _ in 0..4 {
        out.clear();
        base64_encode_into(b"foobar", &mut out);
        assert_eq!(out, b"Zm9vYmFy");
        assert_eq!(out.as_ptr(), ptr, "buffer must not reallocate when capacity suffices");
        assert_eq!(out.capacity(), 64);
    }
}
