// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/media.rs`.

use super::*;

#[test]
fn mediablob_pcm_required_iff_raw_pcm() {
    let l16 = MediaBlob {
        payload: MediaPayload::B64("AA==".into()),
        mime_type: "audio/L16;codec=pcm;rate=24000".into(),
        pcm: Some(PcmParams {
            sample_rate: 24000,
            channels: 1,
            bit_depth: 16,
        }),
    };
    assert!(l16.is_well_formed());

    let l16_missing = MediaBlob {
        pcm: None,
        ..l16.clone()
    };
    assert!(
        !l16_missing.is_well_formed(),
        "raw PCM without params is silently lossy"
    );

    let mp3 = MediaBlob {
        payload: MediaPayload::Bytes(Bytes::from_static(b"\xff\xfb")),
        mime_type: "audio/mpeg".into(),
        pcm: None,
    };
    assert!(mp3.is_well_formed());
}

#[test]
fn base64_roundtrip_and_rfc4648_vectors() {
    // RFC 4648 §10 test vectors — encode must match, decode must invert.
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

#[test]
fn image_output_is_additive_b64_and_url_coexist() {
    let img = ImageOutput {
        b64: Some("iVBORw0KGgo=".into()),
        url: Some("https://example/img.png".into()),
        ..Default::default()
    };
    // Both present, both kept — the losslessness requirement a one-of would break.
    assert!(img.b64.is_some() && img.url.is_some());
    assert!(img.has_payload());
    assert!(!ImageOutput::default().has_payload());
}
