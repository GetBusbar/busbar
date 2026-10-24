// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/proto/stream.rs`.

use super::rewrite_frame_strip_usage;

/// Byte-stripper fallback indistinguishability: when the fast byte-splice path declines and
/// the fallback is taken (here forced by a `data_str` that is NOT a verbatim substring of the raw
/// frame, mirroring a multi-`data:`-line frame), the reframed frame must NOT introduce a wire-shape
/// tell: JSON key ORDER is preserved and the ORIGINAL CRLF terminator is preserved. Only the
/// top-level `usage` key is removed.
#[test]
fn fallback_preserves_key_order_and_crlf() {
    // A CRLF-terminated frame. Keys are in a DELIBERATELY non-sorted order (id, object, choices,
    // usage) so that any BTreeMap/Value round-trip (which would sort to choices, id, object, usage)
    // is detectable. `usage` sits in the MIDDLE, so a correct strip must keep the surrounding order.
    let payload = r#"{"id":"chatcmpl-x","object":"chat.completion.chunk","choices":[{"delta":{"content":"hi"}}],"usage":null}"#;
    // Force the fallback deterministically: hand a frame whose bytes do NOT contain `payload`
    // verbatim (mirroring a multi-`data:`-line frame whose extracted join differs from the raw
    // bytes), with a CRLF terminator. The fast splice's verbatim-find fails, so the fallback runs.
    let raw_frame = b"data: <multiline-join-not-verbatim>\r\n\r\n";
    let out = rewrite_frame_strip_usage(raw_frame, payload);
    let out_str = std::str::from_utf8(&out).unwrap();

    // CRLF terminator preserved.
    assert!(
        out_str.ends_with("\r\n\r\n"),
        "CRLF terminator must be preserved, got {out_str:?}"
    );
    // The `usage` key is gone.
    assert!(
        !out_str.contains("usage"),
        "usage must be stripped: {out_str:?}"
    );
    // Remaining keys keep their ORIGINAL order: id before object before choices. A sorted
    // reserialize would put `choices` first.
    let id_at = out_str.find("\"id\"").expect("id present");
    let object_at = out_str.find("\"object\"").expect("object present");
    let choices_at = out_str.find("\"choices\"").expect("choices present");
    assert!(
        id_at < object_at && object_at < choices_at,
        "original key order (id, object, choices) must be preserved, got {out_str:?}"
    );
}

/// The fallback keeps an LF-only terminator as LF (it must not upgrade LF to CRLF either).
#[test]
fn fallback_preserves_lf_terminator() {
    let payload = r#"{"id":"x","object":"chat.completion.chunk","usage":null,"choices":[]}"#;
    let raw_frame = b"data: <not-verbatim>\n\n";
    let out = rewrite_frame_strip_usage(raw_frame, payload);
    let out_str = std::str::from_utf8(&out).unwrap();
    assert!(
        out_str.ends_with("\n\n"),
        "LF terminator preserved: {out_str:?}"
    );
    assert!(!out_str.contains("\r"), "no CR introduced: {out_str:?}");
    assert!(!out_str.contains("usage"), "usage stripped: {out_str:?}");
}
