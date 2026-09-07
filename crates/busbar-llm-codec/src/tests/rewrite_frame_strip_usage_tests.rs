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

/// A MULTI-`data:`-LINE FRAME MUST COME BACK OUT AS MULTIPLE `data:` LINES.
///
/// In the SSE grammar this stream rides on, a field's value ends at the LINE TERMINATOR; an event
/// that needs a newline inside its value sends a SECOND `data:` line, and the consumer joins the
/// lines with `\n`. `parse_sse_frame` implements exactly that join, so a multi-line frame's
/// extracted payload legitimately CONTAINS `\n`.
///
/// The fallback re-emitted that payload into ONE `data: {payload}` line. The embedded newline is a
/// line terminator on the wire, so it ENDED the `data:` field early and the remainder of the JSON
/// became a line with no field name — which a conforming consumer IGNORES. What the client
/// reassembled was a truncated fragment of the JSON, i.e. unparseable: on a same-protocol OpenAI
/// stream that is the delta the caller paid for, destroyed by the usage strip.
#[test]
fn a_multi_line_payload_is_reframed_as_multiple_data_lines() {
    // What `parse_sse_frame` hands back for a two-`data:`-line frame: the two lines joined with LF.
    let payload = "{\"id\":\"x\",\"usage\":null,\n\"choices\":[]}";
    let out = rewrite_frame_strip_usage(b"data: <not-verbatim>\n\n", payload);
    let out_str = std::str::from_utf8(&out).unwrap();

    // Every line carrying payload bytes is a `data:` line — no bare continuation line.
    let body = out_str.strip_suffix("\n\n").expect("LF frame terminator");
    for line in body.split('\n') {
        assert!(
            line.starts_with("data:"),
            "every payload line must be a `data:` line, got {line:?} in {out_str:?}"
        );
    }
    // And the frame round-trips back through the parser to the stripped JSON, unbroken.
    let (_evt, back) =
        busbar_substrate_values::proto::parse_sse_frame(&out).expect("the frame still parses");
    assert_eq!(
        back, "{\"id\":\"x\",\n\"choices\":[]}",
        "the payload must survive the reframe with only `usage` removed"
    );
    assert!(!out_str.contains("usage"), "usage stripped: {out_str:?}");
}

/// The same reframe on a CRLF stream uses CRLF BETWEEN the `data:` lines too — a mixed-terminator
/// frame is itself a wire-shape tell.
#[test]
fn a_multi_line_payload_keeps_its_line_terminator_between_data_lines() {
    let payload = "{\"a\":1,\n\"usage\":null,\n\"b\":2}";
    let out = rewrite_frame_strip_usage(b"data: <not-verbatim>\r\n\r\n", payload);
    let out_str = std::str::from_utf8(&out).unwrap();
    assert_eq!(
        out_str, "data: {\"a\":1,\r\ndata: \"b\":2}\r\n\r\n",
        "CRLF between the data lines and at the frame end"
    );
    assert!(
        !out_str.contains("\n\"") && !out_str.contains(",\n"),
        "no bare LF may appear inside a CRLF frame: {out_str:?}"
    );
}

/// The grammar's line terminator is CRLF, LF **or a bare CR**, and an event ends with a BLANK line
/// — the terminator twice. The ladder recognized four of the six shapes and silently rewrote a
/// CR-framed frame as LF, changing the framing under a client that chose CR.
#[test]
fn the_terminator_ladder_covers_every_pairing_the_grammar_allows() {
    let payload = r#"{"a":1,"usage":null}"#;
    for term in ["\r\n\r\n", "\n\n", "\r\r", "\r\n", "\n", "\r"] {
        let frame = format!("data: <not-verbatim>{term}");
        let out = rewrite_frame_strip_usage(frame.as_bytes(), payload);
        assert_eq!(
            std::str::from_utf8(&out).unwrap(),
            format!("data: {{\"a\":1}}{term}"),
            "a {term:?}-terminated frame must be reframed with its own terminator"
        );
    }
}

/// A single-line payload is byte-for-byte what it always was — the reframe is a superset.
#[test]
fn a_single_line_payload_is_unchanged() {
    let payload = r#"{"id":"x","usage":null,"choices":[]}"#;
    let out = rewrite_frame_strip_usage(b"data: <not-verbatim>\n\n", payload);
    assert_eq!(
        std::str::from_utf8(&out).unwrap(),
        "data: {\"id\":\"x\",\"choices\":[]}\n\n"
    );
}
