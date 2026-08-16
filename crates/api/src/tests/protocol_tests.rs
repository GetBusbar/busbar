// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The protocol contract's pins. The envelope is the one that matters: it is what a build with ZERO
//! protocol plugins uses to refuse a request, so it must be renderable without naming a dialect.

use super::*;

/// THE ZERO-PLUGIN PROPERTY. The envelope is produced by this crate, which has no dialect in it and
/// cannot acquire one — so a core build with no protocols compiled in can still say what it does not
/// speak. Asserted on the BYTES, because the bytes are what a client parses.
#[test]
fn the_unresolved_envelope_names_no_dialect() {
    let body = unresolved_ingress_error(400, "no protocol is registered for this request");
    let s = String::from_utf8(body).expect("the envelope is valid UTF-8");
    assert_eq!(
        s,
        r#"{"error":{"message":"no protocol is registered for this request","type":"invalid_request_error","code":400}}"#
    );
    // The point, stated as an assertion rather than a comment: no vendor word appears.
    for vendor in [
        "openai",
        "anthropic",
        "gemini",
        "cohere",
        "bedrock",
        "mcp",
        "a2a",
    ] {
        assert!(
            !s.to_ascii_lowercase().contains(vendor),
            "the dialect-free envelope must not name {vendor}"
        );
    }
}

/// A message reaching this path may carry upstream-influenced text. Emitting a raw quote, backslash
/// or control byte inside a JSON string would produce a body the client cannot parse — which turns a
/// clean refusal into a mystery. Escaped, not dropped.
#[test]
fn the_envelope_escapes_text_that_would_otherwise_break_the_json() {
    let body = unresolved_ingress_error(400, "he said \"hi\"\\ and\nthen\tstopped\u{1}");
    let s = String::from_utf8(body).unwrap();
    assert!(s.contains(r#"\"hi\""#), "quotes escaped: {s}");
    assert!(s.contains(r"\\"), "backslash escaped: {s}");
    assert!(
        s.contains(r"\n") && s.contains(r"\t"),
        "controls escaped: {s}"
    );
    // The \u0001 escape, spelled explicitly. An earlier draft asserted `contains(<raw 0x01 byte>)`
    // — which is what the escaping exists to PREVENT appearing in the output, so it tested the
    // opposite of the intent and would have failed the moment it was actually run.
    assert!(s.contains("\\u0001"), "low control escaped: {s}");
    // The whole body must survive a round trip through a real JSON parser.
    let v: serde_json::Value = serde_json::from_str(&s).expect("the envelope must parse as JSON");
    assert_eq!(v["error"]["type"], "invalid_request_error");
}
