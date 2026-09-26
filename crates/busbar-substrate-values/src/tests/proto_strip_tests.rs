// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `strip_top_level_usage_member`'s refusal contract in
//! `crates/busbar-substrate-values/src/proto.rs`.

use super::*;

/// A TRUNCATED top-level object must be refused, not spliced.
///
/// The scanner's member loop exits either on the top-level `}` or by running off the end of the
/// buffer, and only the first is well-formed. When every member happens to parse and just the outer
/// brace is missing — the shape a cut-off upstream SSE chunk has, and busbar forces `include_usage`
/// upstream so `usage` rides every chunk — the stripper used to find its `usage` range anyway and
/// return an UNCLOSED object. The verbatim writer splices that straight back into the frame, so the
/// client receives well-formed SSE framing wrapping invalid JSON, instead of the untouched original
/// bytes the caller's fallback exists to send.
#[test]
fn a_truncated_object_is_refused_rather_than_spliced() {
    for input in [
        r#"{"a":1,"usage":{"x":1}"#,
        r#"{"usage":null,"a":1"#,
        r#"{"usage":{"prompt_tokens":3}"#,
    ] {
        let out = strip_top_level_usage_member(input);
        assert!(
            out.is_none(),
            "a truncated object must fall back, got {out:?} for {input}"
        );
    }
}

/// The refusal above must not have cost the well-formed case: a CLOSED object with a top-level
/// `usage` still strips, byte-for-byte, and the result is parseable.
#[test]
fn a_closed_object_still_strips_and_stays_parseable() {
    let out = strip_top_level_usage_member(r#"{"a":1,"usage":{"x":1},"b":2}"#)
        .expect("a well-formed object still strips");
    assert_eq!(out, r#"{"a":1,"b":2}"#);
    serde_json::from_str::<serde_json::Value>(&out).expect("the stripped object parses");

    let first = strip_top_level_usage_member(r#"{"usage":null,"a":1}"#).expect("first member");
    assert_eq!(first, r#"{"a":1}"#);
}

/// THE SHARED DIALECT-HELPER FIXTURE (#83a SD-3): the host originals answer every case in
/// `testing/plane-copies/dialect-helpers.json` as recorded. The LLM plane's own copies are held to
/// the same file, so the copies cannot drift apart without one of the two suites failing.
#[test]
fn the_host_helpers_answer_the_shared_fixture() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testing/plane-copies/dialect-helpers.json"
    );
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("fixture readable"))
            .expect("fixture is JSON");
    let rows = |k: &str| doc[k].as_array().expect("rows").clone();
    let bytes = |v: &serde_json::Value| hex::decode(v.as_str().expect("hex")).expect("hex");
    let c = &doc["constants"];
    assert_eq!(c["CODE_INVALID_API_KEY"], CODE_INVALID_API_KEY);
    assert_eq!(
        c["PROVIDER_SIGNAL_CONTEXT_LENGTH"],
        PROVIDER_SIGNAL_CONTEXT_LENGTH
    );
    assert_eq!(c["MESSAGE_NAMES_SENTINEL"], MESSAGE_NAMES_SENTINEL);
    assert_eq!(c["SSE_DONE_SENTINEL"], SSE_DONE_SENTINEL);
    assert_eq!(
        c["SSE_DONE_FRAME"].as_str().map(str::as_bytes),
        Some(SSE_DONE_FRAME)
    );
    assert_eq!(c["HDR_AUTHORIZATION"], HDR_AUTHORIZATION);
    assert_eq!(
        c["BASE62_ALPHABET"].as_str().map(str::as_bytes),
        Some(&BASE62_ALPHABET[..])
    );
    assert_eq!(c["BASE62_REJECT_THRESHOLD"], BASE62_REJECT_THRESHOLD);
    for r in rows("bearer_error_code") {
        assert_eq!(bearer_error_code(r["type"].as_str().unwrap()), r["code"]);
    }
    for r in rows("context_length_prose_scan") {
        assert_eq!(
            context_length_prose_scan(r["text"].as_str().unwrap()),
            r["context_length"]
        );
    }
    for r in rows("sse_frames") {
        let frame = bytes(&r["frame_hex"]);
        assert_eq!(sse_event_type(&frame), r["event_type"]);
        assert_eq!(serde_json::json!(parse_sse_frame(&frame)), r["parsed"]);
    }
    for r in rows("write_sse_frame") {
        let mut out = Vec::new();
        write_sse_frame(&mut out, r["event_type"].as_str().unwrap(), &r["data"]);
        assert_eq!(out, bytes(&r["frame_hex"]));
    }
    for r in rows("tool_arguments_to_string") {
        assert_eq!(tool_arguments_to_string(&r["input"]), r["arguments"]);
    }
    for r in rows("rewrite_text_pairs") {
        let messages = r["messages"].as_array().unwrap();
        assert_eq!(serde_json::json!(rewrite_text_pairs(messages)), r["pairs"]);
    }
    for r in rows("strip_top_level_usage_member") {
        let json = r["json"].as_str().unwrap();
        assert_eq!(
            serde_json::json!(strip_top_level_usage_member(json)),
            r["stripped"]
        );
    }
}
