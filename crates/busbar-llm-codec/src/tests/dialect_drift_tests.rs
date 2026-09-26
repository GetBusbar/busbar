// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DIALECT-HELPER DRIFT GUARD (#83a SD-3): the plane's own copies of the shared wire helpers
//! answer exactly what the shared fixture `testing/plane-copies/dialect-helpers.json` records — the
//! same constants, error codes, SSE frame probes, parses and writes, and `usage` strips. The fixture is
//! the host originals' answers, and the host's own suite holds its originals to the same file, so
//! moving a dialect onto its own copy changes no byte it reads or writes.

use super::*;

fn fixture() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testing/plane-copies/dialect-helpers.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("fixture readable"))
        .expect("fixture is JSON")
}

fn rows(doc: &serde_json::Value, key: &str) -> Vec<serde_json::Value> {
    doc[key].as_array().expect(key).clone()
}

fn bytes(v: &serde_json::Value) -> Vec<u8> {
    crate::hex::decode(v.as_str().expect("hex string")).expect("hex")
}

#[test]
fn the_constants_are_the_fixture_constants() {
    let c = &fixture()["constants"];
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
}

#[test]
fn error_codes_and_prose_scans_agree() {
    let doc = fixture();
    for r in rows(&doc, "bearer_error_code") {
        let t = r["type"].as_str().expect("type");
        assert_eq!(bearer_error_code(t), r["code"], "{t}");
    }
    for r in rows(&doc, "context_length_prose_scan") {
        let t = r["text"].as_str().expect("text");
        assert_eq!(context_length_prose_scan(t), r["context_length"], "{t}");
    }
}

#[test]
fn sse_probes_parses_and_writes_agree() {
    let doc = fixture();
    for r in rows(&doc, "sse_frames") {
        let frame = bytes(&r["frame_hex"]);
        assert_eq!(sse_event_type(&frame), r["event_type"], "{frame:?}");
        assert_eq!(
            serde_json::json!(parse_sse_frame(&frame)),
            r["parsed"],
            "{frame:?}"
        );
    }
    for r in rows(&doc, "write_sse_frame") {
        let mut out = Vec::new();
        write_sse_frame(
            &mut out,
            r["event_type"].as_str().expect("event"),
            &r["data"],
        );
        assert_eq!(out, bytes(&r["frame_hex"]), "{}", r["event_type"]);
    }
}

#[test]
fn value_projections_and_the_usage_strip_agree() {
    let doc = fixture();
    for r in rows(&doc, "tool_arguments_to_string") {
        assert_eq!(tool_arguments_to_string(&r["input"]), r["arguments"]);
    }
    for r in rows(&doc, "rewrite_text_pairs") {
        let messages = r["messages"].as_array().expect("messages");
        assert_eq!(serde_json::json!(rewrite_text_pairs(messages)), r["pairs"]);
    }
    for r in rows(&doc, "strip_top_level_usage_member") {
        let json = r["json"].as_str().expect("json");
        assert_eq!(
            serde_json::json!(strip_top_level_usage_member(json)),
            r["stripped"],
            "{json}"
        );
    }
}
