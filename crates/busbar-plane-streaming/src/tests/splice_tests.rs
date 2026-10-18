// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plane-streaming/src/splice.rs`: only the governed object is rebuilt,
//! the caller's members keep their bytes, keys are read as the far end reads them.

use super::*;

fn rule(set: serde_json::Value) -> Rule {
    Rule {
        at: "session",
        cut: &["instructions", "tools"],
        set: match set {
            Value::Object(m) => m,
            _ => Map::new(),
        },
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[test]
fn the_bytes_around_the_governed_object_are_copied_as_they_arrived() {
    let frame = br#"{ "type" : "session.update",  "session":{"voice":"verse" ,"instructions":"x"}, "event_id":"e"}"#;
    let out = splice(frame, &rule(serde_json::json!({"instructions":"locked"}))).expect("spliced");
    assert_eq!(
        text(&out),
        r#"{ "type" : "session.update",  "session":{"voice":"verse","instructions":"locked"}, "event_id":"e"}"#
    );
}

#[test]
fn a_frame_without_the_governed_object_is_unchanged() {
    let frame = br#"{"type":"response.create"}"#;
    let out = splice(frame, &rule(serde_json::json!({}))).expect("spliced");
    assert_eq!(out, frame.to_vec());
}

#[test]
fn an_escaped_or_repeated_key_is_cut_as_the_far_end_reads_it() {
    let frame = br#"{"session":{"instructions":"a","instructions":"b","tools":[1],"x":{"y":[2,{"z":"}"}]}}}"#;
    let out = splice(frame, &rule(serde_json::json!({}))).expect("spliced");
    assert_eq!(text(&out), r#"{"session":{"x":{"y":[2,{"z":"}"}]}}}"#);
}

#[test]
fn a_locked_object_is_merged_into_the_callers_member_by_member() {
    let frame =
        br#"{"session":{"turn_detection":{"type":"server_vad","threshold":0.9,"extra":true}}}"#;
    let out = splice(
        frame,
        &rule(serde_json::json!({"turn_detection":{"threshold":0.5}})),
    )
    .expect("spliced");
    let v: Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(v["session"]["turn_detection"]["type"], "server_vad");
    assert_eq!(v["session"]["turn_detection"]["extra"], true);
    assert_eq!(v["session"]["turn_detection"]["threshold"], 0.5);
}

#[test]
fn a_frame_that_is_not_one_object_is_not_spliced() {
    for bad in [&b"[1]"[..], b"{\"session\":{}} trailing", b"{\"session\":"] {
        assert!(
            splice(bad, &rule(serde_json::json!({}))).is_none(),
            "{}",
            text(bad)
        );
    }
}
