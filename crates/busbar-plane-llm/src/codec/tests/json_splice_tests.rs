// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The byte-level member splices: every byte the edit does not govern stays the caller's.

use super::*;

fn set<'a>(k: &'a str, v: &'a str) -> Edit<'a> {
    Edit::Set(k, Cow::Borrowed(v.as_bytes()))
}

fn run(body: &str, edits: &[Edit<'_>]) -> Option<String> {
    apply_top(body.as_bytes(), edits).map(|b| String::from_utf8(b).expect("utf8"))
}

#[test]
fn a_replaced_value_keeps_every_other_byte() {
    let body = "{ \"z\" : 1.50,\n  \"model\": \"fast\",  \"a\":[1,{\"model\":\"x\"}] }";
    assert_eq!(
        run(body, &[set("model", "\"gpt-4o\"")]).as_deref(),
        Some("{ \"z\" : 1.50,\n  \"model\": \"gpt-4o\",  \"a\":[1,{\"model\":\"x\"}] }")
    );
}

#[test]
fn an_equal_value_is_no_change() {
    assert_eq!(
        run(r#"{"model":"m","a":1}"#, &[set("model", "\"m\"")]),
        None
    );
    assert_eq!(
        run(r#"{"model":"m","a":1}"#, &[set("model", "\"m\"")]),
        None,
        "the same string in another spelling is the same value"
    );
}

#[test]
fn a_missing_member_is_inserted_after_the_brace() {
    assert_eq!(
        run(r#"{ "a":1}"#, &[set("m", "true")]).as_deref(),
        Some(r#"{"m":true, "a":1}"#)
    );
    assert_eq!(
        run("{}", &[set("m", "true")]).as_deref(),
        Some(r#"{"m":true}"#)
    );
    assert_eq!(
        run("{ }", &[set("m", "1"), set("n", "2")]).as_deref(),
        Some(r#"{"m":1,"n":2 }"#)
    );
}

#[test]
fn a_removed_member_takes_exactly_one_comma() {
    assert_eq!(
        run(r#"{"a":1, "x":2, "b":3}"#, &[Edit::Remove("x")]).as_deref(),
        Some(r#"{"a":1, "b":3}"#)
    );
    assert_eq!(
        run(r#"{"x":2, "b":3}"#, &[Edit::Remove("x")]).as_deref(),
        Some(r#"{ "b":3}"#)
    );
    assert_eq!(
        run(r#"{"a":1 , "x":2 }"#, &[Edit::Remove("x")]).as_deref(),
        Some(r#"{"a":1  }"#)
    );
    assert_eq!(
        run(r#"{ "x":2 }"#, &[Edit::Remove("x")]).as_deref(),
        Some("{  }")
    );
    assert_eq!(
        run(r#"{"x":1,"a":2,"x":3}"#, &[Edit::Remove("x")]).as_deref(),
        Some(r#"{"a":2}"#),
        "every duplicate goes"
    );
    assert_eq!(
        run(
            r#"{"x":1,"y":2,"a":3,"x":4,"y":5}"#,
            &[Edit::Remove("x"), Edit::Remove("y")]
        )
        .as_deref(),
        Some(r#"{"a":3}"#)
    );
}

#[test]
fn inserted_then_removed_members_give_back_the_original_bytes() {
    let original = "{\n  \"contents\": [ {\"parts\":[{\"text\":\"hi\"}]} ],\n  \"z\": 1e2\n}";
    let carried = run(original, &[set("model", "\"m\""), set("stream", "true")]).expect("spliced");
    assert_eq!(
        run(&carried, &[Edit::Remove("stream"), Edit::Remove("model")]).as_deref(),
        Some(original)
    );
}

#[test]
fn a_later_edit_of_a_key_wins() {
    assert_eq!(
        run(
            r#"{"model":"a","b":1}"#,
            &[set("model", "\"z\""), Edit::Remove("model")]
        )
        .as_deref(),
        Some(r#"{"b":1}"#)
    );
}

#[test]
fn what_is_not_an_object_is_left_alone() {
    for body in ["[1,2]", "\"s\"", "", "{\"a\":", "{\"a\" 1}", "{\"a\":1"] {
        assert_eq!(run(body, &[set("m", "1")]), None, "{body:?}");
    }
}

#[test]
fn a_nested_object_is_located_for_its_own_edits() {
    let body = br#"{"stream_options":{ "x":1 },"a":2}"#;
    let top = object_at(body, 0).expect("object");
    let so = top.last("stream_options").expect("member");
    let inner = object_at(body, so.value_start).expect("inner object");
    let inner_bytes = apply(
        &body[..so.value_end],
        &inner,
        &[Edit::Set("include_usage", Cow::Borrowed(b"true"))],
    )
    .expect("changed");
    assert_eq!(
        &inner_bytes[so.value_start..],
        br#"{"include_usage":true, "x":1 }"#
    );
}

fn diffed(body: &str, new: serde_json::Value) -> Option<String> {
    let old: serde_json::Value = serde_json::from_str(body).expect("old");
    diff(body.as_bytes(), &old, &new).map(|b| String::from_utf8(b).expect("utf8"))
}

/// A rewrite that changed one block is written back as exactly that block: every other block, the
/// key order and the spacing stay the caller's (F6). A re-serialize, the RED arm, sorts and
/// respaces everything.
#[test]
fn a_write_back_touches_only_the_blocks_that_changed() {
    let body = r#"{"z":1, "model":"m","messages":[{"role":"user","content":[{"type":"image","source":{"b":1,"a":2}},{"type":"text","text":"secret"}]}],"x":1.50}"#;
    let mut new: serde_json::Value = serde_json::from_str(body).expect("parse");
    new["messages"][0]["content"][1]["text"] = serde_json::json!("[redacted]");
    assert_eq!(
        diffed(body, new).as_deref(),
        Some(
            r#"{"z":1, "model":"m","messages":[{"role":"user","content":[{"type":"image","source":{"b":1,"a":2}},{"type":"text","text":"[redacted]"}]}],"x":1.50}"#
        )
    );
}

#[test]
fn a_write_back_adds_and_removes_members_in_place() {
    let body = r#"{"b":1, "a":{"y":2,"x":3}}"#;
    let new = serde_json::json!({"b": 1, "a": {"y": 2}, "tools": []});
    assert_eq!(
        diffed(body, new).as_deref(),
        Some(r#"{"tools":[],"b":1, "a":{"y":2}}"#)
    );
}

#[test]
fn a_write_back_of_a_resized_array_writes_that_array_whole() {
    let body = r#"{"m":[{"b":1,"a":2}], "k":{"z":1,"y":2}}"#;
    let new = serde_json::json!({"m": [{"b": 1, "a": 2}, {"t": 1}], "k": {"z": 1, "y": 2}});
    assert_eq!(
        diffed(body, new).as_deref(),
        Some(r#"{"m":[{"a":2,"b":1},{"t":1}], "k":{"z":1,"y":2}}"#)
    );
}

#[test]
fn an_unchanged_write_back_is_no_change() {
    let body = r#"{"b":1.50, "a":[1,2]}"#;
    let new: serde_json::Value = serde_json::from_str(body).expect("parse");
    assert_eq!(diffed(body, new), None);
}
