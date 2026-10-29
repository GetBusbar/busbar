// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The byte-level member splices: every byte the edit does not govern stays the caller's. The
//! cases are plane-llm's (`codec/tests/json_splice_tests.rs`), moved with the code, and the member
//! reading plane-streaming, plane-a2a and plane-mcp each do over their own frames.

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
    let top = members(body, 0).expect("object");
    let so = top.last("stream_options").expect("member");
    let inner = members(body, so.value_start).expect("inner object");
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

// ══ THE MEMBER READING THE OTHER PLANES DO ═══════════════════════════════════════════════════════

#[test]
fn members_are_located_with_their_keys_unescaped_and_their_values_as_written() {
    // plane-streaming `splice::members` over a realtime frame: each key, where the member starts,
    // and the value's span; the index past the closing brace is `close + 1`.
    let frame =
        br#"{"type":"session.update", "session" : {"max_tokens":12,"x":"a}\"b"}, "n":1e400 }"#;
    let obj = members(frame, 0).expect("object");
    let keys: Vec<&str> = obj.members.iter().map(|m| m.key.as_str()).collect();
    assert_eq!(keys, ["type", "session", "n"]);
    let session = obj.last("session").expect("session");
    assert_eq!(
        &frame[session.value_start..session.value_end],
        br#"{"max_tokens":12,"x":"a}\"b"}"#
    );
    assert_eq!(frame[session.key_start], b'"');
    assert_eq!(
        &frame[obj.last("n").expect("n").value().start..obj.last("n").expect("n").value().end],
        b"1e400",
        "a number past f64 keeps its spelling"
    );
    assert_eq!(obj.close + 1, frame.len());
    // An escaped key reads unescaped, and `RawMember::is` matches it without allocating.
    let escaped = br#"{"res\u0075lt":{"a":1}}"#;
    assert_eq!(
        members(escaped, 0).expect("object").members[0].key,
        "result"
    );
    let mut found = None;
    scan(escaped, 0, |m| {
        if m.is("result") {
            found = Some(m.value());
        }
    })
    .expect("object");
    assert_eq!(found, Some(Span::new(15, 22)));
    // Leading whitespace before the brace is allowed; an empty object has no members.
    assert_eq!(members(b"  {  }", 0).expect("object").members, Vec::new());
}

#[test]
fn a_value_ends_at_its_own_end() {
    // A closer or a quote inside a string never ends a container.
    let b = br#"{"a":"}]","b":[1,{"c":"]"}]} tail"#;
    assert_eq!(value_end(b, 0), Some(b.len() - 5));
    assert_eq!(value_end(b"  true,", 0), Some(6));
    assert_eq!(value_end(b"-1.5e3}", 0), Some(6));
    assert_eq!(value_end(b"123", 0), Some(3), "a scalar may run to the end");
    assert_eq!(value_end(br#""a\"b""#, 0), Some(6));
    // Unterminated, or nothing there.
    for b in [&b"{\"a\":1"[..], b"\"abc", b"[1,2", b"", b"  ", b","] {
        assert_eq!(value_end(b, 0), None, "{:?}", String::from_utf8_lossy(b));
    }
    assert_eq!(string_end(b"x\"", 0), None, "not at a quote");
}
