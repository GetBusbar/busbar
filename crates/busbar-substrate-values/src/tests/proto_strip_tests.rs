// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `strip_top_level_usage_member`'s refusal contract in
//! `crates/busbar-substrate-values/src/proto.rs`.

use super::strip_top_level_usage_member;

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
