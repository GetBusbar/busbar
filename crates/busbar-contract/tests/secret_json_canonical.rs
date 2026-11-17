// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! An invocation's arguments are held as one canonical text (DES-SONIC-WIPE r3 §3.1, §7.3):
//! compact, object keys in byte order, the last of duplicate keys kept, numbers verbatim, and the
//! writer's escapes. That is the text an invocation is screened, counted and sent as, so it must
//! stay what it was: each literal below is the text today's reader and writer produce.

#![forbid(unsafe_code)]

use busbar_contract::ir::facts::IrFacts as _;
use busbar_contract::ir::invoke::InvokeReq;

/// `(input, canonical text)`.
const CORPUS: &[(&str, &str)] = &[
    // Keys in byte order, at every depth.
    (
        r#"{"b":1,"a":{"d":[],"c":{}}}"#,
        r#"{"a":{"c":{},"d":[]},"b":1}"#,
    ),
    (
        r#"{"a":1,"é":2,"z":3,"A":4}"#,
        r#"{"A":4,"a":1,"z":3,"é":2}"#,
    ),
    // The last of duplicate keys, at every depth.
    (r#"{"a":1,"b":2,"a":3}"#, r#"{"a":3,"b":2}"#),
    (
        r#"{"o":{"x":1,"x":{"y":2}},"o2":[{"k":1,"k":2}]}"#,
        r#"{"o":{"x":{"y":2}},"o2":[{"k":2}]}"#,
    ),
    // Whitespace dropped; nested arrays.
    (
        r#" [ 1 , [ 2 , [ 3 , [ ] ] ] , { } ] "#,
        r#"[1,[2,[3,[]]],{}]"#,
    ),
    (
        r#"[true,false,null,"",{"":0}]"#,
        r#"[true,false,null,"",{"":0}]"#,
    ),
    // Numbers verbatim.
    (
        r#"[-0,1e400,18446744073709551617,-18446744073709551617,1.5]"#,
        r#"[-0,1e400,18446744073709551617,-18446744073709551617,1.5]"#,
    ),
    // Escapes: quote and backslash kept, solidus unescaped, control characters as the writer
    // spells them.
    (r#""\"\\\/""#, r#""\"\\/""#),
    (
        r#""\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007\u0008\u0009\u000A\u000B\u000C\u000D\u000E\u000F\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017\u0018\u0019\u001A\u001B\u001C\u001D\u001E\u001F""#,
        r#""\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007\b\t\n\u000b\f\r\u000e\u000f\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017\u0018\u0019\u001a\u001b\u001c\u001d\u001e\u001f""#,
    ),
    (r#""\b\f\n\r\t""#, r#""\b\f\n\r\t""#),
    // Non-ASCII: an escape becomes raw UTF-8 (a surrogate pair one character); raw stays raw.
    (r#""é😀""#, "\"é😀\""),
    ("\"é😀\"", "\"é😀\""),
];

/// The arguments `input` reads as.
fn arguments(input: &str) -> serde_json::Value {
    serde_json::from_slice(input.as_bytes()).expect("a valid corpus document")
}

/// The canonical text of `input`.
fn canonical(input: &str) -> String {
    serde_json::to_string(&arguments(input)).expect("a written document")
}

#[test]
fn canonical_text_is_compact_key_ordered_and_keeps_the_last_duplicate() {
    for (input, expected) in CORPUS {
        assert_eq!(canonical(input), *expected, "{input}");
    }
}

#[test]
fn an_invocation_is_screened_and_counted_over_its_canonical_text() {
    for (input, expected) in CORPUS {
        let request = InvokeReq {
            tool: "corpus".to_owned(),
            arguments: arguments(input),
            extra: Default::default(),
        };
        let items = request.content();
        assert_eq!(items[0].screenable_text(), *expected, "{input}");
        assert_eq!(
            request.shape().text_chars,
            expected.chars().count(),
            "{input}"
        );
    }
}
