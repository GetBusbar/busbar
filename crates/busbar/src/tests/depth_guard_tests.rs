// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/json.rs`.

use super::*;

#[test]
fn rejects_pathologically_nested_input_without_overflow() {
    // A ~2 MB body 1,000,000 arrays deep would abort the process on re-serialize/drop if it
    // reached `from_slice`. The guard rejects it on the raw bytes first, so this returns Err
    // cleanly — no Value is ever built. (Runs on the default test stack; the point is it does
    // NOT abort.)
    let depth = 1_000_000usize;
    let mut s = String::with_capacity(depth * 2);
    for _ in 0..depth {
        s.push('[');
    }
    for _ in 0..depth {
        s.push(']');
    }
    assert!(
        parse::<serde_json::Value>(s.as_bytes()).is_err(),
        "deeply-nested body must be rejected"
    );
    assert!(exceeds_max_depth(s.as_bytes(), MAX_JSON_DEPTH));
}

#[test]
fn accepts_realistic_depth_and_counts_correctly() {
    // A normal chat body (object → messages array → message object → content array → block
    // object) is ~5 deep — nowhere near 128.
    let body = br#"{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"hi [bracket] {brace} in a string is not depth"}]}]}"#;
    assert!(!exceeds_max_depth(body, MAX_JSON_DEPTH));
    assert!(parse::<serde_json::Value>(body).is_ok());
    // Brackets/braces inside string literals must NOT count toward depth.
    assert!(!exceeds_max_depth(br#"{"k":"[[[[[[[[[[ {{{{{{ ]]]]]"}"#, 8));
    // Exactly at the limit parses; one deeper is rejected.
    let at_limit = format!("{}{}", "[".repeat(128), "]".repeat(128));
    assert!(!exceeds_max_depth(at_limit.as_bytes(), MAX_JSON_DEPTH));
    let over = format!("{}{}", "[".repeat(129), "]".repeat(129));
    assert!(exceeds_max_depth(over.as_bytes(), MAX_JSON_DEPTH));
}
