// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE JSON DEPTH GUARD (`spans::exceeds_max_depth`) answers exactly as the copies it replaced.
//!
//! The guard is a security floor that used to live twice, in the host's JSON seam
//! (`busbar-kernel/src/json.rs`) and in the LLM plane's (`codec/json.rs`), held together by a drift
//! test over `testing/plane-copies/json-depth.json`. Both copies were the same scan; it is frozen
//! below as [`kernel_copy`] and the one guard must agree with it on every input here: the whole
//! shared fixture, the edge cases the floor exists for, and every short string over the bytes the
//! scan reads.

use busbar_contract::spans::{exceeds_max_depth, MAX_JSON_DEPTH};

/// The scan as `busbar-kernel/src/json.rs` carried it before the fold, verbatim.
fn kernel_copy(bytes: &[u8], max: usize) -> bool {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    for &b in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

fn agree(body: &[u8], max: usize) -> bool {
    let verdict = exceeds_max_depth(body, max);
    assert_eq!(
        verdict,
        kernel_copy(body, max),
        "the guard and the kernel's copy disagree at max {max} on {:?}",
        String::from_utf8_lossy(body)
    );
    verdict
}

/// One case of the shared fixture, built as the two seams' suites build it.
fn fixture_body(case: &serde_json::Value) -> String {
    if let Some(raw) = case["raw"].as_str() {
        return raw.to_string();
    }
    let n = case["depth"].as_u64().expect("depth") as usize;
    match case["shape"].as_str().expect("shape") {
        "arrays" => format!("{}{}", "[".repeat(n), "]".repeat(n)),
        "objects" => format!("{}1{}", r#"{"k":"#.repeat(n), "}".repeat(n)),
        _ => {
            let open: String = (0..n)
                .map(|i| if i % 2 == 0 { "[" } else { r#"{"k":"# })
                .collect();
            let close: String = (0..n)
                .rev()
                .map(|i| if i % 2 == 0 { "]" } else { "}" })
                .collect();
            format!("{open}1{close}")
        }
    }
}

#[test]
fn the_floor_is_128_and_the_shared_fixture_holds_it() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testing/plane-copies/json-depth.json"
    );
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("fixture readable"))
            .expect("fixture is JSON");
    assert_eq!(MAX_JSON_DEPTH, 128, "the depth floor moved");
    assert_eq!(doc["max_json_depth"], MAX_JSON_DEPTH as u64);
    let cases = doc["cases"].as_array().expect("cases");
    assert!(!cases.is_empty());
    for case in cases {
        let body = fixture_body(case);
        let refused = agree(body.as_bytes(), MAX_JSON_DEPTH);
        // The fixture records the seam's whole verdict (the parse included), so an accepted body
        // must pass the guard, and a nested shape past the floor must be refused by the guard alone.
        if case["accepted"].as_bool().expect("verdict") {
            assert!(!refused, "an accepted body tripped the guard: {case}");
        }
        if let Some(depth) = case["depth"].as_u64() {
            assert_eq!(refused, depth as usize > MAX_JSON_DEPTH, "{case}");
        }
    }
}

#[test]
fn the_edge_cases_the_floor_exists_for() {
    let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    let cases: Vec<(String, bool)> = vec![
        // Exactly at the floor reads; one past is refused; arrays, objects, both.
        (deep(128), false),
        (deep(129), true),
        (
            format!("{}1{}", r#"{"k":"#.repeat(128), "}".repeat(128)),
            false,
        ),
        (
            format!("{}1{}", r#"{"k":"#.repeat(129), "}".repeat(129)),
            true,
        ),
        // Brackets inside a string do not count, however many.
        (format!(r#"{{"s":"{}"}}"#, "[{".repeat(500)), false),
        // An escaped quote does not end the string, so the brackets after it are still text.
        (format!(r#"["\"{}"]"#, "[".repeat(200)), false),
        // An escaped backslash does end its escape, so the quote after it closes the string.
        (
            format!(r#"["\\",{}{}]"#, "[".repeat(128), "]".repeat(128)),
            true,
        ),
        (
            format!(r#"["\\",{}{}]"#, "[".repeat(127), "]".repeat(127)),
            false,
        ),
        // Unterminated: a string never closed swallows the rest; open containers still count.
        (format!(r#"["{}"#, "[".repeat(300)), false),
        ("[".repeat(128), false),
        ("[".repeat(129), true),
        // Closers floor at zero: leading closers buy no headroom, and closing and reopening resets.
        (format!("{}{}", "]".repeat(50), "[".repeat(129)), true),
        (format!("{}{}", "]".repeat(50), "[".repeat(128)), false),
        (format!("{}][", "[".repeat(128)), false),
        (format!("{}][[", "[".repeat(128)), true),
        // Mismatched pairs are not validated: any closer closes.
        (
            format!("{}{}", "[".repeat(64), "}".repeat(64)).repeat(3),
            false,
        ),
        // Not JSON at all, and nothing.
        ("not json".to_string(), false),
        (String::new(), false),
        // A million deep: refused on the scan, no tree built.
        (deep(1_000_000), true),
    ];
    for (body, refused) in &cases {
        assert_eq!(
            agree(body.as_bytes(), MAX_JSON_DEPTH),
            *refused,
            "{body:.80}"
        );
    }
    // The bound is the caller's: zero refuses any container.
    assert!(!agree(b"1", 0));
    assert!(agree(b"[]", 0));
    assert!(!agree(br#""[""#, 0));
}

/// Every string up to six bytes over the bytes the scan reads (plus one it does not), at every
/// bound that can matter at that length: the two must agree on all of them.
#[test]
fn every_short_input_gets_the_kernel_verdict() {
    const ALPHABET: &[u8] = b"[{]}\"\\a";
    let mut body = Vec::with_capacity(6);
    let mut seen = 0usize;
    fn walk(body: &mut Vec<u8>, left: usize, seen: &mut usize) {
        for max in 0..=4 {
            agree(body, max);
        }
        *seen += 1;
        if left == 0 {
            return;
        }
        for &b in ALPHABET {
            body.push(b);
            walk(body, left - 1, seen);
            body.pop();
        }
    }
    walk(&mut body, 6, &mut seen);
    assert_eq!(seen, (0..=6).map(|n| ALPHABET.len().pow(n)).sum::<usize>());
}
