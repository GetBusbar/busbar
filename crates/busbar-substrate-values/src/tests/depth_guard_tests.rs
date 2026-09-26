// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/json.rs`.

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

/// THE SHARED DEPTH-FLOOR FIXTURE (#83a O6): this seam holds the floor and answers every case in
/// `testing/plane-copies/json-depth.json` as recorded. The LLM plane's own copy of the seam is held
/// to the same file, so the two copies of the security floor cannot disagree without one of the two
/// suites failing.
#[test]
fn the_host_seam_holds_the_shared_floor_and_every_shared_verdict() {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            let path = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testing/plane-copies/json-depth.json"
            );
            let doc: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(path).expect("fixture readable"))
                    .expect("fixture is JSON");
            assert_eq!(doc["max_json_depth"], MAX_JSON_DEPTH as u64);
            for case in doc["cases"].as_array().expect("cases") {
                let text = match case["raw"].as_str() {
                    Some(raw) => raw.to_string(),
                    None => {
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
                };
                let accepted = case["accepted"].as_bool().expect("verdict");
                assert_eq!(
                    parse::<serde_json::Value>(text.as_bytes()).is_ok(),
                    accepted,
                    "{case}"
                );
                assert_eq!(
                    parse_str::<serde_json::Value>(&text).is_ok(),
                    accepted,
                    "{case}"
                );
            }
        })
        .expect("spawn")
        .join()
        .expect("the shared verdicts held");
}
