// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the plane's JSON seam (`json.rs`): the depth guard, and the O6 drift guard that holds
//! this copy of the security floor to the host's copy.

use super::*;

#[test]
fn rejects_pathologically_nested_input_without_overflow() {
    // A ~2 MB body 1,000,000 arrays deep would abort the process on re-serialize/drop if it reached
    // `from_slice`. The guard rejects it on the raw bytes first, so this returns Err cleanly.
    let depth = 1_000_000usize;
    let s = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
    assert!(
        parse::<serde_json::Value>(s.as_bytes()).is_err(),
        "deeply-nested body must be rejected"
    );
    assert!(exceeds_max_depth(s.as_bytes(), MAX_JSON_DEPTH));
}

#[test]
fn accepts_realistic_depth_and_counts_correctly() {
    let body = br#"{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"hi [bracket] {brace} in a string is not depth"}]}]}"#;
    assert!(!exceeds_max_depth(body, MAX_JSON_DEPTH));
    assert!(parse::<serde_json::Value>(body).is_ok());
    assert!(!exceeds_max_depth(br#"{"k":"[[[[[[[[[[ {{{{{{ ]]]]]"}"#, 8));
    let at_limit = format!("{}{}", "[".repeat(128), "]".repeat(128));
    assert!(!exceeds_max_depth(at_limit.as_bytes(), MAX_JSON_DEPTH));
    let over = format!("{}{}", "[".repeat(129), "]".repeat(129));
    assert!(exceeds_max_depth(over.as_bytes(), MAX_JSON_DEPTH));
}

/// The shared fixture `testing/plane-copies/json-depth.json`: the floor, and nesting at, under and
/// past it in arrays, objects and a mix, plus bracket text inside strings, escaped quotes, an
/// unterminated string and non-JSON. The host's own suite holds its copy of the seam to the same file.
fn fixture() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testing/plane-copies/json-depth.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("fixture readable"))
        .expect("fixture is JSON")
}

/// One fixture case's body.
fn body(case: &serde_json::Value) -> String {
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

/// THE O6 DRIFT GUARD: this copy of the seam holds the shared floor and answers every shared case
/// exactly as recorded — accepted or refused, through both the byte and the `str` entry — so it and
/// the host's copy cannot disagree without one of the two suites failing.
#[test]
fn the_plane_seam_holds_the_shared_floor_and_every_shared_verdict() {
    // A document 128 deep is ACCEPTED, and building it (and dropping it) recurses once per level; a
    // debug build's frames are large, so the comparison runs on a thread with room for that.
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(check_the_shared_fixture)
        .expect("spawn the check thread")
        .join()
        .expect("the check held");
}

fn check_the_shared_fixture() {
    let doc = fixture();
    assert_eq!(
        doc["max_json_depth"], MAX_JSON_DEPTH as u64,
        "the depth floor moved"
    );
    for case in doc["cases"].as_array().expect("cases") {
        let text = body(case);
        let accepted = case["accepted"].as_bool().expect("verdict");
        assert_eq!(
            parse::<serde_json::Value>(text.as_bytes()).is_ok(),
            accepted,
            "byte verdict on {case}"
        );
        assert_eq!(
            parse_str::<serde_json::Value>(&text).is_ok(),
            accepted,
            "str verdict on {case}"
        );
    }
}
