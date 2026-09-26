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

/// The shared fixture set: nesting at, just under and just past the floor, in arrays, objects and a
/// mix; bracket and brace text inside strings (which is not depth), escaped quotes that must not end
/// a string early, an unterminated string, and a pathological depth.
fn fixtures() -> Vec<String> {
    let arrays = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    let objects = |n: usize| format!("{}1{}", r#"{"k":"#.repeat(n), "}".repeat(n));
    let mixed = |n: usize| {
        let open: String = (0..n)
            .map(|i| if i % 2 == 0 { "[" } else { r#"{"k":"# })
            .collect();
        let close: String = (0..n)
            .rev()
            .map(|i| if i % 2 == 0 { "]" } else { "}" })
            .collect();
        format!("{open}1{close}")
    };
    let mut out = Vec::new();
    for n in [1, 2, 64, 127, 128, 129, 130, 256, 10_000] {
        out.push(arrays(n));
        out.push(objects(n));
        out.push(mixed(n));
    }
    out.push(format!(r#"{{"s":"{}"}}"#, "[".repeat(500)));
    out.push(format!(r#"{{"s":"\"{}\""}}"#, "{".repeat(500)));
    out.push(format!(r#"["\\",{}{}]"#, "[".repeat(128), "]".repeat(128)));
    out.push(format!(r#"["\"{}"#, "[".repeat(200)));
    out.push(r#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#.to_string());
    out.push(String::new());
    out.push("not json".to_string());
    out
}

/// THE O6 DRIFT GUARD: the plane's copy of the seam and the host's copy agree on the floor (128) and
/// on the verdict of every fixture — accepted or refused, through both the byte and the `str` entry.
#[test]
fn the_plane_seam_and_the_host_seam_agree_on_the_floor_and_every_verdict() {
    // A document 128 deep is ACCEPTED, and building it (and dropping it) recurses once per level; a
    // debug build's frames are large, so the comparison runs on a thread with room for that.
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(compare_the_two_seams)
        .expect("spawn the comparison thread")
        .join()
        .expect("the comparison held");
}

fn compare_the_two_seams() {
    assert_eq!(MAX_JSON_DEPTH, 128, "the plane's depth floor moved");
    // The floor, read off the host's verdicts: 128 deep is accepted, 129 deep is refused.
    let at = format!("{}{}", "[".repeat(128), "]".repeat(128));
    let past = format!("{}{}", "[".repeat(129), "]".repeat(129));
    assert!(busbar_kernel::json::parse::<serde_json::Value>(at.as_bytes()).is_ok());
    assert!(busbar_kernel::json::parse::<serde_json::Value>(past.as_bytes()).is_err());
    for fixture in fixtures() {
        let plane = parse::<serde_json::Value>(fixture.as_bytes());
        let host = busbar_kernel::json::parse::<serde_json::Value>(fixture.as_bytes());
        assert_eq!(
            plane.is_ok(),
            host.is_ok(),
            "byte verdict differs on {:.80}",
            fixture
        );
        let plane_str = parse_str::<serde_json::Value>(&fixture);
        let host_str = busbar_kernel::json::parse_str::<serde_json::Value>(&fixture);
        assert_eq!(
            plane_str.is_ok(),
            host_str.is_ok(),
            "str verdict differs on {:.80}",
            fixture
        );
        // The documents themselves, and what each seam serializes them back to, for the fixtures
        // shallow enough to compare on a test thread's stack (a debug-build serializer recurses).
        if exceeds_max_depth(fixture.as_bytes(), 16) {
            continue;
        }
        if let (Ok(plane), Ok(host)) = (plane, host) {
            assert_eq!(plane, host, "document differs on {:.80}", fixture);
            assert_eq!(
                to_vec(&plane).ok(),
                busbar_kernel::json::to_vec(&host).ok(),
                "serialized bytes differ on {:.80}",
                fixture
            );
        }
    }
}
