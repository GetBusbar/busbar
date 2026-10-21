// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SHARED FIXTURES' FLOORS (`testing/plane-copies/*.json`). This plane's suites read five shared
//! fixtures row by row, and a loop over rows passes over a fixture cut to one row or to empty lists
//! exactly as it passes over the whole one. Every list each suite iterates is held here to the size
//! the fixture was recorded at, and the depth cases to both verdicts, so a shrunk fixture is RED in
//! this suite rather than a proof over nothing.

/// `(fixture file, list key, recorded size)`: every list a suite of this plane iterates.
const FLOORS: &[(&str, &str, usize)] = &[
    ("declared-credentials.json", "schemes", 6),
    ("declared-credentials.json", "bindings", 7),
    ("declared-credentials.json", "regions", 7),
    ("declared-credentials.json", "rows", 540),
    ("dialect-helpers.json", "bearer_error_code", 11),
    ("dialect-helpers.json", "constants", 8),
    ("dialect-helpers.json", "context_length_prose_scan", 8),
    ("dialect-helpers.json", "rewrite_text_pairs", 3),
    ("dialect-helpers.json", "sse_frames", 9),
    ("dialect-helpers.json", "strip_top_level_usage_member", 9),
    ("dialect-helpers.json", "tool_arguments_to_string", 4),
    ("dialect-helpers.json", "write_sse_frame", 3),
    ("eventstream-frames.json", "frames", 7),
    ("eventstream-frames.json", "exception_frames", 3),
    ("json-depth.json", "cases", 34),
    ("upstream-classes.json", "rows", 11),
];

/// The depth fixture's two sides: at least this many cases accepted and this many refused.
const DEPTH_ACCEPTED: usize = 18;
const DEPTH_REFUSED: usize = 16;

fn read(file: &str) -> serde_json::Value {
    let path = format!(
        "{}/../../testing/plane-copies/{file}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(&path).expect("fixture readable"))
        .expect("fixture is JSON")
}

fn size(v: &serde_json::Value) -> usize {
    match v {
        serde_json::Value::Array(a) => a.len(),
        serde_json::Value::Object(o) => o.len(),
        _ => 0,
    }
}

/// Every way `doc` (the fixture `file`) is under its recorded floor.
fn under_floor(file: &str, doc: &serde_json::Value) -> Vec<String> {
    let mut out: Vec<String> = FLOORS
        .iter()
        .filter(|(f, _, _)| *f == file)
        .filter_map(|(_, key, floor)| {
            let n = size(&doc[*key]);
            (n < *floor).then(|| format!("{file} `{key}`: {n} entries, under the floor of {floor}"))
        })
        .collect();
    if file == "json-depth.json" {
        let cases = doc["cases"].as_array().map(Vec::as_slice).unwrap_or(&[]);
        let accepted = cases
            .iter()
            .filter(|c| c["accepted"].as_bool() == Some(true))
            .count();
        let refused = cases
            .iter()
            .filter(|c| c["accepted"].as_bool() == Some(false))
            .count();
        if accepted < DEPTH_ACCEPTED || refused < DEPTH_REFUSED {
            out.push(format!(
                "{file}: {accepted} accepted and {refused} refused cases, under the floor of \
                 {DEPTH_ACCEPTED} and {DEPTH_REFUSED}"
            ));
        }
    }
    out
}

fn files() -> Vec<&'static str> {
    let mut f: Vec<&str> = FLOORS.iter().map(|(f, _, _)| *f).collect();
    f.dedup();
    f
}

#[test]
fn every_shared_fixture_this_plane_reads_is_at_its_recorded_size() {
    for file in files() {
        let short = under_floor(file, &read(file));
        assert!(short.is_empty(), "{short:#?}");
    }
}

/// THE FLOOR BITES: each fixture cut to one entry per list, or to empty lists, is under its floor.
#[test]
fn a_cut_shared_fixture_is_under_its_floor() {
    for file in files() {
        let whole = read(file);
        let mut one = whole.clone();
        let mut empty = whole.clone();
        for (_, key, _) in FLOORS.iter().filter(|(f, _, _)| *f == file) {
            match &whole[*key] {
                serde_json::Value::Array(a) => {
                    one[*key] = serde_json::Value::Array(a.iter().take(1).cloned().collect());
                    empty[*key] = serde_json::json!([]);
                }
                serde_json::Value::Object(o) => {
                    one[*key] = serde_json::Value::Object(
                        o.iter()
                            .take(1)
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect(),
                    );
                    empty[*key] = serde_json::json!({});
                }
                other => panic!("{file} `{key}` is {other}, not a list"),
            }
        }
        assert!(
            !under_floor(file, &one).is_empty(),
            "{file} cut to one entry"
        );
        assert!(!under_floor(file, &empty).is_empty(), "{file} cut to empty");
    }
}
