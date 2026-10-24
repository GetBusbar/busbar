// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `GET /api/v1/admin/usage` IS ONE PASS OVER ITS ROWS. A bucket holds a row per (key, lane, era),
//! fleet-wide; once a single count correction exists, each row needs the eras of its own key and
//! lane, and finding them by rescanning every row from inside the per-row loop made the read
//! quadratic in the bucket's rows — on the async worker, at read-only scope, unthrottled.
//!
//! The eras are grouped once, keyed by (key, lane), before the loop. This scan reads the read's
//! own body and fails if the per-row loop walks the rows again.

/// The body of `get_usage`'s per-row loop, as written.
fn per_row_loop(source: &str) -> &str {
    let read = source
        .split("pub(crate) async fn get_usage(")
        .nth(1)
        .expect("the usage read is declared");
    let read = read
        .split("\n    pub(crate) ")
        .next()
        .expect("the read's body ends");
    read.split("for r in &rows {")
        .nth(1)
        .expect("the read loops over its rows")
}

/// RED while the per-row loop re-filtered `rows.iter()` for every row's eras.
#[test]
fn the_usage_reads_per_row_loop_never_rescans_the_rows() {
    let source = include_str!("../src/v1/service_operations.rs");
    let body = per_row_loop(source);
    assert!(
        !rescans(body),
        "the usage read rescans every row from inside its per-row loop (quadratic): {body}"
    );
}

/// Whether a loop body walks `rows` again, however the call is wrapped across lines.
fn rescans(body: &str) -> bool {
    let code: Vec<&str> = body
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .flat_map(str::split_whitespace)
        .collect();
    let flat = code.join(" ");
    flat.contains("rows.iter()") || flat.contains("rows .iter()")
}

/// The scan sees a rescan in a loop body it is handed, and not a body without one.
#[test]
fn the_rescan_scan_sees_a_rescan() {
    let quadratic = "pub(crate) async fn get_usage(\n        for r in &rows {\n            let eras: Vec<u64> = rows.iter().filter(|o| o.key_id == r.key_id).collect();\n        }\n    pub(crate) fn next(";
    assert!(rescans(per_row_loop(quadratic)));
    let wrapped = "pub(crate) async fn get_usage(\n        for r in &rows {\n            let eras: Vec<u64> = rows\n                .iter()\n        }\n    pub(crate) fn next(";
    assert!(rescans(per_row_loop(wrapped)));
    let linear = "pub(crate) async fn get_usage(\n        for r in &rows {\n            let eras = eras_of.get(&key);\n        }\n    pub(crate) fn next(";
    assert!(!rescans(per_row_loop(linear)));
}
