// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PLATFORMS P3 / OQ-3 A: `release/release-targets.json` carries the unsuffixed arm64 Linux row as the
//! armv8.0 baseline (the one the arm64 image packages) and a separate `-armv8.1` row on `+lse`; the
//! `-armv8.0` row of the old default-is-lse layout is gone.

use serde_json::Value;

use crate::repo_root;

fn targets() -> Vec<Value> {
    let path = repo_root().join("release/release-targets.json");
    let text = std::fs::read_to_string(&path).expect("release-targets.json reads");
    let doc: Value = serde_json::from_str(&text).expect("release-targets.json parses");
    doc["targets"].as_array().expect("targets array").clone()
}

fn row<'a>(rows: &'a [Value], name: &str) -> Option<&'a Value> {
    rows.iter().find(|r| r["target"] == name)
}

#[test]
fn the_unsuffixed_arm64_row_is_the_armv8_0_baseline_the_image_packages() {
    let rows = targets();
    let r = row(&rows, "aarch64-unknown-linux-gnu").expect("the unsuffixed arm64 row");
    assert_eq!(
        r["baseline"], true,
        "the 1.5.5 name keeps the armv8.0 baseline"
    );
    assert_eq!(r["packaged_into"], "image-linux-arm64");
    assert_eq!(r["published"], true);
}

#[test]
fn the_armv8_1_row_is_a_published_lse_build_the_image_does_not_package() {
    let rows = targets();
    let r = row(&rows, "aarch64-unknown-linux-gnu-armv8.1").expect("the -armv8.1 row");
    assert_eq!(r["triple"], "aarch64-unknown-linux-gnu");
    assert_eq!(r["baseline"], false, "the -armv8.1 row is the +lse build");
    assert_eq!(r["packaged_into"], "");
    assert_eq!(r["published"], true);
    assert_eq!(r["arch"], "aarch64");
    assert_eq!(r["format"], "elf");
    assert_eq!(r["kind"], "binary");
}

#[test]
fn the_old_armv8_0_row_is_gone_and_exactly_one_row_feeds_the_arm64_image() {
    let rows = targets();
    assert!(row(&rows, "aarch64-unknown-linux-gnu-armv8.0").is_none());
    let feeders = rows
        .iter()
        .filter(|r| r["packaged_into"] == "image-linux-arm64")
        .count();
    assert_eq!(feeders, 1);
}
