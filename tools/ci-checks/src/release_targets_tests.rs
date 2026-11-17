// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PLATFORMS P3 / OQ-3 A: `release/release-targets.json` carries the unsuffixed arm64 Linux row as the
//! armv8.0 baseline (the one the arm64 image packages) and a separate `-armv8.1` row on `+lse`; the
//! `-armv8.0` row of the old default-is-lse layout is gone.

use busbar_contract::json::{self, JsonContainerTrait, JsonValueTrait};

use crate::repo_root;

fn targets() -> Vec<json::Value> {
    let path = repo_root().join("release/release-targets.json");
    let text = std::fs::read(&path).expect("release-targets.json reads");
    let doc: json::Value = json::parse_value(&text).expect("release-targets.json parses");
    doc.get("targets")
        .and_then(|t| t.as_array())
        .expect("targets array")
        .iter()
        .cloned()
        .collect()
}

fn str_of<'a>(r: &'a json::Value, key: &str) -> Option<&'a str> {
    r.get(key).and_then(|v| v.as_str())
}

fn bool_of(r: &json::Value, key: &str) -> Option<bool> {
    r.get(key).and_then(|v| v.as_bool())
}

fn row<'a>(rows: &'a [json::Value], name: &str) -> Option<&'a json::Value> {
    rows.iter().find(|r| str_of(r, "target") == Some(name))
}

#[test]
fn the_unsuffixed_arm64_row_is_the_armv8_0_baseline_the_image_packages() {
    let rows = targets();
    let r = row(&rows, "aarch64-unknown-linux-gnu").expect("the unsuffixed arm64 row");
    assert_eq!(
        bool_of(r, "baseline"),
        Some(true),
        "the 1.5.5 name keeps the armv8.0 baseline"
    );
    assert_eq!(str_of(r, "packaged_into"), Some("image-linux-arm64"));
    assert_eq!(bool_of(r, "published"), Some(true));
}

#[test]
fn the_armv8_1_row_is_a_published_lse_build_the_image_does_not_package() {
    let rows = targets();
    let r = row(&rows, "aarch64-unknown-linux-gnu-armv8.1").expect("the -armv8.1 row");
    assert_eq!(str_of(r, "triple"), Some("aarch64-unknown-linux-gnu"));
    assert_eq!(
        bool_of(r, "baseline"),
        Some(false),
        "the -armv8.1 row is the +lse build"
    );
    assert_eq!(str_of(r, "packaged_into"), Some(""));
    assert_eq!(bool_of(r, "published"), Some(true));
    assert_eq!(str_of(r, "arch"), Some("aarch64"));
    assert_eq!(str_of(r, "format"), Some("elf"));
    assert_eq!(str_of(r, "kind"), Some("binary"));
}

#[test]
fn the_old_armv8_0_row_is_gone_and_exactly_one_row_feeds_the_arm64_image() {
    let rows = targets();
    assert!(row(&rows, "aarch64-unknown-linux-gnu-armv8.0").is_none());
    let feeders = rows
        .iter()
        .filter(|r| str_of(r, "packaged_into") == Some("image-linux-arm64"))
        .count();
    assert_eq!(feeders, 1);
}
