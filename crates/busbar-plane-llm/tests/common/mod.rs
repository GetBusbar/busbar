// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What `field_coverage.rs` shares: the field-coverage classifier ([`coverage`]), the one source
//! classifier the composition root's scanning gates also use (included by path, not copied), and
//! the fixture reader.

#![allow(dead_code)]

#[path = "../../../busbar/tests/common/classify.rs"]
mod classify;
pub use classify::*;

pub mod coverage;

use std::path::Path;

/// The lines of `tests/fixtures/<name>` in this crate: trimmed; blank lines and `#` lines dropped.
/// An absent or empty fixture is a failure, never an empty list (an empty list scans nothing and
/// passes).
pub fn fixture_lines(name: &str) -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));
    let lines: Vec<String> = text
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert!(!lines.is_empty(), "fixture {} is empty", path.display());
    lines
}
