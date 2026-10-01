// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT THE SHIPPED BINARY ACTUALLY CONTAINS — the one source classifier the composition root's
//! scanning gates share.
//!
//! A gate that answers a question about production code by reading a `.rs` file whole is not
//! answering that question. Every crate in this tree keeps its unit tests in the same file as the
//! code they exercise, inside `#[cfg(test)] mod tests { … }`, and that block is not in the shipped
//! binary. So a scan that reads the file whole is satisfied by a token that appears ONLY in a test
//! — including a token the test wrote precisely because it was mocking the production path that is
//! missing. The gate then reports the property holds while the property is absent, which is the
//! exact failure a gate exists to prevent.
//!
//! The construction gate already had the right answer, in Python: `scripts/construction-gate/
//! rules.py` carries a `scan_file` that strips comments (respecting string literals, so a `//`
//! inside a string is not a comment), blanks literal contents (so a brace inside a string does not
//! disturb structure matching), and tracks `#[cfg(test)] mod` depth so every line inside a test
//! module is flagged. This is that classifier, in Rust, with the same rules — so the two gates
//! agree about what "production" means rather than each having a private opinion.
//!
//! [`Line::intest`] is the whole point. Everything else here exists to compute it correctly.

#![allow(dead_code)]

pub mod boot;
pub mod plugins;

mod classify;
pub use classify::*;

use std::path::{Path, PathBuf};

// ── THE PLUGIN VOCABULARY IS DATA ─────────────────────────────────────────────────────────────────
// "A plugin tests itself; the kernel never tests or names a plugin." A scanning gate here still has
// to know WHICH plugin crates and plugin-owned files to read, so that knowledge lives as data: the
// linked-plugin table the composition root itself folds (`[package.metadata.busbar.linked]` /
// `linked-axes` in this crate's Cargo.toml), and, for the plugin-owned files a gate pins, a fixture
// beside the test (`tests/fixtures/*.txt`). The test source spells neither.

/// The lines of `crates/busbar/tests/fixtures/<name>`: trimmed; blank lines and lines starting with `#`
/// dropped (a `#` inside a line is data).
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

/// `[table]` rows `key = "value"` of this crate's Cargo.toml, in file order (the same shape
/// `src/linked_gen.rs` reads). An absent or empty table is a failure.
pub fn manifest_table(table: &str) -> Vec<(String, String)> {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("read crates/busbar/Cargo.toml");
    let header = format!("[{table}]");
    let mut in_table = false;
    let mut rows = Vec::new();
    for line in manifest.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.starts_with('[') {
            in_table = code == header;
            continue;
        }
        if in_table {
            if let Some((k, v)) = code.split_once('=') {
                rows.push((
                    k.trim().trim_matches('"').to_string(),
                    v.trim().trim_matches('"').to_string(),
                ));
            }
        }
    }
    assert!(
        !rows.is_empty(),
        "Cargo.toml: `{header}` is missing or empty"
    );
    rows
}

/// Every LINKED crate whose linked row carries the `plane` axis — the planes this binary links, as
/// `(feature, crate directory under crates/)`, in manifest order.
pub fn linked_plane_crates() -> Vec<(String, String)> {
    let axes = manifest_table("package.metadata.busbar.linked-axes");
    manifest_table("package.metadata.busbar.linked")
        .into_iter()
        .filter(|(feature, _)| {
            axes.iter()
                .any(|(f, a)| f == feature && a.split_whitespace().any(|x| x == "plane"))
        })
        .collect()
}

/// The rows of `tests/fixtures/plane_doctrine.txt` whose first word is `kind`, each the remaining
/// whitespace-split words, leaked once (the doctrine is pinned for the process's life).
pub fn doctrine_rows(kind: &str) -> Vec<Vec<&'static str>> {
    static ROWS: std::sync::OnceLock<Vec<Vec<&'static str>>> = std::sync::OnceLock::new();
    ROWS.get_or_init(|| {
        fixture_lines("plane_doctrine.txt")
            .into_iter()
            .map(|l| {
                let l: &'static str = Box::leak(l.into_boxed_str());
                l.split_whitespace().collect()
            })
            .collect()
    })
    .iter()
    .filter(|r| r[0] == kind)
    .map(|r| r[1..].to_vec())
    .collect()
}

/// The cargo features this build enabled (build.rs publishes them as `BUSBAR_ENABLED_FEATURES`).
pub fn enabled_features() -> std::collections::BTreeSet<&'static str> {
    env!("BUSBAR_ENABLED_FEATURES").split_whitespace().collect()
}

/// THE ROOT LEGS THIS BUILD CARRIES: each doctrine `root-leg <leg> <feature>` row whose feature is
/// enabled. The mcp and a2a legs are the kernel-loop rider those planes are SERVED through, so the
/// feature that links the plane gates them, not a `root-*` feature of their own.
pub fn compiled_root_legs() -> std::collections::BTreeSet<&'static str> {
    let on = enabled_features();
    doctrine_rows("root-leg")
        .into_iter()
        .filter(|r| on.contains(r[1]))
        .map(|r| r[0])
        .collect()
}

/// [`linked_plane_crates`] whose entry module is the crate's OWN `linked` module (no
/// `[package.metadata.busbar.linked-entry]` row) — the planes whose code lives in their own crate,
/// not in a composition-root module.
pub fn linked_plane_crates_own_entry() -> Vec<(String, String)> {
    let entries = manifest_table("package.metadata.busbar.linked-entry");
    linked_plane_crates()
        .into_iter()
        .filter(|(_, krate)| !entries.iter().any(|(k, _)| k == krate))
        .collect()
}
