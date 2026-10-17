// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SELF-CONTAINED-DIALECT WITNESS (design F3 SELF-CONTAINED; spec Part 3 #5: adding a dialect =
//! adding a file). Two source facts, read off the tree:
//!
//! 1. No dialect module names a sibling dialect. What two dialects share is a mechanism and lives in
//!    a shared module; a dialect that reaches into another's module couples the two (editing one
//!    silently changes the other).
//! 2. No shared codec module is named for a vendor: a shared module is named for the mechanism.
//!
//! One reference class is outside this witness: a dialect naming a sibling's GENERATED map tables
//! (`<sibling>::map::…`, emitted by `cargo xtask dialect compile` from a `dialects/*.toml` that
//! includes another dialect's rows or words). The map file rule ("a map file never includes another
//! dialect's rows") is the dialect-map lane's, and its fix is in those toml files, not in code.

use std::path::{Path, PathBuf};

fn codec_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/codec")
}

/// The dialects: every module directory under `src/codec` other than the IR and the test tree.
fn dialects() -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(codec_dir())
        .expect("src/codec")
        .filter_map(Result::ok)
        .filter(|e| e.path().join("mod.rs").is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != "ir" && n != "tests")
        .collect();
    out.sort();
    out
}

/// Every production `.rs` file under `dir` (test trees and `*_tests.rs` files excluded).
fn production_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir)
        .expect("readable dir")
        .filter_map(Result::ok)
    {
        let p = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        if p.is_dir() {
            if name != "tests" {
                production_sources(&p, out);
            }
        } else if name.ends_with(".rs") && !name.ends_with("_tests.rs") {
            out.push(p);
        }
    }
}

/// `true` when `line` names `dialect` as a path segment (`super::x::`, `codec::x::`, `x::`).
fn names_path(line: &str, dialect: &str) -> bool {
    let needle = format!("{dialect}::");
    line.match_indices(&needle).any(|(at, _)| {
        let before = line[..at].chars().next_back();
        let is_segment_start = !before.is_some_and(|c| c.is_alphanumeric() || c == '_');
        let generated_map = line[at + needle.len()..].starts_with("map::");
        is_segment_start && !generated_map
    })
}

#[test]
fn no_dialect_module_names_a_sibling_dialect() {
    let dialects = dialects();
    assert!(dialects.len() >= 2, "found dialects: {dialects:?}");
    let mut offenders = Vec::new();
    for d in &dialects {
        let mut files = Vec::new();
        production_sources(&codec_dir().join(d), &mut files);
        for f in files {
            let text = std::fs::read_to_string(&f).expect("readable source");
            for (n, line) in text.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                for sibling in dialects.iter().filter(|s| *s != d) {
                    if names_path(line, sibling) {
                        offenders.push(format!("{}:{}: {}", f.display(), n + 1, line.trim()));
                    }
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "dialect modules name a sibling dialect (move the shared mechanism to a shared module):\n{}",
        offenders.join("\n")
    );
}

#[test]
fn no_shared_codec_module_is_named_for_a_vendor() {
    let dialects = dialects();
    // The vendor words a dialect name is built from (`openai_chat` -> `openai`, `chat`); the generic
    // halves (`chat`, `responses`) are kept only where they are a whole dialect name.
    let mut nouns: Vec<String> = dialects
        .iter()
        .map(|d| d.split('_').next().unwrap_or(d).to_string())
        .collect();
    nouns.sort();
    nouns.dedup();
    let mut offenders = Vec::new();
    for e in std::fs::read_dir(codec_dir())
        .expect("src/codec")
        .filter_map(Result::ok)
    {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(".rs") else {
            continue;
        };
        if stem.split('_').any(|w| nouns.iter().any(|n| n == w)) {
            offenders.push(name);
        }
    }
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "shared codec modules named for a vendor (name them for the mechanism): {offenders:?}"
    );
}
