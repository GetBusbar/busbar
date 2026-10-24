// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROOT'S INSTALL RECORD IS THE ONE INSTALL PATH (THE DESIGN Part 0: no kernel `OnceLock` seam
//! beyond the two R6 exempts): the configuration projection and the auth-axis opener the
//! composition root hands the kernel ride `RootInstall`, never a process-wide static of this crate.
//! A test binary's own hand-in is a static gated to test builds, which no shipped build has.

use std::path::{Path, PathBuf};

use crate::preflight::{root_rows, RootInstall};

/// Every shipped source file under `dir`: the `tests` directories and `test_support` are test code
/// as a whole.
fn shipped_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("the source directory reads") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            let test_code = path
                .file_name()
                .is_some_and(|n| n == "tests" || n == "test_support");
            if !test_code {
                shipped_sources(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `word` occurs in `hay` as a whole identifier.
fn has_ident(hay: &str, word: &str) -> bool {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    hay.match_indices(word).any(|(at, _)| {
        hay[..at].chars().next_back().is_none_or(|c| !ident(c))
            && hay[at + word.len()..]
                .chars()
                .next()
                .is_none_or(|c| !ident(c))
    })
}

/// The code of `line`, its trailing `//` comment struck.
fn code(line: &str) -> &str {
    line.split("//").next().unwrap_or_default()
}

/// Is the item declared at `lines[at]` gated to test builds: an attribute among the lines just
/// above it (attributes and doc comments) that names `test` in a `cfg`?
fn test_gated(lines: &[&str], at: usize) -> bool {
    lines[..at]
        .iter()
        .rev()
        .map(|l| l.trim())
        .take_while(|l| l.starts_with("#[") || l.starts_with("///"))
        .any(|l| l.starts_with("#[cfg(test)") || l.starts_with("#[cfg(any(test"))
}

/// Every SHIPPED `static` of this crate whose name or type names one of `words`, as
/// `file:line: text`. A static's type is read off its line and the next (a wrapped declaration).
fn shipped_statics_naming(words: &[&str]) -> Vec<String> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    shipped_sources(&src, &mut files);
    files.sort();
    let mut hits = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("a source file reads");
        let lines: Vec<&str> = text.lines().collect();
        for (n, line) in lines.iter().enumerate() {
            let decl = code(line);
            // `static` as an item, not the `'static` lifetime.
            let is_static = decl.match_indices("static ").any(|(at, _)| {
                decl[..at]
                    .chars()
                    .next_back()
                    .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '\''))
            });
            if !is_static || test_gated(&lines, n) {
                continue;
            }
            let next = lines.get(n + 1).copied().map_or("", code);
            if words
                .iter()
                .any(|w| has_ident(decl, w) || has_ident(next, w))
            {
                hits.push(format!("{}:{}: {}", file.display(), n + 1, line.trim()));
            }
        }
    }
    hits
}

/// The root's configuration projection rides its install record: no shipped static of this crate
/// holds a `ConfigProjection`.
#[test]
fn the_config_projection_rides_the_install_record_not_a_static() {
    let hits = shipped_statics_naming(&["ConfigProjection", "CONFIG_PROJECTION"]);
    assert!(
        hits.is_empty(),
        "a process-wide static holds the root's configuration projection:\n{}",
        hits.join("\n")
    );
    // Nothing installed: a build keeps no projection.
    assert!(RootInstall::default().config_projection.is_none());
}

/// The root's auth-axis opener rides its install record: no shipped static of this crate holds an
/// `AuthAxisOpener`.
#[test]
fn the_auth_axis_opener_rides_the_install_record_not_a_static() {
    let hits = shipped_statics_naming(&["AuthAxisOpener", "AUTH_AXIS"]);
    assert!(
        hits.is_empty(),
        "a process-wide static holds the root's auth-axis opener:\n{}",
        hits.join("\n")
    );
    // Nothing installed: no auth row answers. A test build reads the stand-in's opener off the
    // same record.
    assert!(RootInstall::default().auth_axis.is_none());
    assert_eq!(
        root_rows().auth_axis.is_some(),
        cfg!(feature = "test-support"),
        "a test build's install record carries the stand-in opener exactly under `test-support`"
    );
}
