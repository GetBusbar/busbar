// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROOT LEGACY TABLE IS LENT, NEVER INSTALLED (`BUSBAR-1.6.0.md` §2: retired names and
//! migrations "live in the root legacy table, `[package.metadata.busbar.legacy]`"; "add no new
//! kernel `OnceLock` seam beyond the two R6 exempts"). The composition root owns its table and lends
//! it to what reads it — the config load and parse, the migrator and the registry link — so no
//! process-wide static of this crate holds it, and no `install` fills one (`qa/construction.toml`,
//! the installed-store row's `config/legacy.rs::ROWS` debt).

use std::path::{Path, PathBuf};

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
            if !is_static {
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

/// No shipped static of this crate holds the root legacy table's rows, and the kernel's legacy
/// module offers no installer to fill one: the table reaches every reader as a value the root lent.
#[test]
fn no_static_holds_the_root_legacy_table_and_nothing_installs_one() {
    let hits = shipped_statics_naming(&["Rows", "ROWS"]);
    assert!(
        hits.is_empty(),
        "a process-wide static holds the root legacy table:\n{}",
        hits.join("\n")
    );
    let legacy =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/config/legacy.rs"))
            .expect("config/legacy.rs reads");
    let installers: Vec<&str> = legacy
        .lines()
        .map(code)
        .filter(|l| has_ident(l, "fn") && has_ident(l, "install"))
        .collect();
    assert!(
        installers.is_empty(),
        "the kernel's legacy module installs the root's table:\n{}",
        installers.join("\n")
    );
}
