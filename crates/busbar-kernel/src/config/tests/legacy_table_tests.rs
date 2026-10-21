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

/// The 1-based lines of `text` that declare a `static` (plain, `mut`, or in a `thread_local!` /
/// `lazy_static!` body) whose name or type names one of `words`. A static's type is read off its
/// line and the next (a wrapped declaration); comments are not read.
fn statics_naming(text: &str, words: &[&str]) -> Vec<usize> {
    let lines: Vec<&str> = text.lines().collect();
    let mut hits = Vec::new();
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
            hits.push(n + 1);
        }
    }
    hits
}

/// What names the root legacy table in a static's declaration: its rows' type and spelling, and
/// the lent value itself.
const TABLE_WORDS: &[&str] = &["Rows", "ROWS", "Legacy"];

/// Every SHIPPED `static` of this crate whose name or type names one of `words`, as
/// `file:line: text`.
fn shipped_statics_naming(words: &[&str]) -> Vec<String> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    shipped_sources(&src, &mut files);
    files.sort();
    let mut hits = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("a source file reads");
        let lines: Vec<&str> = text.lines().collect();
        for n in statics_naming(&text, words) {
            hits.push(format!("{}:{n}: {}", file.display(), lines[n - 1].trim()));
        }
    }
    hits
}

/// THE SCAN SEES A STATIC THAT HOLDS THE LENT VALUE, whatever cell carries it, and not the value
/// passed as a parameter or kept on a struct.
#[test]
fn the_scan_sees_every_static_holding_the_legacy_table() {
    for (planted, why) in [
        (
            "static TABLE: std::sync::OnceLock<Legacy> = std::sync::OnceLock::new();\n",
            "a OnceLock",
        ),
        (
            "static TABLE: std::sync::LazyLock<Legacy> =\n\
             std::sync::LazyLock::new(Legacy::stand_in);\n",
            "a LazyLock, wrapped",
        ),
        (
            "thread_local! {\n\
             static TABLE: std::cell::Cell<Option<crate::config::Legacy>> =\n\
             const { std::cell::Cell::new(None) };\n\
             }\n",
            "a thread_local",
        ),
        (
            "pub(crate) static mut TABLE: Option<Legacy> = None;\n",
            "a static mut",
        ),
        (
            "static ROWS: std::sync::OnceLock<Rows> = std::sync::OnceLock::new();\n",
            "the rows themselves",
        ),
    ] {
        assert_eq!(
            statics_naming(planted, TABLE_WORDS).len(),
            1,
            "{why} holding the table is not seen:\n{planted}"
        );
    }
    let lent = "pub fn read(legacy: Legacy) -> &'static str {\n    legacy.text(\"k\")\n}\n\
                struct Cfg {\n    legacy: Legacy,\n}\n\
                // static TABLE: OnceLock<Legacy>\n";
    assert!(
        statics_naming(lent, TABLE_WORDS).is_empty(),
        "a lent value or a comment is not a static"
    );
}

/// No shipped static of this crate holds the root legacy table's rows, and the kernel's legacy
/// module offers no installer to fill one: the table reaches every reader as a value the root lent.
#[test]
fn no_static_holds_the_root_legacy_table_and_nothing_installs_one() {
    let hits = shipped_statics_naming(TABLE_WORDS);
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

/// THE TABLE IS A VALUE THE ROOT LENDS: two compositions in one process each read the table they
/// lent, where an installed table answered whichever install came first.
#[test]
fn two_compositions_in_one_process_each_read_the_table_they_lent() {
    use crate::config::Legacy;
    let a = Legacy::new(&[
        ("former.alpha", "alpha-1 alpha-0"),
        ("retired.store.old-alpha", "alpha"),
    ]);
    let b = Legacy::new(&[("former.alpha", "beta-1")]);
    assert_eq!(a.former_names("alpha"), ["alpha-1", "alpha-0"]);
    assert_eq!(b.former_names("alpha"), ["beta-1"]);
    assert!(b.text("retired.store.old-alpha").is_empty());

    let mut section = serde_yaml::Mapping::new();
    section.insert("module".into(), "old-alpha".into());
    assert_eq!(b.rewrite_retired("store", &mut section.clone(), true), None);
    assert_eq!(
        a.rewrite_retired("store", &mut section, true),
        Some(("old-alpha".to_string(), "alpha"))
    );
    assert_eq!(
        section.get("module").and_then(serde_yaml::Value::as_str),
        Some("alpha")
    );
}
