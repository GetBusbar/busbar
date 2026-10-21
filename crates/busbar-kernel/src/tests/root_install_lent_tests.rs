// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROOT'S INSTALL RECORD IS LENT, NEVER INSTALLED (status row 82, D2; THE DESIGN l.1560: no
//! kernel `OnceLock` seam beyond the two R6 exempts). The composition root owns its
//! [`crate::preflight::RootInstall`] — its linked store rows, keyed by store key and canonical
//! name, its hook names and its axes — and lends it to every reader: the configuration it resolves,
//! the registry link, the preflight and the build. The kernel keeps no copy in a static of its own,
//! shipped or test-gated, and has no installer for one.

use std::path::{Path, PathBuf};

/// Every source file of this crate outside its test code (`tests` directories and `test_support`).
fn kernel_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("the source directory reads") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            let test_code = path
                .file_name()
                .is_some_and(|n| n == "tests" || n == "test_support");
            if !test_code {
                kernel_sources(&path, out);
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

/// Whether `decl` declares a `static` item (not the `'static` lifetime).
fn declares_static(decl: &str) -> bool {
    decl.match_indices("static ").any(|(at, _)| {
        decl[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '\''))
    })
}

/// Every `static` of this crate's non-test sources, gated to test builds or not, whose declaration
/// (its line and the next, for a wrapped one) names one of `words`, and every `fn` named one of
/// `fns`, as `file:line: text`.
fn holders_and_installers(words: &[&str], fns: &[&str]) -> Vec<String> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    kernel_sources(&src, &mut files);
    files.sort();
    let mut hits = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("a source file reads");
        let lines: Vec<&str> = text.lines().collect();
        for (n, line) in lines.iter().enumerate() {
            let decl = code(line);
            let next = lines.get(n + 1).copied().map_or("", code);
            let holder = declares_static(decl)
                && words
                    .iter()
                    .any(|w| has_ident(decl, w) || has_ident(next, w));
            let installer = fns
                .iter()
                .any(|f| decl.contains(&format!("fn {f}(")) || decl.contains(&format!("fn {f}<")));
            if holder || installer {
                hits.push(format!("{}:{}: {}", file.display(), n + 1, line.trim()));
            }
        }
    }
    hits
}

/// No static of the kernel holds the root's install record or any part of it a root hands in (its
/// rows, its hook names), and no fn installs one or reads one back: the compose owns the record and
/// lends it to each reader.
#[test]
fn the_root_install_is_lent_by_the_compose_not_held_in_a_static() {
    let hits = holders_and_installers(
        &["RootInstall", "ROOT_ROWS", "TEST_ROOT_HOOK_NAMES"],
        &["install_linked_rows", "root_rows"],
    );
    assert!(
        hits.is_empty(),
        "the kernel holds the root's install record in a static, or installs or reads one:\n{}",
        hits.join("\n")
    );
}

/// The registry link reads the record it is LENT, not one a process holds: the stand-in record's
/// linked store answers by its key through the link that record is lent to, and a record that lends
/// no store (nothing installed, [`Default`]) links none, in the same process.
#[test]
fn the_registry_link_reads_the_record_it_is_lent() {
    use crate::preflight::{linked, RootInstall};
    let stand_in = RootInstall::STAND_IN;
    let (key, ..) = stand_in.stores[0];
    assert!(
        linked(&stand_in, crate::config::Legacy::stand_in())
            .expect("the stand-in's rows link")
            .resolve(key)
            .is_some(),
        "the lent record's store `{key}` is linked"
    );
    assert!(
        linked(&RootInstall::default(), crate::config::Legacy::stand_in())
            .expect("no rows link")
            .resolve(key)
            .is_none(),
        "a record that lends no store links none, whatever another record lent"
    );
}
