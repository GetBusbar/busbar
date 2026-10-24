// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! NO PROCESS-WIDE STATIC HOLDS THE SECTION LIST OR THE EGRESS-TRUST CAPABILITY (THE DESIGN Part 0:
//! no kernel `OnceLock` seam beyond the two R6 exempts). The root's destination guard hears a
//! committed configuration through the root's rules, which every build is handed and every
//! generation keeps; a test binary's egress-trust hand-in is a static gated to test builds, which no
//! shipped build has.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::appbuild::RootRules;
use crate::config::Destinations;

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

/// The parse-time section list has no process-wide provider: no shipped static of this crate holds
/// one (the reader it fed had no caller; a cross-plane refusal is handed its section list).
#[test]
fn no_static_holds_the_plane_section_list() {
    let hits = shipped_statics_naming(&["PLANE_SECTIONS"]);
    assert!(
        hits.is_empty(),
        "a process-wide static holds the section-list provider:\n{}",
        hits.join("\n")
    );
}

/// The egress-trust capability rides no shipped static of this crate: a shipped build holds none,
/// and a test binary's hand-in is gated to test builds.
#[test]
fn no_static_holds_the_egress_trust_capability() {
    let hits = shipped_statics_naming(&["EGRESS_TRUST", "EgressTrustHost"]);
    assert!(
        hits.is_empty(),
        "a process-wide static holds the egress-trust capability:\n{}",
        hits.join("\n")
    );
}

/// Rules that record every commit raised to them.
#[derive(Default)]
struct Hearing(Mutex<Vec<Destinations>>);

impl RootRules for Hearing {
    fn check(&self, _cfg: &crate::config::RootCfg) -> Result<(), String> {
        Ok(())
    }
    fn destinations_applied(&self, destinations: &Destinations) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(destinations.clone());
    }
}

impl Hearing {
    fn heard(&self) -> Vec<Destinations> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// THE COMMIT REACHES THE GUARD THROUGH THE ROOT'S RULES, as it reached it through the installed
/// capability: a build dropped unkept (an apply whose persist or swap failed) raises nothing, and a
/// kept build raises exactly the destinations its configuration states, once.
#[test]
fn a_kept_build_raises_its_destinations_to_the_rules_it_was_judged_by() {
    // The provider dialects a lane may name are DECLARED by a registered plane (ruling 2026-10-16 D).
    crate::test_support::register_neutral_test_plane();
    crate::snapshot::init();
    let cfg = || {
        let mut cfg = crate::test_support::cfg_with_provider_api_key(
            crate::config::SecretRef::env("BUSBAR_TEST_NO_SUCH_KEY_COMMIT_GUARD"),
        );
        cfg.allow_all_metadata = true;
        cfg
    };
    let expected = cfg().destinations();
    assert!(
        expected.allow_all_metadata,
        "the configuration states a destination fact"
    );
    let hearing = Arc::new(Hearing::default());
    let rules: Arc<dyn RootRules> = hearing.clone();

    let (_app, _, unkept) = crate::build_app_from_config(
        cfg(),
        crate::config::PluginsCfg::default(),
        None,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        (None, None),
        None,
        &rules,
    )
    .expect("the configuration builds");
    drop(unkept);
    assert!(
        hearing.heard().is_empty(),
        "a build dropped unkept raises nothing"
    );

    crate::test_support::build_once_under(cfg(), None, &rules).expect("the configuration builds");
    assert_eq!(
        hearing.heard(),
        vec![expected],
        "the kept build raises its configuration's destinations, once"
    );
}
