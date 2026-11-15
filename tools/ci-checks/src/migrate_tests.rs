// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{anchor_finding, anchors, flag_sites, flag_text};
use crate::repo_root;

/// Red (mc1)(3), the real tree: no production text names `--migrate-config`.
#[test]
fn no_production_text_names_the_retired_migrate_flag() {
    let findings = flag_text(&repo_root()).expect("the crates tree scans");
    assert!(findings.is_empty(), "{}", findings.join("\n"));
}

/// Red (mc1)(3), planted: a string, a format string, a doc comment and an unparsable file are
/// found; a comment and test code are not.
#[test]
fn a_planted_flag_string_is_found_and_test_code_is_not() {
    let source = r#"
//! Module doc naming `busbar --migrate-config`.
// a plain comment naming --migrate-config is not text an operator sees
const TEXT: &str = "run busbar --migrate-config";
fn refusal(key: &str) -> String { format!("{key}: busbar --migrate-config removes it") }
/// Doc naming `--migrate-config`.
fn documented() {}
#[cfg(test)]
mod tests { const T: &str = "--migrate-config"; }
#[test]
fn a_test() { let _ = "--migrate-config"; }
"#;
    assert_eq!(flag_sites(source), vec![2, 4, 5, 6]);
    assert_eq!(
        flag_sites("fn broken( {\nlet x = \"--migrate-config\";\n"),
        vec![2]
    );
    assert!(flag_sites("const OK: &str = \"the boot migrates\";\n").is_empty());
}

/// Red (sz1)(3c), the real tree: the three † anchors carry both attributes.
#[test]
fn every_migrate_size_anchor_is_pinned() {
    let findings = anchors(&repo_root()).expect("the anchor files read");
    assert!(findings.is_empty(), "{}", findings.join("\n"));
}

/// Red (sz1)(3c), planted: removing either attribute, or the fn, fails with its own words.
#[test]
fn an_anchor_without_cold_or_inline_never_is_not_pinned() {
    let pinned = "impl Manifest {\n    #[cold]\n    #[inline(never)]\n    fn decode() {}\n}\n";
    assert_eq!(anchor_finding("f.rs", pinned, "Manifest", "decode"), None);
    let free = "#[inline(never)]\n#[cold]\npub fn read_answer() {}\n";
    assert_eq!(anchor_finding("f.rs", free, "", "read_answer"), None);
    for unpinned in [
        "impl Manifest {\n    #[cold]\n    fn decode() {}\n}\n",
        "impl Manifest {\n    #[inline(never)]\n    fn decode() {}\n}\n",
        "impl Manifest {\n    #[cold]\n    #[inline]\n    fn decode() {}\n}\n",
    ] {
        let finding = anchor_finding("f.rs", unpinned, "Manifest", "decode").expect("unpinned");
        assert!(finding.contains("anchor not pinned"), "{finding}");
    }
    let renamed = "impl Manifest {\n    #[cold]\n    #[inline(never)]\n    fn parse() {}\n}\n";
    let finding = anchor_finding("f.rs", renamed, "Manifest", "decode").expect("missing");
    assert!(finding.contains("anchor not found"), "{finding}");
    let other_type = "impl Other {\n    #[cold]\n    #[inline(never)]\n    fn decode() {}\n}\n";
    assert!(anchor_finding("f.rs", other_type, "Manifest", "decode").is_some());
}
