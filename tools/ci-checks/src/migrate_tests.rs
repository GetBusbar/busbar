// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{
    anchor_finding, anchors, flag_sites, flag_text, retired_key_sites, retired_words,
    root_host_sites,
};
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

/// Red (k), the real tree: no retired migration-table key in a `[package.metadata.busbar.*]` table,
/// and no production `RootHost` anywhere.
#[test]
fn no_retired_migration_vocabulary_survives_in_the_real_tree() {
    let findings = retired_words(&repo_root()).expect("the tree scans");
    assert!(findings.is_empty(), "{}", findings.join("\n"));
}

/// Red (k), planted: a `former.x`, `retired.x` and `name_1_5_5.x` key and the migration table's own
/// header are found; the same keys outside a `package.metadata.busbar.*` table are not.
#[test]
fn a_planted_former_key_is_found_in_a_busbar_metadata_table() {
    let toml = "[package.metadata.busbar.migration]\n\"former.x\" = \"y\"\n\
                [package.metadata.busbar.linked]\nstore-memory = \"a\"\n\
                [package.metadata.busbar.other]\n\"name_1_5_5.a\" = \"b\"\n\
                \"retired.store.redis\" = \"valkey\"\n\
                [dependencies]\n\"former.z\" = \"1\"\n";
    assert_eq!(retired_key_sites(toml), vec![1, 2, 6, 7]);
    assert!(
        retired_key_sites("[package.metadata.busbar.linked]\nstore-memory = \"a\"\n").is_empty()
    );
}

/// Red (k), planted: `RootHost` in a type, a path and a macro is found; test code is not.
#[test]
fn a_planted_root_host_is_found_and_test_code_is_not() {
    let source = "pub struct RootHost;\nfn f(_: &RootHost) {}\nfn g() { let _ = format!(\"{}\", RootHost::new()); }\n\
                  #[cfg(test)]\nmod t { fn h(_: RootHost) {} }\n";
    assert_eq!(root_host_sites(source), vec![1, 2, 3]);
    assert!(root_host_sites("fn fine() {}\n").is_empty());
}
