// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::super::repo_root;
use super::{allow_entries, covers, manifest_uses, no_serde_json, rust_uses};

/// The real tree (#162, DEP-3): outside the wave-3 allowlist no first-party file names serde_json,
/// and every allowlist line still covers a file that does.
#[test]
fn no_first_party_code_names_serde_json_outside_the_wave_3_list() {
    let findings = no_serde_json(&repo_root()).expect("the trees scan");
    assert!(findings.is_empty(), "{}", findings.join("\n"));
}

#[test]
fn code_uses_are_found_and_comments_and_literals_are_not() {
    let source = r#"
//! serde_json in a module doc
use serde_json::Value;
// serde_json::json! in a comment
/// serde_json in an item doc
const KEY: &str = "$serde_json::private::Number";
fn f() -> String {
    let raw = r"serde_json::to_string";
    format!("{}", ::serde_json::json!({ "k": raw }))
}
"#;
    assert_eq!(rust_uses(source), [3, 9]);
}

#[test]
fn an_unlexable_file_is_scanned_by_line() {
    let source = "fn broken( {\n    serde_json::to_vec(&1);\n// serde_json\n";
    assert_eq!(rust_uses(source), [2]);
}

#[test]
fn manifest_rows_are_found() {
    let manifest = r#"[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
serde_json_canonicalizer = "0.4"
serde_json.workspace = true

[dev-dependencies.serde_json]
version = "1"
"#;
    assert_eq!(manifest_uses(manifest), [3, 5, 7]);
}

#[test]
fn allowlist_entries_cover_files_and_directories() {
    let entries =
        allow_entries("# wave 3\ncrates/a/src/abi/   # W3-D-CONTRACT\n\ncrates/b/src/x.rs\n");
    assert_eq!(entries, ["crates/a/src/abi/", "crates/b/src/x.rs"]);
    assert!(covers(&entries[0], "crates/a/src/abi/sdk/mod.rs"));
    assert!(!covers(&entries[0], "crates/a/src/abix.rs"));
    assert!(covers(&entries[1], "crates/b/src/x.rs"));
    assert!(!covers(&entries[1], "crates/b/src/x.rs.bak"));
}
