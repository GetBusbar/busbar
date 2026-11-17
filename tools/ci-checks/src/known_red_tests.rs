// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `no-known-red`: a failing fixture the check must find, a passing one it must not, and the real tree.

use std::path::PathBuf;

use super::known_red::{no_known_red, KNOWN_RED_DIR};
use super::repo_root;

/// A fresh scratch tree under the system temp directory, removed first if a previous run left it.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("busbar-known-red-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch tree");
    dir
}

#[test]
fn a_tree_without_the_directory_is_clean() {
    let root = scratch("absent");
    std::fs::create_dir_all(root.join("ci")).expect("ci dir");
    assert_eq!(no_known_red(&root), Ok(Vec::new()));
}

#[test]
fn every_list_in_the_directory_is_a_finding() {
    let root = scratch("lists");
    let dir = root.join(KNOWN_RED_DIR);
    std::fs::create_dir_all(&dir).expect("known-red dir");
    std::fs::write(
        dir.join("core-default.txt"),
        "a::b\tCDT-KNOWN-RED\tstable\n",
    )
    .expect("list");
    std::fs::write(dir.join("plugin.txt"), "").expect("list");
    let findings = no_known_red(&root).expect("the tree reads");
    assert_eq!(findings.len(), 2, "{findings:?}");
    assert!(
        findings[0].starts_with("ci/known-red/core-default.txt: "),
        "{findings:?}"
    );
    assert!(
        findings[1].starts_with("ci/known-red/plugin.txt: "),
        "{findings:?}"
    );
    assert!(findings.iter().all(|f| f.contains("TST-8")), "{findings:?}");
}

#[test]
fn an_empty_directory_is_still_a_finding() {
    let root = scratch("empty");
    std::fs::create_dir_all(root.join(KNOWN_RED_DIR)).expect("known-red dir");
    let findings = no_known_red(&root).expect("the tree reads");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].starts_with("ci/known-red: "), "{findings:?}");
}

/// The real tree holds no known-red list.
#[test]
fn the_real_tree_has_no_known_red_list() {
    let found = no_known_red(&repo_root()).expect("the tree reads");
    assert!(found.is_empty(), "{}", found.join("\n"));
}
