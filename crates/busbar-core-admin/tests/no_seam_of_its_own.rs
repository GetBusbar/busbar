// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ADMIN CRATE HOLDS NO SEAM OF ITS OWN (R6, BUSBAR-1.6.0.md l.1472-1476: the door-only gate
//! "exempts EXACTLY their two `OnceLock` seams (`oauth_as/seam.rs`, `admin/seam.rs`)"; l.1558:
//! "add no new kernel `OnceLock` seam beyond the two R6 exempts").
//!
//! This crate's one seam is the kernel's `admin/seam.rs`, which its [`busbar_core_admin::install`]
//! fills. Anything else the composition root hands it rides that seam or the root's install record
//! the kernel already holds — never a static of this crate's that the root fills by name. A scan
//! over the crate's shipped source (tests excluded) fails, naming `file:line`, on:
//!
//! * (a) a public installer other than `install` itself (`pub fn install_<x>(`);
//! * (b) a `static` holding a borrowed, installed value (`OnceLock<&'static ...>`).
//!
//! Comments are skipped, so prose that names these shapes is not a finding.

use std::path::{Path, PathBuf};

/// A shipped-source line's verdict: which rule it breaks, if any.
fn offends(line: &str) -> Option<&'static str> {
    let code = line.trim_start();
    if code.starts_with("//") {
        return None;
    }
    if code.contains("pub fn install_") {
        return Some("(a) an installer of the crate's own");
    }
    if code.contains("static ") && code.contains("OnceLock<&'static") {
        return Some("(b) a static the root fills");
    }
    None
}

/// Shipped source, as opposed to a fixture or a test.
fn is_shipped_source(path: &Path) -> bool {
    let rel = path.to_string_lossy().replace('\\', "/");
    !rel.contains("/tests/")
        && !rel.ends_with("/tests.rs")
        && !rel.ends_with("_test.rs")
        && !rel.ends_with("_tests.rs")
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("the crate's src tree is readable") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            walk(&path, files);
        } else if path.extension().is_some_and(|e| e == "rs") {
            files.push(path);
        }
    }
}

/// RED while the usage read's dated-history static and the compiled-in hook list's static were
/// this crate's, each with a public installer the composition root called by name.
#[test]
fn the_admin_crate_holds_no_seam_of_its_own() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk(&src, &mut files);
    let shipped: Vec<&PathBuf> = files.iter().filter(|p| is_shipped_source(p)).collect();
    // The walk reached the crate: the file that fills the kernel's admin seam is among them.
    assert!(
        shipped.iter().any(|p| p.ends_with("src/lib.rs")),
        "the scan never reached the crate's shipped source: {shipped:?}"
    );
    let mut offenders = Vec::new();
    for path in shipped {
        let text = std::fs::read_to_string(path).expect("a source file reads");
        for (n, line) in text.lines().enumerate() {
            if let Some(rule) = offends(line) {
                offenders.push(format!(
                    "{}:{}: {rule}: {}",
                    path.display(),
                    n + 1,
                    line.trim()
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "the admin crate holds a seam beyond the kernel's admin seam (R6): {offenders:#?}"
    );
}

/// The scan is a filter and not a wall: it sees each shape it forbids, and it does not see the
/// crate's one installer, its private caches, or prose.
#[test]
fn the_seam_scan_sees_what_it_forbids_and_nothing_else() {
    assert!(offends("pub fn install_usage_rate_history(source: &'static dyn X) {").is_some());
    assert!(offends("pub fn install_hook_plugins(names: &'static [&'static str]) {").is_some());
    // An operation of the service's that installs a plugin is not a seam.
    assert!(offends("    pub(crate) fn install_store_plugin(").is_none());
    assert!(
        offends("static HOOKS: OnceLock<&'static [&'static str]> = OnceLock::new();").is_some()
    );
    assert!(offends("pub fn install() {").is_none());
    assert!(
        offends("static CACHE: OnceLock<Mutex<HashMap<PathBuf, Entry>>> = OnceLock::new();")
            .is_none()
    );
    assert!(offends("/// pub fn install_x() is what this rule forbids").is_none());
}
