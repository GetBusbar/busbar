// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The take-site count the documentation states, against the kernel's own source (items 315, 320,
//! 326). The construction gate's `seal-sites` rule CONFINES the take's literal spelling to the
//! kernel; it does not count, and a take through a named grant does not spell the literal. This
//! counts every `.take(&` on a code line of the kernel's non-test source — the cell's take is the
//! only method there that borrows its argument — and holds the sentences that name the count to it.

use std::path::{Path, PathBuf};

const WORDS: [&str; 7] = ["zero", "one", "two", "three", "four", "five", "six"];

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("the kernel's source is readable at {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("a directory entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if path.is_dir() {
            if name != "tests" && name != "test_support" {
                rs_files(&path, out);
            }
        } else if name.ends_with(".rs") && name != "tests.rs" && !name.ends_with("_tests.rs") {
            out.push(path);
        }
    }
}

fn kernel_take_sites() -> Vec<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../busbar-kernel/src");
    let mut files = Vec::new();
    rs_files(&root, &mut files);
    assert!(files.len() > 10, "the walk found the kernel's source");
    let mut sites = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("a readable source file");
        for (i, line) in text.lines().enumerate() {
            if !line.trim_start().starts_with("//") && line.contains(".take(&") {
                sites.push(format!("{}:{}", file.display(), i + 1));
            }
        }
    }
    sites
}

#[test]
fn the_documented_take_site_count_is_the_kernels() {
    let sites = kernel_take_sites();
    let word = WORDS
        .get(sites.len())
        .unwrap_or_else(|| panic!("more take sites than this census has words for: {sites:?}"));
    let hold = include_str!("../hold.rs");
    assert_eq!(
        hold.matches(&format!("Exactly {word} take sites")).count()
            + hold.matches(&format!("exactly {word} take sites")).count(),
        2,
        "hold.rs's module doc and `HoldCell::take`'s doc both state the kernel's {} take \
         sites: {sites:?}",
        sites.len()
    );
    assert!(
        include_str!("../mod.rs").contains(&format!("at exactly {word} sites")),
        "the crate's honesty table states the kernel's {} take sites: {sites:?}",
        sites.len()
    );
}
