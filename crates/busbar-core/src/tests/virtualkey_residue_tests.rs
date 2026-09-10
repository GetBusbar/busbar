// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! How much of the legacy key is still in here, as a number that may only go down.
//!
//! Owner ruling 13:0x (6): the enforced key's one shape for 1.6.0 is `ResolvedKey` in
//! the auth unit, and `VirtualKey` **dies with this crate**. That is a deliberate decision not
//! to migrate these call sites: they are the retiring 1.5.5 engine's, they will be deleted rather
//! than moved, and touching them would be churn against code with a deletion date.
//!
//! A decision like that needs a number attached, or "it dies with core" becomes the reason nothing
//! ever shrinks. So the residue is COUNTED, and the count is a ratchet: it may fall as the engine
//! empties and it may not rise. A new reader of the legacy key added to this crate is a new thing
//! the deletion has to move, and it should have to argue for itself.
//!
//! ## Why this counts text rather than types
//!
//! Because what is being measured is how much WORK the deletion is, and that is a property of the
//! source rather than of the type graph: a mention in a doc comment naming the type is one more
//! place a reader will look for it after it is gone, and a `use` line is one more edit. The count
//! is therefore honest about being an upper bound on references and not a count of enforcement
//! sites — the census in `docs/design/1.6.0-virtualkey-reader-table.md` is where the enforcement
//! sites are named one by one.

use std::path::{Path, PathBuf};

/// The residue as of the ResolvedKey cut, split the way the deletion will meet it.
///
/// PRODUCTION is what has to be replaced. TESTS is what can simply be deleted alongside it, which
/// is why the two are ratcheted separately rather than summed: a cut that moves ten production
/// readers and leaves thirty test mentions behind is real progress, and one number would hide it.
const PRODUCTION_CEILING: usize = 96;
const TEST_CEILING: usize = 173;

/// Every `.rs` file under this crate's `src/`.
fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Whether a path is test code by the tree's own classification: a `tests/` directory, or the
/// `test_support` module that exists only to build fixtures.
fn is_test_path(path: &Path) -> bool {
    path.components().any(|c| {
        let s = c.as_os_str().to_string_lossy();
        s == "tests" || s == "test_support"
    })
}

fn residue() -> (usize, usize) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&root, &mut files);
    assert!(
        files.len() > 50,
        "the source walk found only {} files under {}; it is not measuring this crate",
        files.len(),
        root.display()
    );
    let mut production = 0usize;
    let mut tests = 0usize;
    for path in &files {
        // This file is not part of the residue it measures. Counting itself would make every
        // sentence written here cost a line of the budget, which would push a maintainer towards
        // saying less about the rule rather than more.
        if path
            .file_name()
            .is_some_and(|f| f == "virtualkey_residue_tests.rs")
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let n = text.matches("VirtualKey").count();
        if n == 0 {
            continue;
        }
        if is_test_path(path) {
            tests += n;
        } else {
            production += n;
        }
    }
    (production, tests)
}

#[test]
fn the_legacy_keys_residue_in_this_crate_only_shrinks() {
    let (production, tests) = residue();
    assert!(
        production <= PRODUCTION_CEILING,
        "busbar-core now names `VirtualKey` {production} times in production source, up from \
         {PRODUCTION_CEILING}. The legacy key dies with this crate (owner ruling 13:0x (6)) and \
         the enforced key's one shape is the auth unit's `ResolvedKey`. A NEW production reader \
         here is one more thing the deletion has to move: add it to `ResolvedKey` instead, or \
         argue for it and re-ratchet this number."
    );
    assert!(
        tests <= TEST_CEILING,
        "busbar-core's tests now name `VirtualKey` {tests} times, up from {TEST_CEILING}. These \
         are deleted with the crate rather than migrated, so the number is cheap to hold — but it \
         is held, because a battery written against the legacy key is a battery that will have to \
         be rewritten to prove anything about the shape that replaces it."
    );
}

#[test]
fn the_residue_ratchet_is_measuring_something() {
    // A ratchet that measured zero would pass forever. The count is asserted NON-ZERO from the
    // other side, so the day the engine actually empties, this test fails and says so rather than
    // going quietly green on a rule that has stopped applying.
    let (production, tests) = residue();
    assert!(
        production > 0 || tests > 0,
        "busbar-core no longer names `VirtualKey` anywhere. The retirement this ratchet was \
         watching is DONE: delete this file, and with it the last thing holding the number."
    );
}
