//! INVARIANT 1: A MODULE IS A FILE OR A FOLDER, NEVER BOTH.
//!
//! `admin.rs` beside `admin/` is the shape that makes "I'm looking for X, I know where it is" stop
//! being true: half the module is in one place and half in the other, and which half is a coin
//! flip. Rust permits it, `docs/code-layout.md` does not, and this is what says so.
//!
//! The rule runs BEFORE the corpus floor, exactly as the shell ran it before its denominator check:
//! it asks about DIRECTORY SHAPE rather than about file contents, so an empty scan set says nothing
//! about it either way, and a tree that cannot be scanned should still be told this much.

use std::collections::BTreeSet;

use crate::ctx::{Ctx, WalkSpec};
use crate::gates::structure_lint::{row, Findings};
use crate::ledger::Row;

pub const ROW_HYBRID: &str = "structure-lint:hybrid-modules";

pub fn finding(base: &str) -> String {
    format!("HYBRID: {base}.rs coexists with {base}/ — fold {base}.rs into {base}/mod.rs")
}

pub fn scan(cx: &Ctx, f: &mut Findings) {
    // The directories are derived from the walk rather than read off the filesystem, so a plant
    // that adds a file is a plant this rule can see — and a directory holding no `.rs` at any depth
    // is a directory no Rust module lives in, so it cannot be half of a hybrid.
    //
    // A WALK THAT COULD NOT RUN IS A FINDING, not an early return. This rule's whole subject is
    // directory shape, and "no hybrids found" over a walk that never happened is the false green
    // the rest of this gate spends its floors refusing.
    let files = match cx.walk(&WalkSpec::new([super::roots::CRATES]).ext("rs")) {
        Ok(files) => files,
        Err(e) => {
            f.hybrid.push(format!(
                "HYBRID-SCAN-FAILED: the module walk could not run ({e}), so this rule saw no \
                 directory shape at all"
            ));
            return;
        }
    };
    let mut dirs: BTreeSet<String> = BTreeSet::new();
    for s in &files {
        let rel = s.rel_str();
        let mut cursor = rel.as_str();
        while let Some((parent, _)) = cursor.rsplit_once('/') {
            dirs.insert(parent.to_string());
            cursor = parent;
        }
    }
    for dir in dirs {
        if cx.exists(format!("{dir}.rs")) {
            f.hybrid.push(finding(&dir));
        }
    }
}

pub fn rows(f: &Findings) -> Vec<Row> {
    vec![row(
        ROW_HYBRID,
        "no module is both a file and a folder",
        "a module is a file AND a folder, so half of it is in each",
        &f.hybrid,
    )]
}
