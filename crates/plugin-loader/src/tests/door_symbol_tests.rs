// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **NO RLIB THE TEST BINARY LINKS EXPORTS `busbar_plugin_door`.** A `-plugin` crate is
//! `crate-type = ["cdylib", "rlib"]` and its `export_door!` line is unconditional, so its rlib
//! carries the one unmangled symbol too. Linking one into the loader's test binary is harmless
//! until fat LTO merges the bitcode of two doors ("symbol multiply defined"), which is how the
//! release leg of the both-ways suites failed to link.
//!
//! Every both-ways row names its plugin repo's LOGIC crate, and the loader holds a row's `-plugin`
//! crate as a dev-dependency ONLY so cargo builds its cdylib. That is safe exactly while nothing
//! NAMES the `-plugin` crate (rustc does not link an unnamed `--extern`). These tests are the
//! guard, over EVERY row of the table, not one kind's: no row names a `-plugin` crate, the
//! generated table's cdylib column is the row's logic crate plus `_plugin`, and no source of this
//! crate nor the table `build.rs` generates names any row's `-plugin` crate. The real proof is the
//! release profile with LTO on linking at all.

use std::path::Path;

/// The suffix of a plugin repo's packaging crate, in snake case.
const PACKAGING_SUFFIX: &str = "_plugin";

/// Every `(row, crate)` of `Cargo.toml`'s `[package.metadata.busbar.both-ways]`, the crate in snake
/// case, read from the manifest itself rather than from the table `build.rs` derives from it.
fn rows() -> Vec<(String, String)> {
    let manifest = include_str!("../../Cargo.toml");
    let mut in_table = false;
    let mut out = Vec::new();
    for line in manifest.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.starts_with('[') {
            in_table = code == "[package.metadata.busbar.both-ways]";
            continue;
        }
        if let (true, Some((row, krate))) = (in_table, code.split_once('=')) {
            out.push((
                row.trim().trim_matches('"').to_string(),
                krate.trim().trim_matches('"').replace('-', "_"),
            ));
        }
    }
    out
}

/// The packaging crate of every row: the row's crate itself when it names one, else its
/// `-plugin` twin.
fn packaging_crates() -> Vec<String> {
    rows()
        .into_iter()
        .map(|(_, krate)| {
            if krate.ends_with(PACKAGING_SUFFIX) {
                krate
            } else {
                format!("{krate}{PACKAGING_SUFFIX}")
            }
        })
        .collect()
}

/// Whether `line` names `krate` by a path or a `use`.
fn names(line: &str, krate: &str) -> bool {
    line.contains(&format!("{krate}::")) || line.contains(&format!("::{krate} "))
}

fn sources(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).expect("read dir").flatten() {
        let p = e.path();
        if p.is_dir() {
            sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn every_both_ways_row_names_its_logic_crate_never_a_packaging_crate() {
    let rows = rows();
    assert!(!rows.is_empty(), "the both-ways table has rows to guard");
    for (row, krate) in &rows {
        assert!(
            !krate.ends_with(PACKAGING_SUFFIX),
            "both-ways row `{row}` names the packaging crate {krate}: its rlib exports \
             busbar_plugin_door, so the row names the logic crate and the cdylib is derived"
        );
    }
    for &(row, logic, cdylib) in crate::both_ways::FIXTURES {
        assert_eq!(
            cdylib,
            format!("{logic}{PACKAGING_SUFFIX}"),
            "the `{row}` row's cdylib is its logic crate's packaging crate"
        );
    }
}

#[test]
fn nothing_names_a_packaging_crates_rlib_so_none_is_linked() {
    let packaging = packaging_crates();
    assert!(!packaging.is_empty(), "the table has a row to guard");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    sources(&root.join("src"), &mut files);
    sources(&root.join("tests"), &mut files);
    let generated = std::fs::read_to_string(concat!(env!("OUT_DIR"), "/both_ways.rs"))
        .expect("the generated table");
    let this = file!();
    for krate in &packaging {
        // `use ::<crate>` / `<crate>::path`: a name that links it. Comments may mention it.
        let uses = |text: &str| {
            text.lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .any(|l| names(l, krate))
        };
        assert!(!uses(&generated), "both_ways.rs names {krate}");
        for f in &files {
            if f.ends_with(Path::new(this).file_name().expect("name")) {
                continue;
            }
            let text = std::fs::read_to_string(f).expect("read");
            assert!(
                !uses(&text),
                "{} names {krate}: its rlib exports busbar_plugin_door and would link",
                f.display()
            );
        }
    }
}

/// THE RED ARM, KEPT: the matcher the guard uses refuses the line that would link the crate.
#[test]
fn the_guard_sees_a_line_that_names_the_crate() {
    let krate = packaging_crates().remove(0);
    assert!(names(
        &format!("pub(crate) use ::{krate} as alias;"),
        &krate
    ));
    assert!(names(&format!("let d = {krate}::door;"), &krate));
    assert!(!names("let d = something_else::door;", &krate));
}
