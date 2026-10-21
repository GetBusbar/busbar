// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **NO RLIB THE TEST BINARY LINKS EXPORTS `busbar_plugin_door`.** A `-plugin` crate is
//! `crate-type = ["cdylib", "rlib"]` and its `export_door!` line is unconditional, so its rlib
//! carries the one unmangled symbol too. Linking one into the loader's test binary is harmless
//! until fat LTO merges the bitcode of two doors ("symbol multiply defined"), which is how the
//! release leg of the both-ways suites failed to link.
//!
//! The loader holds a both-ways row's `-plugin` crate as a dev-dependency ONLY so cargo builds its
//! cdylib; the linked door comes from the row's logic crate. That is safe exactly while nothing
//! NAMES a `-plugin` crate (rustc does not link an unnamed `--extern`). This test is the guard, for
//! EVERY row of every kind: no source of this crate names a row's `-plugin` crate, and the table
//! `build.rs` generates names none either. The real proof is the release profile with LTO on
//! linking at all.

use std::path::Path;

/// The `-plugin` crate of every both-ways row, read off the manifest independently of `build.rs`:
/// the row's crate with its `-plugin` suffix, whether the row named the logic crate or the twin.
fn twin_crates() -> Vec<String> {
    let manifest = include_str!("../../Cargo.toml");
    let mut in_table = false;
    let mut out = Vec::new();
    for line in manifest.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.starts_with('[') {
            in_table = code == "[package.metadata.busbar.both-ways]";
            continue;
        }
        if let (true, Some((_, krate))) = (in_table, code.split_once('=')) {
            let krate = krate.trim().trim_matches('"');
            let logic = krate.strip_suffix("-plugin").unwrap_or(krate);
            out.push(format!("{logic}_plugin").replace('-', "_"));
        }
    }
    out
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
fn nothing_names_a_fixtures_plugin_rlib_so_none_is_linked() {
    let twins = twin_crates();
    assert_eq!(
        twins.len(),
        crate::both_ways::BOTH_WAYS_ROWS.len(),
        "every row of the table is guarded"
    );
    for (row, logic, _) in crate::both_ways::BOTH_WAYS_ROWS {
        assert!(
            !logic.ends_with("_plugin"),
            "row `{row}` links {logic}, a `-plugin` crate"
        );
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    sources(&root.join("src"), &mut files);
    sources(&root.join("tests"), &mut files);
    let generated = std::fs::read_to_string(concat!(env!("OUT_DIR"), "/both_ways.rs"))
        .expect("the generated table");
    let this = file!();
    for krate in &twins {
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
    let krate = twin_crates().remove(0);
    assert!(names(
        &format!("pub(crate) use ::{krate} as alias;"),
        &krate
    ));
    assert!(names(&format!("let d = {krate}::door;"), &krate));
    assert!(!names("let d = something_else::door;", &krate));
}
