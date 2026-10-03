// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **NO RLIB THE TEST BINARY LINKS EXPORTS `busbar_plugin_door`.** A `-plugin` crate is
//! `crate-type = ["cdylib", "rlib"]` and its `export_door!` line is unconditional, so its rlib
//! carries the one unmangled symbol too. Linking one into the loader's test binary is harmless
//! until fat LTO merges the bitcode of two doors ("symbol multiply defined"), which is how the
//! release leg of the both-ways suites failed to link.
//!
//! The loader holds a hot kind's `-plugin` crate as a dev-dependency ONLY so cargo builds its
//! cdylib. That is safe exactly while nothing NAMES the crate (rustc does not link an unnamed
//! `--extern`). This test is the guard: no source of this crate names a hot both-ways row's crate,
//! and the table `build.rs` generates names none either. The real proof is the release profile
//! with LTO on linking at all.

use std::path::Path;

const HOT_KINDS: &[&str] = &["plane", "transport"];

fn hot_crates() -> Vec<String> {
    let manifest = include_str!("../../Cargo.toml");
    let mut in_table = false;
    let mut out = Vec::new();
    for line in manifest.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.starts_with('[') {
            in_table = code == "[package.metadata.busbar.both-ways]";
            continue;
        }
        if let (true, Some((kind, krate))) = (in_table, code.split_once('=')) {
            if HOT_KINDS.contains(&kind.trim().trim_matches('"')) {
                out.push(krate.trim().trim_matches('"').replace('-', "_"));
            }
        }
    }
    out
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
fn nothing_names_a_hot_fixtures_rlib_so_none_is_linked() {
    let hot = hot_crates();
    assert!(!hot.is_empty(), "the table has a hot row to guard");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    sources(&root.join("src"), &mut files);
    sources(&root.join("tests"), &mut files);
    let generated = std::fs::read_to_string(concat!(env!("OUT_DIR"), "/both_ways.rs"))
        .expect("the generated table");
    let this = file!();
    for krate in &hot {
        // `use ::<crate>` / `<crate>::path`: a name that links it. Comments may mention it.
        let uses = |text: &str| {
            text.lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .any(|l| l.contains(&format!("{krate}::")) || l.contains(&format!("::{krate} ")))
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
    let krate = "busbar_transport_tcp_plugin";
    let uses = |l: &str| l.contains(&format!("{krate}::")) || l.contains(&format!("::{krate} "));
    assert!(uses(
        "pub(crate) use ::busbar_transport_tcp_plugin as transport_fixture;"
    ));
    assert!(uses("let d = busbar_transport_tcp_plugin::door;"));
    assert!(!uses("let d = something_else::door;"));
}
