// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COMPOSITION ROOT NAMES NO LINKED PLUGIN (K1, #2 rule (1)).
//!
//! Which plugins a build links is DATA: the `[package.metadata.busbar.linked]`,
//! `[package.metadata.busbar.linked-entry]` and `[package.metadata.busbar.root-units]` tables of this
//! crate's manifest. `build.rs` turns them into the tables `main.rs` includes, and the registration
//! path in `src/root/linked.rs` folds every entry the same way whether it was linked in or dropped
//! in. So `main.rs` has no reason to spell a plugin crate or a root unit module, and a spelling there
//! is a registration that bypassed the one path — a plugin wired by name, which the next plugin
//! would have to copy.
//!
//! The names are read from the manifest, never listed here: a crate added to the table tomorrow is
//! judged the day it lands. Comments are not code and are skipped; string literals are kept, so a
//! name smuggled through a literal still counts.

use std::path::Path;

/// The manifest reader `build.rs` generates the tables with, so the names judged here are the names
/// the tables were generated from.
#[allow(dead_code)]
mod generator {
    include!("../src/linked_gen.rs");
}
use generator::{ident, linked_source, metadata_map};

/// Every name the manifest's linked tables list, in each spelling code could use it by: a linked
/// crate as its identifier and as its package name, a root unit module by its module name, and an
/// entry path's module.
fn listed_names(manifest: &str) -> Vec<String> {
    let mut names = Vec::new();
    for (_, krate) in metadata_map(manifest, "package.metadata.busbar.linked") {
        names.push(ident(&krate));
        names.push(krate);
    }
    for (_, module) in metadata_map(manifest, "package.metadata.busbar.root-units") {
        names.push(module);
    }
    for (_, path) in metadata_map(manifest, "package.metadata.busbar.linked-entry") {
        // `crate::root::<module>` — the module is the name.
        if let Some(module) = path.rsplit("::").next() {
            names.push(module.to_string());
        }
    }
    names.sort();
    names.dedup();
    names
}

/// `src` with every line and block comment blanked, string and char literals kept.
fn code_only(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
            i += 2;
            while i < b.len() && !(b[i] == b'*' && b.get(i + 1) == Some(&b'/')) {
                if b[i] == b'\n' {
                    out.push('\n');
                }
                i += 1;
            }
            i += 2;
        } else if b[i] == b'"' {
            let start = i;
            i += 1;
            while i < b.len() && b[i] != b'"' {
                if b[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
            out.push_str(&src[start..i.min(b.len())]);
        } else {
            let ch = src[i..].chars().next().expect("a char boundary");
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// Every `(line, name)` where `name` stands as a whole word in `code`. A word boundary is anything
/// but an identifier character or `-` (so `busbar-foo` is not found inside `busbar-foo-bar`).
fn named(code: &str, names: &[String]) -> Vec<(usize, String)> {
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b'-';
    let mut hits = Vec::new();
    for (no, line) in code.lines().enumerate() {
        for name in names {
            for (at, _) in line.match_indices(name.as_str()) {
                let before = at.checked_sub(1).map(|p| line.as_bytes()[p]);
                let after = line.as_bytes().get(at + name.len()).copied();
                if !before.is_some_and(word) && !after.is_some_and(word) {
                    hits.push((no + 1, name.clone()));
                }
            }
        }
    }
    hits
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
        .unwrap_or_else(|e| panic!("{rel}: {e}"))
}

#[test]
fn main_rs_names_no_crate_or_root_unit_the_linked_tables_list() {
    let manifest = read("Cargo.toml");
    let names = listed_names(&manifest);
    // NON-VACUITY: the tables list the plugins the default build links, and main.rs is the file that
    // includes what they generate. A scan over no names, or over a root that registers through
    // something else, would pass everything.
    assert!(
        names.len() >= 10,
        "the linked tables list only {names:?} — a scan over (almost) nothing proves nothing"
    );
    let main = read("src/main.rs");
    assert!(
        main.contains(r#"include!(concat!(env!("OUT_DIR"), "/linked.rs"));"#),
        "main.rs does not include the generated linked tables, so it registers through something else"
    );

    let hits = named(&code_only(&main), &names);
    assert!(
        hits.is_empty(),
        "crates/busbar/src/main.rs names what the manifest's linked tables list — register it through \
         the generated table instead: {hits:?}"
    );
}

/// The instrument, on text it must and must not catch: a name as a path segment, a package name and
/// a literal are caught; a comment, a longer identifier and a longer package name are not.
#[test]
fn the_scan_catches_a_listed_name_and_nothing_else() {
    let manifest = read("Cargo.toml");
    let names = listed_names(&manifest);
    let (krate, id) = metadata_map(&manifest, "package.metadata.busbar.linked")
        .into_iter()
        .map(|(_, k)| (k.clone(), ident(&k)))
        .next()
        .expect("a linked row");
    for planted in [
        format!("fn f() {{ let _ = {id}::LINKED; }}"),
        format!("use {id};"),
        format!("const S: &str = \"{krate}\";"),
    ] {
        assert!(
            !named(&code_only(&planted), &names).is_empty(),
            "missed: {planted}"
        );
    }
    for clean in [
        format!("// {id}::LINKED"),
        format!("/* {id} */ fn f() {{}}"),
        format!("fn {id}_twin() {{}}"),
        format!("const S: &str = \"{krate}-twin\";"),
    ] {
        assert!(
            named(&code_only(&clean), &names).is_empty(),
            "false hit: {clean}"
        );
    }
}

/// The generator itself, over a synthetic manifest: only ENABLED rows are emitted, in manifest order,
/// each on exactly the axes its row lists, an entry override replaces `<crate>::linked`, a seam axis
/// becomes a cfg, and a row whose feature the manifest does not declare — or a crate with no axes
/// row, or an unknown axis — is refused rather than silently dropped from every build.
#[test]
fn the_generator_emits_the_enabled_rows_in_manifest_order() {
    let manifest = r#"
[features]
one = []
two = []
three = []
unit-a = []
unit-b = []

[package.metadata.busbar.linked]
one = "busbar-first"
two = "busbar-second"
three = "busbar-third"

[package.metadata.busbar.linked-axes]
one = "plane protocols"
two = "plane egress"
three = "plane diagnostics egress"

[package.metadata.busbar.linked-entry]
busbar-third = "crate::root::third_half"

[package.metadata.busbar.root-units]
unit-a = "alpha"
unit-b = "beta"
"#;
    let enabled = |f: &str| matches!(f, "one" | "three" | "unit-b");
    let (out, cfgs) = linked_source(manifest, &enabled);
    let first = out
        .find("extern crate busbar_first as _;")
        .expect("the first row");
    let third = out
        .find("extern crate busbar_third as _;")
        .expect("the third row");
    assert!(first < third, "manifest order: {out}");
    assert!(
        !out.contains("busbar_second"),
        "a disabled row is emitted: {out}"
    );
    assert!(out.contains("PlaneDecl; 2] = ["), "two plane rows: {out}");
    assert!(out.contains("assemble(crate::root::third_half::PLANE_DECLARATION, crate::root::third_half::PLANE_HOOKS)"));
    assert!(out.contains("    protocols: &[busbar_first::linked::PROTOCOLS, ],\n"));
    assert!(out.contains("    diagnostics: &[crate::root::third_half::DIAGNOSTICS, ],\n"));
    assert!(
        out.contains("    stdio_serve: &[],\n"),
        "an axis nobody lists is empty: {out}"
    );
    assert!(out.contains("    &crate::root::beta::ROOT_UNIT,\n];"));
    assert!(
        !out.contains("alpha"),
        "a disabled root unit is emitted: {out}"
    );
    assert_eq!(
        cfgs,
        vec!["linked_egress"],
        "only the seam an ENABLED entry drives"
    );

    for broken in [
        manifest.replace("three = []\n", ""),
        manifest.replace("three = \"plane diagnostics egress\"\n", ""),
        manifest.replace("plane diagnostics egress", "plane diagnostics teleport"),
    ] {
        let refused = std::panic::catch_unwind(|| linked_source(&broken, &enabled));
        assert!(refused.is_err(), "must be refused:\n{broken}");
    }
}
