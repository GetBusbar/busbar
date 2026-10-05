// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// THE TEST-LINKED PLANE TABLE (SEAM-T, N02 ruling). This crate's cross-plane integration tests
// (`tests/*_cross_plane.rs` and their siblings) need the real planes installed, but "a plugin tests
// itself; the kernel never tests or names a plugin" — so their sources name no plane crate.
// `[package.metadata.busbar] test-linked = [...]` in Cargo.toml lists the linked dev-dependency
// crates as DATA; this script turns that list into `$OUT_DIR/test_linked.rs` (`extern crate X as _;`
// per crate plus one static array of each crate's `testkit::TEST_SEAM` entry), which
// `tests/linked/mod.rs` includes and loops. The tests then address each plane by what its
// declaration states (the section it owns, the fallback flag), read back from the registry. A
// `door:<crate>` row is a plane served through its memory-ABI door only: the table names its
// `plane_door::door`, and the tests fold its registry row from its Statement as the root does.
//
// The production library never includes the file: only the integration-test targets, which link
// the listed crates as dev-dependencies, do. Same generator shape as busbar-core-admin's build.rs.

use std::path::Path;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    let manifest = Path::new(&manifest_dir).join("Cargo.toml");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", manifest.display());
    let text = std::fs::read_to_string(&manifest).expect("read Cargo.toml");
    let rows = metadata_list(&text, "package.metadata.busbar", "test-linked");
    let mut code = linked_table(
        &seam_rows(&rows),
        "TEST_LINKED",
        "busbar_kernel::test_support::seam::TestPlaneSeam",
        "testkit::TEST_SEAM",
    );
    code.push_str(&door_table(&rows));
    std::fs::write(Path::new(&out_dir).join("test_linked.rs"), code).expect("write test_linked.rs");
}

/// The prefix of a `test-linked` row that is a plane served through its memory-ABI door only.
const DOOR_ROW: &str = "door:";

/// The `test-linked` rows that are linked crates with a `testkit::TEST_SEAM` entry (every row that
/// is not a [`DOOR_ROW`]).
fn seam_rows(rows: &[String]) -> Vec<String> {
    rows.iter()
        .filter(|r| !r.starts_with(DOOR_ROW))
        .cloned()
        .collect()
}

/// THE TEST-LINKED DOOR PLANES (`door:<crate>` rows): `extern crate`, then
/// `static TEST_LINKED_DOORS: &[(&str, DoorFn)]` naming each row's `<crate>::plane_door::door` (the
/// door crate's conventional path), and `static TEST_LINKED_ORDER: &[bool]`, the list's install
/// order (`false` the next `TEST_LINKED` entry, `true` the next door). The tests fold each door's
/// registry row from its Statement exactly as the composition root does
/// (`root::linked::door_rows`), so their sources name no plane crate here either.
fn door_table(rows: &[String]) -> String {
    let mut out = String::new();
    let doors: Vec<String> = rows
        .iter()
        .filter_map(|r| r.strip_prefix(DOOR_ROW))
        .map(|c| c.replace('-', "_"))
        .collect();
    for id in &doors {
        out.push_str(&format!("extern crate {id} as _;\n"));
    }
    out.push_str(
        "static TEST_LINKED_DOORS: &[(&str, ::busbar_contract::abi::mechanism::door::DoorFn)] = &[\n",
    );
    for id in &doors {
        out.push_str(&format!("    ({id:?}, {id}::plane_door::door),\n"));
    }
    out.push_str("];\nstatic TEST_LINKED_ORDER: &[bool] = &[");
    for r in rows {
        out.push_str(if r.starts_with(DOOR_ROW) {
            "true, "
        } else {
            "false, "
        });
    }
    out.push_str("];\n");
    out
}

/// The string array `key = [...]` under the `[table]` header of a Cargo manifest. Deliberately not a
/// TOML parser (a build script with no dependencies): the array may span lines, entries are
/// double-quoted crate names. An absent or empty list is a build failure, never an empty table — an
/// empty table would silently install nothing and the tests would read an empty roster.
fn metadata_list(manifest: &str, table: &str, key: &str) -> Vec<String> {
    let header = format!("[{table}]");
    let mut in_table = false;
    let mut collecting = false;
    let mut body = String::new();
    for line in manifest.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if !collecting && code.starts_with('[') {
            in_table = code == header;
            continue;
        }
        if collecting {
            body.push_str(code);
        } else if in_table {
            if let Some((k, v)) = code.split_once('=') {
                if k.trim() == key {
                    collecting = true;
                    body.push_str(v.trim());
                }
            }
        }
        if collecting && body.contains(']') {
            break;
        }
    }
    let list: Vec<String> = body
        .trim()
        .trim_start_matches('[')
        .split(']')
        .next()
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect();
    assert!(
        !list.is_empty(),
        "Cargo.toml: `{key}` under `{header}` is missing or empty"
    );
    list
}

/// `extern crate <ident> as _;` for every listed crate, then
/// `static <name>: &[<ty>] = &[<ident>::<entry>, ...];` in list order.
fn linked_table(crates: &[String], name: &str, ty: &str, entry: &str) -> String {
    let idents: Vec<String> = crates.iter().map(|c| c.replace('-', "_")).collect();
    let mut out = String::from("// @generated by build.rs from Cargo.toml metadata.\n");
    for id in &idents {
        out.push_str(&format!("extern crate {id} as _;\n"));
    }
    out.push_str(&format!("static {name}: &[{ty}] = &[\n"));
    for id in &idents {
        out.push_str(&format!("    {id}::{entry},\n"));
    }
    out.push_str("];\n");
    out
}
