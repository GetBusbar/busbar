//! THE CENSUS AND FACE READINGS OVER THE REAL TREE, one plant each (row 159, audit XC1 HIGH 2-4).
//!
//! Each test runs the rule the plant is about over the pinned mount with the plant laid on top, and
//! asks for the finding by name: a path dependency onto a crate the census never read, a
//! `[ package ]` header with spaces, a face reached through a path the reader does not follow, and
//! a door built over another kind's ops table. The selftest battery carries the same plants
//! (`cargo xtask selftest kind-isolation`); these are the ones `cargo test` runs.

use super::*;
use crate::ledger::Status;

/// The workspace as the gate reads it: the pinned checkouts mounted beneath ([`pinned`]).
fn ws() -> Ctx {
    pinned::with_pinned(&Ctx::workspace().expect("the workspace opens"))
}

/// The census exactly as [`KindIsolationGate::run`] builds it, over the pinned mount.
fn crates_of(cx: &Ctx) -> Vec<CrateInfo> {
    let mut crates = census(&pinned::with_pinned(cx)).expect("the census reads");
    let (planes, ports) = vocabularies(&crates);
    assign_instances(&mut crates, &planes, &ports);
    crates
}

fn registry_row(cx: &Ctx) -> Row {
    let crates = crates_of(cx);
    let reg = load_registry(cx).expect("the registry reads");
    rule_registry(cx, &crates, &reg, false)
}

fn faces_row(cx: &Ctx) -> Row {
    let crates = crates_of(cx);
    let reg = load_registry(cx).expect("the registry reads");
    let idx = index_sources(cx).expect("the source index reads");
    rule_faces(cx, &crates, &idx, &reg, false)
}

fn assert_red_naming(row: &Row, naming: &[&str]) {
    assert_ne!(
        row.status,
        Status::Pass,
        "{} stayed green: {}",
        row.id,
        row.detail
    );
    for n in naming {
        assert!(
            row.detail.contains(n),
            "{} did not name `{n}`: {}",
            row.id,
            row.detail
        );
    }
}

/// A plant over the transport crate's manifest: its text plus `extra`.
fn stdio_manifest_plus(cx: &Ctx, extra: &str) -> String {
    let rel = "crates/busbar-transport-stdio/Cargo.toml";
    format!("{}{extra}", cx.read(rel).expect("the stdio manifest reads"))
}

#[test]
fn a_path_dependency_onto_a_crate_the_census_never_read_is_refused() {
    let cx = ws();
    assert!(
        !registry_row(&cx).detail.contains("unread-path-dep"),
        "the real tree path-depends only on crates of the census"
    );
    let mut ov = Overlay::new();
    ov.set(
        ".vendor/busbar-plane-shadow/Cargo.toml",
        "[package]\nname = \"busbar-plane-shadow\"\nversion = \"0.0.0\"\n",
    );
    ov.set(
        "crates/busbar-transport-stdio/Cargo.toml",
        stdio_manifest_plus(
            &cx,
            "\n[dependencies]\nbusbar-plane-shadow = { path = \"../../.vendor/busbar-plane-shadow\" }\n",
        ),
    );
    assert_red_naming(
        &registry_row(&cx.with_overlay(ov)),
        &[
            "unread-path-dep",
            ".vendor/busbar-plane-shadow",
            "busbar-transport-stdio",
        ],
    );
}

#[test]
fn a_spaced_or_quoted_package_header_names_its_crate() {
    assert!(is_package_header("[package]"));
    assert!(is_package_header("[ package ]"));
    assert!(is_package_header("[\"package\"]"));
    assert!(!is_package_header("[[package]]"));
    assert!(!is_package_header("[package.metadata]"));
    let cx = ws();
    let mut ov = Overlay::new();
    ov.set(
        "vendor/busbar-plane-spaced/Cargo.toml",
        "[ package ]\nname = \"busbar-plane-spaced\"\nversion = \"0.0.0\"\n",
    );
    assert_red_naming(
        &registry_row(&cx.with_overlay(ov)),
        &["off-tree-crate", "vendor/busbar-plane-spaced"],
    );
}

#[test]
fn a_face_reached_through_a_reexport_super_or_a_renamed_contract_is_the_face() {
    let cx = ws();
    let mut ov = Overlay::new();
    ov.set(
        "crates/busbar-transport-stdio/src/planted_reexported.rs",
        "use crate::Plane;\npub struct WireR;\nimpl Plane for WireR {}\n\
         pub struct WireS;\nimpl super::Plane for WireS {}\n\
         pub struct WireC;\nimpl contract::plane::Plane for WireC {}\n",
    );
    assert_red_naming(
        &faces_row(&cx.with_overlay(ov)),
        &[
            "foreign-entry",
            "busbar-transport-stdio",
            "`Plane` 3 time(s)",
        ],
    );
}

#[test]
fn a_plane_building_another_kinds_door_is_a_foreign_entry() {
    let cx = ws();
    let mut ov = Overlay::new();
    ov.set(
        "crates/busbar-plane-llm/src/planted_wire_door.rs",
        "use busbar_contract::abi::transport as wire;\n\
         busbar_contract::plugin_door! {\n    ops: wire::Ops,\n    \
         statement: busbar_contract::abi::sdk::door::statement(\"wire\", \"1.0.0\", 64),\n    \
         lifecycle: life(Wire),\n    kind_ops: { send: Send },\n}\n",
    );
    ov.set(
        "crates/busbar-plane-llm/src/planted_store_door.rs",
        "busbar_contract::store_door! {\n    store: Kept,\n}\n",
    );
    assert_red_naming(
        &faces_row(&cx.with_overlay(ov)),
        &[
            "foreign-entry",
            "busbar-plane-llm",
            "`Transport` 1 time(s)",
            "`Store` 1 time(s)",
        ],
    );
}

#[test]
fn naming_another_kinds_abi_without_building_its_door_is_no_face() {
    let text = "use busbar_contract::abi::transport::{FAULT_NONE, Ops};\n\
                pub const KEEP: u32 = FAULT_NONE;\n\
                pub fn width() -> usize { core::mem::size_of::<Ops>() }\n\
                pub struct Held { kind_ops: u8 }\n";
    assert!(built_door_kinds(text).is_empty());
    let built = "use busbar_contract::abi::secret::Ops as Table;\n\
                 busbar_contract::plugin_door! { ops: Table, }\nbusbar_contract::hook_door! {}\n";
    assert_eq!(built_door_kinds(built), vec!["secret", "hooks"]);
}

#[test]
fn a_kind_whose_door_table_the_contract_no_longer_defines_is_refused() {
    let cx = ws();
    let wire_abi = "crates/busbar-contract/src/abi/transport/mod.rs";
    let mut ov = Overlay::new();
    ov.set(
        wire_abi,
        cx.read(wire_abi)
            .expect("the transport ABI reads")
            .replace("pub struct Ops {", "pub struct OpsMoved {"),
    );
    assert_red_naming(
        &faces_row(&cx.with_overlay(ov)),
        &["face-door-gone", "transport"],
    );
}
