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
    include!("../../../crates/busbar/src/linked_gen.rs");
}
use generator::linked_source;

fn read(rel: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
        .unwrap_or_else(|e| panic!("{rel}: {e}"))
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
four = []
unit-a = []
unit-b = []

[package.metadata.busbar.linked]
one = "busbar-first"
two = "busbar-second"
three = "busbar-third"
four = "busbar-fourth"

[package.metadata.busbar.linked-axes]
one = "plane protocols"
two = "plane egress"
three = "plane diagnostics egress"
four = "plane-door"

[package.metadata.busbar.linked-entry]
busbar-third = "crate::root::third_half"

[package.metadata.busbar.root-units]
unit-a = "alpha"
unit-b = "beta"
"#;
    let enabled = |f: &str| matches!(f, "one" | "three" | "four" | "unit-b");
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
        out.contains("    plane_doors: &[busbar_fourth::linked::door, ],\n"),
        "the plane door axis references the entry's door: {out}"
    );
    assert!(
        !out.contains("hot_planes"),
        "the HOT plane lane is deleted: no LINKED table carries it: {out}"
    );
    assert!(
        out.contains("    compose: &[],\n"),
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
        // RED: the deleted HOT plane lane's axis is an unknown axis, refused.
        manifest.replace("four = \"plane-door\"", "four = \"hot-plane\""),
    ] {
        let refused = std::panic::catch_unwind(|| linked_source(&broken, &enabled));
        assert!(refused.is_err(), "must be refused:\n{broken}");
    }
}

/// THE TRANSPORT AND CLAIMS AXES, and the rows no feature can drop. A row whose crate is a required
/// dependency is linked in every build and its key only names the row; two rows may share a crate,
/// each naming its own entry; a `transport` row fills `transports` with the row its bare `door`
/// makes (`linked_transport!`: key, layers, build, claims and upgrade claims, all read off the door's
/// Statement), and never names a constant of its entry's (BUSBAR-1.6.0.md l.3560-3561); a `claims` row fills
/// `claims` with its `PLANE` and `CLAIMS`. A row on an OPTIONAL crate still needs its feature,
/// `claims` off the plane axis is refused, and so is a `transport` row off the door axis: a
/// transport is linked only as its memory-ABI door (step 36).
#[test]
fn the_generator_folds_the_transport_and_claims_axes() {
    let manifest = r#"
[dependencies]
busbar-wire = { path = "../busbar-wire" }
busbar-plane-host = { path = "../busbar-plane-host", optional = true }

[features]
host = ["dep:busbar-plane-host"]

[package.metadata.busbar.linked]
host = "busbar-plane-host"
wire-low = "busbar-wire"
wire-high = "busbar-wire"

[package.metadata.busbar.linked-axes]
host = "plane claims"
wire-low = "transport transport-door"
wire-high = "transport transport-door"

[package.metadata.busbar.linked-entry]
wire-high = "busbar_wire::linked::high"

[package.metadata.busbar.root-units]
host = "unit"
"#;
    let (out, _) = linked_source(manifest, &|f: &str| f == "host");
    assert_eq!(
        out.matches("extern crate busbar_wire as _;").count(),
        1,
        "two rows on one crate link it once: {out}"
    );
    // A door row is its bare door: the one row macro reads its key, layers, claims, upgrades, lines
    // and offered points off the door's Statement (`crate::root::linked::linked_transport!`).
    assert!(
        out.contains(
            "    transports: &[crate::root::linked::linked_transport!(busbar_wire::linked::door), \
             crate::root::linked::linked_transport!(busbar_wire::linked::high::door), ],"
        ),
        "{out}"
    );
    // RED: no row reads a constant its entry exports beside `door`.
    for constant in ["::KEY", "::COMPOSES_OVER", "::SESSION"] {
        assert!(!out.contains(constant), "a row names `{constant}`: {out}");
    }
    // The connector's view is the same doors, keyed by what each Statement states.
    assert!(
        out.contains("&[busbar_wire::linked::door, busbar_wire::linked::high::door, ];"),
        "{out}"
    );
    assert!(
        out.contains(".map(|door| (crate::root::doors::row_facts(*door).key, *door))"),
        "{out}"
    );
    // An entry at the crate root links the same way: the row reads `<entry>::door`.
    let at_root = manifest.replace(
        "wire-high = \"busbar_wire::linked::high\"",
        "wire-high = \"busbar_wire\"",
    );
    let (rooted, _) = linked_source(&at_root, &|f: &str| f == "host");
    assert!(
        rooted.contains("crate::root::linked::linked_transport!(busbar_wire::door), "),
        "{rooted}"
    );
    assert!(out.contains("::std::sync::Arc::new(busbar_plane_host::linked::PLANE), claims: busbar_plane_host::linked::CLAIMS"), "{out}");

    let (off, _) = linked_source(manifest, &|_: &str| false);
    assert!(
        off.contains("crate::root::linked::linked_transport!(busbar_wire::linked::door)"),
        "a required crate's row is always linked: {off}"
    );
    assert!(
        !off.contains("busbar_plane_host"),
        "an optional crate's row follows its feature: {off}"
    );

    for broken in [
        manifest.replace(
            "wire-low = \"busbar-wire\"",
            "wire-low = \"busbar-plane-host\"",
        ),
        manifest.replace("host = \"plane claims\"", "host = \"claims\""),
        manifest.replace(
            "wire-low = \"transport transport-door\"",
            "wire-low = \"transport\"",
        ),
    ] {
        let refused = std::panic::catch_unwind(|| linked_source(&broken, &|f: &str| f == "host"));
        assert!(refused.is_err(), "must be refused:\n{broken}");
    }
}

/// THE PLANE DOOR AXIS (#2, THE DESIGN §11.4): a `plane-door` row fills `plane_doors` with its
/// entry's `door`, the table the root hands the loader beside every dropped-in plane door; with its
/// feature off the table is empty.
#[test]
fn the_generator_folds_the_plane_door_axis() {
    let manifest = r#"
[dependencies]
busbar-plane-door = { path = "../busbar-plane-door", optional = true }

[features]
door = ["dep:busbar-plane-door"]

[package.metadata.busbar.linked]
door = "busbar-plane-door"

[package.metadata.busbar.linked-axes]
door = "plane-door"

[package.metadata.busbar.linked-entry]
door = "busbar_plane_door::plane_door"

[package.metadata.busbar.root-units]
door = "unit"
"#;
    let (on, _) = linked_source(manifest, &|f: &str| f == "door");
    assert!(
        on.contains("plane_doors: &[busbar_plane_door::plane_door::door, ],"),
        "{on}"
    );
    let (off, _) = linked_source(manifest, &|_: &str| false);
    assert!(off.contains("plane_doors: &[],"), "{off}");
}

/// A PLANE IS SERVED THROUGH ITS DOOR (#2, #30; BUSBAR-1.6.0.md Part 3 §12 "The switch"): this
/// manifest has a build that links a plane's memory-ABI door on the `plane-door` axis, so the
/// compiled-in plane is bound through the loader's one load, the same table its dropped-in build is.
#[test]
fn the_manifest_links_a_plane_through_its_door() {
    let manifest = read("Cargo.toml");
    let (all, _) = linked_source(&manifest, &|_: &str| true);
    let doors = all
        .lines()
        .find_map(|l| l.trim().strip_prefix("plane_doors: &["))
        .unwrap_or_else(|| panic!("no plane_doors table generated:\n{all}"));
    assert!(
        doors.contains("::door, "),
        "no build of this manifest links a plane door: plane_doors = [{doors}"
    );
}

/// EVERY FOLD IS DONE (BUSBAR-1.6.0.md Part 3 §12 "The switch": a fold's development-only switch is
/// deleted when the fold completes; status row 155): the manifest states no `<plane>-on-driver`
/// feature, and the default build links every plane door any feature links, so the shipped binary
/// serves each plane through its door. The doors are read off the manifest, so this names no plane.
/// RED: a `-on-driver` switch back in `[features]`, or a plane's switch taken out of `default`.
#[test]
fn no_fold_switch_remains_and_the_default_build_links_every_plane_door() {
    let manifest = read("Cargo.toml");
    let default: Vec<String> = manifest
        .lines()
        .find_map(|l| l.trim().strip_prefix("default = ["))
        .expect("the manifest states a default feature set")
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect();
    let switches: Vec<String> = manifest
        .lines()
        .filter_map(|l| l.trim().split_once(" = ["))
        .map(|(name, _)| name.trim().to_string())
        .filter(|name| name.ends_with("-on-driver"))
        .collect();
    assert!(
        switches.is_empty(),
        "a development-only fold switch is still stated: {switches:?}"
    );
    let doors_of = |on: &dyn Fn(&str) -> bool| -> Vec<String> {
        let (src, _) = linked_source(&manifest, on);
        let table = src
            .lines()
            .find_map(|l| l.trim().strip_prefix("plane_doors: &[").map(str::to_string))
            .unwrap_or_else(|| panic!("no plane_doors table generated:\n{src}"));
        table
            .split(", ")
            .filter(|d| d.ends_with("::door"))
            .map(str::to_string)
            .collect()
    };
    // The default set as cargo resolves it: each feature with every feature its `[features]` row
    // turns on (`dep:` and `crate/feature` entries name no feature of this crate).
    let rows: Vec<(String, Vec<String>)> = manifest
        .split("\n[features]\n")
        .nth(1)
        .and_then(|rest| rest.split("\n[").next())
        .expect("the manifest states a `[features]` table")
        .lines()
        .filter_map(|l| l.split_once(" = ["))
        .map(|(name, list)| {
            let on = list
                .split('"')
                .skip(1)
                .step_by(2)
                .map(str::to_string)
                .collect();
            (name.trim().to_string(), on)
        })
        .collect();
    let mut resolved = default;
    let mut at = 0;
    while at < resolved.len() {
        let implied: Vec<String> = rows
            .iter()
            .filter(|(name, _)| *name == resolved[at])
            .flat_map(|(_, on)| on.iter().cloned())
            .filter(|f| !f.contains(':') && !f.contains('/') && !resolved.contains(f))
            .collect();
        resolved.extend(implied);
        at += 1;
    }
    let every = doors_of(&|_: &str| true);
    let shipped = doors_of(&|f: &str| resolved.iter().any(|d| d == f));
    assert!(!every.is_empty(), "no feature links a plane door");
    let missing: Vec<&String> = every.iter().filter(|d| !shipped.contains(d)).collect();
    assert!(
        missing.is_empty(),
        "the default build does not link these plane doors: {missing:?} (shipped = {shipped:?})"
    );
}
