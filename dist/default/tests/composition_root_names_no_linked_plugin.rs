// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::Path;

mod generator {
    include!("../../../crates/busbar/src/linked_gen.rs");
}
use generator::linked_source;

#[test]
fn linked_min3_images_use_checked_admission_without_legacy_store_rows() {
    let manifest = r#"
[dependencies]
neutral-store = "1"
[features]
optional-image = []
[package.metadata.busbar.linked]
store = "neutral-store"
optional-image = "optional-plugin"
[package.metadata.busbar.linked-axes]
store = "min3-images"
optional-image = "min3-images"
"#;
    let (source, _) = linked_source(manifest, &|_| false);
    assert!(
        source.contains("admit_linked(&neutral_store::PLUGIN)"),
        "{source}"
    );
    assert!(!source.contains("optional_plugin"), "{source}");
    assert!(!source.contains("neutral_store::linked"), "{source}");
    assert!(!source.contains("neutral_store::STORE"), "{source}");
    assert!(!source.contains("neutral_store::door"), "{source}");
    let (enabled, _) = linked_source(manifest, &|_| true);
    assert!(
        enabled.contains("admit_linked(&optional_plugin::PLUGIN)"),
        "{enabled}"
    );
}

const CARRIER_MANIFEST: &str = r#"
[dependencies]
busbar-wire-a = "1"
busbar-wire-b = "1"
busbar-door = "1"
[features]
wire-c = []
[package.metadata.busbar.linked]
wire-a = "busbar-wire-a"
wire-b = "busbar-wire-b"
wire-c = "busbar-wire-c"
door = "busbar-door"
[package.metadata.busbar.linked-axes]
wire-a = "min3-images"
wire-b = "min3-images"
wire-c = "min3-images"
door = "transport transport-door"
[package.metadata.busbar.linked-entry]
wire-b = "busbar_wire_b::image"
[package.metadata.busbar.carriers]
http = "wire-a"
rtc = "wire-b"
websocket = "wire-c"
"#;

fn carrier_row(constant: &str, entry: &str) -> String {
    format!(
        "    crate::root::min3_framers::LinkedCarrier {{ carrier: ::busbar_plugin_abi::plane::{constant}, \
         admit: || ::busbar_plugin_loader::admit::admit_linked(&{entry}::PLUGIN) }},\n"
    )
}

#[test]
fn the_generator_emits_one_carrier_pair_per_assigned_enabled_row() {
    assert_eq!(
        generator::carrier_rows(CARRIER_MANIFEST),
        vec![
            ("http".to_string(), "CARRIER_HTTP", "wire-a".to_string()),
            ("rtc".to_string(), "CARRIER_RTC", "wire-b".to_string()),
            (
                "websocket".to_string(),
                "CARRIER_WEBSOCKET",
                "wire-c".to_string()
            ),
        ]
    );
    let (off, _) = linked_source(CARRIER_MANIFEST, &|_| false);
    let table = "static LINKED_CARRIERS: &[crate::root::min3_framers::LinkedCarrier] = &[\n";
    let at = off
        .find(table)
        .unwrap_or_else(|| panic!("no carrier table: {off}"));
    let rows = &off[at + table.len()..];
    let rows = &rows[..rows.find("];\n").expect("the table closes")];
    assert_eq!(
        rows,
        carrier_row("CARRIER_HTTP", "busbar_wire_a")
            + &carrier_row("CARRIER_RTC", "busbar_wire_b::image"),
        "a disabled row assigns nothing; an entry override names the header's module"
    );
    let (on, _) = linked_source(CARRIER_MANIFEST, &|_| true);
    assert!(
        on.contains(&carrier_row("CARRIER_WEBSOCKET", "busbar_wire_c")),
        "{on}"
    );

    let unstated = CARRIER_MANIFEST
        .split("[package.metadata.busbar.carriers]")
        .next()
        .expect("the manifest head");
    assert!(generator::carrier_rows(unstated).is_empty());
    let (none, _) = linked_source(unstated, &|_| true);
    assert!(none.contains(&format!("{table}];\n")), "{none}");
}

/// A carrier may name its row by package (`busbar-...`), the spelling a build that excludes the plugin drops with its
/// other rows (the FIPS repository's `ci/exclude-plugins.sh`); the generator reads it as the row it names.
#[test]
fn a_carrier_may_name_its_row_by_package_and_the_two_spellings_are_one_row() {
    let by_package = CARRIER_MANIFEST
        .replace("http = \"wire-a\"", "http = \"busbar-wire-a\"")
        .replace("rtc = \"wire-b\"", "rtc = \"busbar-wire-b\"");
    assert_eq!(
        generator::carrier_rows(&by_package),
        generator::carrier_rows(CARRIER_MANIFEST),
        "a package names the same rows as their keys"
    );
    let (by_key, _) = linked_source(CARRIER_MANIFEST, &|_| true);
    let (by_name, _) = linked_source(&by_package, &|_| true);
    assert_eq!(
        by_name, by_key,
        "the generated source does not depend on the spelling"
    );
    let twice = CARRIER_MANIFEST.replace("rtc = \"wire-b\"", "rtc = \"busbar-wire-a\"");
    assert!(
        std::panic::catch_unwind(|| generator::carrier_rows(&twice)).is_err(),
        "one row under two carriers is refused whichever spelling names it"
    );
}

#[test]
fn the_generator_refuses_a_bad_carrier_table() {
    for (why, broken) in [
        (
            "an unknown carrier key",
            CARRIER_MANIFEST.replace("rtc = \"wire-b\"", "stdio = \"wire-b\""),
        ),
        (
            "a carrier stated twice",
            CARRIER_MANIFEST.replace("rtc = \"wire-b\"", "rtc = \"wire-b\"\nhttp = \"wire-b\""),
        ),
        (
            "a row that is not a MIN-3 image",
            CARRIER_MANIFEST.replace("rtc = \"wire-b\"", "rtc = \"door\""),
        ),
        (
            "a row that is not linked",
            CARRIER_MANIFEST.replace("rtc = \"wire-b\"", "rtc = \"nowhere\""),
        ),
        (
            "one row under two carriers",
            CARRIER_MANIFEST.replace("rtc = \"wire-b\"", "rtc = \"wire-a\""),
        ),
        (
            "a stated table with no row",
            CARRIER_MANIFEST.replace(
                "http = \"wire-a\"\nrtc = \"wire-b\"\nwebsocket = \"wire-c\"\n",
                "",
            ),
        ),
    ] {
        let refused = std::panic::catch_unwind(|| linked_source(&broken, &|_| true));
        assert!(refused.is_err(), "{why} must be refused:\n{broken}");
    }
}

#[test]
fn the_manifest_carrier_table_names_only_linked_images() {
    let manifest = read("Cargo.toml");
    let rows = generator::carrier_rows(&manifest);
    let (all, _) = linked_source(&manifest, &|_: &str| true);
    assert!(
        all.contains("static LINKED_CARRIERS: &[crate::root::min3_framers::LinkedCarrier] = &["),
        "{all}"
    );
    assert_eq!(
        all.matches("crate::root::min3_framers::LinkedCarrier { carrier:")
            .count(),
        rows.len(),
        "every assigned row is linked in the build with every feature on"
    );
    assert!(
        !manifest.contains("connector-door"),
        "the retired axis word selects nothing and is refused"
    );
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
        .unwrap_or_else(|e| panic!("{rel}: {e}"))
}

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
one = "plane-door protocols"
two = "plane-door egress"
three = "plane-door diagnostics egress"
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
    assert!(
        !out.contains("protocols:") && !out.contains("::PROTOCOLS"),
        "executable codec declarations must not enter the shipping linked table: {out}"
    );
    assert!(out.contains("    diagnostics: &[crate::root::third_half::DIAGNOSTICS, ],\n"));
    assert!(
        out.contains("    plane_doors: &[busbar_first::linked::door, crate::root::third_half::door, busbar_fourth::linked::door, ],\n"),
        "the enabled doors retain manifest order and the entry override: {out}"
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
        manifest.replace("three = \"plane-door diagnostics egress\"\n", ""),
        manifest.replace(
            "plane-door diagnostics egress",
            "plane-door diagnostics teleport",
        ),
        manifest.replace("four = \"plane-door\"", "four = \"hot-plane\""),
    ] {
        let refused = std::panic::catch_unwind(|| linked_source(&broken, &enabled));
        assert!(refused.is_err(), "must be refused:\n{broken}");
    }
}

#[test]
fn the_generator_refuses_the_retired_body_arrival_axis() {
    let manifest = r#"
[features]
plane = []
[package.metadata.busbar.linked]
plane = "busbar-example"
[package.metadata.busbar.linked-axes]
plane = "plane-door body-ingress"
"#;
    let refused = std::panic::catch_unwind(|| linked_source(manifest, &|_| true));
    assert!(
        refused.is_err(),
        "a body-arrival callback bypasses the plane door"
    );
}

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

    assert!(
        out.contains(
            "    transports: &[crate::root::linked::linked_transport!(busbar_wire::linked::door), \
             crate::root::linked::linked_transport!(busbar_wire::linked::high::door), ],"
        ),
        "{out}"
    );

    for constant in ["::KEY", "::COMPOSES_OVER", "::SESSION"] {
        assert!(!out.contains(constant), "a row names `{constant}`: {out}");
    }

    assert!(
        out.contains("&[busbar_wire::linked::door, busbar_wire::linked::high::door, ];"),
        "{out}"
    );
    assert!(
        out.contains(".map(|door| (crate::root::doors::row_facts(*door).key, *door))"),
        "{out}"
    );

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

#[test]
fn every_declared_build_cfg_is_set_by_some_feature_set() {
    // Every cfg rule only ever turns on as features are added, so the build with every feature
    // on is the union of every feature set: a declared cfg it leaves off is off in every build,
    // and the code it gates runs nowhere.
    let manifest = read("Cargo.toml");
    let never: Vec<String> = generator::build_cfgs(&manifest, &|_| true)
        .into_iter()
        .filter(|(_, on)| !on)
        .map(|(cfg, _)| cfg)
        .collect();
    assert!(
        never.is_empty(),
        "declared cfgs that no feature set of this distribution sets (the code they gate runs \
         in no build): {never:?}"
    );
}

#[test]
fn a_build_cfg_follows_the_rows_that_drive_it() {
    let manifest = r#"
[features]
one = []
two = []

[package.metadata.busbar.linked]
one = "busbar-first"
two = "busbar-second"

[package.metadata.busbar.linked-axes]
one = "min3-images egress"
two = "min3-images"

[package.metadata.busbar.linked-section]
one = "pools"
two = "tools"
"#;
    let on = |enabled: &dyn Fn(&str) -> bool, name: &str| {
        generator::build_cfgs(manifest, enabled)
            .into_iter()
            .find(|(cfg, _)| cfg == name)
            .map(|(_, on)| on)
    };
    assert_eq!(on(&|f| f == "one", "linked_axis_min3_images"), Some(true));
    assert_eq!(on(&|_| false, "linked_axis_min3_images"), Some(false));
    assert_eq!(on(&|f| f == "one", "linked_section_pools"), Some(true));
    assert_eq!(on(&|f| f == "one", "linked_section_tools"), Some(false));
    assert_eq!(on(&|_| true, "linked_section_tools"), Some(true));
    assert_eq!(on(&|f| f == "one", "linked_egress"), Some(true));
    let unseamed = manifest.replace("min3-images egress", "min3-images");
    assert!(
        !generator::build_cfgs(&unseamed, &|_| true)
            .iter()
            .any(|(cfg, _)| cfg == "linked_egress"),
        "a seam no row drives is not declared"
    );
}
