// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LINKED DOOR-ROOT TABLE (status row 195): its generator writes a row for each crate the
//! door-root table names and no other, each admitted through `open_linked`; and the table this
//! build generated names exactly the crates this crate's manifest names. RED: a row with no
//! `linked-<crate>` feature, a row whose crate is not an optional edge, a door outside its crate, and
//! a `linked-*` feature the table does not name are each refused.

/// The generator `build.rs` runs, verbatim.
#[allow(dead_code)]
mod generator {
    include!("../linked_gen.rs");
}

const MANIFEST: &str = r#"
[dependencies]
busbar-contract = { path = "../busbar-contract" }
busbar-wire-a = { workspace = true, optional = true }
busbar-wire-b = { workspace = true, optional = true }

[features]
pack = ["dep:jsonschema"]
linked-busbar-wire-a = ["dep:busbar-wire-a"]
linked-busbar-wire-b = ["dep:busbar-wire-b"]

[package.metadata.busbar.door-root]
busbar-wire-a = "busbar_wire_a::door"
busbar-wire-b = "busbar_wire_b::door"
"#;

/// Every `busbar_*` crate path the source names (`::busbar_x::…`).
fn named_crates(src: &str) -> Vec<String> {
    let mut out: Vec<String> = src
        .match_indices("::busbar_")
        .map(|(at, _)| {
            src[at + 2..]
                .split("::")
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .filter(|c| c != "busbar_contract")
        .collect();
    out.sort();
    out.dedup();
    out
}

#[test]
fn the_generated_table_names_only_the_door_root_crates() {
    let src = generator::linked_doors_source(MANIFEST);
    assert_eq!(
        named_crates(&src),
        ["busbar_wire_a", "busbar_wire_b"],
        "{src}"
    );
    for krate in ["busbar-wire-a", "busbar-wire-b"] {
        assert!(
            src.contains(&format!("#[cfg(feature = \"linked-{krate}\")]")),
            "`{krate}` is admitted only where its feature links it:\n{src}"
        );
    }
    assert_eq!(
        src.matches("crate::dispatch::load::open_linked(").count(),
        2,
        "every row is admitted through the one entry:\n{src}"
    );
    for broken in [
        MANIFEST.replace("linked-busbar-wire-b = [\"dep:busbar-wire-b\"]\n", ""),
        MANIFEST.replace(
            "busbar-wire-b = { workspace = true, optional = true }",
            "busbar-wire-b = { workspace = true }",
        ),
        MANIFEST.replace("busbar_wire_b::door", "busbar_wire_a::door"),
        MANIFEST.replace(
            "linked-busbar-wire-b = [\"dep:busbar-wire-b\"]\n",
            "linked-busbar-wire-b = [\"dep:busbar-wire-b\"]\nlinked-busbar-other = []\n",
        ),
    ] {
        let refused = std::panic::catch_unwind(|| generator::linked_doors_source(&broken));
        assert!(refused.is_err(), "must be refused:\n{broken}");
    }
}

/// THIS BUILD'S TABLE: the generated file names exactly the crates this crate's manifest's
/// door-root table names, and the safe API answers each by name.
#[test]
fn this_builds_table_names_exactly_its_manifests_door_root_crates() {
    let manifest = include_str!("../../Cargo.toml");
    let named: Vec<String> = generator::door_root_rows(manifest)
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    assert_eq!(super::named(), named.as_slice());
    let generated = std::fs::read_to_string(concat!(env!("OUT_DIR"), "/linked_doors.rs"))
        .expect("read the generated table");
    let mut want: Vec<String> = named.iter().map(|k| k.replace('-', "_")).collect();
    want.sort();
    assert_eq!(named_crates(&generated), want, "{generated}");
    for krate in super::linked() {
        assert!(
            named.iter().any(|k| k == krate),
            "`{krate}` is in the table"
        );
    }
    assert!(
        super::door("busbar-no-such-crate").is_err(),
        "a crate the table does not link has no door"
    );
}
