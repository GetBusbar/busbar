// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The verify step's guards have one home, and it is not this crate.
//!
//! The pool allow-list, the fallback walk and the unpriced-destination gate that refuse a unit before
//! it is charged are the kernel door's. A second copy here, with its own seal rule, its own ordering
//! and its own weighted selector, ran in no shipped path: its tests proved a rule the node never
//! applied, and the copy had already drifted from the one that refuses real requests (it asked a
//! billing question the door deliberately does not). A capability that is never constructed does not
//! ship, so the copy is gone, and this test keeps it gone.
//!
//! What stays under `trust` is the network readers the connector and the kernel call: `net`.

use std::path::Path;

/// The modules the trust tree may hold: the network readers, and the module root that names them.
const ALLOWED: &[&str] = &["mod.rs", "net.rs"];

#[test]
fn the_trust_tree_holds_the_network_readers_and_no_second_verify_step() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/trust");
    let mut strays: Vec<String> = std::fs::read_dir(&dir)
        .expect("the trust module is readable")
        .flatten()
        .filter(|e| e.path().is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| !ALLOWED.contains(&name.as_str()))
        .collect();
    strays.sort();
    assert!(
        strays.is_empty(),
        "the trust tree carries modules no shipped path constructs (a second verify step, \
         ordering, lane model or selector beside the kernel door's): {strays:?}"
    );
}

#[test]
fn no_verify_unit_is_exported() {
    let root =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/trust/mod.rs"))
            .expect("the trust module root is readable");
    for item in [
        "pub mod unit",
        "pub mod guard",
        "pub mod destination",
        "pub mod lane",
        "pub mod order",
        "pub mod swrr",
        "pub mod counterparty",
        "pub mod arity",
    ] {
        assert!(
            !root.contains(item),
            "the trust module still declares `{item}`, which no shipped path constructs"
        );
    }
}
