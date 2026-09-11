// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A PLANE POOL NAME, PINNED ACROSS THE TWO CRATES THAT SPELL IT, FROM THE TOOLING SIDE.
//!
//! The composition root admits and meters every unit of the A2A plane against one pool name, and it
//! restates that name rather than depending on the codec crate that declares it: a root that
//! carried a Cargo edge to a codec crate would be reaching past the contract face, which
//! `kind-isolation:deps` scores and refuses. A restated value has to be pinned, and a copy that is
//! checked is not a second opinion — a copy that is not is how one node ends up admitting against
//! one pool and metering against another, with both halves looking healthy because an empty bucket
//! reconciles.
//!
//! THE CELL LIVES HERE, NOT IN EITHER CRATE, and that is the whole point. A cell that must name
//! BOTH halves lives where both may be named: `xtask` is the gate runner, a workspace member and
//! not a crate of the product tree — it has no kind, it ships in no artifact, and every rule here
//! is a rule it enforces rather than one it is subject to. Asking this of the root's own test tree
//! would make the root name a codec crate in source AND read that crate's file at build time,
//! which `kind-isolation:vocab` and `kind-isolation:build-inputs` both refuse — correctly, because
//! a build-time file read compiles a crate in with no edge to score.
//!
//! The two halves are read as TEXT, at run time, from the tree the runner is run in. Nothing is
//! compiled in, so no edge is created in either direction.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask/ has a parent, which is the repository root")
        .to_path_buf()
}

fn read(rel: &str) -> String {
    let p = repo_root().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{} is readable: {e}", p.display()))
}

/// The one string literal a `pub const <NAME>: &str = "…";` line binds, read out of source text.
fn declared_str(source: &str, name: &str) -> String {
    let needle = format!("pub const {name}: &str = ");
    source
        .lines()
        .find_map(|l| l.trim().strip_prefix(needle.as_str()))
        .and_then(|rest| rest.split('"').nth(1))
        .unwrap_or_else(|| panic!("`{name}` is declared as a string literal"))
        .to_string()
}

/// **The pool the root admits and meters against is the codec kind's own declared section name.**
#[test]
fn the_roots_plane_pool_is_the_a2a_codec_sections_own_name() {
    let root = read("crates/busbar/src/root/units_a2a_leg.rs");
    let codec = read("crates/busbar-a2a-codec/src/lib.rs");
    assert_eq!(
        declared_str(&root, "PLANE_POOL"),
        declared_str(&codec, "CONFIG_SECTION"),
        "the root's restated pool name and the codec kind's own section name are one string"
    );
}
