// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The transport module carries the door's vocabulary and nothing the door replaced (Q128 contract
//! part 13).
//!
//! A transport reaches the host through its memory-ABI door and the kind's ops table, and nothing
//! else (BUSBAR-1.6.0.md THE DESIGN §11.1: "Every kind of plugin is called through a table of
//! function pointers over data in fixed C layout"). The inbound route match is spelled once, in
//! `abi/transport` (§6 step 3: "The match vocabulary is defined once in `abi/transport`"). A
//! capability with no production construction site does not ship (Part 1: "A capability that is
//! never constructed does not ship"). And the contract names no protocol (Law 1; §1: "kernel,
//! contract and cleanliness crates × every kind instance = 0").
//!
//! The check is a source scan, because the property is "this item is not spelled here", which no
//! type can state about itself.

use std::path::{Path, PathBuf};

fn transport_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/transport")
}

fn source(file: &str) -> String {
    let path = transport_dir().join(file);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{} is readable: {e}", path.display()))
}

/// The code lines of a file: every line that is not a comment.
fn code_lines(text: &str) -> Vec<(usize, &str)> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| {
            let t = l.trim_start();
            !t.starts_with("//")
        })
        .map(|(i, l)| (i + 1, l))
        .collect()
}

fn offenders(file: &str, needles: &[&str]) -> Vec<String> {
    let text = source(file);
    code_lines(&text)
        .into_iter()
        .filter(|(_, l)| needles.iter().any(|n| l.contains(n)))
        .map(|(n, l)| format!("transport/{file}:{n}: {}", l.trim()))
        .collect()
}

/// No second inbound seam: the Rust-trait arrival hand-off (`driver`, `UnitDriver`) is not in the
/// module tree. An arrival reaches the kernel from a transport's guest list, through its door (THE
/// DESIGN §6 step 4), and nothing constructs or implements the trait.
#[test]
fn the_transport_module_carries_no_second_inbound_seam() {
    let dir = transport_dir();
    assert!(
        !dir.join("driver.rs").exists(),
        "a second inbound seam is still in the tree: transport/driver.rs"
    );
    let declared = offenders("mod.rs", &["pub mod driver", "UnitDriver"]);
    assert!(
        declared.is_empty(),
        "the transport module still declares or re-exports the second inbound seam: {declared:#?}"
    );
}

/// The superseded role derivation is gone: a framer states an EMPTY `composes_over` too (THE
/// DESIGN §2: "A framer states an EMPTY `composes_over`"; the 2026-10-14 ruling: "the role is the
/// export"), so a role computed from that list calls every conforming framer a carrier. Nothing
/// above the ABI derives a role.
#[test]
fn no_role_is_derived_from_composes_over() {
    let found = offenders("stack.rs", &["fn role_of", "pub enum Role", "fn role("]);
    let exported = offenders("mod.rs", &["role_of", " Role,"]);
    let all: Vec<_> = found.into_iter().chain(exported).collect();
    assert!(
        all.is_empty(),
        "a role is still derived from composes_over: {all:#?}"
    );
}

/// The status key names no protocol: a status is read in the numbering its transport declares,
/// through the one neutral accessor, never through an accessor named for a protocol.
#[test]
fn the_wire_status_has_no_protocol_named_accessor() {
    let found = offenders("wire.rs", &["fn http(", "fn grpc("]);
    assert!(
        found.is_empty(),
        "the contract's status vocabulary names a protocol: {found:#?}"
    );
}
