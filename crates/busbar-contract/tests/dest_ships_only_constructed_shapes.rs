// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RED (Q128 contract u15 MEDIUM): the destination module ships no shape that nothing constructs
//! (Part 1: "A capability that is never constructed does not ship ... A built type or verb with no
//! production construction site is either wired or deleted before the cut"). The one-time secret
//! placeholder, the outbound decoration and its secret slot, and the candidate permutation
//! vocabulary had no production construction site; they are deleted, with their root re-exports.

const DEST: &str = include_str!("../src/dest.rs");
const ROOT: &str = include_str!("../src/lib.rs");

#[test]
fn the_destination_module_ships_no_unconstructed_shape() {
    for name in [
        "SecretOnce",
        "AuthDecoration",
        "SecretSlot",
        "Permutation",
        "CandidateSet",
        "OnEmpty",
        "VetoCode",
        "CandidateIdx",
    ] {
        for (file, src) in [("dest.rs", DEST), ("lib.rs", ROOT)] {
            let named = src.split(|c: char| !c.is_alphanumeric() && c != '_');
            assert!(
                !named.into_iter().any(|w| w == name),
                "{file} still ships `{name}`"
            );
        }
    }
    assert!(
        DEST.contains("pub enum DestinationFacts"),
        "the scan reads the module (positive control)"
    );
}
