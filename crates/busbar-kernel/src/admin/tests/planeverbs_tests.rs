// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROOF THAT THE TRUST VERB SURFACE IS ONE SURFACE.
//!
//! The mounted behaviour of each plane's verbs is driven over the REAL router where it lives
//! (`mcp/tests/adminverbs_tests.rs`, `a2a/tests/adminverbs_tests.rs`). What those cannot prove is
//! what this file exists for: that there is one surface above them, that its refusal and its audit
//! naming are DERIVED from the plane rather than written per plane, and that it contains no branch
//! on which plane it is serving.

use super::*;

/// EVERY PLANE KEY THIS TREE SHIPS, read off the workspace rather than written here: each
/// `crates/busbar-plane-<key>` directory is one plane (the same derivation `cargo xtask gate
/// plane-purity` uses for its vocabulary). A list typed into this file would itself name the planes
/// the ratchet exists to keep out of the shared surface — and would miss the next plane to land.
fn shipped_plane_keys() -> Vec<String> {
    let crates_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the kernel crate sits inside the workspace `crates/` directory");
    let mut keys: Vec<String> = std::fs::read_dir(crates_dir)
        .expect("the workspace `crates/` directory is readable")
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            e.file_name()
                .to_str()
                .and_then(|n| n.strip_prefix("busbar-plane-"))
                .map(str::to_string)
        })
        .collect();
    keys.sort();
    // A derivation that found nothing would make both ratchets below pass on any source at all.
    assert!(
        keys.len() >= 2,
        "the plane roster read off `crates/busbar-plane-*` is {keys:?} — too small to be the tree"
    );
    keys
}

/// A plane key as code spells it: lowercase (`key`), Capitalised (a type or variant) and UPPERCASE
/// (a constant or acronym).
fn spellings(key: &str) -> [String; 3] {
    let mut chars = key.chars();
    let capitalised = chars
        .next()
        .map(|c| c.to_ascii_uppercase().to_string() + chars.as_str())
        .unwrap_or_default();
    [key.to_string(), capitalised, key.to_ascii_uppercase()]
}

/// The shared surface's source with comment lines dropped.
fn planeverbs_code() -> String {
    include_str!("../planeverbs.rs")
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// THE RATCHET, the same one the shared sweep job and choke point F carry. This file is shared
/// because it names no plane; the moment it does, the sibling plane stops being able to
/// parameterise it and grows a copy instead.
///
/// Comments are stripped first: the header has to be able to EXPLAIN which planes it serves and how
/// their vocabularies differ, and prose that explains a boundary is not code that crosses it.
#[test]
fn the_shared_verb_surface_names_no_plane_in_its_code() {
    // The planes' own subject vocabulary, then every shipped plane key in each spelling.
    const SUBJECT_NOUNS: &[&str] = &[
        "tool", "Tool", "agent", "Agent", "skill", "Skill", "card", "Card",
    ];
    let mut banned: Vec<String> = SUBJECT_NOUNS.iter().map(|s| s.to_string()).collect();
    for key in shipped_plane_keys() {
        banned.extend(spellings(&key));
    }
    let code = planeverbs_code();
    for needle in &banned {
        assert!(
            !code.contains(needle.as_str()),
            "the shared trust verb surface names `{needle}` in its CODE. The plane's vocabulary \
             belongs in `Plane::subject_noun` / `Plane::audit_kind` and in the plane's own \
             `PlaneTrust` impl, never in the surface both planes share."
        );
    }
}

/// THE ACCEPTANCE TEST, mechanically: the plane is a type parameter and a pair of lookups, never a
/// branch. A `match` on it here would mean the handler had been re-forked inside one file, which
/// reads as unified and is not.
#[test]
fn the_plane_is_a_parameter_and_never_a_branch() {
    let code = planeverbs_code();
    let mut branches: Vec<String> = ["match plane", "match P::PLANE", "if plane =="]
        .iter()
        .map(|s| s.to_string())
        .collect();
    // A branch on one named plane: `Plane::<Key>` for every shipped plane.
    for key in shipped_plane_keys() {
        let [_, capitalised, _] = spellings(&key);
        branches.push(format!("Plane::{capitalised}"));
    }
    for needle in &branches {
        assert!(
            !code.contains(needle.as_str()),
            "the shared trust verb surface contains `{needle}`. One handler set, parameterised by \
             plane — a branch here is one handler set per plane with extra steps."
        );
    }
}

// `the_not_found_names_the_plane_s_own_subject` MOVED to
// `tests/admin_planeverbs_cross_plane.rs`: it renders `to_admin_error("mcp", ...)`/`("a2a", ...)`
// and asserts the REAL subject-noun prose ("MCP server", "fronted agent") those plane decls carry —
// naming that real vocabulary here (even via a synthetic `#[cfg(test)]` decl) is exactly what
// `cargo xtask gate construction`'s `neutral-no-dialect` rule (ceiling 0) forbids in this crate. See
// that file for the relocated test.

/// A LOOKUP THAT RESOLVED IS PASSED STRAIGHT THROUGH. The shared rule decides the refusal and
/// nothing else; it never inspects, rewrites or re-validates what the plane found.
#[test]
fn a_resolved_lookup_is_returned_untouched() {
    let found =
        registered(|| Some(("entry", "cfg"))).expect("a lookup that resolved must not be refused");
    assert_eq!(found, ("entry", "cfg"));
}

// `the_admin_route_table_method_path_scope_is_byte_identical` and
// `the_audit_naming_is_derived_from_the_plane` also MOVED to `tests/admin_planeverbs_cross_plane.rs`
// for the same reason as the test above them: both pin the REAL mcp/a2a admin route table and audit
// vocabulary, which only `plane_decl("mcp")`/`plane_decl("a2a")` over the REAL registered roster can
// answer — real plane behaviour, not "a plane merely needs to exist".
