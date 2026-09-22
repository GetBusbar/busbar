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

/// THE RATCHET, the same one the shared sweep job and choke point F carry. This file is shared
/// because it names no plane; the moment it does, the sibling plane stops being able to
/// parameterise it and grows a copy instead.
///
/// Comments are stripped first: the header has to be able to EXPLAIN which planes it serves and how
/// their vocabularies differ, and prose that explains a boundary is not code that crosses it.
#[test]
fn the_shared_verb_surface_names_no_plane_in_its_code() {
    const BANNED: &[&str] = &[
        "mcp", "Mcp", "MCP", "a2a", "A2a", "A2A", "tool", "Tool", "agent", "Agent", "skill",
        "Skill", "card", "Card",
    ];
    let source = include_str!("../planeverbs.rs");
    let code: String = source
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for needle in BANNED {
        assert!(
            !code.contains(needle),
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
    let source = include_str!("../planeverbs.rs");
    let code: String = source
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for needle in [
        "match plane",
        "match P::PLANE",
        "if plane ==",
        "Plane::Mcp",
        "Plane::A2a",
    ] {
        assert!(
            !code.contains(needle),
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

