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

/// THE `404` IS DERIVED FROM THE PLANE, so the wording cannot drift apart between two planes and a
/// third plane gets the same refusal for free.
#[test]
fn the_not_found_names_the_plane_s_own_subject() {
    let refused = registered("mcp", "billing", || None::<()>)
        .expect_err("a lookup that resolved nothing must refuse");
    let rendered = format!("{refused:?}");
    assert!(
        rendered.contains("MCP server `billing`"),
        "the refusal must name the plane's own subject noun: {rendered}"
    );

    let refused = registered("a2a", "planner", || None::<()>)
        .expect_err("a lookup that resolved nothing must refuse");
    let rendered = format!("{refused:?}");
    assert!(
        rendered.contains("fronted agent `planner`"),
        "the refusal must name the plane's own subject noun: {rendered}"
    );
}

/// A LOOKUP THAT RESOLVED IS PASSED STRAIGHT THROUGH. The shared rule decides the refusal and
/// nothing else; it never inspects, rewrites or re-validates what the plane found.
#[test]
fn a_resolved_lookup_is_returned_untouched() {
    let found = registered("mcp", "billing", || Some(("entry", "cfg")))
        .expect("a lookup that resolved must not be refused");
    assert_eq!(found, ("entry", "cfg"));
}

/// THE AUDIT ACTION AND RESOURCE are `<kind>.<verb>` on `<kind>:<name>`, with the kind coming off
/// the spine. These exact strings are read back by audit queries and compliance exports, so they are
/// pinned here rather than left to whatever `format!` happens to produce.
#[test]
fn the_audit_naming_is_derived_from_the_plane() {
    assert_eq!(crate::plane::builtin_decl("mcp").audit_kind, "mcp_server");
    assert_eq!(crate::plane::builtin_decl("a2a").audit_kind, "a2a_agent");
    assert_eq!(
        format!(
            "{}.{}",
            crate::plane::builtin_decl("mcp").audit_kind,
            "connect"
        ),
        "mcp_server.connect",
        "the MCP connect action word is a published audit string and may not change shape"
    );
    assert_eq!(
        format!(
            "{}.{}",
            crate::plane::builtin_decl("a2a").audit_kind,
            "connect"
        ),
        "a2a_agent.connect"
    );
    assert_eq!(
        format!(
            "{}.{}",
            crate::plane::builtin_decl("a2a").audit_kind,
            "approve"
        ),
        "a2a_agent.approve"
    );
}
