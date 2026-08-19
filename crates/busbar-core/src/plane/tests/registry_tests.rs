// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE-KIND SEAM, proven the way the protocol registry proves itself: by folding a
//! declaration core has never heard of through the SAME functions production folds the built-ins
//! through, and showing the difference reaches a production refusal.
//!
//! These tests drive [`merged_boot_plane_decls`] and [`config_sections_from`] directly rather than
//! the process `OnceLock`, for the reason the protocol registry's own tests give: a process
//! singleton can be initialised once per test binary, which would leave the fold's order and skip
//! rules provable only by booting binaries.

use crate::plane::config::{config_sections_from, refuse_cross_plane_reference};
use crate::plane::registry::{builtin_plane_decls, merged_boot_plane_decls, PlaneDecl};
use crate::plane::Plane;

/// A PLANE BUSBAR DOES NOT HAVE. Nothing in core names it, nothing in core has an enum variant for
/// it, and no `match` anywhere has an arm for it — which is precisely the property under test.
/// Stands in for the `busbar-plane-a2a` crate's own `PLANE_DECL`.
static WIDGET_PLANE: PlaneDecl = PlaneDecl {
    key: "widget",
    config_section: "widgets",
    scope_kinds: &["widget"],
    subject_noun: "fronted widget",
    audit_kind: "widget_thing",
    wire_format_names: || &["widgetrpc"],
};

fn installed() -> Vec<&'static PlaneDecl> {
    merged_boot_plane_decls(&[&WIDGET_PLANE], builtin_plane_decls())
}

/// THE HEADLINE BEHAVIOUR. A plane registered from OUTSIDE core changes what a production config
/// refusal says — `widgets.foo` in a `hooks:` list is refused as a CROSS-PLANE reach, naming the
/// section, with nothing written for `widget` anywhere in this crate.
///
/// Watched RED before the seam existed: with the built-ins alone the same reference is refused as
/// `NotBare` (a dotted name naming no section busbar knows), which is a different sentence telling
/// the operator to do a different thing.
#[test]
fn an_installed_plane_reaches_the_cross_plane_refusal() {
    let sections = config_sections_from(&installed());

    let refusal = refuse_cross_plane_reference("widgets.reporter", "widgets.audit", &sections)
        .expect_err("a reach onto a registered plane's section is refused");
    assert!(
        refusal.contains("reaches onto the `widgets:` plane"),
        "the refusal must name the registered plane's own section: {refusal}"
    );
    assert!(
        refusal.contains("Did you mean the hook `audit`?"),
        "and must offer the bare name the operator probably meant: {refusal}"
    );

    // THE CONTROL: without the registration, core has no idea `widgets:` is a plane, and the same
    // reference gets the generic not-a-bare-name sentence instead. This is what the seam changed.
    let builtin_only = config_sections_from(builtin_plane_decls());
    let refusal = refuse_cross_plane_reference("widgets.reporter", "widgets.audit", &builtin_only)
        .expect_err("still refused, but for a different reason");
    assert!(
        !refusal.contains("reaches onto"),
        "unregistered: must NOT be diagnosed as a cross-plane reach: {refusal}"
    );
    assert!(
        refusal.contains("is not a bare name"),
        "unregistered: the generic diagnosis: {refusal}"
    );
}

/// INSTALLED FOLD AHEAD OF BUILT-INS, and the built-ins' own operator-visible order is
/// BYTE-IDENTICAL either side of the fold — the hard property the protocol control earned, restated
/// on the plane axis. A plane becoming a crate must not renumber the sections an operator reads.
#[test]
fn installed_planes_fold_ahead_and_the_builtin_order_is_unchanged() {
    let keys: Vec<&str> = installed().iter().map(|d| d.key).collect();
    assert_eq!(keys, vec!["widget", "llm", "mcp", "a2a"]);

    let builtin_keys: Vec<&str> = builtin_plane_decls().iter().map(|d| d.key).collect();
    assert_eq!(
        builtin_keys,
        vec!["llm", "mcp", "a2a"],
        "the layering order Plane::ALL has always reported"
    );
    assert_eq!(
        &keys[1..],
        builtin_keys.as_slice(),
        "an installed plane prepends; it must not reorder the built-ins behind it"
    );

    // The same property where it is actually operator-visible: the config-section list.
    let sections = config_sections_from(&installed());
    assert_eq!(sections[0], "widgets");
    assert_eq!(
        &sections[1..4],
        &["pools", "tools", "agents"],
        "the plane sections keep their layering order behind the installed one"
    );
    assert_eq!(
        config_sections_from(builtin_plane_decls()),
        sections[1..].to_vec(),
        "removing the installed plane leaves the built-in grammar byte-identical"
    );
}

/// A SAME-KEY RE-REGISTRATION IS SKIPPED, not asserted on — the `test-support` shape, where a build
/// compiles an extracted plane back in as a built-in while the composition root still installs the
/// crate's own copy. The FIRST (installed) copy wins and the list does not grow.
#[test]
fn a_same_key_registration_is_skipped_and_the_first_copy_wins() {
    static A2A_FROM_THE_CRATE: PlaneDecl = PlaneDecl {
        key: "a2a",
        config_section: "agents",
        scope_kinds: &["agent"],
        subject_noun: "fronted agent",
        audit_kind: "a2a_agent",
        wire_format_names: || &["jsonrpc"],
    };

    let folded = merged_boot_plane_decls(&[&A2A_FROM_THE_CRATE], builtin_plane_decls());
    let keys: Vec<&str> = folded.iter().map(|d| d.key).collect();
    assert_eq!(
        keys,
        vec!["a2a", "llm", "mcp"],
        "one entry per key: the built-in a2a row is skipped, not duplicated"
    );
    assert!(
        std::ptr::eq(folded[0], &A2A_FROM_THE_CRATE),
        "the installed copy is the one that survives"
    );
    // And the grammar does not gain a duplicate section from the doubled registration.
    let sections = config_sections_from(&folded);
    assert_eq!(
        sections.iter().filter(|s| **s == "agents").count(),
        1,
        "`agents:` appears once: {sections:?}"
    );
}

/// ONE SOURCE PER FACT. The enum's accessors now READ their declaration, so a fact cannot be stated
/// twice and drift. This pins the direction: every `Plane` variant resolves to a built-in decl, and
/// what it answers is exactly what that decl says.
#[test]
fn every_plane_variant_answers_from_its_declaration() {
    for plane in Plane::ALL {
        let decl = plane.decl();
        assert_eq!(plane.key(), decl.key);
        assert_eq!(plane.config_section(), decl.config_section);
        assert_eq!(plane.scope_kinds(), decl.scope_kinds);
        assert_eq!(plane.subject_noun(), decl.subject_noun);
        assert_eq!(plane.audit_kind(), decl.audit_kind);
        assert_eq!(plane.wire_format_names(), (decl.wire_format_names)());
    }
    // The values themselves are unchanged by the rewiring — the operator-visible strings that
    // metrics, audit records and grants are keyed by.
    assert_eq!(Plane::Llm.key(), "llm");
    assert_eq!(Plane::Mcp.audit_kind(), "mcp_server");
    assert_eq!(Plane::A2a.audit_kind(), "a2a_agent");
    assert_eq!(Plane::A2a.subject_noun(), "fronted agent");
    assert_eq!(Plane::Mcp.scope_kinds(), &["mcp_server", "mcp_tool"]);
}

/// THE LLM PLANE'S WIRE-FORMAT LIST IS STILL READ OFF THE LIVE PROTOCOL REGISTRY, through the decl's
/// function pointer. This is the join between the two registries, and it is what keeps the
/// superset-IR rule a RULE: a seventh dialect moves this list with nothing edited on the plane axis.
#[test]
fn the_llm_decl_reads_the_protocol_registry() {
    assert_eq!(
        Plane::Llm.wire_format_names(),
        crate::proto::known_protocols(),
        "the LLM plane's dialects are the registered protocols, not a literal"
    );
    assert!(
        Plane::Llm.wire_formats() > 1,
        "and the superset-IR threshold is computed from that list"
    );
}

/// NO TWO PLANES MAY SHARE A SCOPE KIND OR AN AUDIT KIND — the collision rule the enum's docs state,
/// now enforced over the FOLDED list rather than the three hardcoded variants. A registered plane
/// that claimed `agent` as a scope kind would have its grants admit A2A traffic; that is a boot-time
/// refusal's job, and this pins the property the refusal would defend.
#[test]
fn a_registered_plane_cannot_collide_with_a_builtin_vocabulary() {
    let folded = installed();
    let mut scope_kinds: Vec<&str> = folded
        .iter()
        .flat_map(|d| d.scope_kinds.iter().copied())
        .collect();
    let before = scope_kinds.len();
    scope_kinds.sort_unstable();
    scope_kinds.dedup();
    assert_eq!(
        before,
        scope_kinds.len(),
        "scope kinds collide: {scope_kinds:?}"
    );

    let mut audit_kinds: Vec<&str> = folded.iter().map(|d| d.audit_kind).collect();
    let before = audit_kinds.len();
    audit_kinds.sort_unstable();
    audit_kinds.dedup();
    assert_eq!(
        before,
        audit_kinds.len(),
        "audit kinds collide: {audit_kinds:?}"
    );

    let mut sections: Vec<&str> = folded.iter().map(|d| d.config_section).collect();
    let before = sections.len();
    sections.sort_unstable();
    sections.dedup();
    assert_eq!(
        before,
        sections.len(),
        "config sections collide: {sections:?}"
    );
}
