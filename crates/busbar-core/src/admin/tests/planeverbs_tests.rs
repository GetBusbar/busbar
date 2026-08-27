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
    // `registered` now returns the neutral, wordless `PlaneVerbError::NotFound`; the frozen wording is
    // reconstructed at the CORE boundary (`to_admin_error`) from the plane decl. That the two planes
    // still get their own subject noun — and get it for free from the one map — is what this asserts.
    let refused =
        registered(|| None::<()>).expect_err("a lookup that resolved nothing must refuse");
    let rendered = super::to_admin_error("mcp", "billing", refused).message();
    assert!(
        rendered.contains("MCP server `billing`"),
        "the refusal must name the plane's own subject noun: {rendered}"
    );

    let refused =
        registered(|| None::<()>).expect_err("a lookup that resolved nothing must refuse");
    let rendered = super::to_admin_error("a2a", "planner", refused).message();
    assert!(
        rendered.contains("fronted agent `planner`"),
        "the refusal must name the plane's own subject noun: {rendered}"
    );
}

/// A LOOKUP THAT RESOLVED IS PASSED STRAIGHT THROUGH. The shared rule decides the refusal and
/// nothing else; it never inspects, rewrites or re-validates what the plane found.
#[test]
fn a_resolved_lookup_is_returned_untouched() {
    let found =
        registered(|| Some(("entry", "cfg"))).expect("a lookup that resolved must not be refused");
    assert_eq!(found, ("entry", "cfg"));
}

/// THE SCOPE RATCHET: boot the WHOLE admin trust-verb route table from the plane decls the admin
/// router mounts from, and assert the set of `(method, absolute path, required_scope)` rows is
/// byte-identical to the frozen table. This is the ADMIN-3 non-negotiable guard: the route-mount seam
/// re-registers each plane verb through a core adapter, and if that adapter (or a plane's spec) altered
/// a verb's `(method, path)` — mounting `connect`/`approve` as a `GET`, say — the auth middleware's
/// `required_scope(method, path)` would silently drop it from `Full` to `ReadOnly`, a privilege
/// escalation invisible to a green build.
///
/// It is NOT a tautology: `required_scope` is the REAL enforcement function the middleware calls, run
/// here over the REAL specs the adapter mounts (`decl.admin_routes`, the same fn the router iterates).
/// A method flip would make `required_scope` return `ReadOnly` and mismatch the frozen `Full`. The
/// declared `AdminScope` on each spec is additionally cross-checked against the enforced scope, so a
/// spec cannot ship a mutation that DECLARES `ReadOnly` either.
#[test]
fn the_admin_route_table_method_path_scope_is_byte_identical() {
    use crate::admin::v1::contract::{required_scope, Scope};
    use busbar_plugin::cold::http_endpoint::RouteMethod;
    use busbar_substrate::admin_verbs::AdminScope;

    // The FROZEN rows the mcp + a2a admin verbs mount at, with the scope the middleware enforces. Reads
    // are `read-only`; both `connect`s and `approve` are mutations at `full`.
    let expected: Vec<(&str, &str, &str)> = vec![
        ("GET", "/api/v1/admin/tools/{name}/changes", "ReadOnly"),
        ("GET", "/api/v1/admin/tools/{name}/health", "ReadOnly"),
        ("POST", "/api/v1/admin/agents/{name}/approve", "Full"),
        ("POST", "/api/v1/admin/agents/{name}/connect", "Full"),
        ("POST", "/api/v1/admin/tools/{name}/connect", "Full"),
    ];

    let mut actual: Vec<(String, String, String)> = Vec::new();
    for decl in crate::plane::registry::plane_decls() {
        let Some(admin_routes) = decl.admin_routes else {
            continue;
        };
        // The specs' paths/methods are static; the `&dyn Any` slot is unread by the admin verbs (they
        // read the request's own snapshot at call time), so a unit placeholder drives the enumeration.
        for spec in admin_routes(&() as &dyn std::any::Any) {
            let abs = format!("{}{}", busbar_substrate::api::ADMIN_PREFIX, spec.path);
            let method = match spec.method {
                RouteMethod::Get => axum::http::Method::GET,
                RouteMethod::Post => axum::http::Method::POST,
                RouteMethod::Put => axum::http::Method::PUT,
                RouteMethod::Patch => axum::http::Method::PATCH,
                RouteMethod::Delete => axum::http::Method::DELETE,
            };
            // The ENFORCED scope, derived by the same fn the auth middleware runs — over the real row.
            let enforced = required_scope(&method, &abs);
            let declared = match spec.scope {
                AdminScope::ReadOnly => Scope::ReadOnly,
                AdminScope::Full => Scope::Full,
            };
            assert_eq!(
                enforced,
                declared,
                "{} {abs}: the spec DECLARES {declared:?} but the auth middleware ENFORCES \
                 {enforced:?} — a route cannot declare a scope it is not admitted at",
                spec.method.as_str()
            );
            actual.push((
                spec.method.as_str().to_string(),
                abs,
                format!("{enforced:?}"),
            ));
        }
    }
    actual.sort();
    let actual_ref: Vec<(&str, &str, &str)> = actual
        .iter()
        .map(|(m, p, s)| (m.as_str(), p.as_str(), s.as_str()))
        .collect();
    assert_eq!(
        actual_ref, expected,
        "the admin trust-verb route table (method, path, required_scope) drifted from the frozen \
         set — a mounted verb changed method/path or a plane's spec list changed"
    );
}

/// THE AUDIT ACTION AND RESOURCE are `<kind>.<verb>` on `<kind>:<name>`, with the kind coming off
/// the spine. These exact strings are read back by audit queries and compliance exports, so they are
/// pinned here rather than left to whatever `format!` happens to produce.
#[test]
fn the_audit_naming_is_derived_from_the_plane() {
    assert_eq!(crate::plane::plane_decl("mcp").audit_kind, "mcp_server");
    assert_eq!(crate::plane::plane_decl("a2a").audit_kind, "a2a_agent");
    assert_eq!(
        format!(
            "{}.{}",
            crate::plane::plane_decl("mcp").audit_kind,
            "connect"
        ),
        "mcp_server.connect",
        "the MCP connect action word is a published audit string and may not change shape"
    );
    assert_eq!(
        format!(
            "{}.{}",
            crate::plane::plane_decl("a2a").audit_kind,
            "connect"
        ),
        "a2a_agent.connect"
    );
    assert_eq!(
        format!(
            "{}.{}",
            crate::plane::plane_decl("a2a").audit_kind,
            "approve"
        ),
        "a2a_agent.approve"
    );
}
