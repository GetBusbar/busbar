// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-PLANE ADMIN TRUST-VERB TESTS, relocated here from `src/admin/tests/planeverbs_tests.rs`
//! (the "fix the 38" pass after the A6/HostCtx dev-dependency-cycle cleanup): these three tests pin
//! the REAL `mcp`/`a2a` planes' own vocabulary — `plane_decl("mcp").subject_noun ==
//! "MCP server"`/`audit_kind == "mcp_server"`, `plane_decl("a2a")`'s equivalents, and the REAL
//! `(method, path, scope)` admin route table `busbar_mcp`/`busbar_a2a` mount. That is real plane
//! BEHAVIOUR — core naming those literals to fake it, even behind a synthetic `#[cfg(test)]` decl,
//! is exactly what `cargo xtask gate construction`'s `neutral-no-dialect` rule (ceiling 0) forbids.
//! The other three tests in `planeverbs_tests.rs` (the source-scanning "no plane named in the shared
//! surface's code" ratchets, and the untouched-passthrough test) name no plane key at all and stay
//! there.

fn register_planes() {
    busbar_mcp::testkit::install_test_seams();
    busbar_a2a::testkit::install_test_seams();
}

/// THE `404` IS DERIVED FROM THE PLANE, so the wording cannot drift apart between two planes and a
/// third plane gets the same refusal for free.
#[test]
fn the_not_found_names_the_plane_s_own_subject() {
    register_planes();
    // `registered` now returns the neutral, wordless `PlaneVerbError::NotFound`; the frozen wording is
    // reconstructed at the CORE boundary (`to_admin_error`) from the plane decl. That the two planes
    // still get their own subject noun — and get it for free from the one map — is what this asserts.
    let refused = busbar_kernel::admin_verbs::registered(|| None::<()>)
        .expect_err("a lookup that resolved nothing must refuse");
    let rendered = busbar_kernel::admin::planeverbs::to_admin_error("mcp", "billing", refused).message();
    assert!(
        rendered.contains("MCP server `billing`"),
        "the refusal must name the plane's own subject noun: {rendered}"
    );

    let refused = busbar_kernel::admin_verbs::registered(|| None::<()>)
        .expect_err("a lookup that resolved nothing must refuse");
    let rendered = busbar_kernel::admin::planeverbs::to_admin_error("a2a", "planner", refused).message();
    assert!(
        rendered.contains("fronted agent `planner`"),
        "the refusal must name the plane's own subject noun: {rendered}"
    );
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
    use busbar_kernel::admin::v1::contract::{required_scope, Scope};
    use busbar_kernel::admin_verbs::AdminScope;
    use busbar_plugin::cold::endpoint::RouteMethod;

    register_planes();

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
    for decl in busbar_kernel::plane::registry::plane_decls() {
        let Some(admin_routes) = decl.admin_routes else {
            continue;
        };
        // The specs' paths/methods are static; the `&dyn Any` slot is unread by the admin verbs (they
        // read the request's own snapshot at call time), so a unit placeholder drives the enumeration.
        for spec in admin_routes(&() as &dyn std::any::Any) {
            let abs = format!("{}{}", busbar_kernel::api::ADMIN_PREFIX, spec.path);
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
    register_planes();
    assert_eq!(
        busbar_kernel::plane::plane_decl("mcp").audit_kind,
        "mcp_server"
    );
    assert_eq!(
        busbar_kernel::plane::plane_decl("a2a").audit_kind,
        "a2a_agent"
    );
    assert_eq!(
        format!(
            "{}.{}",
            busbar_kernel::plane::plane_decl("mcp").audit_kind,
            "connect"
        ),
        "mcp_server.connect",
        "the MCP connect action word is a published audit string and may not change shape"
    );
    assert_eq!(
        format!(
            "{}.{}",
            busbar_kernel::plane::plane_decl("a2a").audit_kind,
            "connect"
        ),
        "a2a_agent.connect"
    );
    assert_eq!(
        format!(
            "{}.{}",
            busbar_kernel::plane::plane_decl("a2a").audit_kind,
            "approve"
        ),
        "a2a_agent.approve"
    );
}
