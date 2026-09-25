// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-PLANE ADMIN TRUST-VERB TESTS, relocated here from `src/admin/tests/planeverbs_tests.rs`:
//! the kernel's derivations (the not-found wording, the audit action/resource) and the REAL
//! `(method, path, scope)` admin route table, driven over the planes this binary links (the
//! test-linked table, `tests/linked/mod.rs`) and addressed by what each declares — never by a plane
//! key or crate spelled here ("a plugin tests itself; the kernel never tests or names a plugin").
//! The planes' own published literals (subject noun, audit kind, action words) are pinned in their
//! own suites. The source-scanning ratchets in `planeverbs_tests.rs` name no plane and stay there.

mod linked;

fn register_planes() {
    linked::install();
}

/// Every linked plane that mounts admin trust verbs, read back from the registry.
fn verb_planes() -> Vec<&'static busbar_kernel::plane::registry::PlaneDecl> {
    register_planes();
    let planes: Vec<_> = linked::planes()
        .iter()
        .copied()
        .filter(|d| d.admin_routes.is_some())
        .collect();
    assert!(
        planes.len() >= 2,
        "the test-linked roster carries at least two planes with admin trust verbs: {:?}",
        planes.iter().map(|d| d.key).collect::<Vec<_>>()
    );
    planes
}

/// THE `404` IS DERIVED FROM THE PLANE, so the wording cannot drift apart between two planes and a
/// third plane gets the same refusal for free. Driven for EVERY linked plane with admin verbs; each
/// plane pins its own subject noun literal in its own suite (busbar-mcp `codec/tests/decl_tests.rs`,
/// busbar-a2a `a2a/tests/serve_tests.rs`).
#[test]
fn the_not_found_names_the_plane_s_own_subject() {
    // `registered` now returns the neutral, wordless `PlaneVerbError::NotFound`; the frozen wording is
    // reconstructed at the CORE boundary (`to_admin_error`) from the plane decl. That each plane gets
    // its own subject noun — and gets it for free from the one map — is what this asserts.
    for decl in verb_planes() {
        let refused = busbar_kernel::admin_verbs::registered(|| None::<()>)
            .expect_err("a lookup that resolved nothing must refuse");
        let rendered =
            busbar_kernel::admin::planeverbs::to_admin_error(decl.key, "billing", refused)
                .message();
        assert!(
            rendered.contains(&format!("{} `billing`", decl.subject_noun)),
            "the `{}` refusal must name the plane's own subject noun: {rendered}",
            decl.key
        );
    }
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
/// the spine. These strings are read back by audit queries and compliance exports, so the kernel's
/// ONE recorder (`admin::planeverbs::audit`) is driven for every linked plane with admin verbs and
/// the row it writes is read back off the audit ring. Each plane pins its own published literals
/// (`<kind>`, `<kind>.connect`, `<kind>.approve`) in its own suite (busbar-mcp
/// `codec/tests/decl_tests.rs`, busbar-a2a `a2a/tests/serve_tests.rs`).
#[test]
fn the_audit_naming_is_derived_from_the_plane() {
    use busbar_kernel::audit_ring::AUDIT;
    let principal = busbar_contract::auth::AuthPrincipal(None);
    for decl in verb_planes() {
        assert_eq!(
            busbar_kernel::plane::plane_decl(decl.key).audit_kind,
            decl.audit_kind,
            "the registry resolves `{}` to its own declaration",
            decl.key
        );
        for verb in ["connect", "approve"] {
            let name = format!("k3-audit-{}-{verb}", decl.key);
            busbar_kernel::admin::planeverbs::audit(decl.key, verb, &name, "applied", &principal);
            let resource = format!("{}:{name}", decl.audit_kind);
            let rows = AUDIT.list_filtered(0, 8, None, Some(&resource));
            assert_eq!(rows.len(), 1, "one audit row on `{resource}`: {rows:?}");
            assert_eq!(
                rows[0].action,
                format!("{}.{verb}", decl.audit_kind),
                "the action word is `<kind>.<verb>` for `{}`",
                decl.key
            );
        }
    }
}
