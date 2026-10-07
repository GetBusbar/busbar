// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-PLANE ADMIN TRUST-VERB TESTS: the REAL `(method, path, scope)` admin route table against the
//! scope matrix the kernel's admin gate enforces (`admin::gate::required_scope`), driven over the planes this binary links (the
//! test-linked table, `tests/linked/mod.rs`) and addressed by what each declares — never by a plane
//! key or crate spelled here ("a plugin tests itself; the kernel never tests or names a plugin").
//! The not-found wording and the audit naming moved with the plane-verb envelope to
//! `busbar-core-admin` (`src/tests/planeverbs_tests.rs`, P2 D4).

mod linked;

fn register_planes() {
    linked::install();
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
    use busbar_contract::abi::mechanism::route::RouteMethod;
    use busbar_contract::authz::Scope;
    use busbar_kernel::admin::gate::required_scope;
    use busbar_kernel::admin_verbs::AdminScope;

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
