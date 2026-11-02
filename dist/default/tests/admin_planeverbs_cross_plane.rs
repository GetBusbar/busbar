// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod linked;

fn register_planes() {
    linked::install();
}

#[test]
fn the_admin_route_table_method_path_scope_is_byte_identical() {
    use busbar_contract::abi::mechanism::route::RouteMethod;
    use busbar_contract::authz::Scope;
    use busbar_kernel::admin::gate::required_scope;
    use busbar_kernel::admin_verbs::AdminScope;

    register_planes();

    let expected: Vec<(&str, &str, &str)> = vec![
        ("GET", "/api/v1/admin/tools/{name}/changes", "ReadOnly"),
        ("GET", "/api/v1/admin/tools/{name}/health", "ReadOnly"),
        ("POST", "/api/v1/admin/agents/{name}/approve", "Full"),
        ("POST", "/api/v1/admin/agents/{name}/connect", "Full"),
        ("POST", "/api/v1/admin/tools/{name}/connect", "Full"),
    ];

    let mut actual: Vec<(String, String, String)> = Vec::new();
    for decl in busbar_kernel::plane_driver::registry::plane_decls() {
        let Some(admin_routes) = decl.admin_routes else {
            continue;
        };

        for spec in admin_routes(decl, &() as &dyn std::any::Any) {
            let abs = format!("{}{}", busbar_kernel::api::ADMIN_PREFIX, spec.path);
            let method = match spec.method {
                RouteMethod::Get => axum::http::Method::GET,
                RouteMethod::Post => axum::http::Method::POST,
                RouteMethod::Put => axum::http::Method::PUT,
                RouteMethod::Patch => axum::http::Method::PATCH,
                RouteMethod::Delete => axum::http::Method::DELETE,
            };

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

fn verb_planes() -> Vec<&'static busbar_kernel::plane_driver::registry::PlaneDecl> {
    register_planes();
    let planes: Vec<_> = busbar_kernel::plane_driver::registry::plane_decls()
        .iter()
        .copied()
        .filter(|d| d.admin_routes.is_some())
        .collect();
    assert!(
        planes.len() >= 2,
        "the linked roster carries at least two planes with admin trust verbs: {:?}",
        planes.iter().map(|d| d.key).collect::<Vec<_>>()
    );
    planes
}

#[test]
fn the_not_found_names_the_plane_s_own_subject() {
    for decl in verb_planes() {
        let refused = busbar_core_admin::planeverbs::registered(|| None::<()>)
            .expect_err("a lookup that resolved nothing must refuse");
        let rendered =
            busbar_core_admin::planeverbs::to_admin_error(decl.key, "billing", refused).message();
        assert!(
            rendered.contains(&format!("{} `billing`", decl.subject_noun)),
            "the `{}` refusal must name the plane's own subject noun: {rendered}",
            decl.key
        );
    }
}

#[test]
fn the_audit_naming_is_derived_from_the_plane() {
    use busbar_kernel::audit::auditlog::AUDIT_LOG as AUDIT;

    let _ = busbar_kernel_testkit::test_support::TestApp::new().build();
    let principal = busbar_contract::auth::AuthPrincipal(None);
    for decl in verb_planes() {
        assert_eq!(
            busbar_kernel::plane_driver::dispatch::plane_decl(decl.key).audit_kind,
            decl.audit_kind,
            "the registry resolves `{}` to its own declaration",
            decl.key
        );
        for verb in ["connect", "approve"] {
            let name = format!("k3-audit-{}-{verb}", decl.key);
            busbar_core_admin::planeverbs::audit(decl.key, verb, &name, "applied", &principal);
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
