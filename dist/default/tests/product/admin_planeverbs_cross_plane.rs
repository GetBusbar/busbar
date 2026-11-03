// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

fn register_planes() {
    crate::dist_root_install::install();
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

    use crate::root::test_plugins as plugins;
    use std::sync::Arc;
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("admin-planeverbs-audit");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the audit deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    busbar_kernel::audit::auditlog::register_test_audit_stream(&app);
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
