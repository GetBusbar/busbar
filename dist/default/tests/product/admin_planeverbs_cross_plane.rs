// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

fn register_planes() {
    crate::dist_root_install::install();
}

/// THE ADMIN TRUST VERBS (method, path under the admin prefix, the scope they are admitted at),
/// frozen. The planes declare them natively (`ROUTE_ADMIN`, answered by `port_admin` through
/// core-admin's fallback); the door-era `PlaneDecl::admin_routes` hook that listed them is gone
/// (695b0f9cb6), so the frozen table itself is what the admission gate is held to.
const ADMIN_VERBS: [(&str, &str, &str); 5] = [
    ("GET", "/tools/{name}/changes", "ReadOnly"),
    ("GET", "/tools/{name}/health", "ReadOnly"),
    ("POST", "/agents/{name}/approve", "Full"),
    ("POST", "/agents/{name}/connect", "Full"),
    ("POST", "/tools/{name}/connect", "Full"),
];

#[test]
fn the_admin_route_table_method_path_scope_is_byte_identical() {
    use busbar_kernel::admin::gate::required_scope;

    register_planes();

    for (method, path, scope) in ADMIN_VERBS {
        let abs = format!("{}{}", busbar_kernel::api::ADMIN_PREFIX, path);
        let method = axum::http::Method::from_bytes(method.as_bytes()).expect("a method");
        let enforced = required_scope(&method, &abs);
        assert_eq!(
            format!("{enforced:?}"),
            scope,
            "{method} {abs}: the auth middleware ENFORCES {enforced:?}, not the frozen {scope} — \
             an admin trust verb is admitted at a scope other than its own"
        );
    }
}

/// The planes whose section the frozen admin trust verbs are mounted under.
pub(super) fn verb_planes() -> Vec<&'static busbar_kernel::plane_driver::registry::PlaneDecl> {
    register_planes();
    let planes: Vec<_> = busbar_kernel::plane_driver::registry::plane_decls()
        .iter()
        .copied()
        .filter(|d| {
            ADMIN_VERBS.iter().any(|(_, path, _)| {
                path.trim_start_matches('/').split('/').next() == Some(d.config_section)
            })
        })
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

#[tokio::test]
async fn the_audit_naming_is_derived_from_the_plane() {
    use busbar_kernel::audit::auditlog::AUDIT_LOG as AUDIT;

    use crate::root::test_plugins as plugins;
    use busbar_contract::json::JsonValueTrait as _;
    use std::sync::Arc;
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let module = crate::root::test_plugins::native_image(&library_path).name;
    let manifest = crate::root::test_plugins::native_manifest(
        "store",
        &library_path,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("admin-planeverbs-audit");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings = crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        serde_json::json!({
            "providers": {},
            "models": {},
            "auth": { "chain": [] },
            "store": { "module": module, "settings": settings },
            "advanced": {  },
        }),
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = crate::root::real_store::build_app(
        crate::root::test_plugins::plaintext_listeners(config),
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .await
    .expect("the actual product builds the audit deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, "configured-store")
        .await
        .expect("the actual configured Store binds boot rate history before activation");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let _app = crate::root::real_store::hydrated(Arc::new(app)).await;
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
            busbar_kernel::audit::auditlog::flush_pending()
                .await
                .expect("the explicitly enqueued audit record is confirmed before reading");
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
