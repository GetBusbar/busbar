// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_kernel as kernel;
use busbar_kernel::plane_driver::live_standing;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[test]
fn a_role_bound_standing_is_rechecked_against_the_live_snapshot_bindings() {
    let mut roles = std::collections::BTreeMap::new();
    roles.insert("eng".to_string(), kernel::config::RoleBindingCfg::default());
    let mut rb = kernel::config::RoleBindings::new();
    rb.insert("idp".to_string(), roles);
    let principal = kernel::auth::Principal {
        id: "alice@example.com".to_string(),
        name: None,
        roles: vec!["eng".to_string()],
        ttl_secs: None,
    };
    let key = kernel::governance::synthesize_bound_key("idp", &principal, &rb).expect("bound");
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
    let directory = plugins::scratch(&format!(
        "plane-host-role-{}",
        kernel::door::op_id().counter()
    ));
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
    let deploy = kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules =
        Arc::new(crate::root::door_steps::Rules::default()) as Arc<dyn kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the host deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let without_bindings = Arc::new(app.clone());
    assert!(without_bindings.role_bindings.is_empty());
    app.role_bindings = rb;
    let handle = Arc::new(kernel::state::AppHandle::new(Arc::new(app)));
    let standing = live_standing(Arc::clone(&handle));

    let now = standing(&key, 1_700_000_000).expect("the binding stands");
    assert_eq!(now.id, "alice@example.com");

    handle.swap(without_bindings);
    assert!(
        standing(&key, 1_700_000_000).is_none(),
        "the binding is gone from the live snapshot, so the principal no longer stands"
    );
}

fn hook_accesses_under(
    journal: &kernel::audit::amend::NodeAmendments,
    op: &str,
) -> Vec<kernel::audit::amend::Access> {
    journal
        .recent()
        .into_iter()
        .filter_map(|a| match a.body {
            kernel::audit::amend::AmendBody::Access(x) if x.op_class.as_str() == op => Some(x),
            _ => None,
        })
        .collect()
}

#[test]
fn the_host_hook_read_port_seals_one_access_amendment_on_the_node_journal() {
    const OP: &str = "access-host-port";
    let build = || {
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
        let directory = plugins::scratch(&format!(
            "plane-host-audit-{}",
            kernel::door::op_id().counter()
        ));
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
        let deploy = kernel::config::deploy_from_deserializer(serde_json::json!({
            "providers": {},
            "models": {},
            "auth": { "chain": [], "admin_auth": [] },
            "store": { "module": module, "settings": settings },
            "advanced": { "allow_destinations": ["127.0.0.1"] },
        }))
        .expect("the product deployment parses");
        let config = kernel::config::resolve(&deploy, &Default::default())
            .expect("the product deployment resolves");
        let plugin_config = crate::root::test_plugins::trusted_config(&directory);
        let rules = Arc::new(crate::root::door_steps::Rules::default())
            as Arc<dyn kernel::appbuild::RootRules>;
        let (app, rotate, limits) = kernel::build_app_from_config(
            config,
            plugin_config,
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .expect("the actual product builds the host deployment");
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        Arc::new(app)
    };
    let app = build();
    let other = build();
    let host = kernel::plane_driver::engine_host(&app);
    host.hook_read("port-hook", Some("key-1"), OP, true);
    assert!(
        hook_accesses_under(&other.amendments, OP).is_empty(),
        "another node's journal recorded this node's hook read"
    );
    let seen = hook_accesses_under(&app.amendments, OP);
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].name, "port-hook");
    assert_eq!(
        seen[0].subject,
        kernel::audit::amend::Subject::PrincipalId("key-1".to_string())
    );
    assert_eq!(
        seen[0].fields,
        vec!["content".to_string(), "identity".to_string()]
    );
}
