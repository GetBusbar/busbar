// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use axum::body::Bytes;
use busbar_contract::plane_calls::PlaneCalls;
use busbar_kernel as kernel;
use busbar_plugin_loader::dispatch::kinds::plane::{open_door, Plane};
use busbar_plugin_loader::dispatch::plane_calls::PlaneInstance;
use busbar_plugin_loader::dispatch::{load_linked, Bind, ConnTable, LinkedRow, NoSink};
use kernel::plane_driver::serve::{AdminServe, ServeRoute, ServeTable};

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

fn actual_mcp_health_calls(
    app: &kernel::state::App,
    config: &kernel::config::RootCfg,
) -> (Arc<dyn PlaneCalls>, Vec<ServeRoute>) {
    let late = crate::root::serve::LateServices::new();
    let (credentials, _credential_handle) = crate::root::credentials::AppCredentials::late();
    crate::root::serve::compose(
        crate::root::connector::dest_judge(config),
        &late,
        credentials,
    );
    let declarations: Vec<_> = kernel::plane_driver::registry::plane_decls()
        .iter()
        .map(|decl| &decl.declaration)
        .collect();
    crate::root::serve::attach(
        &late,
        app.governance.as_deref(),
        None,
        &app.demotion_record,
        &declarations,
    );
    let dispatcher = Arc::new(crate::root::dispatch::build(2, &late));
    crate::root::connector::install_io(&dispatcher);
    let row = LinkedRow::of(busbar_plane_mcp::door).expect("the actual MCP door statement");
    let plugin = Arc::new(
        load_linked::<Plane>(
            &row,
            Bind {
                instance: format!("plane-serve-{}", kernel::door::op_id().counter()).into(),
                max_inflight_cap: 64,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: ConnTable::Host(crate::root::connector::the().clone()),
            },
        )
        .expect("the actual MCP door binds to the root host"),
    );
    let snapshot = open_door(
        &plugin,
        br#"{"x":{"url":"http://127.0.0.1:1","allow_private":true,"pin":{"mechanism":"unpinned"}}}"#,
        b"{}",
        None,
    ).expect("the actual MCP door opens its registered health subject");
    let routes = snapshot
        .admin_routes
        .iter()
        .map(|route| ServeRoute {
            verb: route.verb.clone(),
            target: route.target.clone(),
            flags: route.flags,
            audit_verb: route.audit_verb.clone(),
        })
        .collect();
    (Arc::new(PlaneInstance::new(plugin, dispatcher, 0)), routes)
}

fn health_table(instance: &str, calls: Arc<dyn PlaneCalls>, routes: &[ServeRoute]) -> ServeTable {
    ServeTable {
        instance: instance.to_string(),
        audit_kind: "mcp".to_string(),
        calls,
        caps: kernel::plane_driver::BufferCaps::default(),
        routes: routes
            .iter()
            .map(|route| {
                let subject = route
                    .target
                    .strip_prefix("/tools/")
                    .expect("the actual MCP admin route carries its tools mount");
                ServeRoute {
                    target: format!("/{instance}/{subject}"),
                    ..route.clone()
                }
            })
            .collect(),
        records: None,
    }
}

fn asked<'a>(path: &'a str, headers: &'a axum::http::HeaderMap) -> AdminServe<'a> {
    AdminServe {
        method: "GET",
        path,
        query: None,
        headers,
        consumed: None,
        principal: None,
    }
}

#[tokio::test]
async fn two_apps_lent_two_tables_each_serve_only_their_own_instance() {
    let _publishing = crate::root::PUBLISHING.lock().await;
    let build = || {
        crate::dist_root_install::install();
        let library_path = crate::root::test_plugins::application_store_library();
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
        let directory =
            plugins::scratch(&format!("plane-serve-{}", kernel::door::op_id().counter()));
        let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
        std::fs::write(directory.join("store.tar.gz"), archive)
            .expect("stage the actual store archive");
        let settings: serde_json::Value =
            crate::root::test_plugins::application_store_settings(&directory);
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
        let calls_config = kernel::config::resolve(&deploy, &Default::default())
            .expect("the same normal deployment resolves for host services");
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
        (app, calls_config)
    };
    let (mut a, config) = build();
    let (mut b, _) = build();
    let (unlent, _) = build();
    let (calls, routes) = actual_mcp_health_calls(&a, &config);
    let (lent_a, lent_b) = (
        kernel::plane_driver::serve::ServeTables::default(),
        kernel::plane_driver::serve::ServeTables::default(),
    );
    lent_a
        .publish(health_table("lent-a", calls.clone(), &routes), &[])
        .expect("publishes");
    lent_b
        .publish(health_table("lent-b", calls, &routes), &[])
        .expect("publishes");
    a.serve_tables = lent_a;
    b.serve_tables = lent_b;
    let headers = axum::http::HeaderMap::new();
    for (on, own, other) in [(&a, "lent-a", "lent-b"), (&b, "lent-b", "lent-a")] {
        let (own, other) = (format!("/{own}/x/health"), format!("/{other}/x/health"));
        let served = on
            .serve_tables
            .served_at(asked(&own, &headers), Bytes::new())
            .await;
        assert_eq!(
            served
                .expect("its own instance names it")
                .expect("served")
                .status,
            200
        );
        let theirs = on
            .serve_tables
            .served_at(asked(&other, &headers), Bytes::new())
            .await;
        assert!(
            theirs.is_none(),
            "{other}: the other root's instance is not on this table"
        );
    }
    for path in ["/lent-a/x/health", "/lent-b/x/health"] {
        let none = unlent
            .serve_tables
            .served_at(asked(path, &headers), Bytes::new())
            .await;
        assert!(
            none.is_none(),
            "{path}: a generation lent no table serves nothing"
        );
    }
}

#[tokio::test]
async fn a_rebuild_carries_the_published_admin_table() {
    let _publishing = crate::root::PUBLISHING.lock().await;
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
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
    let directory = plugins::scratch(&format!("plane-serve-{}", kernel::door::op_id().counter()));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
    let calls_config = kernel::config::resolve(&deploy, &Default::default())
        .expect("the same normal deployment resolves for host services");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules =
        Arc::new(crate::root::door_steps::Rules::default()) as Arc<dyn kernel::appbuild::RootRules>;
    let (boot, rotate, limits) = kernel::build_app_from_config(
        config,
        plugin_config.clone(),
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

    let (calls, routes) = actual_mcp_health_calls(&boot, &calls_config);
    let headers = axum::http::HeaderMap::new();
    let served = |on: &kernel::state::App, path: &str| {
        let headers = headers.clone();
        let tables = on.serve_tables.clone();
        let path = path.to_string();
        async move {
            tables
                .served_at(asked(&path, &headers), Bytes::new())
                .await
                .map(|answer| answer.expect("served").status)
        }
    };
    assert_eq!(
        served(&boot, "/carried/x/health").await,
        None,
        "the boot generation starts with an empty table"
    );
    boot.serve_tables
        .publish(health_table("carried", calls.clone(), &routes), &[])
        .expect("publishes");
    let (applied, rotate, limits) = kernel::build_app_from_config(
        kernel::config::resolve(&deploy, &Default::default())
            .expect("the same normal deployment resolves"),
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        Some(&boot),
        &rules,
    )
    .expect("rebuild");
    limits.keep().expect("the rebuilt product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    applied
        .serve_tables
        .publish(health_table("after", calls, &routes), &[])
        .expect("publishes");
    for on in [&boot, &applied] {
        for path in ["/carried/x/health", "/after/x/health"] {
            assert_eq!(served(on, path).await, Some(200), "{path}");
        }
    }
}
