// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::net::SocketAddr;
use std::sync::Arc;

#[path = "../../../crates/busbar/src/root/tests/test_plugins.rs"]
mod plugins;

fn app() -> Arc<busbar_kernel::state::App> {
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
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("installed-door-route");
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
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
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
    .expect("the actual product builds the door deployment");
    drop(limits);
    drop(rotate);
    Arc::new(app)
}

const LEDGER_PATHS: &[&str] = &[
    "/api/v1/admin/ledger/totals",
    "/api/v1/admin/ledger/checkpoints",
    "/api/v1/admin/ledger/reconciliation",
    "/api/v1/admin/ledger/migration",
    "/api/v1/admin/ledger/openapi.json",
];

const A_PATH_THAT_DOES_NOT_EXIST: &str = "/api/v1/admin/nope";

/// One response, reduced to the three things the oracle compares.
#[derive(Debug, PartialEq, Eq)]
struct Answer {
    status: u16,
    content_type: Option<String>,
    body: String,
}

async fn ask(addr: SocketAddr, path: &str) -> Answer {
    let response = reqwest::Client::new()
        .get(format!("http://{addr}{path}"))
        .send()
        .await
        .expect("the surface answers");
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);
    let body = response.text().await.expect("a body");
    Answer {
        status,
        content_type,
        body,
    }
}

#[tokio::test]
async fn the_legacy_admin_surface_has_never_heard_of_a_ledger_path() {
    busbar_core_admin::install();

    let app = app();
    let (_data, admin, _handle) =
        busbar_kernel::build_split_routers_with_limits(app, 1 << 20, 0, false);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a port");
    let addr = listener.local_addr().expect("an address");
    let serving = tokio::spawn(async move { axum::serve(listener, admin).await });

    let unknown = ask(addr, A_PATH_THAT_DOES_NOT_EXIST).await;
    assert_eq!(
        unknown.status, 404,
        "the control is not the unknown-path answer this test compares against"
    );

    for path in LEDGER_PATHS {
        assert_eq!(
            ask(addr, path).await,
            unknown,
            "{path} does not answer the way an unknown admin path answers"
        );
    }

    let known = ask(addr, "/api/v1/admin/info").await;
    assert_ne!(
        known.status, 404,
        "the surface answered 404 to an operation it has always had"
    );

    serving.abort();
}

#[tokio::test]
async fn the_served_document_describes_the_ledger_views_as_the_loops() {
    busbar_core_admin::install();
    let app = app();
    let (_data, admin, _handle) =
        busbar_kernel::build_split_routers_with_limits(app, 1 << 20, 0, false);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a port");
    let addr = listener.local_addr().expect("an address");
    let serving = tokio::spawn(async move { axum::serve(listener, admin).await });

    let served = ask(addr, "/api/v1/admin/openapi.json").await;
    assert_eq!(served.status, 200, "the surface serves its document");
    let document: serde_json::Value =
        serde_json::from_str(&served.body).expect("the served document is JSON");
    let paths = document["paths"].as_object().expect("it declares paths");

    for path in LEDGER_PATHS {
        let op = &paths
            .get(*path)
            .unwrap_or_else(|| panic!("{path} is a served verb and in no document"))["get"];
        assert_eq!(
            op["x-busbar-since"], "1.6.0",
            "{path} is answered by the administrative loop and the document must say so"
        );
        assert_eq!(op["x-busbar-required-scope"], "read-only");
    }

    assert!(
        paths.contains_key("/api/v1/admin/usage"),
        "the served document is not the administrative document"
    );

    serving.abort();
}
