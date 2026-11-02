// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[tokio::test]
async fn a_door_route_installed_at_construction_is_answered_ahead_of_the_fallback() {
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
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);

    const DOOR: &str = "/door-route-test/call";
    let route = busbar_kernel::plane_routes::PlaneRouteSpec {
        path: DOOR.to_string(),
        method: busbar_contract::abi::mechanism::route::RouteMethod::Post,
        auth: busbar_contract::abi::mechanism::route::RouteAuth::None,
        handler: Arc::new(|ctx: busbar_kernel::plane_routes::PlaneReqCtx| {
            Box::pin(async move {
                let body = format!("door {} {}", ctx.path, String::from_utf8_lossy(&ctx.body));
                axum::response::Response::new(axum::body::Body::from(body))
            })
        }),
    };
    let router = busbar_kernel::build_split_routers_serving(
        app,
        vec![route],
        busbar_kernel_egress::upstream::max_translate_body_bytes(),
        busbar_kernel::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        busbar_kernel::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    )
    .0;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let response = reqwest::Client::new()
        .post(format!("http://{addr}{DOOR}"))
        .body("piece")
        .send()
        .await
        .unwrap();
    let code = response.status().as_u16();
    let body = response.text().await.unwrap();
    server.abort();
    assert_eq!(code, 200, "the installed door route answers: {body}");
    assert_eq!(body, format!("door {DOOR} piece"));
}
