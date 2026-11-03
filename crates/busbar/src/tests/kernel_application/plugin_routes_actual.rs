// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::root::test_plugins as plugins;
use std::sync::Arc;

fn metrics_routes() -> std::sync::Arc<busbar_kernel::plugin_routes::PluginRouteTable> {
    use crate::root::loader::dispatch::{
        kinds::export::{Export, ExportFacts},
        load_dropped, rendering_of_library, Bind, ConnTable, DispatchConfig, Dispatcher, NoSink,
    };
    let path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_TEST_PROMETHEUS_CDYLIB")
            .expect("BUSBAR_TEST_PROMETHEUS_CDYLIB names the actual built metrics exporter"),
    );
    let statement = rendering_of_library(&path)
        .expect("the actual exporter statement reads")
        .expect("the actual exporter carries its statement");
    let dispatcher = std::sync::Arc::new(Dispatcher::new(DispatchConfig::default()));
    let plugin = load_dropped::<Export>(
        &path,
        &statement,
        Bind {
            instance: "serve-http-metrics".into(),
            max_inflight_cap: 64,
            sink: std::sync::Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("the actual HTTP exporter loads through its memory ABI");
    let routes = plugin
        .context::<ExportFacts>()
        .expect("the actual exporter declares its routes")
        .routes
        .clone();
    assert!(
        routes.iter().any(|route| route.path == "/metrics"),
        "the actual exporter declares the scrape route"
    );
    let exporter = std::sync::Arc::new(
        crate::root::loader::export_door::ExportInstance::open(plugin, dispatcher, b"{}")
            .expect("the actual HTTP exporter opens"),
    );
    let dispatch = busbar_kernel::export::serve_test_sink(exporter);
    let declarations = routes
        .into_iter()
        .map(|mut route| {
            // A neutral host declaration changes only admission placement: the body is
            // still handled by the actual exporter through its real dispatcher.
            if route.path == "/metrics/hooks" {
                route.auth = busbar_contract::abi::mechanism::route::RouteAuth::Admin;
            }
            busbar_kernel::plugin_routes::RouteDecl {
                owner: "serve-http-metrics".into(),
                source_instance: "serve-http-metrics".into(),
                dispatch_available: true,
                kind: busbar_kernel::plugin_routes::RouteKind::Export,
                scrape: matches!(route.path.as_str(), "/metrics" | "/metrics/hooks"),
                persistent: false,
                route,
                dispatch: dispatch.clone(),
            }
        })
        .collect();
    std::sync::Arc::new(
        busbar_kernel::plugin_routes::build_route_table(declarations)
            .expect("the actual export routes obey the product namespace rules"),
    )
}

#[tokio::test]
async fn actual_export_dispatch_resolves_the_live_table_on_the_same_listener() {
    const CHILD: &str = "BUSBAR_ACTUAL_PLUGIN_ROUTES_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let name = std::thread::current().name().unwrap().to_string();
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("actual plugin route swap completed")
        );
        return;
    }
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
    let directory = plugins::scratch("actual-plugin-route-swap");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([9u8; 32]))
        .expect("write the actual configured signing key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&operator_token, "actual-route-operator").unwrap();
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing } },
        "identity-providers": {},
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": {"file": operator_token},
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        None,
        true,
    )
    .expect("the actual product builds the session deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }

    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(60));
    let actual_routes = metrics_routes();
    app.plugin_routes = actual_routes.clone();
    let app = Arc::new(app);
    let (router, admin_router, handle) =
        busbar_kernel::build_split_routers_with_limits(app.clone(), 1 << 20, 0, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    struct Server(tokio::task::JoinHandle<()>);
    impl Drop for Server {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _server = Server(server);
    let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_address = admin_listener.local_addr().unwrap();
    let _admin_server = Server(tokio::spawn(async move {
        axum::serve(admin_listener, admin_router).await.unwrap()
    }));
    let client = reqwest::Client::new();
    let path = "/metrics/hooks";
    assert_eq!(client.get(format!("http://{address}{path}")).header("x-admin-token", "actual-route-operator").send().await.unwrap().status().as_u16(), 404,
        "the plugin auth:admin dispatcher route is physically absent from the data listener even with valid authority");
    let admin_crossing = client
        .get(format!("http://{admin_address}{path}"))
        .header("x-admin-token", "actual-route-operator")
        .send()
        .await
        .unwrap();
    assert_eq!(
        admin_crossing.status().as_u16(),
        200,
        "the plugin auth:admin dispatcher reaches the actual exporter on the admin listener"
    );
    assert_eq!(
        admin_crossing.headers()["content-type"],
        "text/plain; version=0.0.4; charset=utf-8"
    );
    assert!(
        admin_crossing.bytes().await.unwrap().is_empty(),
        "the real exporter renders the empty hook snapshot across plugin dispatch"
    );
    let url = format!("http://{address}/metrics");
    let first = client.get(&url).send().await.unwrap();
    assert_eq!(
        first.status().as_u16(),
        200,
        "the actual export dispatch serves its declared route"
    );
    let body = first.text().await.unwrap();
    assert!(
        body.contains("# HELP") || body.contains("# TYPE"),
        "the actual owner emits Prometheus exposition: {body}"
    );
    assert_eq!(
        client.head(&url).send().await.unwrap().status().as_u16(),
        200
    );
    let mut withdrawn = (*app).clone();
    withdrawn.plugin_routes = Arc::new(busbar_kernel::plugin_routes::PluginRouteTable::empty());
    handle.swap(Arc::new(withdrawn));
    assert_eq!(client.get(&url).send().await.unwrap().status().as_u16(), 404,
        "the SAME listener resolves the current withdrawn table instead of retaining the old exporter");
    assert_eq!(
        client.head(&url).send().await.unwrap().status().as_u16(),
        404,
        "HEAD also resolves the withdrawn owner rather than a stale GET handler"
    );
    handle.swap(app);
    assert_eq!(
        client.get(&url).send().await.unwrap().status().as_u16(),
        200,
        "the SAME listener resolves the restored actual exporter"
    );
    println!("actual plugin route swap completed");
}
