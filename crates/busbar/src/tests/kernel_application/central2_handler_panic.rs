// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use std::sync::Arc;
use std::time::{Duration, Instant};
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;
#[tokio::test]
async fn a_panicking_handler_fails_only_its_own_request() {
    const CHILD: &str = "BUSBAR_CENTRAL2_HANDLER_PANIC_CHILD";
    const WITNESS: &str = "actual root handler panic completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
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
    let directory = plugins::scratch("central2-handler-panic");
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
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    crate::root::kernel::ROOT_CARD.keep_in_store(
        app.governance
            .as_ref()
            .unwrap()
            .store_calls()
            .expect("actual Store calls"),
        113,
    );
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .expect("actual rate history boots");
    limits.keep().expect("actual rates and limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    async fn boom() -> &'static str {
        panic!("deliberate handler panic (request-panic boundary test)")
    }
    async fn fine() -> &'static str {
        "fine"
    }
    use axum::response::IntoResponse as _;
    use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
    use busbar_kernel::plane_routes::{PlaneReqCtx, PlaneRouteSpec};
    // Fault only the specific request handler; the actual application and serving stack remain normal.
    let routes = vec![
        PlaneRouteSpec {
            path: "/v1/chat/completions".into(),
            method: RouteMethod::Post,
            auth: RouteAuth::None,
            handler: Arc::new(|_: PlaneReqCtx| Box::pin(async { boom().await.into_response() })),
        },
        PlaneRouteSpec {
            path: "/still-serving".into(),
            method: RouteMethod::Get,
            auth: RouteAuth::None,
            handler: Arc::new(|_: PlaneReqCtx| Box::pin(async { fine().await.into_response() })),
        },
    ];
    let (router, _admin, _handle) =
        busbar_kernel::build_split_routers_serving(app, routes, 1 << 20, 0, false);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let r = client
        .post(format!("http://{addr}/v1/chat/completions"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("a panicking handler must still produce a RESPONSE, not a torn-down connection");
    assert_eq!(r.status().as_u16(), 500, "the one request fails with 500");
    let ct = r
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ct.starts_with("application/json"),
        "content-type was `{ct}`"
    );
    let v: serde_json::Value = r.json().await.expect("the 500 body is JSON");
    assert_eq!(
        v["error"]["type"], "api_error",
        "the kernel's standard dialect-native error body, got {v}"
    );

    for _ in 0..3 {
        let ok = client
            .get(format!("http://{addr}/still-serving"))
            .send()
            .await
            .expect("the listener keeps serving after a request panicked");
        assert_eq!(ok.status().as_u16(), 200);
        assert_eq!(ok.text().await.unwrap(), "fine");
    }
    server.abort();
    println!("{WITNESS}");
}
