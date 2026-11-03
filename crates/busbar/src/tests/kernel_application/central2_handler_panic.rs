// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use std::sync::Arc;
use std::time::{Duration, Instant};
use crate::root::test_plugins as plugins;
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
    use tracing_subscriber::layer::SubscriberExt as _;
    let captured = plugins::scratch("central2-handler-log").join("panic.log");
    let log = std::fs::File::create(&captured).unwrap();
    let _subscriber = tracing::subscriber::set_default(
        tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .without_time()
                .with_ansi(false)
                .with_writer(move || log.try_clone().unwrap()),
        ),
    );
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
    let directory = plugins::scratch("central2-handler-panic");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module.clone(), "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
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
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let book = crate::root::boot::book(&app, &module).expect("the actual Store boots rate history");
    let _book = book;
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
        PlaneRouteSpec {
            path: "/door/x".into(),
            method: RouteMethod::Post,
            auth: RouteAuth::None,
            handler: Arc::new(|_: PlaneReqCtx| Box::pin(async { fine().await.into_response() })),
        },
        PlaneRouteSpec {
            path: "/door/failed".into(),
            method: RouteMethod::Post,
            auth: RouteAuth::None,
            handler: Arc::new(|_: PlaneReqCtx| Box::pin(async { fine().await.into_response() })),
        },
    ];
    let (router, admin, handle) =
        busbar_kernel::build_split_routers_serving(Arc::new(app), routes, 1 << 20, 0, false);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    // Deliberately fault request dispatch inside the real administrative panic boundary.
    // Application construction, auth configuration and refusal rendering remain production-owned.
    let admin = admin
        .layer(axum::middleware::from_fn(
            |req: axum::extract::Request, next: axum::middleware::Next| async move {
                assert_ne!(
                    req.headers()
                        .get("authorization")
                        .and_then(|v| v.to_str().ok()),
                    Some("Bearer boom"),
                    "deliberate administrative request panic"
                );
                next.run(req).await
            },
        ))
        .layer(busbar_kernel::router::CatchPanicLayer::new(handle.clone()));
    let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_addr = admin_listener.local_addr().unwrap();
    let admin_server =
        tokio::spawn(async move { axum::serve(admin_listener, admin).await.unwrap() });
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
    let response = client
        .get(format!("http://{admin_addr}/api/v1/admin/keys"))
        .bearer_auth("boom")
        .send()
        .await
        .expect("the administrative panic answers");
    assert_eq!(response.status().as_u16(), 500);
    assert!(response.headers()["content-type"]
        .to_str()
        .unwrap()
        .starts_with("application/json"));
    let envelope: serde_json::Value = response.json().await.unwrap();
    assert_eq!(envelope["error"]["code"], "internal");
    let next = client
        .get(format!("http://{admin_addr}/api/v1/admin/keys"))
        .bearer_auth("not-boom")
        .send()
        .await
        .unwrap();
    assert_ne!(next.status().as_u16(), 500);
    let health = client
        .get(format!("http://{admin_addr}/healthz"))
        .send()
        .await
        .unwrap();
    assert_ne!(health.status().as_u16(), 500);
    let logged = std::fs::read_to_string(captured).unwrap();
    for path in ["/v1/chat/completions", "/api/v1/admin/keys"] {
        assert_eq!(
            logged
                .lines()
                .filter(|line| line.contains("a request handler panicked") && line.contains(path))
                .count(),
            1,
            "{logged}"
        );
    }
    // The same normally built application's method fallback asks the physical door,
    // preserves every refusal field, and uses its own envelope when no door renders.
    let response = client
        .get(format!("http://{addr}/door/x?q=1"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 405);
    assert_ne!(response.bytes().await.unwrap().as_ref(), b"door");
    use busbar_contract::caps::ReasonCode;
    use busbar_kernel::plane_routes::{KernelRefusal, PlaneRefuseByPathFn};
    type Seen = Vec<(ReasonCode, u16, String, String, String)>;
    let seen: Arc<std::sync::Mutex<Seen>> = Arc::default();
    let observations = seen.clone();
    let refuser: PlaneRefuseByPathFn = Arc::new(move |r: &KernelRefusal<'_>| {
        observations.lock().unwrap().push((
            r.reason,
            r.status,
            r.text.into(),
            r.path.into(),
            r.target.into(),
        ));
        (r.path != "/door/failed").then(|| {
            axum::http::Response::builder()
                .status(r.status)
                .body(axum::body::Body::from("door"))
                .unwrap()
        })
    });
    handle.bind_door_refuser(refuser);
    let response = client
        .get(format!("http://{addr}/door/x?q=1"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 405);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"door");
    assert_eq!(
        seen.lock().unwrap().last().cloned(),
        Some((
            ReasonCode::MethodNotAllowed,
            405,
            "method not allowed for this resource".into(),
            "/door/x".into(),
            "/door/x?q=1".into(),
        ))
    );
    let response = client
        .get(format!("http://{addr}/door/failed?q=1"))
        .send()
        .await
        .unwrap();
    assert_ne!(response.bytes().await.unwrap().as_ref(), b"door");
    let asked = seen.lock().unwrap().len();
    let response = client
        .post(format!("http://{admin_addr}/api/v1/admin/info?q=1"))
        .send()
        .await
        .unwrap();
    assert_ne!(response.bytes().await.unwrap().as_ref(), b"door");
    assert_eq!(
        seen.lock().unwrap().len(),
        asked,
        "the native API root asks no door"
    );
    admin_server.abort();
    server.abort();
    println!("{WITNESS}");
}
