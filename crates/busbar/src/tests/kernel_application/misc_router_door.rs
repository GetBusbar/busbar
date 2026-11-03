// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel as kernel;
use std::sync::Arc;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

use axum::Router;
use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
use kernel::plane_routes::{PlaneReqCtx, PlaneRouteSpec};

const DOOR: &str = "/door-route-test/call";

fn door(auth: RouteAuth) -> PlaneRouteSpec {
    door_at(DOOR, auth)
}

fn door_at(path: &str, auth: RouteAuth) -> PlaneRouteSpec {
    PlaneRouteSpec {
        path: path.to_string(),
        method: RouteMethod::Post,
        auth,
        handler: Arc::new(|ctx: PlaneReqCtx| {
            Box::pin(async move {
                let body = format!("door {} {}", ctx.path, String::from_utf8_lossy(&ctx.body));
                axum::response::Response::new(axum::body::Body::from(body))
            })
        }),
    }
}

fn data_router(doors: Vec<PlaneRouteSpec>) -> Router {
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
    let directory = plugins::scratch(&format!("router-door-{}", kernel::door::op_id().counter()));
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
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules =
        Arc::new(crate::root::door_steps::Rules::default()) as Arc<dyn kernel::appbuild::RootRules>;
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
    let app = Arc::new(app);
    kernel::build_split_routers_serving(
        app,
        doors,
        busbar_kernel_egress::upstream::max_translate_body_bytes(),
        kernel::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        kernel::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    )
    .0
}

async fn post(router: Router, path: &str) -> (u16, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .body("piece")
        .send()
        .await
        .unwrap();
    let code = resp.status().as_u16();
    let body = resp.text().await.unwrap();
    server.abort();
    (code, body)
}

#[tokio::test]
async fn without_the_install_the_same_path_is_the_fallbacks() {
    let (code, body) = post(data_router(Vec::new()), DOOR).await;
    assert_ne!(code, 200, "no door route, so the fallback answers: {body}");
    assert!(!body.starts_with("door "), "{body}");
}

const CLAIMED_UNDER_API: &str = "/api/door-route-test/evaluate";

#[tokio::test]
async fn a_planes_exact_claim_under_the_api_root_is_admitted_at_its_own_bar() {
    let (code, body) = post(
        data_router(vec![door_at(CLAIMED_UNDER_API, RouteAuth::Key)]),
        CLAIMED_UNDER_API,
    )
    .await;
    assert_eq!(code, 200, "the claimed path is the plane's: {body}");
    assert_eq!(body, format!("door {CLAIMED_UNDER_API} piece"));
}

#[tokio::test]
async fn an_unclaimed_path_under_the_api_root_stays_behind_the_operator_chain() {
    let (code, body) = post(
        data_router(vec![door_at(CLAIMED_UNDER_API, RouteAuth::Key)]),
        "/api/door-route-test/unclaimed",
    )
    .await;
    assert_eq!(code, 401, "the admin prefix fails closed: {body}");
}

#[tokio::test]
async fn a_http_plane_receives_no_scheme_derived_from_a_raw_credential() {
    let spec = PlaneRouteSpec {
        path: DOOR.into(),
        method: RouteMethod::Post,
        auth: RouteAuth::Key,
        handler: Arc::new(|ctx: PlaneReqCtx| {
            Box::pin(async move {
                assert!(!ctx.headers.contains_key("x-api-key"));
                assert!(!ctx.headers.contains_key("authorization"));
                axum::response::IntoResponse::into_response(axum::Json(ctx.consumed_fields))
            })
        }),
    };
    let router = data_router(vec![spec]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let response = reqwest::Client::new()
        .post(format!("http://{addr}{DOOR}"))
        .header("x-api-key", "secret-prefix secret-tail")
        .header("authorization", "Bearer caller-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let fields: Vec<(String, String)> = response.json().await.unwrap();
    server.abort();
    assert!(fields.contains(&("x-api-key".into(), String::new())));
    assert!(fields.contains(&("authorization".into(), "Bearer".into())));
    assert!(!format!("{fields:?}").contains("secret"));
}
