// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR PLANES' DATA ROUTES, installed at the router's construction (ARCHITECT Q-SW1,
//! 2026-10-02): a route handed to `build_split_routers_serving` is answered by its own handler,
//! ahead of the protocol fallback, at the bar it declares; the same path without the install is the
//! fallback's.

use std::sync::Arc;

use axum::Router;
use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
use busbar_kernel::plane_routes::{PlaneReqCtx, PlaneRouteSpec};

const DOOR: &str = "/door-route-test/call";

/// A door route whose handler answers 200 with the request's own path and body.
fn door(auth: RouteAuth) -> PlaneRouteSpec {
    PlaneRouteSpec {
        path: DOOR.to_string(),
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
    let app = crate::test_support::TestApp::new().build();
    crate::build_split_routers_serving(
        app,
        doors,
        busbar_kernel::proxy::max_translate_body_bytes(),
        crate::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        crate::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
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
async fn a_door_route_installed_at_construction_is_answered_ahead_of_the_fallback() {
    let (code, body) = post(data_router(vec![door(RouteAuth::None)]), DOOR).await;
    assert_eq!(code, 200, "the installed door route answers: {body}");
    assert_eq!(body, format!("door {DOOR} piece"));
}

#[tokio::test]
async fn without_the_install_the_same_path_is_the_fallbacks() {
    let (code, body) = post(data_router(Vec::new()), DOOR).await;
    assert_ne!(code, 200, "no door route, so the fallback answers: {body}");
    assert!(!body.starts_with("door "), "{body}");
}

#[test]
fn a_door_route_is_recorded_at_the_bar_it_declares() {
    let app = crate::test_support::TestApp::new().build();
    let table = crate::router::base_data_router(
        &app.plugin_routes,
        &app.plane_slots,
        app.oauth_as.as_ref(),
        vec![door(RouteAuth::Key)],
        Vec::new(),
    )
    .1;
    let row = table
        .routes()
        .iter()
        .find(|r| r.path == DOOR)
        .map(|r| (r.method.as_str(), r.auth));
    assert_eq!(row, Some(("POST", RouteAuth::Key)));
}
