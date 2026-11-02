// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
use busbar_kernel::plane_routes::{PlaneReqCtx, PlaneRouteSpec};

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

#[test]
fn a_door_route_is_recorded_at_the_bar_it_declares() {
    let table = crate::router::base_data_router(
        &crate::plugin_routes::PluginRouteTable::default(),
        &Default::default(),
        None,
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
