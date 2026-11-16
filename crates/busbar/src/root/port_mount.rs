// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The HTTP mount of the MIN-3 plane instances (PLANE-DRIVER.md slice 9, PLANE-BOOT-MOUNT). Every data route a
//! plane declares (`PortRoutes.data`, slice 8) becomes one [`PlaneRouteSpec`] per HTTP verb of its method mask;
//! the handler turns the request into a [`ServeIn`], runs [`PortDriver::serve`] (admission, the whole session,
//! the books) and renders the client items it answers as one response.
//!
//! Not mounted here, each owned by a later step (PLANE-BOOT-MOUNT.md): ROUTE_ADMIN (the admin router and its
//! scope middleware), ROUTE_UPGRADE (the §12.27 upgrade sequence), ROUTE_CATALOG (the model list), and a streamed
//! reply (the items are joined into one body). A request is not a billed unit on this path yet (`unit: None`: audit
//! rows only) and a FORWARD has no walk (`upstream: None`: the session fails `NotDriven`) until the egress half of
//! slice 5 lands.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
use busbar_contract::abi::transport::route::{
    METHOD_DELETE, METHOD_GET, METHOD_PATCH, METHOD_POST, METHOD_PUT,
};
use busbar_kernel::plane_driver::port::{HttpIn, PortSeat, ServeIn, Served};
use busbar_kernel::plane_driver::port_auth::{subject_identity, Credentials, Principal};
use busbar_kernel::plane_driver::port_routes::Mounted;
use busbar_kernel::plane_driver::port_session::ToClient;
use busbar_kernel::plane_driver::HeadFields;
use busbar_kernel::plane_routes::{PlaneReqCtx, PlaneResponse, PlaneRouteFuture, PlaneRouteSpec};
use busbar_plugin_abi::plane::AUTH_PRINCIPAL;

/// The request ids this mount hands the planes: unique inside the process, never zero.
static REQUEST_IDS: AtomicU64 = AtomicU64::new(1);

/// The HTTP verbs of a route's method mask (`method_bit`): the five a route can be mounted on.
pub(crate) fn methods_of(mask: u32) -> Vec<RouteMethod> {
    [
        (METHOD_GET, RouteMethod::Get),
        (METHOD_POST, RouteMethod::Post),
        (METHOD_PUT, RouteMethod::Put),
        (METHOD_PATCH, RouteMethod::Patch),
        (METHOD_DELETE, RouteMethod::Delete),
    ]
    .into_iter()
    .filter(|(bit, _)| mask & bit != 0)
    .map(|(_, method)| method)
    .collect()
}

/// What the data listener enforces before the handler runs. Only a route that is `AUTH_PRINCIPAL` and nothing else
/// needs the data auth chain's verdict; every other class set is classified per request by core's admission
/// (§12.11), which the chain must not pre-empt (a ticket is not a client token).
pub(crate) fn auth_of(effective: u32) -> RouteAuth {
    if effective == AUTH_PRINCIPAL {
        RouteAuth::Key
    } else {
        RouteAuth::None
    }
}

/// The credential the request carries: the route's own header when it names one (`D_ROUTE_CRED_HEADER`), else the
/// `Authorization: Bearer` token.
pub(crate) fn bearer_of(headers: &HeaderMap, cred_header: Option<&str>) -> Option<String> {
    let value = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    match cred_header {
        Some(name) => value(name).map(str::to_owned),
        None => {
            let auth = value(header::AUTHORIZATION.as_str())?;
            let (scheme, token) = auth.split_once(' ')?;
            scheme
                .eq_ignore_ascii_case("bearer")
                .then(|| token.trim().to_owned())
        }
    }
}

/// The status, head fields and joined body of the client items. No head = the plane wrote no answer: 502 with
/// nothing, never a 200 nobody stated. Trailers and the end mark carry nothing on a buffered reply.
pub(crate) fn parts_of(items: Vec<ToClient>) -> (u16, HeadFields, Vec<u8>) {
    let mut head = None;
    let mut body = Vec::new();
    for item in items {
        match item {
            ToClient::Head { status, fields } => {
                head.get_or_insert((status, fields));
            }
            ToClient::Body(bytes) | ToClient::Msg { bytes, .. } => body.extend_from_slice(&bytes),
            ToClient::Trailers(_) | ToClient::End => {}
        }
    }
    match head {
        Some((status, fields)) => (status, fields, body),
        None => (502, Vec::new(), Vec::new()),
    }
}

fn response_of(items: Vec<ToClient>) -> PlaneResponse {
    let (status, fields, body) = parts_of(items);
    let mut response = PlaneResponse::new(Body::from(body));
    *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    for (name, value) in fields {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(&name),
            HeaderValue::from_bytes(&value),
        ) {
            response.headers_mut().append(name, value);
        }
    }
    response
}

fn failed(status: StatusCode) -> PlaneResponse {
    let mut response = PlaneResponse::new(Body::empty());
    *response.status_mut() = status;
    response
}

fn http_in(ctx: &PlaneReqCtx) -> HttpIn {
    HttpIn {
        method: ctx.method.as_str().to_owned(),
        path: ctx.uri.path().to_owned(),
        query: ctx.uri.query().unwrap_or_default().to_owned(),
        headers: ctx
            .headers
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect(),
        body: ctx.body.to_vec(),
        request_id: REQUEST_IDS.fetch_add(1, Ordering::Relaxed),
    }
}

async fn answer(seat: &PortSeat, route: &Mounted, ctx: PlaneReqCtx) -> PlaneResponse {
    // The data chain's verdict, when the route sat behind it: the verified principal's id is its subject.
    let principal: Option<Arc<str>> = ctx
        .principal
        .as_ref()
        .and_then(|p| p.0.as_ref())
        .map(|p| Arc::from(p.id.as_str()));
    let identity = principal.as_deref().map(subject_identity);
    let bearer = bearer_of(&ctx.headers, route.cred_header.as_deref());
    let creds = Credentials {
        bearer: bearer.as_deref(),
        principal: match &identity {
            Some(records) => Principal::Verified(records),
            None => Principal::Anonymous,
        },
        operator: false,
        signed: None,
    };
    let input = ServeIn {
        route: route.route,
        http: http_in(&ctx),
        creds,
        audience: seat.audience.as_deref().unwrap_or_default(),
        now_s: busbar_kernel::store::now(),
        principal,
        unit: None,
        upstream: None,
        intents: Arc::clone(&seat.intents),
    };
    match seat.driver.serve(input).await {
        Ok(Served::Refused(items)) => response_of(items),
        Ok(Served::Ran(ran)) => response_of(ran.client),
        Err(error) => {
            tracing::warn!(instance = %seat.instance, route = route.route, ?error, "a plane request failed");
            failed(StatusCode::BAD_GATEWAY)
        }
    }
}

/// One spec per (data route, verb) of every seat. A catalog route is not mounted (see the module docs).
pub(crate) fn routes(seats: &[PortSeat]) -> Vec<PlaneRouteSpec> {
    let mut out = Vec::new();
    for seat in seats {
        for route in seat.driver.routes().data.iter().filter(|m| !m.catalog) {
            for method in methods_of(route.methods) {
                let seat = seat.clone();
                let mounted = route.clone();
                out.push(PlaneRouteSpec {
                    path: route.pattern.to_string(),
                    method,
                    auth: auth_of(route.effective),
                    handler: Arc::new(move |ctx: PlaneReqCtx| -> PlaneRouteFuture {
                        let seat = seat.clone();
                        let mounted = mounted.clone();
                        Box::pin(async move { answer(&seat, &mounted, ctx).await })
                    }),
                });
            }
        }
    }
    out
}

#[cfg(test)]
#[path = "tests/port_mount.rs"]
mod tests;
