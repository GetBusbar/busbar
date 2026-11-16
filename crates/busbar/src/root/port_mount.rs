// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The HTTP mount of the MIN-3 plane instances (PLANE-DRIVER.md slice 9, PLANE-BOOT-MOUNT). Every data route a
//! plane declares (`PortRoutes.data`, slice 8) becomes one [`PlaneRouteSpec`] per HTTP verb of its method mask;
//! the handler turns the request into a [`ServeIn`], runs [`PortDriver::serve`] (admission, the whole session,
//! the books) and renders the client items it answers as one response.
//!
//! Not mounted here, each owned by a later step (PLANE-BOOT-MOUNT.md): ROUTE_ADMIN (the admin router and its
//! scope middleware), ROUTE_UPGRADE (the §12.27 upgrade sequence), ROUTE_CATALOG (the model list), and a streamed
//! reply (the items are joined into one body). A request that carries a resolved key under a governed
//! process is a billed unit ([`PortBilling`]: admitted through the key's budget chain, its usage, checkpoints and
//! end posted through the money seam by the cancel table, settled when the answer is out); without a key or a
//! governance book it is audit rows only. A FORWARD has no walk (`upstream: None`: the session fails `NotDriven`)
//! until the egress half of slice 5 lands.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::root::door_steps::exhaustion_of;
use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
use busbar_contract::abi::transport::route::{
    METHOD_DELETE, METHOD_GET, METHOD_PATCH, METHOD_POST, METHOD_PUT,
};
use busbar_kernel::governance::LimitBlocked;
use busbar_kernel::plane_driver::port::{HttpIn, PortSeat, ServeIn, Served, Unit};
use busbar_kernel::plane_driver::port_auth::{subject_identity, Credentials, Principal};
use busbar_kernel::plane_driver::port_billing::{end_of, Admit, PortBilling};
use busbar_kernel::plane_driver::port_routes::Mounted;
use busbar_kernel::plane_driver::port_session::ToClient;
use busbar_kernel::plane_driver::HeadFields;
use busbar_kernel::plane_routes::{PlaneReqCtx, PlaneResponse, PlaneRouteFuture, PlaneRouteSpec};
use busbar_kernel::state::{App, AppHandle};
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

/// The app generation the request was routed under: the data listener lends it as the request's engine.
fn app_of(engine: Arc<dyn std::any::Any + Send + Sync>) -> Option<Arc<App>> {
    match engine.downcast::<App>() {
        Ok(app) => Some(app),
        Err(engine) => Some(engine.downcast::<AppHandle>().ok()?.load()),
    }
}

/// A request the governance book refused to admit: the status its limit maps to, the wait it names (if any).
pub(crate) fn blocked_response(blocked: &LimitBlocked) -> PlaneResponse {
    let (status, _, message, retry_after) = busbar_kernel::ingress::limit_refusal("", blocked);
    let mut response = PlaneResponse::new(Body::from(message));
    *response.status_mut() = status;
    if let Some(seconds) = retry_after {
        if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
    }
    response
}

/// The request as a billed unit: admitted through its resolved key's budget chain and opened on the plane money.
/// `None` = not billed (no billing installed, no governed key on the request, or no app generation to price
/// under): the request runs with audit rows only.
fn open_unit(
    seat: &PortSeat,
    billing: Option<&PortBilling>,
    ctx: &PlaneReqCtx,
) -> Result<Option<Unit>, LimitBlocked> {
    let Some(billing) = billing else {
        return Ok(None);
    };
    let Some(key) = ctx.gov.as_ref().and_then(|gov| gov.key.clone()) else {
        return Ok(None);
    };
    let Some(app) = app_of(Arc::clone(&ctx.engine)) else {
        return Ok(None);
    };
    let mode = exhaustion_of(&app, &key);
    billing
        .open(Admit {
            instance: &seat.instance,
            classes: seat.driver.usage_classes(),
            key,
            cost: Arc::clone(&app.cost),
            mode,
            arrived: busbar_kernel::store::now(),
        })
        .map(Some)
}

/// A unit's settlement, owed once whatever becomes of the request: dropped unfinished (a panic, a cancelled
/// task) it settles as a gateway failure that ran nothing, so the unit never stays open and its hold never leaks.
struct Settle {
    billing: PortBilling,
    key: busbar_contract::UnitKey,
    done: bool,
}

impl Settle {
    fn finish(mut self, status: u16, ran: bool) {
        self.done = true;
        self.billing
            .settle(self.key, end_of(u32::from(status), ran));
    }
}

impl Drop for Settle {
    fn drop(&mut self) {
        if !self.done {
            self.billing.settle(self.key, end_of(502, false));
        }
    }
}

async fn answer(
    seat: &PortSeat,
    route: &Mounted,
    billing: Option<&PortBilling>,
    ctx: PlaneReqCtx,
) -> PlaneResponse {
    let unit = match open_unit(seat, billing, &ctx) {
        Ok(unit) => unit,
        Err(blocked) => return blocked_response(&blocked),
    };
    let settle = match (&unit, billing) {
        (Some(unit), Some(billing)) => Some(Settle {
            billing: billing.clone(),
            key: unit.ctx.key,
            done: false,
        }),
        _ => None,
    };
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
        unit,
        upstream: None,
        intents: Arc::clone(&seat.intents),
    };
    let (response, ran) = match seat.driver.serve(input).await {
        Ok(Served::Refused(items)) => (response_of(items), false),
        Ok(Served::Ran(ran)) => (response_of(ran.client), true),
        Err(error) => {
            tracing::warn!(instance = %seat.instance, route = route.route, ?error, "a plane request failed");
            (failed(StatusCode::BAD_GATEWAY), false)
        }
    };
    if let Some(settle) = settle {
        settle.finish(response.status().as_u16(), ran);
    }
    response
}

/// One spec per (data route, verb) of every seat. A catalog route is not mounted (see the module docs).
pub(crate) fn routes(seats: &[PortSeat], billing: Option<&PortBilling>) -> Vec<PlaneRouteSpec> {
    let mut out = Vec::new();
    for seat in seats {
        for route in seat.driver.routes().data.iter().filter(|m| !m.catalog) {
            for method in methods_of(route.methods) {
                let seat = seat.clone();
                let mounted = route.clone();
                let billing = billing.cloned();
                out.push(PlaneRouteSpec {
                    path: route.pattern.to_string(),
                    method,
                    auth: auth_of(route.effective),
                    handler: Arc::new(move |ctx: PlaneReqCtx| -> PlaneRouteFuture {
                        let seat = seat.clone();
                        let mounted = mounted.clone();
                        let billing = billing.clone();
                        // A session outlives its client's connection: it runs to its end, and its unit is
                        // settled, on its own task.
                        Box::pin(async move {
                            tokio::spawn(async move {
                                answer(&seat, &mounted, billing.as_ref(), ctx).await
                            })
                            .await
                            .unwrap_or_else(|_| failed(StatusCode::BAD_GATEWAY))
                        })
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
