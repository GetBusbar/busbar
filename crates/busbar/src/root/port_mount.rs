// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The HTTP mount of the MIN-3 plane instances (PLANE-DRIVER.md slice 9, PLANE-BOOT-MOUNT). Every data route a
//! plane declares (`PortRoutes.data`, slice 8) becomes one [`PlaneRouteSpec`] per HTTP verb of its method mask;
//! the handler turns the request into a [`ServeIn`] and runs [`PortDriver::serve`] (admission, the whole session,
//! the books) on its own task. The session hands the client's items to a sink as the plane writes them: the first
//! head decides the response and the body streams after it (a reply is no longer joined into one body); a request
//! the session answered without a head (an admission refusal, a plane that wrote nothing) is one buffered response.
//!
//! Not mounted here, each owned by a later step (PLANE-BOOT-MOUNT.md): ROUTE_ADMIN (the admin router and its
//! scope middleware), ROUTE_UPGRADE (the §12.27 upgrade sequence) and ROUTE_CATALOG (the model list). A request is
//! not a billed unit on this path yet (`unit: None`: audit rows only), and a FORWARD walks only when the seat
//! carries a `PortEgress` (`PortSeat::upstream`; the boot sets none until the MIN-3 pools compose an `Egress`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
use busbar_contract::abi::transport::route::{
    METHOD_DELETE, METHOD_GET, METHOD_PATCH, METHOD_POST, METHOD_PUT,
};
use busbar_kernel::plane_driver::port::{HttpIn, PortSeat, ServeError, ServeIn, Served};
use busbar_kernel::plane_driver::port_auth::{subject_identity, Credentials, Principal};
use busbar_kernel::plane_driver::port_routes::Mounted;
use busbar_kernel::plane_driver::port_session::{ClientSink, ToClient};
use busbar_kernel::plane_driver::HeadFields;
use busbar_kernel::plane_routes::{PlaneReqCtx, PlaneResponse, PlaneRouteFuture, PlaneRouteSpec};
use busbar_plugin_abi::plane::AUTH_PRINCIPAL;
use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

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

fn with_head(status: u16, fields: HeadFields, body: Body) -> PlaneResponse {
    let mut response = PlaneResponse::new(body);
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

fn response_of(items: Vec<ToClient>) -> PlaneResponse {
    let (status, fields, body) = parts_of(items);
    with_head(status, fields, Body::from(body))
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

/// The client's end of a streamed reply (`ClientSink`): the plane's first head decides the response, every later
/// body or message item feeds its body as it is written. Trailers and the end mark carry nothing on HTTP/1.
struct Pipe {
    head: Mutex<Option<oneshot::Sender<(u16, HeadFields)>>>,
    body: mpsc::UnboundedSender<Bytes>,
}

impl ClientSink for Pipe {
    fn items(&self, items: Vec<ToClient>) -> bool {
        for item in items {
            match item {
                ToClient::Head { status, fields } => {
                    let sender = self
                        .head
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .take();
                    if let Some(sender) = sender {
                        if sender.send((status, fields)).is_err() {
                            return false;
                        }
                    }
                }
                ToClient::Body(bytes) | ToClient::Msg { bytes, .. } => {
                    if !bytes.is_empty() && self.body.send(Bytes::from(bytes)).is_err() {
                        return false;
                    }
                }
                ToClient::Trailers(_) | ToClient::End => {}
            }
        }
        true
    }
}

/// The response body of a streamed reply: what the plane writes, as it writes it, until the session ends (its
/// sink drops) or the client goes away (this body drops, and the next item stops the session's reading).
struct PipeBody(mpsc::UnboundedReceiver<Bytes>);

impl http_body::Body for PipeBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        self.0
            .poll_recv(cx)
            .map(|bytes| bytes.map(|bytes| Ok(http_body::Frame::data(bytes))))
    }
}

/// How a request that was not streamed ended: the refusal's items, or the items the session collected.
fn finished(done: Result<Result<Served, ServeError>, tokio::task::JoinError>) -> PlaneResponse {
    match done {
        Ok(Ok(Served::Refused(items))) => response_of(items),
        Ok(Ok(Served::Ran(ran))) => response_of(ran.client),
        Ok(Err(error)) => {
            tracing::warn!(?error, "a plane request failed");
            failed(StatusCode::BAD_GATEWAY)
        }
        Err(_) => failed(StatusCode::BAD_GATEWAY),
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
    let http = http_in(&ctx);
    let (head_tx, mut head_rx) = oneshot::channel();
    let (body_tx, body_rx) = mpsc::unbounded_channel();
    let pipe = Pipe {
        head: Mutex::new(Some(head_tx)),
        body: body_tx,
    };
    let (seat, route) = (seat.clone(), route.clone());
    // The session outlives this call when its reply streams, so it owns everything it borrows.
    let mut session = tokio::spawn(async move {
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
            http,
            creds,
            audience: seat.audience.as_deref().unwrap_or_default(),
            now_s: busbar_kernel::store::now(),
            principal,
            unit: None,
            upstream: seat.upstream.clone(),
            client: Some(Arc::new(pipe)),
            intents: Arc::clone(&seat.intents),
        };
        let served = seat.driver.serve(input).await;
        if let Err(error) = &served {
            tracing::warn!(instance = %seat.instance, route = route.route, ?error, "a plane request failed");
        }
        served
    });
    tokio::select! {
        head = &mut head_rx => match head {
            Ok((status, fields)) => with_head(status, fields, Body::new(PipeBody(body_rx))),
            // The session ended without writing a head.
            Err(_) => finished(session.await),
        },
        done = &mut session => match head_rx.try_recv() {
            // It wrote its head and ended before this call looked: the whole body is queued.
            Ok((status, fields)) => with_head(status, fields, Body::new(PipeBody(body_rx))),
            Err(_) => finished(done),
        },
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
