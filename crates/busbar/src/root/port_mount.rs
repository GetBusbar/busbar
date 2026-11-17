// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The HTTP mount of the MIN-3 plane instances (PLANE-DRIVER.md slice 9, PLANE-BOOT-MOUNT, PLANE-SERVICES). Every
//! data route a plane declares (`PortRoutes.data`, slice 8) becomes one [`PlaneRouteSpec`] per HTTP verb of its
//! method mask; the handler turns the request into a [`ServeIn`] and runs [`PortDriver::serve`] (admission, the whole
//! session, the books) on its own task. The session hands the client's items to a sink as the plane writes them: the
//! first head decides the response and the body streams after it (a reply is no longer joined into one body); a
//! request the session answered without a head (an admission refusal, a plane that wrote nothing) is one buffered
//! response.
//!
//! - ROUTE_CATALOG routes are mounted like any data route; the principal's model list is handed to the plane's
//!   `render(RENDER_CATALOG)` (`ServeIn.models`, core's `catalog_names`). A request with no governance context lists
//!   nothing (fail closed), never every model.
//! - A route the data chain does not gate (OPTIONAL, or PRINCIPAL beside TICKET) takes the principal its credential
//!   names, resolved here through the same chain ([`chain_principal`]); an anonymous request stays anonymous and a
//!   credential the chain refuses is a refusal of the route's class.
//! - AUTH_SIGNED_INGRESS runs the Standard Webhooks check and the replay claim ([`signed_of`]) before admission. The
//!   route's webhook secret has no configured source yet, so a signed route admits nothing until one is stated.
//! - ROUTE_ADMIN is served on the admin listener, not here (`port_admin`, installed at boot).
//!
//! Not mounted, owned by a later step: ROUTE_UPGRADE (the §12.27 upgrade sequence adopts the connection's stream).
//! A request is not a billed unit on this path yet (`unit: None`: audit rows only), and a FORWARD walks only when
//! the seat carries a `PortEgress` (`PortSeat::upstream`).

use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
use busbar_contract::abi::transport::route::{
    METHOD_DELETE, METHOD_GET, METHOD_PATCH, METHOD_POST, METHOD_PUT,
};
use busbar_contract::secret_ref::SecretRef;
use busbar_kernel::auth::{AuthPrincipal, ChainHead, IdentityRefusal};
use busbar_kernel::governance::{GovCtx, LimitBlocked};
use busbar_kernel::ingress::signed_ingress;
use busbar_kernel::plane_driver::dispatch::LaneQualifier;
use busbar_kernel::plane_driver::port::{HttpIn, PortSeat, ServeError, ServeIn, Served, Unit};
use busbar_kernel::plane_driver::port_admin;
use busbar_kernel::plane_driver::port_auth::{
    self, subject_identity, Credentials, Presented, Principal,
};
use busbar_kernel::plane_driver::port_billing::{end_of, Admit, PortBilling};
use busbar_kernel::plane_driver::port_intents::Namespace;
use busbar_kernel::plane_driver::port_routes::Mounted;
use busbar_kernel::plane_driver::port_session::{ClientSink, ToClient};
use busbar_kernel::plane_driver::HeadFields;
use busbar_kernel::plane_grants::{IngressVerifier, ReplayGuard};
use busbar_kernel::plane_routes::{PlaneReqCtx, PlaneResponse, PlaneRouteFuture, PlaneRouteSpec};
use busbar_kernel::state::{App, AppHandle};
use busbar_plugin_abi::fail::refused::R_BAD_CREDENTIAL;
use busbar_plugin_abi::plane::AUTH_PRINCIPAL;
use busbar_plugin_abi::plane::{AUTH_OPTIONAL, AUTH_SIGNED_INGRESS};
use busbar_plugin_abi::types::{Bytes as WireBytes, Pair, Str};
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

/// The same native route table admitted by the driver seals physical listener claims. The
/// route id is the renderer's native selector; native render has no legacy dialect number.
pub(crate) fn guest_lines(
    seats: &[PortSeat],
    chain: &[(String, busbar_contract::abi::auth::AuthPoints)],
) -> Vec<busbar_kernel::guest::Line> {
    use busbar_contract::abi::transport::route::{method_bit, PATH_EXACT, PATH_PATTERN};
    use busbar_kernel::guest::{Claimant, Line, LineAuth, Route};
    seats
        .iter()
        .flat_map(|seat| {
            seat.driver.routes().data.iter().filter_map(|route| {
                let methods = methods_of(route.methods)
                    .into_iter()
                    .fold(0, |mask, method| mask | method_bit(method.as_str()));
                (methods != 0).then(|| Line {
                    route: Route {
                        methods,
                        path_form: if route.pattern.contains('{') {
                            PATH_PATTERN
                        } else {
                            PATH_EXACT
                        },
                        path: route.pattern.to_string(),
                        fields: Vec::new(),
                        rung: route.route,
                    },
                    claimant: Claimant::Plane(seat.instance.clone()),
                    dialect: 0,
                    auth: if auth_of(route.effective) == RouteAuth::Key {
                        super::serve::chain_auth(chain)
                    } else {
                        LineAuth::None
                    },
                    upgrade: None,
                    offered: crate::root::doors::offers_unstated(),
                })
            })
        })
        .collect()
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
    let (status, fields, body) = port_admin::joined(items);
    with_head(status, fields, Body::from(body))
}

/// Unitless rendering has only the selected route and core's refusal. It cannot open billing,
/// authenticate, consume replay, or obtain an invocation's effect authority.
pub(crate) fn render_kernel_refusal(
    seat: &PortSeat,
    route: u32,
    method: &str,
    target: &str,
    refusal: busbar_kernel::refusal::ClientRefusal,
) -> PlaneResponse {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let http = HttpIn {
        method: method.to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        headers: Vec::new(),
        body: Bytes::new(),
        request_id: REQUEST_IDS.fetch_add(1, Ordering::Relaxed),
    };
    match seat.driver.render_refusal_now(route, http, refusal.clone()) {
        Ok(items) => response_of(items),
        Err(_) => response_of(port_auth::plain_refusal(&refusal)),
    }
}

pub(crate) fn refusal_specs(
    seats: &[PortSeat],
) -> Vec<busbar_kernel::plane_routes::PlaneRefusalSpec> {
    use busbar_kernel::plane_routes::{DoorRouteId, PlaneRefusalSpec};
    let mut out = Vec::new();
    for seat in seats {
        for route in &seat.driver.routes().data {
            if auth_of(route.effective) != RouteAuth::Key {
                continue;
            }
            for method in methods_of(route.methods) {
                let seat = seat.clone();
                let id = route.route;
                out.push(PlaneRefusalSpec {
                    route: DoorRouteId {
                        path: route.pattern.to_string(),
                        method,
                    },
                    ticket_prefix: None,
                    signed_ingress: Arc::from([]),
                    refuse: Arc::new(move |reason, target| {
                        let refusal = super::native_refusals::client(
                            reason,
                            busbar_kernel::plane_driver::refusal_status(reason) as u16,
                            reason.as_str(),
                        );
                        render_kernel_refusal(&seat, id, method.as_str(), target, refusal)
                    }),
                });
            }
        }
    }
    out
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
        body: ctx.body.clone(),
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

/// What the credential of a request named, for a route the data chain does not gate.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Seen {
    /// No credential, or an open chain: the identity is empty.
    Anonymous,
    /// The chain identified it: the principal's id is the subject.
    Verified(Arc<str>),
    /// A credential the chain (or the governance binding) refused.
    Rejected,
}

/// The chain's verdict, as the principal the route is handed.
pub(crate) fn seen_of(resolved: Result<(AuthPrincipal, GovCtx), IdentityRefusal>) -> Seen {
    match resolved {
        Ok((AuthPrincipal(Some(principal)), _)) => Seen::Verified(Arc::from(principal.id.as_str())),
        Ok((AuthPrincipal(None), _)) => Seen::Anonymous,
        Err(_) => Seen::Rejected,
    }
}

/// Whether the mount resolves the credential itself: the route is not gated by the data chain (`auth_of`) and its
/// class set can take a principal (OPTIONAL, or a PRINCIPAL per-request pick beside TICKET or OPTIONAL).
pub(crate) fn resolves_credential(effective: u32) -> bool {
    effective != AUTH_PRINCIPAL && effective & (AUTH_PRINCIPAL | AUTH_OPTIONAL) != 0
}

fn app_of(engine: &Arc<dyn std::any::Any + Send + Sync>) -> Option<Arc<App>> {
    match Arc::clone(engine).downcast::<App>() {
        Ok(app) => Some(app),
        Err(engine) => Some(engine.downcast::<AppHandle>().ok()?.load()),
    }
}

/// The principal `bearer` names under the data auth chain, for a route the chain did not gate. No credential, or a
/// chain with nothing configured, is anonymous.
async fn chain_principal(ctx: &PlaneReqCtx, bearer: Option<&str>) -> (Seen, Option<GovCtx>) {
    let Some(token) = bearer else {
        return (Seen::Anonymous, None);
    };
    let Some(app) = app_of(&ctx.engine) else {
        return (Seen::Rejected, None);
    };
    if app.auth.is_open() {
        return (Seen::Anonymous, None);
    }
    let target = ctx
        .uri
        .path_and_query()
        .map_or_else(|| ctx.uri.path(), |pq| pq.as_str());
    let head = ChainHead::of_parts(ctx.method.as_str(), target, &ctx.headers);
    let verdict = busbar_kernel::auth::AuthMiddleware::run_chain_on_request_path(
        &app.auth,
        Some(token.to_owned()),
        head,
        app.governance.clone(),
        None,
    )
    .await;
    match busbar_kernel::auth::resolve_data_plane_identity(&app, verdict) {
        Ok((principal, gov)) => (seen_of(Ok((principal, GovCtx::default()))), Some(gov)),
        Err(why) => (seen_of(Err(why)), None),
    }
}

/// The webhook secret configured for (plane instance, route), if any.
pub(crate) type IngressSecrets = Arc<dyn Fn(&str, u32) -> Option<SecretRef> + Send + Sync>;

/// What a signed route needs, built at boot from the process's custody: the Standard Webhooks verifier, the replay
/// guard, and the webhook secret of (plane instance, route) the operator configured.
pub(crate) struct Ingress {
    pub(crate) verifier: Arc<dyn IngressVerifier>,
    pub(crate) replay: Arc<dyn ReplayGuard>,
    pub(crate) secrets: IngressSecrets,
}

/// The route's signature check for `PlaneIn`'s admission: `None` when the route is not AUTH_SIGNED_INGRESS (no
/// check ran), `Some(true)` only for a verified first sighting, else `Some(false)`. A route with no configured
/// secret is `Some(false)`: nothing is admitted unsigned.
pub(crate) async fn signed_of(
    ingress: &Ingress,
    who: &Namespace,
    route: &Mounted,
    headers: &[(String, Vec<u8>)],
    body: &[u8],
    now_s: u64,
) -> Option<bool> {
    if route.effective != AUTH_SIGNED_INGRESS {
        return None;
    }
    let Some(secret) = (ingress.secrets)(&who.name, route.route) else {
        return Some(false);
    };
    let pairs: Vec<Pair<'_>> = headers
        .iter()
        .map(|(name, value)| Pair {
            name: Str::new(name),
            value: WireBytes::new(value),
        })
        .collect();
    let admitted = signed_ingress::admit(
        &*ingress.verifier,
        &*ingress.replay,
        &who.caller(),
        &secret,
        &pairs,
        body,
        now_s,
    )
    .await;
    Some(admitted.is_ok())
}

/// The model names a ROUTE_CATALOG route lists: the governed principal's view. A request that carries no governance
/// context lists nothing.
fn models_of(ctx: &PlaneReqCtx) -> Vec<String> {
    let (Some(app), Some(gov)) = (app_of(&ctx.engine), ctx.gov.as_ref()) else {
        return Vec::new();
    };
    busbar_kernel::endpoints::catalog_names(&app, gov, &LaneQualifier::default())
}

/// A request the governance book refused to admit: the status its limit maps to, the wait it names (if any).
pub(crate) fn blocked_response(blocked: &LimitBlocked) -> PlaneResponse {
    let (refusal, retry_after) = blocked_client(blocked);
    let mut response = response_of(port_auth::plain_refusal(&refusal));
    retry_header(&mut response, retry_after);
    response
}

fn blocked_client(blocked: &LimitBlocked) -> (busbar_kernel::refusal::ClientRefusal, Option<u64>) {
    use busbar_contract::caps::ReasonCode;
    let (status, _, message, retry_after) = busbar_kernel::ingress::limit_refusal("", blocked);
    let reason = match blocked {
        LimitBlocked::Limit {
            metric: "budget", ..
        } => ReasonCode::OverBudget,
        LimitBlocked::Limit { .. } => ReasonCode::RateLimited,
        LimitBlocked::Disabled(_) => ReasonCode::GroupFrozen,
        LimitBlocked::MissingGroup(_) => ReasonCode::ScopeDenied,
        LimitBlocked::Draining => ReasonCode::Drain,
        LimitBlocked::CustodyFull { .. } => ReasonCode::SessionBudget,
    };
    (
        super::native_refusals::client(reason, status.as_u16(), &message),
        retry_after,
    )
}

fn retry_header(response: &mut PlaneResponse, retry_after: Option<u64>) {
    if let Some(seconds) = retry_after {
        if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
    }
}

/// The request as a billed unit: admitted through its resolved key's budget chain and opened on the plane money.
/// `None` = not billed (no billing installed, no governed key on the request, or no app generation to price
/// under): the request runs with audit rows only.
fn open_unit(
    seat: &PortSeat,
    billing: Option<&PortBilling>,
    ctx: &PlaneReqCtx,
    arrived: u64,
) -> Result<Option<Unit>, LimitBlocked> {
    let Some(billing) = billing else {
        return Ok(None);
    };
    let Some(key) = ctx.gov.as_ref().and_then(|gov| gov.key.clone()) else {
        return Ok(None);
    };
    let Some(app) = app_of(&ctx.engine) else {
        return Ok(None);
    };
    let mode = busbar_kernel::config::groups::ExhaustionMode::FinishUnit;
    billing
        .open(Admit {
            instance: &seat.instance,
            classes: seat.driver.usage_classes(),
            key,
            cost: Arc::clone(&app.cost),
            mode,
            arrived,
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

/// The client sink that also remembers the status of the head the plane wrote, so the unit settles by what the
/// client was answered (0 = no head was written), and that closes the response body at the plane's `End`: a session
/// that outlives its response (a held channel, a media bridge, a DETACH) must not hold its client's body open. What
/// the plane writes after the end has no client to go to and is dropped (the client is not gone, so `true`).
struct Counted {
    inner: Mutex<Option<Pipe>>,
    status: Arc<AtomicU16>,
}

impl ClientSink for Counted {
    fn items(&self, items: Vec<ToClient>) -> bool {
        for item in &items {
            if let ToClient::Head { status, .. } = item {
                let _ =
                    self.status
                        .compare_exchange(0, *status, Ordering::Relaxed, Ordering::Relaxed);
            }
        }
        let ended = items.iter().any(|item| matches!(item, ToClient::End));
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(pipe) = inner.as_ref() else {
            return true;
        };
        let open = pipe.items(items);
        if ended {
            *inner = None;
        }
        open
    }
}

async fn answer(
    seat: &PortSeat,
    route: &Mounted,
    ingress: Option<&Ingress>,
    billing: Option<&PortBilling>,
    generation: Option<&Arc<super::serve::DataRoutes>>,
    mut ctx: PlaneReqCtx,
) -> PlaneResponse {
    let now_s = busbar_kernel::store::now();
    let bearer = bearer_of(&ctx.headers, route.cred_header.as_deref());
    // Resolve the optional credential before billing. Retain the exact admitted key; the
    // principal's subject text alone cannot reconstruct external identity grants or budgets.
    let seen = match ctx.principal.as_ref().and_then(|p| p.0.as_ref()) {
        Some(p) => Seen::Verified(Arc::from(p.id.as_str())),
        None if resolves_credential(route.effective) => {
            let (seen, gov) = chain_principal(&ctx, bearer.as_deref()).await;
            ctx.gov = gov;
            seen
        }
        None => Seen::Anonymous,
    };
    let unit = match open_unit(seat, billing, &ctx, now_s) {
        Ok(unit) => unit,
        Err(blocked) => {
            let (refusal, retry_after) = blocked_client(&blocked);
            let mut response =
                match seat
                    .driver
                    .render_refusal_now(route.route, http_in(&ctx), refusal)
                {
                    Ok(items) => response_of(items),
                    Err(_) => blocked_response(&blocked),
                };
            retry_header(&mut response, retry_after);
            return response;
        }
    };
    let settle = match (&unit, billing) {
        (Some(unit), Some(billing)) => Some(Settle {
            billing: billing.clone(),
            key: unit.ctx.key,
            done: false,
        }),
        _ => None,
    };
    let invocation = match (&unit, generation) {
        (Some(unit), Some(generation)) => match generation.native_unit(seat, unit, &ctx) {
            Ok(invocation) => Some(invocation),
            Err(why) => {
                tracing::warn!(instance = %seat.instance, why, "native invocation refused");
                return failed(StatusCode::SERVICE_UNAVAILABLE);
            }
        },
        (Some(_), None) => return failed(StatusCode::SERVICE_UNAVAILABLE),
        (None, _) => None,
    };
    let (principal, identity) = match &seen {
        Seen::Verified(id) => (Some(Arc::clone(id)), Some(subject_identity(id))),
        Seen::Anonymous | Seen::Rejected => (None, None),
    };
    let http = http_in(&ctx);
    let request = ctx.request.clone();
    let signed = match ingress {
        Some(ingress) => {
            signed_of(ingress, &seat.who, route, &http.headers, &http.body, now_s).await
        }
        None => None,
    };
    let models = if route.catalog {
        models_of(&ctx)
    } else {
        Vec::new()
    };
    let (head_tx, mut head_rx) = oneshot::channel();
    let (body_tx, body_rx) = mpsc::unbounded_channel();
    let status = Arc::new(AtomicU16::new(0));
    let pipe = Counted {
        inner: Mutex::new(Some(Pipe {
            head: Mutex::new(Some(head_tx)),
            body: body_tx,
        })),
        status: Arc::clone(&status),
    };
    let (seat, route) = (seat.clone(), route.clone());
    // The session outlives this call when its reply streams, so it owns everything it borrows.
    let mut session = tokio::spawn(async move {
        let creds = Credentials {
            bearer: bearer.as_deref().map(Presented::new),
            principal: match (&seen, &identity) {
                (Seen::Verified(_), Some(records)) => Principal::Verified(records),
                (Seen::Rejected, _) => Principal::Rejected(R_BAD_CREDENTIAL),
                _ => Principal::Anonymous,
            },
            operator: false,
            signed,
        };
        let input = ServeIn {
            request,
            invocation: invocation.as_ref().map(|owner| owner.context.clone()),
            route: route.route,
            http,
            creds,
            audience: seat.audience.as_deref().unwrap_or_default(),
            now_s,
            principal,
            unit,
            upstream: seat.upstream.clone(),
            client: Some(Arc::new(pipe)),
            carrier: seat.carrier.clone(),
            intents: Arc::clone(&seat.intents),
            models,
        };
        let served = seat.driver.serve(input).await;
        drop(invocation);
        if let Err(error) = &served {
            tracing::warn!(instance = %seat.instance, route = route.route, ?error, "a plane request failed");
        }
        if let Some(settle) = settle {
            match &served {
                Ok(Served::Refused(items)) => {
                    settle.finish(port_admin::joined(items.clone()).0, false)
                }
                Ok(Served::Ran(_)) => settle.finish(
                    match status.load(Ordering::Relaxed) {
                        0 => 502,
                        status => status,
                    },
                    true,
                ),
                Err(_) => settle.finish(502, false),
            }
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

/// One spec per (data route, verb) of every seat, catalog routes included. `ingress` is what an
/// AUTH_SIGNED_INGRESS route verifies with (`None` = no route can be admitted as signed).
pub(crate) fn routes(
    seats: &[PortSeat],
    ingress: Option<Arc<Ingress>>,
    billing: Option<&PortBilling>,
    generation: Option<Arc<super::serve::DataRoutes>>,
) -> Vec<PlaneRouteSpec> {
    let mut out = Vec::new();
    for seat in seats {
        for route in seat.driver.routes().data.iter() {
            for method in methods_of(route.methods) {
                let seat = seat.clone();
                let mounted = route.clone();
                let ingress = ingress.clone();
                let billing = billing.cloned();
                let generation = generation.clone();
                out.push(PlaneRouteSpec {
                    path: route.pattern.to_string(),
                    method,
                    auth: auth_of(route.effective),
                    handler: Arc::new(move |ctx: PlaneReqCtx| -> PlaneRouteFuture {
                        let seat = seat.clone();
                        let mounted = mounted.clone();
                        let ingress = ingress.clone();
                        let billing = billing.clone();
                        let generation = generation.clone();
                        Box::pin(async move {
                            answer(
                                &seat,
                                &mounted,
                                ingress.as_deref(),
                                billing.as_ref(),
                                generation.as_ref(),
                                ctx,
                            )
                            .await
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
