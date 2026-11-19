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
//! - ROUTE_UPGRADE (§12.27) is sealed as a line of its plane ([`guest_lines`]) and served by the native listener:
//!   the route's auth chain first, then [`upgrade_step`]: 400 for a request that does not ask for websocket, 501
//!   when no admitted instance declares D_PROTOCOL `websocket`, else the hand-over seam
//!   ([`UpgradeStep::HandOver`]), whose adopter is linked with the websocket transport (E9b). Core's refusal comes before the plane's `request`, which
//!   is never called for it; the plane only renders it.
//!
//! A request is not a billed unit on this path yet (`unit: None`: audit rows only), and a FORWARD walks only when
//! the seat carries a `PortEgress` (`PortSeat::upstream`).

use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use busbar_contract::route::{RouteAuth, RouteMethod};
use busbar_contract::route::{METHOD_DELETE, METHOD_GET, METHOD_PATCH, METHOD_POST, METHOD_PUT};
use busbar_contract::secret_ref::SecretRef;
use busbar_kernel::auth::{AuthPrincipal, ChainHead, IdentityRefusal};
use busbar_kernel::governance::{GovCtx, LimitBlocked};
use busbar_kernel::ingress::signed_ingress;
use busbar_kernel::plane_driver::dispatch::LaneQualifier;
use busbar_kernel::plane_driver::port::{
    HttpHead, HttpIn, PortSeat, ServeError, ServeIn, Served, Unit,
};
use busbar_kernel::plane_driver::port_admin;
use busbar_kernel::plane_driver::port_admission::{AdmittedUnit, Pending};
use busbar_kernel::plane_driver::port_auth::{self, Credentials, Presented, Principal, Subject};
use busbar_kernel::plane_driver::port_billing::{end_of, PortBilling};
use busbar_kernel::plane_driver::port_intents::Namespace;
use busbar_kernel::plane_driver::port_routes::Mounted;
use busbar_kernel::plane_driver::port_session::{ClientSink, ToClient};
use busbar_kernel::plane_driver::request_admission::RequestAllocation;
use busbar_kernel::plane_driver::{HeadFields, NativeAdmissionError};
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

/// The auth points a native line offers: the head, and the head with its body (what a transport
/// that states no offer of its own has always offered).
pub(crate) const LINE_OFFERED: busbar_contract::route::AuthPoints =
    busbar_contract::route::AuthPoints(
        busbar_contract::route::POINT_HEAD | busbar_contract::route::POINT_HEAD_BODY,
    );

/// The routes whose effective chain is not the data chain (§12.11), by plane instance and route id:
/// `Some(chain)`, or `None` for a route that is not served (not mounted at all). Resolved once per
/// candidate, kept by the listener plan's assembly only.
pub(crate) type RouteChains = std::collections::BTreeMap<
    String,
    std::collections::BTreeMap<u32, Option<Vec<super::serve::ChainAuth>>>,
>;

/// The same native route table admitted by the driver seals physical listener claims. The
/// route id is the renderer's native selector; native render has no legacy dialect number.
/// A route in `route_chains` runs its own effective chain; every other one runs `chain`.
pub(crate) fn guest_lines(
    seats: &[PortSeat],
    chain: &[super::serve::ChainAuth],
    route_chains: &RouteChains,
) -> Vec<busbar_kernel::guest::Line> {
    use busbar_contract::route::{method_bit, PATH_EXACT, PATH_PATTERN};
    use busbar_kernel::guest::{Claimant, Line, LineAuth, Route};
    seats
        .iter()
        .flat_map(|seat| {
            let routes = seat.driver.routes();
            let own = route_chains.get(&seat.instance);
            // A ROUTE_UPGRADE route (§12.27) is sealed like a data route: its head is matched,
            // authenticated and answered by the native listener (`listener_native_upgrade.rs`).
            routes
                .data
                .iter()
                .chain(&routes.upgrade)
                .filter_map(move |route| {
                    // A route that is not served is not mounted (§12.11 as ruled).
                    let (chain, own_chain) = match own.and_then(|own| own.get(&route.route)) {
                        Some(None) => return None,
                        Some(Some(own)) => (own.as_slice(), true),
                        None => (chain, false),
                    };
                    // A signed route's line names its own chain (the readers of its signature
                    // header): that chain is its signature verifier, bound by the listener plan
                    // as a `NativeSignedRoute`. It never names the data chain: a signed route
                    // with no chain of its own is not mounted at all.
                    let signed = own_chain && route.effective == AUTH_SIGNED_INGRESS;
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
                        auth: if auth_of(route.effective) == RouteAuth::Key || signed {
                            super::serve::chain_auth(chain)
                        } else {
                            LineAuth::None
                        },
                        upgrade: None,
                        offered: LINE_OFFERED,
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
        // The value's own allocation becomes the header value (checked as `from_bytes` checks
        // it): the head's values are handed to the response, not copied into it.
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(&name),
            HeaderValue::from_maybe_shared(Bytes::from(value)),
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
    let http = HttpIn::new(
        HttpHead::Text {
            method: method.to_owned(),
            path: path.to_owned(),
            query: query.to_owned(),
            headers: Vec::new(),
        },
        Bytes::new(),
        REQUEST_IDS.fetch_add(1, Ordering::Relaxed),
    );
    match seat.driver.render_refusal_now(route, &http, &refusal) {
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

/// The request as the plane is served it: its parts move in (the header map leaves `ctx`, which reads none after this).
fn http_in(ctx: &mut PlaneReqCtx) -> HttpIn {
    HttpIn::new(
        HttpHead::Parts {
            method: ctx.method.as_str(),
            uri: ctx.uri.clone(),
            headers: std::mem::take(&mut ctx.headers),
        },
        ctx.body.clone(),
        REQUEST_IDS.fetch_add(1, Ordering::Relaxed),
    )
}

/// The client's end of a streamed reply (`ClientSink`): the plane's first head decides the response, every later
/// body or message item feeds its body as it is written. Trailers and the end mark carry nothing on HTTP/1.
struct Pipe {
    head: Mutex<Option<oneshot::Sender<(u16, HeadFields)>>>,
    body: mpsc::UnboundedSender<Bytes>,
}

impl ClientSink for Pipe {
    /// The body channel has no bound here, so items are taken at once and nothing waits.
    fn poll_items(
        &self,
        _cx: &mut std::task::Context<'_>,
        items: &mut Vec<ToClient>,
    ) -> std::task::Poll<bool> {
        std::task::Poll::Ready(self.items(std::mem::take(items)))
    }
}

impl Pipe {
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
        Ok(Ok(Served::Refused(refused))) => response_of(refused.items),
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
    /// The chain identified it: its principal, moved out of the verdict (the subject is its id).
    Verified(busbar_contract::auth::Principal),
    /// A credential the chain (or the governance binding) refused.
    Rejected,
}

/// The chain's verdict, as the principal the route is handed.
pub(crate) fn seen_of(resolved: Result<(AuthPrincipal, GovCtx), IdentityRefusal>) -> Seen {
    match resolved {
        Ok((AuthPrincipal(Some(principal)), _)) => Seen::Verified(principal),
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
async fn chain_principal(
    ctx: &PlaneReqCtx,
    bearer: Option<&str>,
) -> (
    Seen,
    Option<GovCtx>,
    Option<busbar_kernel::auth::SignedRequestAuthority>,
) {
    let Some(token) = bearer else {
        return (Seen::Anonymous, None, None);
    };
    let Some(app) = app_of(&ctx.engine) else {
        return (Seen::Rejected, None, None);
    };
    if app.auth.is_open() {
        return (Seen::Anonymous, None, None);
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
    let signed = match &verdict {
        busbar_kernel::auth::ChainVerdict::Identified {
            signed_authority, ..
        } => signed_authority.clone(),
        _ => None,
    };
    match busbar_kernel::auth::resolve_data_plane_identity(&app, verdict) {
        Ok((principal, gov)) => (
            seen_of(Ok((principal, GovCtx::default()))),
            Some(gov),
            signed,
        ),
        Err(why) => (seen_of(Err(why)), None, None),
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
    http: &HttpIn,
    now_s: u64,
) -> Option<bool> {
    if route.effective != AUTH_SIGNED_INGRESS {
        return None;
    }
    let Some(secret) = (ingress.secrets)(&who.name, route.route) else {
        return Some(false);
    };
    let mut pairs: Vec<Pair<'_>> = Vec::new();
    http.each_header(|name, value| {
        pairs.push(Pair {
            name: Str::new(name),
            value: WireBytes::new(value),
        });
    });
    let admitted = signed_ingress::admit(
        &*ingress.verifier,
        &*ingress.replay,
        &who.caller(),
        &secret,
        &pairs,
        &http.body,
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
#[cfg(test)]
pub(crate) fn blocked_response(blocked: &LimitBlocked) -> PlaneResponse {
    let (refusal, retry_after) = blocked_client(blocked);
    let mut response = response_of(port_auth::plain_refusal(&refusal));
    retry_header(&mut response, retry_after);
    response
}

pub(crate) fn blocked_client(
    blocked: &LimitBlocked,
) -> (busbar_kernel::refusal::ClientRefusal, Option<u64>) {
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
        super::native_refusals::client(reason, status.as_u16(), message),
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

/// Allocate only the unit identity. The retained task's checked pool receipt owns the later
/// monetary admission; allocation itself charges nothing and acquires no governor hold.
fn allocate_unit(
    seat: &PortSeat,
    billing: Option<&PortBilling>,
    ctx: &PlaneReqCtx,
) -> Option<Unit> {
    let billing = billing?;
    ctx.gov.as_ref()?.key.as_ref()?;
    app_of(&ctx.engine)?;
    Some(billing.allocate(seat.driver.usage_classes()))
}

/// A unit's settlement, owed once whatever becomes of the request: dropped unfinished (a panic, a cancelled
/// task) it settles as `end_of(502, false)`, so the unit never stays open and its hold never leaks. The money
/// rule is that a session bills exactly the usage it accepted, once, whatever its ending: a dropped or failed
/// session bills what it accepted so far, a request whose far end was dialled stays counted as having run, an
/// unpriced final report writes `BUSBAR-5046` `plane-usage-unread` and leaves the unit unresolved, and a
/// refused report is audited, never billed.
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
    fn poll_items(
        &self,
        _cx: &mut std::task::Context<'_>,
        items: &mut Vec<ToClient>,
    ) -> std::task::Poll<bool> {
        std::task::Poll::Ready(self.items(std::mem::take(items)))
    }
}

impl Counted {
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
    let seen = match ctx.principal.take().and_then(|p| p.0) {
        Some(p) => Seen::Verified(p),
        None if resolves_credential(route.effective) => {
            let (seen, gov, signed_authority) = chain_principal(&ctx, bearer.as_deref()).await;
            ctx.gov = gov;
            ctx.signed_authority = signed_authority;
            seen
        }
        None => Seen::Anonymous,
    };
    // The occurrence proof owns its original key. An unrelated resolved key may not
    // select the payer before the atomic one-shot registration below.
    if let Some(authority) = &ctx.signed_authority {
        if !ctx
            .gov
            .as_ref()
            .and_then(|gov| gov.key.as_ref())
            .is_some_and(|key| Arc::ptr_eq(key, authority.original_key()))
        {
            return failed(StatusCode::UNAUTHORIZED);
        }
    }
    let mut unit = allocate_unit(seat, billing, &ctx);
    // A billable unit opens only while its node's journal can record its money.
    if unit.is_some() {
        let gate = generation.and_then(|routes| routes.post.node());
        if let Some(Err(refusal)) = gate.map(|node| node.money_gate()) {
            let target = ctx
                .uri
                .path_and_query()
                .map_or(ctx.path.as_str(), |pq| pq.as_str());
            return render_kernel_refusal(seat, route.route, ctx.method.as_str(), target, refusal);
        }
    }

    let settle = match (&unit, billing) {
        (Some(unit), Some(billing)) => Some(Settle {
            billing: billing.clone(),
            key: unit.ctx.key,
            done: false,
        }),
        _ => None,
    };
    let invocation = match (&mut unit, generation) {
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
    let retry_after = Arc::new(Mutex::new(None));
    let admission = match (unit, &invocation, billing) {
        (Some(unit), Some(invocation), Some(billing)) => {
            let Some(app) = app_of(&ctx.engine) else {
                return failed(StatusCode::SERVICE_UNAVAILABLE);
            };
            let allocation = match RequestAllocation::new(
                invocation.context.clone(),
                Arc::clone(&app.cost),
                now_s,
            ) {
                Ok(allocation) => allocation,
                Err(_) => return failed(StatusCode::SERVICE_UNAVAILABLE),
            };
            let Some(original_route) = seat.retain_route(&invocation.context, route.route) else {
                return failed(StatusCode::SERVICE_UNAVAILABLE);
            };
            let billing = billing.clone();
            let classes = seat.driver.usage_classes();
            let route_id = route.route;
            let retry_after = Arc::clone(&retry_after);
            Some(Arc::new(
                Pending::new(
                    allocation,
                    Arc::clone(&seat.request_routes),
                    unit.journal.clone(),
                    move |receipt| {
                        use busbar_kernel::refusal::RefusalMap;
                        let unavailable = || {
                            busbar_kernel::refusal::CoreRefusals::new()
                                .for_core(route_id, busbar_plugin_abi::fail::refused::R_NO_ROUTE)
                        };
                        let receipt = receipt.begin().map_err(|_| unavailable())?;
                        let request = billing
                            .admit_existing(
                                receipt,
                                classes,
                                busbar_kernel::plane_driver::FeeRefund::PlaneFeeUnits(
                                    Arc::from([]),
                                ),
                                busbar_kernel::config::groups::ExhaustionMode::FinishUnit,
                            )
                            .map_err(|error| match error {
                                NativeAdmissionError::Blocked(blocked) => {
                                    let (refusal, wait) = blocked_client(&blocked);
                                    *retry_after.lock().unwrap_or_else(PoisonError::into_inner) =
                                        wait;
                                    refusal
                                }
                                _ => unavailable(),
                            })?;
                        let rollback = billing
                            .admission_rollback(&request)
                            .map_err(|_| unavailable())?;
                        AdmittedUnit::ordinary(request, unit, rollback).map_err(|_| unavailable())
                    },
                )
                .with_channel_budget(seat.channel_budget.unit())
                .with_current_rates(ctx.handle.selected_rate_admission())
                .with_route(original_route),
            ))
        }
        (None, None, _) => None,
        _ => return failed(StatusCode::SERVICE_UNAVAILABLE),
    };
    let http = http_in(&mut ctx);
    let request = ctx.request.clone();
    let signed = match ingress {
        Some(ingress) => signed_of(ingress, &seat.who, route, &http, now_s).await,
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
            principal: match seen {
                Seen::Verified(p) => Principal::Verified(Subject::Principal(Arc::new(p))),
                Seen::Rejected => Principal::Rejected(R_BAD_CREDENTIAL),
                Seen::Anonymous => Principal::Anonymous,
            },
            operator: false,
            signed,
        };
        let input = ServeIn {
            request,
            admission,
            invocation: invocation.as_ref().map(|owner| owner.context.clone()),
            route: route.route,
            http,
            creds,
            audience: seat.audience.as_deref().unwrap_or_default(),
            now_s,
            unit: None,
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
                    settle.finish(port_admin::joined(items.items.clone()).0, false)
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
    let mut response = tokio::select! {
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
    };
    let wait = *retry_after.lock().unwrap_or_else(PoisonError::into_inner);
    retry_header(&mut response, wait);
    response
}

/// §12.27 step 1's header test: the request asks to switch protocols to websocket
/// (`connection` lists the `upgrade` token and `upgrade` lists `websocket`, both case-insensitive).
pub(crate) fn asks_websocket<'a>(headers: impl Iterator<Item = (&'a str, &'a [u8])>) -> bool {
    fn lists(value: &[u8], token: &str) -> bool {
        std::str::from_utf8(value).is_ok_and(|value| {
            value
                .split(',')
                .any(|item| item.trim().eq_ignore_ascii_case(token))
        })
    }
    let (mut connection, mut upgrade) = (false, false);
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("connection") {
            connection |= lists(value, "upgrade");
        } else if name.eq_ignore_ascii_case("upgrade") {
            upgrade |= lists(value, "websocket");
        }
    }
    connection && upgrade
}

/// What core does with an authorized ROUTE_UPGRADE request (§12.27 steps 1-2). The header and
/// instance tests run after the route's auth, not before as step 1 lists them: on the native
/// listener an anonymous request to a missing route and to a gated one look the same, and a pre-auth
/// 400 or 501 would tell an anonymous caller that the route exists, that it upgrades and what the
/// listener lacks. A refusal is written before any 101 as a plain status
/// response the plane renders (`render(RENDER_REFUSAL)`), and the plane's `request` is never called.
pub(crate) enum UpgradeStep<'a> {
    /// The request does not ask to switch to websocket (400 R_INVALID), or no admitted instance on
    /// this listener declares D_PROTOCOL `websocket` (501 R_UNSUPPORTED).
    Refuse(busbar_kernel::refusal::ClientRefusal),
    /// Hand the request to this instance (§12.27 steps 2-5). THE HAND-OVER SEAM for the step that
    /// links the websocket transport (E9b): the request is consumed once with the kernel's
    /// `CompletingPhysicalRequest::complete_upgrade(authorization)`, whose `PhysicalUpgrade` carries
    /// the charged head, the verified identity, the governed key and the plane route. The carrier
    /// then calls the plane's `request` on that head with an empty body, commits on its
    /// RESPOND(101) and `begin`s this instance with CONN_UPGRADED and the head + H_STATUS(101) + the
    /// plane's PAIR*. Until that adopter is linked, listener-plan assembly refuses a candidate
    /// whose upgrade routes could reach this arm.
    HandOver(&'a super::min3_boot::transports::ServedTransport),
}

/// The words of core's two refusals before any 101.
pub(crate) const NOT_AN_UPGRADE: &str = "this route accepts only a websocket upgrade request";
pub(crate) const NO_WEBSOCKET: &str = "no transport on this listener can carry a websocket upgrade";

pub(crate) fn upgrade_step(
    asks: bool,
    websocket: Option<&super::min3_boot::transports::ServedTransport>,
) -> UpgradeStep<'_> {
    use busbar_kernel::refusal::ClientRefusal;
    use busbar_plugin_abi::fail::refused::{R_INVALID, R_UNSUPPORTED};
    match (asks, websocket) {
        (false, _) => UpgradeStep::Refuse(ClientRefusal {
            status: 400,
            code: R_INVALID,
            text: NOT_AN_UPGRADE.into(),
        }),
        (true, None) => UpgradeStep::Refuse(ClientRefusal {
            status: 501,
            code: R_UNSUPPORTED,
            text: NO_WEBSOCKET.into(),
        }),
        (true, Some(websocket)) => UpgradeStep::HandOver(websocket),
    }
}

/// The client items of core's refusal on an upgrade route: the plane's rendering of it on that
/// route (the plane is lent the head, never called with `request`), else core's plain refusal.
pub(crate) fn upgrade_refusal_items(
    seat: &PortSeat,
    route: u32,
    head: &Arc<busbar_kernel::inbound::request_snapshot::ChargedRequestSnapshot>,
    withheld: &Arc<[Box<str>]>,
    request_id: u64,
    refusal: busbar_kernel::refusal::ClientRefusal,
) -> Vec<ToClient> {
    let mut http = HttpIn::new(
        HttpHead::Snapshot(Arc::clone(head)),
        Bytes::new(),
        request_id,
    );
    // The plane renders the refusal on the head it is lent: never the route's credential carriers.
    http.withhold(Arc::clone(withheld));
    // A direct call on this thread; the snapshot `head` keeps the request's charged input for it.
    match seat.driver.render_refusal_now(route, &http, &refusal) {
        Ok(items) => items,
        Err(_) => port_auth::plain_refusal(&refusal),
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
