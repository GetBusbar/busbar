// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::Router;

use crate::off_path::router::base_data_router_scoped;
pub(crate) use crate::off_path::router::project_auth_scope_caps;
use crate::{auth, endpoints, limits, state};

pub(crate) const HEADER_SERVER_TIMING: &str = "server-timing";

/// The [`UPSTREAM_RTT_US`] value of a request that dispatched no upstream call: its
/// `Server-Timing` reports the full processing time.
pub(crate) const NO_UPSTREAM_RTT: u64 = u64::MAX;

tokio::task_local! {
    /// The `Server-Timing` measurement of the request in flight, scoped by
    /// [`ServerTiming::measure`] for exactly that request: where the forward path records the
    /// upstream round trip. Absent whenever the header is off, so a deployment without it records
    /// nothing and reads no clock.
    static MEASURING: ServerTiming;
}

/// The request's upstream round-trip slot, when `Server-Timing` is measuring this request.
///
/// The forward path takes it once per attempt, reads the clock only when it is `Some`, and stores
/// with [`record_upstream_rtt`]. A unit polled outside the request's scope (a streamed body pumped
/// after the head went out, a detached child) finds none, after the header was already written.
pub(crate) fn upstream_rtt_slot() -> Option<std::sync::Arc<std::sync::atomic::AtomicU64>> {
    MEASURING
        .try_with(|timing| std::sync::Arc::clone(&timing.upstream_us))
        .ok()
}

/// Record `rtt` as the request's upstream round trip. The last recording wins, as in 1.5.5: on
/// failover the answering attempt's round trip replaces a failed one's.
pub(crate) fn record_upstream_rtt(slot: &std::sync::atomic::AtomicU64, rtt: std::time::Duration) {
    let us = u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX - 1);
    slot.store(us, std::sync::atomic::Ordering::Relaxed);
}

static SERVER_TIMING_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Set once at boot from `advanced.response_headers.server_timing` (restart-to-apply), for the
/// request paths that do not run through a router this module composes: the framed listener serves
/// a plane's arrival straight to the plane, and asks [`ServerTiming::start`] per request.
pub fn configure_server_timing(enabled: bool) {
    let _ = SERVER_TIMING_ENABLED.set(enabled);
}

/// One request's `Server-Timing: busbar;dur=<ms>` measurement: Busbar's OWN added latency, the
/// request's wall-clock MINUS the upstream round trip the forward path recorded while it ran
/// [`ServerTiming::measure`] (`PlaneUnits::attempts`). A request that dispatched no upstream call
/// reports its full processing time. W3C `dur` is milliseconds, written at µs precision.
#[derive(Debug, Clone)]
pub struct ServerTiming {
    /// The request's one start reading of the node's monotonic clock, in nanoseconds.
    start_ns: u64,
    upstream_us: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl ServerTiming {
    /// The header's name.
    pub const HEADER: &'static str = HEADER_SERVER_TIMING;

    /// The measurement for a request arriving now, or `None` when the header is off (configured
    /// by [`configure_server_timing`]): nothing allocated, no clock read.
    #[must_use]
    pub fn start() -> Option<Self> {
        SERVER_TIMING_ENABLED
            .get()
            .copied()
            .unwrap_or(false)
            .then(Self::now)
    }

    fn now() -> Self {
        Self {
            start_ns: crate::store::monotonic_ns(),
            upstream_us: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(NO_UPSTREAM_RTT)),
        }
    }

    /// Serve the request under this measurement, so its forward path records its round trip here.
    pub async fn measure<F: std::future::Future>(&self, serving: F) -> F::Output {
        MEASURING.scope(self.clone(), serving).await
    }

    /// The header's value as of now for the request being measured ([`ServerTiming::measure`]),
    /// for a response head written from inside it; `None` when the header is off.
    #[must_use]
    pub fn current_value() -> Option<String> {
        MEASURING
            .try_with(|timing| String::from(timing.value().as_str()))
            .ok()
    }

    /// The header's value as of now: `busbar;dur=<ms>`, written on the stack.
    #[must_use]
    pub(crate) fn value(&self) -> ServerTimingValue {
        let total_us = crate::store::monotonic_ns().saturating_sub(self.start_ns) / 1000;
        let upstream_us = self.upstream_us.load(std::sync::atomic::Ordering::Relaxed);
        let mut value = ServerTimingValue::default();
        // `busbar;dur=` plus at most 20 integer digits and `.NNN` fits the buffer.
        let _ = std::fmt::Write::write_fmt(
            &mut value,
            format_args!(
                "busbar;dur={:.3}",
                server_timing_dur_ms(total_us, upstream_us)
            ),
        );
        value
    }
}

/// A `Server-Timing` header value, written into a fixed stack buffer so a measured response
/// allocates no string for it.
#[derive(Clone, Copy)]
pub(crate) struct ServerTimingValue {
    bytes: [u8; 64],
    len: usize,
}

impl Default for ServerTimingValue {
    fn default() -> Self {
        Self {
            bytes: [0; 64],
            len: 0,
        }
    }
}

impl ServerTimingValue {
    /// The value's text.
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len]).unwrap_or_default()
    }
}

impl std::fmt::Write for ServerTimingValue {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let end = self.len + s.len();
        let dst = self.bytes.get_mut(self.len..end).ok_or(std::fmt::Error)?;
        dst.copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

tokio::task_local! {
    // A router's physical ownership, retained across its middleware and handler future.
    static PHYSICAL_REFUSER: (bool, Option<crate::plane_routes::PlaneRefuseByPathFn>);
}

/// Admin responses can contain credentials, including an idempotent replay. Apply this outside
/// every handler/replay path. Axum extractor refusals are plain text and may quote request values;
/// replace those framework errors without inspecting or retaining their body.
async fn admin_response_boundary(
    axum::extract::State(handle): axum::extract::State<std::sync::Arc<state::AppHandle>>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::{header::CONTENT_TYPE, StatusCode};
    let prefix = crate::admin::gate::ADMIN_PREFIX;
    let admin = !is_private_listener()
        && (req.uri().path() == prefix
            || req
                .uri()
                .path()
                .strip_prefix(prefix)
                .is_some_and(|tail| tail.starts_with('/')));
    if !admin {
        return next.run(req).await;
    }
    let request_id = crate::admin::gate::request_id_of(handle.load().next_request_id());
    // The admin router layer that owns ETags and `Idempotency-Key` (ADMIN-API-1.6 6) reads the
    // handle from here: a layer on a `Router<Arc<AppHandle>>` cannot extract `State`.
    req.extensions_mut().insert(handle.clone());
    let mut response = crate::admin::gate::with_request_id(request_id.clone(), next.run(req)).await;
    let plain_text = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(';').next() == Some("text/plain"));
    if plain_text {
        response = match response.status() {
            StatusCode::BAD_REQUEST
            | StatusCode::UNSUPPORTED_MEDIA_TYPE
            | StatusCode::UNPROCESSABLE_ENTITY => {
                crate::admin::gate::in_request_scope(&request_id, || {
                    crate::admin::gate::admin_error_envelope(
                        400,
                        "invalid_request",
                        "malformed admin request",
                    )
                })
            }
            StatusCode::PAYLOAD_TOO_LARGE => {
                crate::admin::gate::in_request_scope(&request_id, || {
                    crate::admin::gate::admin_error_envelope(
                        413,
                        busbar_contract::protocol::ERR_TYPE_REQUEST_TOO_LARGE,
                        "admin request body exceeds the configured limit",
                    )
                })
            }
            _ => response,
        };
    }
    if let Ok(value) = axum::http::HeaderValue::from_str(&request_id) {
        response
            .headers_mut()
            .entry(crate::admin::gate::HEADER_REQUEST_ID)
            .or_insert(value);
    }
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

pub(crate) fn is_private_listener() -> bool {
    PHYSICAL_REFUSER
        .try_with(|(private, _)| *private)
        .unwrap_or(false)
}

pub(crate) fn private_listener_scope<T>(f: impl FnOnce() -> T) -> T {
    PHYSICAL_REFUSER.sync_scope((true, None), f)
}

pub fn fallback_error_response(
    planes: &crate::plane_driver::dispatch::PlaneDispatch,
    path: &str,
    status: axum::http::StatusCode,
    kind: &str,
    message: &str,
) -> axum::response::Response {
    if is_private_listener() {
        return crate::ingress::native::native_error(
            crate::plane_driver::dispatch::Ingress::Fallback(None),
            status,
            kind,
            message,
        );
    }

    {
        use crate::admin::gate::ApiError;
        if under_api_root(path) {
            if status == axum::http::StatusCode::PAYLOAD_TOO_LARGE {
                return crate::admin::gate::admin_error_envelope(status.as_u16(), kind, message);
            }
            let e = if status == axum::http::StatusCode::METHOD_NOT_ALLOWED {
                ApiError::MethodNotAllowed
            } else if status == axum::http::StatusCode::INTERNAL_SERVER_ERROR {
                ApiError::Internal
            } else {
                ApiError::NotFound
            };
            return crate::admin::gate::err_json(&e);
        }
    }

    crate::ingress::native::native_error(planes.ingress_of(path), status, kind, message)
}

#[expect(
    clippy::too_many_arguments,
    reason = "config: the refusal renderer receives every field of the refusal it renders"
)]
pub(crate) fn kernel_refusal_response(
    handle: &state::AppHandle,
    planes: &crate::plane_driver::dispatch::PlaneDispatch,
    reason: busbar_contract::caps::ReasonCode,
    path: &str,
    target: &str,
    status: axum::http::StatusCode,
    kind: &str,
    message: &str,
) -> axum::response::Response {
    let native_api = !is_private_listener() && under_api_root(path);
    if !native_api {
        let refusal = busbar_kernel::plane_routes::KernelRefusal {
            reason,
            status: status.as_u16(),
            text: message,
            path,
            target,
            selected_line: None,
        };
        let rendered = PHYSICAL_REFUSER
            .try_with(|(_, render)| render.as_ref().and_then(|render| render(&refusal)))
            .unwrap_or_else(|_| handle.door_refusal(&refusal));
        if let Some(rendered) = rendered {
            return rendered;
        }
    }
    fallback_error_response(planes, path, status, kind, message)
}

/// Whether `path` is the admin API root or under it (`API_ROOT` or `API_ROOT/...`).
fn under_api_root(path: &str) -> bool {
    path.strip_prefix(crate::admin::gate::API_ROOT)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

fn target_of(uri: &axum::http::Uri) -> &str {
    uri.path_and_query()
        .map_or_else(|| uri.path(), axum::http::uri::PathAndQuery::as_str)
}

pub(crate) async fn method_not_allowed_handler(
    axum::extract::State(handle): axum::extract::State<std::sync::Arc<state::AppHandle>>,
    state::CurrentApp(app): state::CurrentApp,
    uri: axum::http::Uri,
) -> axum::response::Response {
    kernel_refusal_response(
        &handle,
        &app.planes,
        busbar_contract::caps::ReasonCode::MethodNotAllowed,
        uri.path(),
        target_of(&uri),
        axum::http::StatusCode::METHOD_NOT_ALLOWED,
        busbar_contract::protocol::ERR_TYPE_INVALID_REQUEST,
        "method not allowed for this resource",
    )
}

pub(crate) async fn private_not_found(
    axum::extract::State(handle): axum::extract::State<std::sync::Arc<state::AppHandle>>,
    state::CurrentApp(app): state::CurrentApp,
    uri: axum::http::Uri,
) -> axum::response::Response {
    kernel_refusal_response(
        &handle,
        &app.planes,
        busbar_contract::caps::ReasonCode::NoDestination,
        uri.path(),
        target_of(&uri),
        axum::http::StatusCode::NOT_FOUND,
        busbar_contract::protocol::ERR_TYPE_NOT_FOUND,
        "the requested resource was not found",
    )
}

pub(crate) const AXUM_BODY_LIMIT_413_MARKER: &[u8] = b"length limit exceeded";

pub(crate) async fn reshape_body_limit_413(
    axum::extract::State(handle): axum::extract::State<std::sync::Arc<state::AppHandle>>,
    state::CurrentApp(app): state::CurrentApp,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // The URI's parts share the request head's bytes: kept by reference count, not copied, in
    // case the response is a 413 that names them.
    let uri = req.uri().clone();
    let resp = next.run(req).await;

    if resp.status() != axum::http::StatusCode::PAYLOAD_TOO_LARGE {
        return resp;
    }

    let render = || {
        kernel_refusal_response(
            &handle,
            &app.planes,
            busbar_contract::caps::ReasonCode::BodyTooLarge,
            uri.path(),
            target_of(&uri),
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            busbar_contract::protocol::KIND_REQUEST_TOO_LARGE,
            OVERSIZED_MESSAGE,
        )
    };
    reshape_oversized_413_with(render, resp).await
}

const OVERSIZED_MESSAGE: &str = "request body exceeds the maximum allowed size";

pub static REQUEST_ACTIVITY_TICKS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub(crate) fn server_timing_dur_ms(total_us: u64, upstream_us: u64) -> f64 {
    let internal_us = if upstream_us == NO_UPSTREAM_RTT {
        total_us
    } else {
        total_us.saturating_sub(upstream_us)
    };
    internal_us as f64 / 1000.0
}

pub(crate) async fn request_activity_tick(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    REQUEST_ACTIVITY_TICKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    next.run(req).await
}

/// Stamps `Server-Timing: busbar;dur=<ms>` ([`ServerTiming`]) on a response this router serves.
///
/// Installed as a layer ONLY when `advanced.response_headers.server_timing` is on
/// ([`apply_common_layers`]), so a deployment without the header pays nothing per request.
pub(crate) async fn server_timing(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let timing = ServerTiming::now();
    let mut resp = timing.measure(next.run(req)).await;
    if let Ok(v) = axum::http::HeaderValue::from_str(timing.value().as_str()) {
        resp.headers_mut()
            .insert(axum::http::HeaderName::from_static(HEADER_SERVER_TIMING), v);
    }
    resp
}

#[cfg(test)]
pub(crate) async fn reshape_oversized_413(
    planes: &crate::plane_driver::dispatch::PlaneDispatch,
    path: &str,
    resp: axum::response::Response,
) -> axum::response::Response {
    let render = || {
        fallback_error_response(
            planes,
            path,
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            busbar_contract::protocol::KIND_REQUEST_TOO_LARGE,
            OVERSIZED_MESSAGE,
        )
    };
    reshape_oversized_413_with(render, resp).await
}

async fn reshape_oversized_413_with(
    render: impl FnOnce() -> axum::response::Response,
    resp: axum::response::Response,
) -> axum::response::Response {
    if resp.status() != axum::http::StatusCode::PAYLOAD_TOO_LARGE {
        return resp;
    }

    let is_json = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|ct| ct.starts_with(busbar_contract::protocol::APPLICATION_JSON));
    if is_json {
        return resp;
    }

    use http_body_util::BodyExt as _;
    let (parts, body) = resp.into_parts();
    let bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),

        Err(_) => return axum::response::Response::from_parts(parts, axum::body::Body::empty()),
    };
    if !bytes
        .windows(AXUM_BODY_LIMIT_413_MARKER.len())
        .any(|w| w == AXUM_BODY_LIMIT_413_MARKER)
    {
        return axum::response::Response::from_parts(parts, axum::body::Body::from(bytes));
    }
    render()
}

pub fn build_router(app: std::sync::Arc<state::App>) -> Router {
    build_router_with_limits(
        app,
        busbar_kernel_egress::upstream::max_translate_body_bytes(),
        crate::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        crate::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    )
    .0
}

pub fn build_router_with_limits(
    app: std::sync::Arc<state::App>,
    request_body_max_bytes: usize,
    max_inbound_concurrent: usize,
    server_timing_enabled: bool,
) -> (Router, std::sync::Arc<state::AppHandle>) {
    let plugin_routes = app.plugin_routes.clone();

    // The data router borrows the snapshot's plane slots before the handle takes the snapshot.
    let router = base_data_router_scoped(
        &plugin_routes,
        &app.plane_slots,
        app.oauth_as.as_ref(),
        Vec::new(),
        Vec::new(),
        true,
    );
    let handle = std::sync::Arc::new(state::AppHandle::new(app));
    let (router, core_routes) = crate::admin::seam::mount_admin(router).into_parts();
    let router = crate::plugin_routes::mount_plugin_routes(router, &plugin_routes, true);
    let router = apply_common_layers(
        router,
        core_routes,
        &handle,
        request_body_max_bytes,
        server_timing_enabled,
    );
    (
        apply_inbound_concurrency_limit(router, max_inbound_concurrent),
        handle,
    )
}

pub(crate) fn base_data_router(
    plugin_routes: &crate::plugin_routes::PluginRouteTable,
    plane_slots: &std::collections::BTreeMap<
        &'static str,
        std::sync::Arc<dyn std::any::Any + Send + Sync>,
    >,
    oauth_as: Option<&std::sync::Arc<dyn std::any::Any + Send + Sync>>,
    doors: Vec<busbar_kernel::plane_routes::PlaneRouteSpec>,
    sessions: Vec<busbar_kernel::plane_routes::PlaneSessionSpec>,
) -> (
    Router<std::sync::Arc<state::AppHandle>>,
    crate::core_routes::CoreRouteTable,
) {
    base_data_router_scoped(plugin_routes, plane_slots, oauth_as, doors, sessions, true)
        .into_parts()
}

pub(crate) fn mount_plane_route(
    router: crate::core_routes::CoreRouter,
    slot: std::sync::Arc<dyn std::any::Any + Send + Sync>,
    spec: busbar_kernel::plane_routes::PlaneRouteSpec,
) -> crate::core_routes::CoreRouter {
    let busbar_kernel::plane_routes::PlaneRouteSpec {
        path,
        method,
        auth,
        handler,
    } = spec;

    let ctx_path = path.clone();
    router.route(
        path,
        method,
        auth,
        move |state::CurrentApp(app): state::CurrentApp,

              _: axum::extract::RawPathParams,
              uri: axum::http::Uri,
              gov: Option<axum::extract::Extension<busbar_contract::records::PlaneRequestCtx>>,
              principal: Option<axum::extract::Extension<busbar_contract::auth::AuthPrincipal>>,
              consumed: Option<axum::extract::Extension<auth::ConsumedCredentials>>,
              listener: Option<
            axum::extract::Extension<busbar_kernel::plane_routes::ListenerScheme>,
        >,
              mut headers: axum::http::HeaderMap,
              body: axum::body::Bytes| {
            let consumed_fields =
                auth::ConsumedCredentials::fields_of(consumed.as_deref(), &headers);
            auth::ConsumedCredentials::strip_from(consumed.as_deref(), &mut headers);
            let caller_credential = consumed.as_deref().and_then(|c| c.caller.clone());
            let ticket = consumed.as_deref().and_then(|c| c.ticket.clone());
            let host_ticket_admission = consumed
                .as_deref()
                .and_then(|c| c.host_ticket_admission.clone());
            let handler = handler.clone();
            let slot = slot.clone();
            let ctx_path = ctx_path.clone();
            async move {
                let engine: std::sync::Arc<dyn std::any::Any + Send + Sync> = app;
                let ctx = busbar_kernel::plane_routes::PlaneReqCtx {
                    path: ctx_path,
                    uri,
                    method,
                    headers,
                    body,
                    gov: gov.map(|axum::extract::Extension(g)| g),
                    principal: principal.map(|axum::extract::Extension(p)| p),
                    caller_credential,
                    ticket,
                    host_ticket_admission,
                    consumed_fields,
                    engine,
                    slot,
                    scheme: listener.map_or(
                        busbar_contract::abi::host::service::SCHEME_UNDECLARED,
                        |axum::extract::Extension(l)| l.0,
                    ),
                };
                handler(ctx).await
            }
        },
    )
}

pub(crate) fn mount_plane_session(
    router: crate::core_routes::CoreRouter,
    slot: std::sync::Arc<dyn std::any::Any + Send + Sync>,
    spec: busbar_kernel::plane_routes::PlaneSessionSpec,
) -> crate::core_routes::CoreRouter {
    use busbar_contract::abi::mechanism::route::RouteMethod;
    let busbar_kernel::plane_routes::PlaneSessionSpec {
        path,
        auth,
        handler,
    } = spec;
    let ctx_path = path.clone();
    router.route(
        path,
        RouteMethod::Get,
        auth,
        move |upgrade: busbar_kernel::ingress::session::SessionUpgrade,
              state::CurrentApp(app): state::CurrentApp,
              _: axum::extract::RawPathParams,
              uri: axum::http::Uri,
              gov: Option<axum::extract::Extension<busbar_contract::records::PlaneRequestCtx>>,
              principal: Option<axum::extract::Extension<busbar_contract::auth::AuthPrincipal>>,
              consumed: Option<axum::extract::Extension<auth::ConsumedCredentials>>,
              listener: Option<
            axum::extract::Extension<busbar_kernel::plane_routes::ListenerScheme>,
        >,
              mut headers: axum::http::HeaderMap| {
            let consumed_fields =
                auth::ConsumedCredentials::fields_of(consumed.as_deref(), &headers);
            auth::ConsumedCredentials::strip_from(consumed.as_deref(), &mut headers);
            let caller_credential = consumed.as_deref().and_then(|c| c.caller.clone());
            let ticket = consumed.as_deref().and_then(|c| c.ticket.clone());
            let host_ticket_admission = consumed
                .as_deref()
                .and_then(|c| c.host_ticket_admission.clone());
            let handler = handler.clone();
            let slot = slot.clone();
            let ctx_path = ctx_path.clone();
            async move {
                let engine: std::sync::Arc<dyn std::any::Any + Send + Sync> = app;
                let ctx = busbar_kernel::plane_routes::PlaneReqCtx {
                    path: ctx_path,
                    uri,
                    method: RouteMethod::Get,
                    headers,
                    body: axum::body::Bytes::new(),
                    gov: gov.map(|axum::extract::Extension(g)| g),
                    principal: principal.map(|axum::extract::Extension(p)| p),
                    engine,
                    slot,
                    caller_credential,
                    scheme: listener.map_or(
                        busbar_contract::abi::host::service::SCHEME_UNDECLARED,
                        |axum::extract::Extension(l)| l.0,
                    ),
                    ticket,
                    host_ticket_admission,
                    consumed_fields,
                };
                match handler(ctx).await {
                    busbar_kernel::plane_routes::SessionAnswer::Refused(response) => response,
                    busbar_kernel::plane_routes::SessionAnswer::Accepted(pipe) => {
                        busbar_kernel::ingress::session::bridge(upgrade, pipe)
                    }
                }
            }
        },
    )
}

pub(crate) fn apply_common_layers(
    router: Router<std::sync::Arc<state::AppHandle>>,
    core_routes: crate::core_routes::CoreRouteTable,
    handle: &std::sync::Arc<state::AppHandle>,
    request_body_max_bytes: usize,
    server_timing_enabled: bool,
) -> Router {
    let observe_mounts = handle.load().planes.has_mounts();
    apply_common_layers_for_mounts(
        router,
        core_routes,
        handle,
        request_body_max_bytes,
        server_timing_enabled,
        observe_mounts,
    )
}

fn apply_common_layers_for_mounts(
    router: Router<std::sync::Arc<state::AppHandle>>,
    core_routes: crate::core_routes::CoreRouteTable,
    handle: &std::sync::Arc<state::AppHandle>,
    request_body_max_bytes: usize,
    server_timing_enabled: bool,
    observe_mounts: bool,
) -> Router {
    let core_routes = std::sync::Arc::new(core_routes);
    let auth_handle = handle.clone();
    let router = router
        .layer(axum::middleware::from_fn_with_state(
            handle.clone(),
            move |app: crate::state::CurrentApp,
                  req: axum::extract::Request,
                  next: axum::middleware::Next| {
                let core_routes = core_routes.clone();
                let auth_handle = auth_handle.clone();
                async move {
                    auth::auth_middleware(
                        app,
                        auth_handle,
                        request_body_max_bytes,
                        &core_routes,
                        req,
                        next,
                    )
                    .await
                }
            },
        ))
        .layer(axum::extract::DefaultBodyLimit::max(request_body_max_bytes))
        .layer(axum::middleware::from_fn_with_state(
            handle.clone(),
            reshape_body_limit_413,
        ));

    let router = if observe_mounts {
        router.layer(axum::middleware::from_fn_with_state(
            handle.clone(),
            crate::ingress::observe::observe,
        ))
    } else {
        router
    };

    let router = router.layer(axum::middleware::from_fn(request_activity_tick));

    let router = if server_timing_enabled {
        router.layer(axum::middleware::from_fn(server_timing))
    } else {
        router
    };

    let router = router.layer(CatchPanicLayer::new(handle.clone()));
    router
        .layer(axum::middleware::from_fn_with_state(
            handle.clone(),
            admin_response_boundary,
        ))
        .with_state(handle.clone())
}

/// POLICY: **A PANIC IN A REQUEST HANDLER FAILS THAT REQUEST — NEVER THE
/// CONNECTION, NEVER ITS MULTIPLEXED SIBLINGS.**
///
/// The workspace keeps `panic = "unwind"` on purpose (see the root `Cargo.toml`) so one request's
/// panic cannot abort the gateway. Unwinding alone is not isolation, though: with no boundary on
/// the request path the unwind leaves the handler future and tears down hyper's CONNECTION task,
/// so the client sees a reset connection and every other request multiplexed on that h2 connection
/// dies with it. This layer is that boundary. It polls the whole inner stack inside
/// `catch_unwind`; when the unwind reaches it, the one request is answered with a `500` in the
/// kernel's standard error body for its path ([`fallback_error_response`]: the native-API root's
/// frozen `{error:{code:"internal"}}`, a mounted plane's JSON-RPC refusal, otherwise the path's
/// dialect-native envelope with the agnostic `api_error` kind), and the panic is logged ONCE, at
/// `error`, with its source location — see `install_request_panic_hook` for how the location
/// is captured without the default hook printing the same panic a second time.
///
/// WHAT IT COVERS: the handler future and every middleware inside it, from `call` until the
/// response HEAD is produced. WHAT IT CANNOT COVER: a panic while polling a streaming response
/// BODY after the head was returned — that is hyper polling the body, outside any service future.
///
/// ENFORCED: `apply_common_layers` is the only place a kernel router becomes servable (the one
/// `.with_state`), and it installs this as its last layer; the structural gate
/// `the_request_panic_boundary_wraps_every_served_router` fails if a router is built any other way.
///
/// Cost on the success path: one thread-local increment/decrement and a `catch_unwind` frame per
/// poll, and a cheap `Uri` clone per request (refcounted bytes). Nothing else — the snapshot load
/// and the error shaping happen only after a panic.
#[derive(Clone)]
pub struct CatchPanicLayer {
    handle: std::sync::Arc<state::AppHandle>,
}

impl CatchPanicLayer {
    pub fn new(handle: std::sync::Arc<state::AppHandle>) -> Self {
        install_request_panic_hook();
        Self { handle }
    }
}

impl<S> tower::Layer<S> for CatchPanicLayer {
    type Service = CatchPanic<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CatchPanic {
            inner,
            handle: self.handle.clone(),
        }
    }
}

/// The service [`CatchPanicLayer`] wraps a router in.
#[derive(Clone)]
pub struct CatchPanic<S> {
    inner: S,
    handle: std::sync::Arc<state::AppHandle>,
}

impl<S> tower::Service<axum::extract::Request> for CatchPanic<S>
where
    S: tower::Service<
            axum::extract::Request,
            Response = axum::response::Response,
            Error = std::convert::Infallible,
        > + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = axum::response::Response;
    type Error = std::convert::Infallible;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: axum::extract::Request) -> Self::Future {
        use std::future::Future as _;
        use std::panic::{catch_unwind, AssertUnwindSafe};
        use std::task::Poll;

        let mut inner = self.inner.clone();
        let handle = self.handle.clone();
        let selected = req
            .extensions()
            .get::<crate::inbound::RequestAdmission>()
            .map(crate::inbound::RequestAdmission::app)
            .or_else(|| {
                req.extensions()
                    .get::<std::sync::Arc<state::App>>()
                    .cloned()
            })
            .unwrap_or_else(|| handle.load());
        let uri = req.uri().clone();
        let method = req.method().clone();
        Box::pin(async move {
            let started = catch_unwind(AssertUnwindSafe(|| {
                let _scope = RequestPanicScope::enter();
                inner.call(req)
            }));
            let outcome = match started {
                Err(payload) => Err(payload),
                Ok(fut) => {
                    let mut fut = std::pin::pin!(fut);
                    std::future::poll_fn(|cx| {
                        match catch_unwind(AssertUnwindSafe(|| {
                            let _scope = RequestPanicScope::enter();
                            fut.as_mut().poll(cx)
                        })) {
                            Ok(Poll::Ready(r)) => Poll::Ready(Ok(r)),
                            Ok(Poll::Pending) => Poll::Pending,
                            Err(payload) => Poll::Ready(Err(payload)),
                        }
                    })
                    .await
                }
            };
            match outcome {
                Ok(r) => r,
                Err(payload) => Ok(request_panicked(
                    &handle,
                    &selected,
                    &method,
                    &uri,
                    payload.as_ref(),
                )),
            }
        })
    }
}

fn request_panicked(
    handle: &std::sync::Arc<state::AppHandle>,
    selected: &state::App,
    method: &axum::http::Method,
    uri: &axum::http::Uri,
    payload: &(dyn std::any::Any + Send),
) -> axum::response::Response {
    let message = panic_payload_message(payload);
    let (location, backtrace) = take_panic_seen()
        .map_or_else(crate::cold::host::router_panic_unseen, |s| {
            (s.location, s.backtrace)
        });
    tracing::error!(
        method = %method,
        path = %uri.path(),
        panic.location = %location,
        panic.message = %message,
        backtrace = %backtrace,
        "a request handler panicked; that request was answered 500 and the connection kept serving"
    );
    kernel_refusal_response(
        handle,
        &selected.planes,
        busbar_contract::caps::ReasonCode::Internal,
        uri.path(),
        target_of(uri),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        busbar_contract::protocol::KIND_API_ERROR,
        "internal error",
    )
}

fn panic_payload_message(payload: &(dyn std::any::Any + Send)) -> &str {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        s
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.as_str()
    } else {
        "<non-string panic payload>"
    }
}

struct PanicSeen {
    location: String,

    backtrace: String,
}

thread_local! {
    /// How many [`CatchPanic`] polls are on this thread's stack right now (nesting-safe).
    static REQUEST_PANIC_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    /// The last panic the hook saw inside a request scope on this thread, for the boundary to log.
    static REQUEST_PANIC_SEEN: std::cell::RefCell<Option<PanicSeen>> = const { std::cell::RefCell::new(None) };
}

struct RequestPanicScope;

impl RequestPanicScope {
    fn enter() -> Self {
        REQUEST_PANIC_DEPTH.with(|d| d.set(d.get().saturating_add(1)));
        Self
    }
}

impl Drop for RequestPanicScope {
    fn drop(&mut self) {
        REQUEST_PANIC_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));

        if REQUEST_PANIC_DEPTH.with(std::cell::Cell::get) == 0 && !std::thread::panicking() {
            if let Some(seen) = take_panic_seen() {
                tracing::error!(
                    panic.location = %seen.location,
                    backtrace = %seen.backtrace,
                    "a panic inside a request was caught by an inner unwind boundary"
                );
            }
        }
    }
}

fn take_panic_seen() -> Option<PanicSeen> {
    REQUEST_PANIC_SEEN.with(|s| s.borrow_mut().take())
}

pub(crate) fn install_request_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if REQUEST_PANIC_DEPTH.with(std::cell::Cell::get) == 0 {
                previous(info);
                return;
            }
            let location = crate::cold::host::router_panic_location(info.location());
            let captured = std::backtrace::Backtrace::capture();
            let backtrace = crate::cold::host::router_panic_backtrace(&captured);
            REQUEST_PANIC_SEEN.with(|s| {
                if let Ok(mut slot) = s.try_borrow_mut() {
                    *slot = Some(PanicSeen {
                        location,
                        backtrace,
                    });
                }
            });
        }));
    });
}

pub fn build_split_routers_with_limits(
    app: std::sync::Arc<state::App>,
    request_body_max_bytes: usize,
    max_inbound_concurrent: usize,
    server_timing_enabled: bool,
) -> (Router, Router, std::sync::Arc<state::AppHandle>) {
    build_split_routers_serving(
        app,
        Vec::new(),
        request_body_max_bytes,
        max_inbound_concurrent,
        server_timing_enabled,
    )
}

pub fn build_split_routers_serving(
    app: std::sync::Arc<state::App>,
    doors: Vec<busbar_kernel::plane_routes::PlaneRouteSpec>,
    request_body_max_bytes: usize,
    max_inbound_concurrent: usize,
    server_timing_enabled: bool,
) -> (Router, Router, std::sync::Arc<state::AppHandle>) {
    build_split_routers_serving_sessions(
        app,
        doors,
        Vec::new(),
        request_body_max_bytes,
        max_inbound_concurrent,
        server_timing_enabled,
    )
}

pub fn build_split_routers_serving_sessions(
    app: std::sync::Arc<state::App>,
    doors: Vec<busbar_kernel::plane_routes::PlaneRouteSpec>,
    sessions: Vec<busbar_kernel::plane_routes::PlaneSessionSpec>,
    request_body_max_bytes: usize,
    max_inbound_concurrent: usize,
    server_timing_enabled: bool,
) -> (Router, Router, std::sync::Arc<state::AppHandle>) {
    build_split_routers_serving_doors(
        app,
        doors,
        sessions,
        Vec::new(),
        request_body_max_bytes,
        max_inbound_concurrent,
        server_timing_enabled,
    )
}

pub fn build_split_routers_serving_doors(
    app: std::sync::Arc<state::App>,
    doors: Vec<busbar_kernel::plane_routes::PlaneRouteSpec>,
    sessions: Vec<busbar_kernel::plane_routes::PlaneSessionSpec>,
    refusals: Vec<busbar_kernel::plane_routes::PlaneRefusalSpec>,
    request_body_max_bytes: usize,
    max_inbound_concurrent: usize,
    server_timing_enabled: bool,
) -> (Router, Router, std::sync::Arc<state::AppHandle>) {
    let plugin_routes = app.plugin_routes.clone();
    build_split_routers_serving_listener(
        app,
        &plugin_routes,
        doors,
        sessions,
        refusals,
        request_body_max_bytes,
        max_inbound_concurrent,
        server_timing_enabled,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "boot: a listener's routers are built once from every input the listener serves"
)]
pub fn build_split_routers_serving_listener(
    app: std::sync::Arc<state::App>,
    data_plugins: &crate::plugin_routes::PluginRouteTable,
    doors: Vec<crate::plane_routes::PlaneRouteSpec>,
    sessions: Vec<crate::plane_routes::PlaneSessionSpec>,
    refusals: Vec<crate::plane_routes::PlaneRefusalSpec>,
    request_body_max_bytes: usize,
    max_inbound_concurrent: usize,
    server_timing_enabled: bool,
) -> (Router, Router, std::sync::Arc<state::AppHandle>) {
    // The data router borrows the snapshot's plane slots before the handle takes the snapshot.
    let (data, data_core_routes) = base_data_router(
        data_plugins,
        &app.plane_slots,
        app.oauth_as.as_ref(),
        doors,
        sessions,
    );
    let handle = std::sync::Arc::new(state::AppHandle::new(app));
    let data = apply_common_layers(
        data,
        data_core_routes.with_door_refusals(refusals),
        &handle,
        request_body_max_bytes,
        server_timing_enabled,
    );
    let data = apply_inbound_concurrency_limit(data, max_inbound_concurrent);
    let admin = build_admin_router_on(&handle, request_body_max_bytes, server_timing_enabled);
    (data, admin, handle)
}

pub fn build_admin_router_on(
    handle: &std::sync::Arc<state::AppHandle>,
    request_body_max_bytes: usize,
    server_timing_enabled: bool,
) -> Router {
    build_admin_router_on_with_dispatch_layer(
        handle,
        request_body_max_bytes,
        server_timing_enabled,
        unchanged_dispatch_layer,
    )
}

/// A composition-owned layer applied inside authentication and inbound admission.
pub type DispatchLayer =
    fn(Router<std::sync::Arc<state::AppHandle>>) -> Router<std::sync::Arc<state::AppHandle>>;

pub(crate) fn unchanged_dispatch_layer(
    router: Router<std::sync::Arc<state::AppHandle>>,
) -> Router<std::sync::Arc<state::AppHandle>> {
    router
}

pub fn build_admin_router_on_with_dispatch_layer(
    handle: &std::sync::Arc<state::AppHandle>,
    request_body_max_bytes: usize,
    server_timing_enabled: bool,
    dispatch_layer: DispatchLayer,
) -> Router {
    let plugin_routes = handle.load().plugin_routes.clone();

    let admin = crate::core_routes::CoreRouter::new()
        .route(
            crate::auth::HEALTHZ_PATH,
            busbar_contract::abi::mechanism::route::RouteMethod::Get,
            busbar_contract::abi::mechanism::route::RouteAuth::None,
            endpoints::healthz,
        )
        .route(
            crate::auth::LIVEZ_PATH,
            busbar_contract::abi::mechanism::route::RouteMethod::Get,
            busbar_contract::abi::mechanism::route::RouteAuth::None,
            endpoints::livez,
        )
        .route(
            crate::auth::READYZ_PATH,
            busbar_contract::abi::mechanism::route::RouteMethod::Get,
            busbar_contract::abi::mechanism::route::RouteAuth::None,
            endpoints::readyz,
        );
    let (admin, admin_core_routes) = crate::admin::seam::mount_admin(admin).into_parts();
    let admin = crate::plugin_routes::mount_plugin_routes(admin, &plugin_routes, true);
    apply_common_layers(
        dispatch_layer(admin),
        admin_core_routes,
        handle,
        request_body_max_bytes,
        server_timing_enabled,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "boot: a listener's routers are built once from every input the listener serves"
)]
pub fn build_data_router_on(
    handle: &std::sync::Arc<state::AppHandle>,
    plugins: &crate::plugin_routes::PluginRouteTable,
    doors: Vec<busbar_kernel::plane_routes::PlaneRouteSpec>,
    sessions: Vec<busbar_kernel::plane_routes::PlaneSessionSpec>,
    refusals: Vec<busbar_kernel::plane_routes::PlaneRefusalSpec>,
    refuse_by_path: Option<busbar_kernel::plane_routes::PlaneRefuseByPathFn>,
    request_body_max_bytes: usize,
    max_inbound_concurrent: usize,
    server_timing_enabled: bool,
) -> Router {
    let (data, core_routes) = base_data_router_scoped(
        plugins,
        &std::collections::BTreeMap::new(),
        None,
        doors,
        sessions,
        false,
    )
    .into_parts();
    let data = apply_common_layers(
        data,
        core_routes.with_door_refusals(refusals),
        handle,
        request_body_max_bytes,
        server_timing_enabled,
    );
    apply_inbound_concurrency_limit(data, max_inbound_concurrent).layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let refuse = refuse_by_path.clone();
            async move {
                PHYSICAL_REFUSER
                    .scope((true, refuse), next.run(request))
                    .await
            }
        },
    ))
}

pub struct PreparedListener {
    pub(crate) physical: Option<std::sync::Arc<crate::inbound::native::PhysicalPlan>>,
    pub(crate) data: Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>,
    pub(crate) router: Router<std::sync::Arc<state::AppHandle>>,
    pub(crate) core_routes: crate::core_routes::CoreRouteTable,

    pub refusals: Vec<crate::plane_routes::PlaneRefusalSpec>,
    pub(crate) refuse_by_path: Option<crate::plane_routes::PlaneRefuseByPathFn>,
    pub(crate) root_surface: bool,
    pub(crate) dispatch_layer: DispatchLayer,
}

impl std::fmt::Debug for PreparedListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedListener")
            .field("root_surface", &self.root_surface)
            .finish_non_exhaustive()
    }
}

impl PreparedListener {
    /// Complete root-owned routes and their authentication declarations together before publication.
    pub fn with_core_routes(
        mut self,
        mount: impl FnOnce(crate::core_routes::CoreRouter) -> crate::core_routes::CoreRouter,
    ) -> Self {
        let routes = crate::core_routes::CoreRouter::from_parts(self.router, self.core_routes);
        (self.router, self.core_routes) = mount(routes).into_parts();
        self
    }

    /// The refusal producer captured with this prepared listener's route snapshot.
    pub fn refusal_renderer(&self) -> Option<crate::plane_routes::PlaneRefuseByPathFn> {
        self.refuse_by_path.clone()
    }

    /// Retain the composition's neutral dispatcher with this exact route snapshot.
    pub fn with_data(mut self, data: std::sync::Arc<dyn std::any::Any + Send + Sync>) -> Self {
        self.data = Some(data);
        self
    }

    pub fn data(&self) -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
        self.data.clone()
    }

    /// Apply the composition's dispatch preparation after auth, under the listener's one cap.
    pub fn with_dispatch_layer(mut self, layer: DispatchLayer) -> Self {
        self.dispatch_layer = layer;
        self
    }

    fn bind(
        &self,
        handle: &std::sync::Arc<state::AppHandle>,
        app: &state::App,
        body_limit: usize,
        server_timing: bool,
    ) -> Router {
        let body_limit = app
            .limits
            .as_ref()
            .map_or(body_limit, |limits| limits.request_body_max_bytes);
        let router = apply_common_layers_for_mounts(
            (self.dispatch_layer)(self.router.clone()),
            self.core_routes.clone(),
            handle,
            body_limit,
            server_timing,
            app.planes.has_mounts(),
        );
        let refuse = self.refuse_by_path.clone();
        let private = !self.root_surface;
        router.layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let refuse = refuse.clone();
                async move {
                    PHYSICAL_REFUSER
                        .scope((private, refuse), next.run(request))
                        .await
                }
            },
        ))
    }
}

struct CachedListener {
    app: std::sync::Weak<state::App>,
    router: Router,
}

pub fn serve_listener_generations(
    handle: std::sync::Arc<state::AppHandle>,
    select: impl Fn(&state::App) -> Option<std::sync::Arc<PreparedListener>> + Send + Sync + 'static,
    request_body_max_bytes: usize,
    max_inbound_concurrent: usize,
    server_timing_enabled: bool,
) -> Router {
    use axum::response::IntoResponse as _;
    use std::sync::{Arc, Mutex, Weak};
    use tower::ServiceExt as _;
    let cache: Arc<Mutex<Option<CachedListener>>> = Arc::default();
    let select = Arc::new(select);
    let serving_handle = Arc::clone(&handle);
    let router = Router::new()
        .fallback(
            move |state::CurrentApp(app): state::CurrentApp,
                  mut request: axum::extract::Request| {
                let (cache, select, handle) =
                    (cache.clone(), select.clone(), serving_handle.clone());
                async move {
                    request.extensions_mut().insert(Arc::clone(&app));
                    let cached = cache
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .as_ref()
                        .filter(|previous| Weak::ptr_eq(&previous.app, &Arc::downgrade(&app)))
                        .map(|cached| cached.router.clone());
                    let router = if let Some(router) = cached {
                        router
                    } else {
                        let Some(prepared) = select(&app) else {
                            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
                        };
                        let router = prepared.bind(
                            &handle,
                            &app,
                            request_body_max_bytes,
                            server_timing_enabled,
                        );
                        let retired = {
                            let mut cache = cache
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            cache.replace(CachedListener {
                                app: Arc::downgrade(&app),
                                router: router.clone(),
                            })
                        };
                        drop(retired);
                        router
                    };
                    match router.oneshot(request).await {
                        Ok(response) => response,
                        Err(never) => match never {},
                    }
                }
            },
        )
        .with_state(handle);

    apply_inbound_concurrency_limit(router, max_inbound_concurrent)
}

pub(crate) fn apply_inbound_concurrency_limit(
    router: Router,
    max_inbound_concurrent: usize,
) -> Router {
    if max_inbound_concurrent > 0 {
        router.layer(limits::admission::InboundAdmissionLayer::new(
            max_inbound_concurrent,
        ))
    } else {
        router
    }
}

#[cfg(test)]
#[path = "tests/router_door_tests.rs"]
mod router_door_tests;

#[cfg(test)]
#[path = "tests/router_session_tests.rs"]
mod router_session_tests;
