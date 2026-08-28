//! THE ROUTER — the single place a request surface is wired: the split data/admin routers, the
//! shared layers (body-cap reshapers, server-timing, request-activity tick), and the fallback
//! error response. Step 4 of 1.6.0 registers protocol mounts through here; keeping the mount
//! wiring in ONE file is what makes that registration a one-file change in core plus one call in
//! the binary's composition root.

use axum::Router;

#[allow(unused_imports)]
use crate::{
    admin, audit, auth, auth_cache, billing, breaker, catalogue, config, config_validate,
    core_routes, cost, durable, egress_auth, endpoints, eventstream, export, failover, governance,
    handlers, health, hooks, ingress, ir, json, limits, lossless, media, metrics, net_guard,
    oauth_as, observability, operation, plane, plugin_routes, profile, proto, proxy, sigv4, state,
    store, telemetry, tls, transport, trust,
};

/// Response header name for the W3C Server-Timing field.
pub(crate) const HEADER_SERVER_TIMING: &str = "server-timing";

/// Sentinel value stored in the `UPSTREAM_RTT_US` task-local when NO upstream hop was dispatched
/// (admin / health / early error). `server_timing_dur_ms` treats this as "report the full request
/// time" rather than subtracting a nonexistent RTT. Only this exact u64::MAX meaning is replaced
/// with the const; overflow/conversion fallbacks that happen to produce u64::MAX are NOT this.
pub(crate) const NO_UPSTREAM_RTT: u64 = u64::MAX;

/// Render a native ingress error envelope (`application/json`) for the fallback handlers, in the
/// dialect the path is spoken in — attaching the `x-amzn-*` headers when that dialect is Bedrock,
/// so the response is indistinguishable from a real vendor 404/405, and answering in JSON-RPC on a
/// path a plane has been MOUNTED on. Shared by the 404 catch-all, [`method_not_allowed_handler`]
/// (405, wrong method on a valid path) and the oversized-body 413 reshape.
///
/// `planes` is the mount table, and it is a parameter rather than something inferred here because
/// a mount is a fact about the deployment: no amount of looking at the path reveals it, and the
/// version of this function that tried shipped an OpenAI envelope onto the MCP plane.
pub fn fallback_error_response(
    planes: &crate::plane::PlaneDispatch,
    path: &str,
    status: axum::http::StatusCode,
    kind: &str,
    message: &str,
) -> axum::response::Response {
    // The NATIVE-API root speaks the frozen admin envelope for EVERY response — including unmatched
    // paths and wrong methods, which previously fell through to the vendor-native shaping below and
    // leaked `{error:{type}}` bodies onto a surface that promises `{error:{code}}`.
    // Boundary-safe: exact root or root + '/'.
    {
        use crate::admin::v1::contract::{AdminError, API_ROOT};
        if path == API_ROOT || path.starts_with(&format!("{API_ROOT}/")) {
            let e = if status == axum::http::StatusCode::METHOD_NOT_ALLOWED {
                AdminError::MethodNotAllowed
            } else {
                AdminError::not_found("resource")
            };
            return crate::admin::v1::json::err_json(&e);
        }
    }
    // ONE resolver, ONE shaping seam. The provider-specific response headers (Bedrock
    // `x-amzn-RequestId`/`x-amzn-errortype`; Anthropic `request-id`) come with it, dispatched
    // through the writer vtable inside `proxy::ingress_error`, so this handler matches the shape
    // the hot path produces and carries no provider name-branch of its own.
    crate::ingress::native::native_error(planes.ingress_of(path), status, kind, message)
}

// NOTE: the 404 fallback handler is superseded by `ingress::protocol_dispatch`, which owns the
// catch-all and reproduces the same native-envelope 404 shaping for non-protocol paths.

/// 405 fallback: a valid ingress path hit with the wrong method (e.g. GET on a POST-only ingress).
/// axum's built-in 405 is an `Allow`-header-only empty body; reshape to the protocol-native envelope
/// so an SDK sees a vendor-shaped error instead of a bare proxy tell.
pub(crate) async fn method_not_allowed_handler(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    uri: axum::http::Uri,
) -> axum::response::Response {
    fallback_error_response(
        &app.planes,
        uri.path(),
        axum::http::StatusCode::METHOD_NOT_ALLOWED,
        crate::admin::ERR_TYPE_INVALID_REQUEST,
        "method not allowed for this resource",
    )
}

/// The SENTINEL substring in the `text/plain` body axum's `DefaultBodyLimit` emits when a request
/// exceeds the limit — used to distinguish axum's OWN body-limit 413 from a forward-path-relayed
/// upstream 413, which must pass through untouched.
///
/// SUBSTRING, NOT BYTE-EQUALITY, and that is the fix. This was pinned to axum 0.7's EXACT body
/// (`"length limit exceeded"`), and axum-core 0.5 renders the same rejection as
/// `"Failed to buffer the request body: length limit exceeded"` — the `__define_rejection!`
/// Error-variant arm prefixes the outer `FailedToBufferBody` prose onto the inner error. So on
/// axum 0.8 the equality gate NEVER matched and the whole reshape was dead code in production:
/// every oversized request, admin and data plane alike, answered with a bare `text/plain` body.
/// That broke the admin surface's frozen `{error:{code}}` envelope (tooling that branches on `code`
/// throws on parse) and handed official OpenAI/Anthropic/Bedrock SDKs a router tell instead of the
/// vendor-native JSON envelope.
///
/// Matching the inner error's own words survives that wrapping. The residual risk — a relayed
/// UPSTREAM `text/plain` 413 whose body happens to contain this phrase being reshaped into a JSON
/// envelope of the same status — is far smaller than the risk this replaced, and is bounded to the
/// envelope shape (the status is 413 either way).
///
/// THE REAL GUARD IS THE TEST, not this constant. Every prior test of this path hand-constructed
/// the marker and called the pure reshape function, so all four stayed green while the layer was
/// dead. `oversized_request_413_is_reshaped_on_the_live_stack` drives a real oversized request
/// through the real layer stack, so the next time axum changes its prose the build goes red instead
/// of the reshape silently switching itself off.
pub(crate) const AXUM_BODY_LIMIT_413_MARKER: &[u8] = b"length limit exceeded";

/// Reshape an oversized-body rejection into a protocol-native error. axum's `DefaultBodyLimit`
/// rejects a too-large request with HTTP 413 and a bare `text/plain` body (`"length limit
/// exceeded"`) — a router/proxy tell no native vendor API emits. This middleware wraps the
/// body-limit layer: it captures the request path, runs the inner
/// stack, and when the result is axum's OWN body-limit 413 (identified by the
/// [`AXUM_BODY_LIMIT_413_MARKER`] sentinel body — NOT merely any non-JSON 413), it replaces that
/// response with the inferred ingress protocol's native JSON `request_too_large` envelope (Bedrock
/// variants also gain `x-amzn-*` headers, via [`fallback_error_response`]). Any other 413 — a
/// forward-path-relayed UPSTREAM 413 (whatever its content-type), or one a real ingress handler
/// already shaped as JSON — is passed through untouched.
///
/// The envelope is the one the PATH's resolved ingress speaks, which is why this layer takes the
/// swappable app handle: a body cap fires OUTSIDE routing and OUTSIDE auth, so the mount table is
/// the only thing that can tell it whether `/mcp` is an MCP plane or an unclaimed residual path.
/// Before it had one, every oversized POST — mounted plane or not — was answered in an OpenAI
/// envelope.
pub(crate) async fn reshape_body_limit_413(
    axum::extract::State(handle): axum::extract::State<std::sync::Arc<state::AppHandle>>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = req.uri().path().to_owned();
    let resp = next.run(req).await;
    // FAST PATH: only a 413 is ever reshaped ([`reshape_oversized_413`]'s own first check), so a
    // non-413 — every ordinary request — must not pay even the snapshot the reshape needs.
    // Verified equivalent: for any other status the function returns its input untouched.
    if resp.status() != axum::http::StatusCode::PAYLOAD_TOO_LARGE {
        return resp;
    }
    // The snapshot is taken AFTER the inner stack runs, so a config apply mid-request shapes the
    // answer with the mount table that is live when the answer is written.
    reshape_oversized_413(&handle.snapshot().planes, &path, resp).await
}

/// Per-process count of requests that entered the middleware stack — the idleness signal for the
/// jemalloc idle-purge fallback (bumped once per request in `server_timing`, read every sweep tick
/// by the purge thread). Wraps harmlessly (only equality-across-a-window is compared).
pub static REQUEST_ACTIVITY_TICKS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Compute the `Server-Timing` `dur` value (milliseconds) for a request: Busbar's own processing
/// time = total request wall-clock minus the upstream round-trip. `upstream_us == u64::MAX` means
/// "no upstream hop" (admin/health/early error), so the full time is reported. Saturating, so clock
/// skew (upstream measured slightly larger than total) can never underflow into a huge value.
pub(crate) fn server_timing_dur_ms(total_us: u64, upstream_us: u64) -> f64 {
    let internal_us = if upstream_us == NO_UPSTREAM_RTT {
        total_us
    } else {
        total_us.saturating_sub(upstream_us)
    };
    internal_us as f64 / 1000.0
}

/// Always-installed OUTERMOST-ISH middleware: bumps the jemalloc idle-purge activity ticker (see
/// `spawn_jemalloc_idle_purge_fallback`) on every request. Split out of `server_timing`
/// so the ticker keeps incrementing regardless of whether `advanced.response_headers.server_timing`
/// is enabled — the `server_timing` layer itself is now COMPOSED OUT of the stack entirely when
/// disabled (see `apply_common_layers`), so this is the one piece of its old unconditional behavior
/// that must survive the split. One relaxed atomic add; no allocation, no `Instant::now()`.
pub(crate) async fn request_activity_tick(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    REQUEST_ACTIVITY_TICKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    next.run(req).await
}

/// Outermost middleware: stamps a standard `Server-Timing: busbar;dur=<ms>` response header
/// reporting the latency Busbar itself added — total request wall-clock MINUS the upstream
/// round-trip — so operators (and browser DevTools / APM tools) can see the gateway's own cost
/// in-band on every response, without scraping `/metrics` or wiring traces. The upstream RTT is
/// recorded by the forward path into the [`proxy::UPSTREAM_RTT_US`] task-local for the duration
/// of this scope; a request that never dispatched upstream (admin / health / early error) reports
/// its full processing time. W3C `Server-Timing` `dur` is milliseconds; emitted at µs precision.
///
/// Gated by `advanced.response_headers.server_timing` (default `false`) — but NOT with an internal
/// `if` check like the pre-task-#139 version. `apply_common_layers` installs this middleware LAYER
/// ONLY when the flag is enabled (composition, mirroring `apply_inbound_concurrency_limit`'s
/// `max_inbound_concurrent > 0` gate), so a disabled deployment never runs this function at all: no
/// per-request `Arc<AtomicU64>` allocation, no `Instant::now()`, no task-local `.scope()` — the
/// former anti-pattern where the flag only suppressed the RESPONSE HEADER after paying the full
/// per-request cost regardless.
pub(crate) async fn server_timing(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use std::sync::atomic::Ordering;
    let slot = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(NO_UPSTREAM_RTT));
    let start = std::time::Instant::now();
    let mut resp = proxy::UPSTREAM_RTT_US
        .scope(slot.clone(), next.run(req))
        .await;
    let total_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
    let dur_ms = server_timing_dur_ms(total_us, slot.load(Ordering::Relaxed));
    if let Ok(v) = axum::http::HeaderValue::from_str(&format!("busbar;dur={dur_ms:.3}")) {
        resp.headers_mut()
            .insert(axum::http::HeaderName::from_static(HEADER_SERVER_TIMING), v);
    }
    resp
}

/// Pure reshaping step of [`reshape_body_limit_413`], split out so it is unit-testable without
/// constructing a `Next`. Returns `resp` unchanged unless it is axum's OWN body-limit 413 —
/// identified by status 413 with a non-JSON content-type AND a body exactly equal to
/// [`AXUM_BODY_LIMIT_413_MARKER`] — in which case it is replaced by the inferred ingress protocol's
/// native JSON `request_too_large` envelope. A 413 a real ingress handler already shaped as
/// `application/json`, or any forward-relayed UPSTREAM 413 (different/non-marker body), is passed
/// through verbatim (the body is buffered to inspect the sentinel, then re-attached unchanged).
pub(crate) async fn reshape_oversized_413(
    planes: &crate::plane::PlaneDispatch,
    path: &str,
    resp: axum::response::Response,
) -> axum::response::Response {
    if resp.status() != axum::http::StatusCode::PAYLOAD_TOO_LARGE {
        return resp;
    }
    // A handler (or upstream relay) that already produced an `application/json` 413 is a native
    // too-large envelope — leave it alone without even buffering the body; re-wrapping would
    // corrupt it, and axum's own body-limit reject is never JSON.
    let is_json = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|ct| ct.starts_with(crate::proxy::APPLICATION_JSON));
    if is_json {
        return resp;
    }
    // Non-JSON 413: it could be axum's OWN body-limit reject (reshape it) OR a forward-relayed
    // UPSTREAM 413 that happens to be non-JSON (e.g. a `text/plain`/`text/html` upstream error —
    // must pass through untouched). Distinguish by the sentinel body. Buffer the body so
    // we can compare it; if it is not the sentinel, re-attach the buffered bytes verbatim.
    use http_body_util::BodyExt as _;
    let (parts, body) = resp.into_parts();
    let bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        // A 413 body that fails to buffer cannot be confirmed as axum's sentinel; pass the
        // already-consumed parts through with an empty body rather than reshape a non-axum reject.
        Err(_) => return axum::response::Response::from_parts(parts, axum::body::Body::empty()),
    };
    if !bytes
        .windows(AXUM_BODY_LIMIT_413_MARKER.len())
        .any(|w| w == AXUM_BODY_LIMIT_413_MARKER)
    {
        // A relayed upstream 413 (or any non-axum 413): pass through untouched, body re-attached.
        return axum::response::Response::from_parts(parts, axum::body::Body::from(bytes));
    }
    fallback_error_response(
        planes,
        path,
        axum::http::StatusCode::PAYLOAD_TOO_LARGE,
        // CANONICAL kind for an oversized payload across the protocol writers.
        crate::proxy::KIND_REQUEST_TOO_LARGE,
        "request body exceeds the maximum allowed size",
    )
}

/// Build the busbar HTTP router for a given `App` state with default limits. Factored out so the
/// full route table + auth middleware can be exercised end-to-end in tests; production (`main`) calls
/// `build_router_with_limits` with the operator-configured values, so this convenience wrapper is
/// reached only from the test harness.
#[cfg_attr(not(test), allow(dead_code))]
pub fn build_router(app: std::sync::Arc<state::App>) -> Router {
    // Convenience builder for tests / callers without an explicit limits handle: the historical 32
    // MiB body cap (via the installed `limits`, falling back to the default when uninstalled) and NO
    // inbound-concurrency layer (`0` = unlimited) — byte-for-byte today's behavior. Production goes
    // through `build_router_with_limits` with the operator-configured values.
    build_router_with_limits(
        app,
        limits::translate_body_max_bytes(),
        crate::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        crate::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    )
    .0
}

/// Router builder with EXPLICIT limits, building the COMBINED router (admin mounted on the data
/// routes). Used only by the test harness (`build_router`) to exercise the full route table + auth
/// middleware end-to-end on one router; production always serves admin on its OWN listener via
/// `build_split_routers_with_limits`, so admin and data never share a listener at runtime.
/// `max_inbound_concurrent == 0` ⇒ NO concurrency layer (a true no-op); `> 0` wraps the whole router
/// in a `limits::admission::InboundAdmissionLayer` as the OUTERMOST layer.
#[cfg_attr(not(test), allow(dead_code))]
pub fn build_router_with_limits(
    app: std::sync::Arc<state::App>,
    request_body_max_bytes: usize,
    max_inbound_concurrent: usize,
    server_timing_enabled: bool,
) -> (Router, std::sync::Arc<state::AppHandle>) {
    // Capture the plugin route table before `app` moves into the handle (both planes mount from it).
    let plugin_routes = app.plugin_routes.clone();
    // The plane slots are captured before `app` moves into the handle, for the same reason the
    // plugin route table is: the mount is decided ONCE, from this generation's config, and a route
    // set is not something a later hot-swap can rewrite. Each plane's `mount` reads its own slot.
    let plane_slots = app.plane_slots.clone();
    let oauth_as = app.oauth_as.clone();
    let handle = std::sync::Arc::new(state::AppHandle::new(app));
    // TEST-ONLY combined router: mount the Admin API v1 onto the DATA route table so one router
    // exercises the whole surface. Production never does this — `build_split_routers_with_limits`
    // mounts admin on its OWN router served on a separate listener. Both planes' plugin routes are
    // mounted here (the combined router IS both listeners).
    let (router, core_routes) = base_data_router(&plugin_routes, &plane_slots, oauth_as.as_ref());
    let router = admin::transport::mount(router, &admin::JsonV1);
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

/// The DATA-plane route table — protocols, discovery, and health/metrics/stats — WITHOUT the admin
/// surface. Pre-state (`Router<Arc<AppHandle>>`); the admin API is mounted separately (onto this
/// router in the single-listener case, or onto its own router in the split case) so it can move to
/// a dedicated listener without any of these routes coming with it.
pub(crate) fn base_data_router(
    plugin_routes: &crate::plugin_routes::PluginRouteTable,
    plane_slots: &std::collections::BTreeMap<
        &'static str,
        std::sync::Arc<dyn std::any::Any + Send + Sync>,
    >,
    oauth_as: Option<&std::sync::Arc<crate::oauth_as::plane::AsPlane>>,
) -> (
    Router<std::sync::Arc<state::AppHandle>>,
    crate::core_routes::CoreRouteTable,
) {
    use busbar_plugin_loader::{RouteAuth, RouteMethod};
    // EVERY core route is mounted through `CoreRouter::route`, which takes the handler and the
    // admission bar in ONE act (`core_routes`): a route the auth middleware knows nothing about is
    // not a thing this function can produce.
    let router = crate::core_routes::CoreRouter::new()
        .route("/stats", RouteMethod::Get, RouteAuth::Key, endpoints::stats)
        // The liveness probe is the one always-open core route: a probe must not require a caller
        // token. Declared here rather than asserted by the middleware, so the openness belongs to
        // the route and travels with whichever router mounts it.
        .route(
            crate::auth::HEALTHZ_PATH,
            RouteMethod::Get,
            RouteAuth::None,
            endpoints::healthz,
        );
    // METRICS ARE OPT-IN (the built-in `prometheus` EXPORTER, `export.prometheus`). 1.5.3: busbar's
    // OWN `/metrics` exposition is no longer a core route here — it is served by the built-in
    // prometheus exporter through the plugin HTTP endpoint registration (`mount_plugin_routes` below,
    // the well-known `/metrics` exception), resolved at scrape time so a hot-swap never leaves it
    // stale. The HOOK-metrics scrape (`/metrics/hooks`) stays a core route, mounted only
    // when the recorder is installed (`metrics::enabled()`), reserved against plugin claims.
    let router = if metrics::enabled() {
        // A SEPARATE exposition from busbar's own `/metrics` so a hook can never type-conflict or
        // shadow a first-party series. Verbatim hook metric names + an auto `hook="<name>"` label, so
        // an external dashboard built against a hook repoints here and just works.
        // Stale-while-revalidate; never blocks on a hook socket.
        router.route(
            "/metrics/hooks",
            RouteMethod::Get,
            RouteAuth::Key,
            crate::hooks::scrape::handler,
        )
    } else {
        router
    };
    let router = router
        // busbar's OWN API keeps explicit routes (it is not a protocol dialect): discovery,
        // health/metrics/stats above, and the named/adhoc conveniences below.
        // OpenAI list-models: SDKs call `models.list()` first; UIs build pickers from it.
        // Governance-scoped like /stats (restricted keys see only their reachable names).
        // Token exchange (1.5.2): a verified IdP identity mints its own self-serve key. DATA plane
        // only, and declared `RouteAuth::None` because the handler runs the auth chain ITSELF (it
        // needs the identified principal to self-scope the minted key). The declaration is what
        // confines that bypass to this router: the admin plane, which does not mount the route,
        // does not inherit its bypass.
        .route(
            crate::auth::exchange::AUTH_TOKEN_PATH,
            RouteMethod::Get,
            RouteAuth::None,
            crate::auth::token::browser,
        )
        .route(
            crate::auth::exchange::AUTH_TOKEN_PATH,
            RouteMethod::Post,
            RouteAuth::None,
            crate::auth::exchange::exchange,
        )
        .route(
            "/v1/models",
            RouteMethod::Get,
            RouteAuth::Key,
            endpoints::list_models,
        )
        .route(
            "/v1beta/models",
            RouteMethod::Get,
            RouteAuth::Key,
            endpoints::list_models_v1beta,
        )
        .route(
            "/{name}/v1/messages",
            RouteMethod::Post,
            RouteAuth::Key,
            ingress::named,
        )
        .route(
            "/{provider}/{model}/v1/messages",
            RouteMethod::Post,
            RouteAuth::Key,
            ingress::adhoc,
        );
    // THE PLANES' DATA ROUTES, contributed through the registry rather than named here. For every
    // registered plane with a `mount` fn AND a runtime object this generation (its slot), the plane's
    // own `mount` mounts its routes from that slot — the MCP door when `mcp:` is configured, the A2A
    // door when `agents:`+`public_url` is. A plane the operator did not configure has no slot and is
    // skipped, exactly as the old typed-`Option` guards skipped it: a deployment that is not an MCP
    // (or A2A) server carries none of those routes, so "is this deployment an MCP server?" stays a
    // question the mounted surface answers rather than a config flag someone has to trust. The mount
    // fns are granted only the router and their own `&dyn Any` slot — never a `Store`/`GovCtx`/audit
    // handle. Declaration order (MCP before A2A) is preserved, so the route order is stable.
    let mut router = router;
    for decl in crate::plane::registry::plane_decls() {
        let Some(slot) = plane_slots.get(decl.key) else {
            continue;
        };
        // A plane contributes its data routes through the neutral `routes` seam (S4a Option A: a flat
        // list of `PlaneRouteSpec`, mounted by the core adapter below so the plane names no
        // `CoreRouter`). `None` for a plane that answers on no data path.
        if let Some(routes) = decl.routes {
            for spec in routes(slot.as_ref()) {
                router = mount_plane_route(router, slot.clone(), spec);
            }
        }
    }
    // THE AUTHORIZATION SERVER'S ROUTES, or none of them. Same posture as the two planes above: a
    // deployment that is not an authorization server carries no `/authorize`, no `/token`, no
    // metadata document and nothing in the route table.
    let router = crate::oauth_as::routes::mount(router, oauth_as);
    // PLUGIN HTTP ROUTES: the collision-checked, namespace-confined `none`/`key`-auth
    // routes an export/hook plugin declared. Reserved HERE — BEFORE the catch-all fallback below —
    // because `ingress::protocol_dispatch` claims every unclaimed path by construction, so a plugin
    // route wired after it would never match. The admin-auth routes are mounted on the admin listener
    // instead (see `build_split_routers_with_limits`), physically absent from this data plane.
    // They carry their OWN declared auth (`plugin_routes::PluginRouteTable`), so they are outside
    // the core table by construction rather than by omission.
    let router =
        router.map_router(|r| crate::plugin_routes::mount_plugin_routes(r, plugin_routes, false));
    router
        .map_router(|r| {
            r
                // EVERY protocol endpoint — chat and the 1.2 operations, all six dialects — flows
                // through the catch-all: Router (dumb protocol ID from path+headers) → that
                // protocol's RequestHandler (reads path+body, decides the operation) → its
                // OperationHandler cell. Adding a protocol or an operation never touches this file.
                // Unknown paths / wrong methods keep the pre-collapse native-envelope 404/405
                // shaping (no bare-proxy tells). A fallback claims no path, so it declares no route:
                // it takes the normal data-plane bar like any unclaimed path always has.
                .fallback(ingress::protocol_dispatch)
                // Wrong-method hits on a VALID path (axum's built-in 405) get the same
                // native-envelope treatment as the 404 fallback above.
                .method_not_allowed_fallback(method_not_allowed_handler)
        })
        .into_parts()
}

/// Mount ONE neutral [`busbar_substrate::plane_routes::PlaneRouteSpec`] onto the core router (S4a
/// Option A). This is the SINGLE place a plane's neutral route touches core router vocabulary: it
/// calls the SAME [`crate::core_routes::CoreRouter::route`] the legacy `mount` fns called, with the
/// spec's own `(path, method, auth)`, so the `CoreRouteTable` row is byte-identical — the security
/// invariant this seam preserves. The handler it wires is a CORE-owned axum closure that extracts
/// exactly the request pieces the old typed plane handlers took: the swappable `AppHandle` state, the
/// middleware-resolved governance/principal extensions (absent — hence `Option` — on a
/// `RouteAuth::None` route, which the auth middleware bypasses before attaching them), the path
/// captures, the headers and the buffered body. It assembles a neutral
/// [`busbar_substrate::plane_routes::PlaneReqCtx`] and awaits the plane's own handler. The plane
/// names none of these core/axum types; this adapter names them all.
fn mount_plane_route(
    router: crate::core_routes::CoreRouter,
    slot: std::sync::Arc<dyn std::any::Any + Send + Sync>,
    spec: busbar_substrate::plane_routes::PlaneRouteSpec,
) -> crate::core_routes::CoreRouter {
    let busbar_substrate::plane_routes::PlaneRouteSpec {
        path,
        method,
        auth,
        handler,
    } = spec;
    // The spec's path is CONSUMED as the mount pattern (and recorded in the `CoreRouteTable`); a
    // copy rides into every `PlaneReqCtx` this route builds so the handler can read the path it was
    // matched at.
    let ctx_path = path.clone();
    router.route(
        path,
        method,
        auth,
        move |axum::extract::State(handle): axum::extract::State<
            std::sync::Arc<state::AppHandle>,
        >,
              raw_params: axum::extract::RawPathParams,
              uri: axum::http::Uri,
              gov: Option<axum::extract::Extension<busbar_api::PlaneRequestCtx>>,
              principal: Option<axum::extract::Extension<busbar_api::AuthPrincipal>>,
              headers: axum::http::HeaderMap,
              body: axum::body::Bytes| {
            let handler = handler.clone();
            let slot = slot.clone();
            let ctx_path = ctx_path.clone();
            let path_params: Vec<(String, String)> = raw_params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            async move {
                let gov = gov.map(|axum::extract::Extension(g)| g);
                // The one identity fact a `Key`-auth handler binds request-scoped state to — the
                // resolved key id — lifted from the middleware-attached `gov` so the handler never
                // re-runs the identity chain (which would double-run it and change behaviour).
                let caller_principal = gov
                    .as_ref()
                    .and_then(|g| g.key.as_ref().map(|k| k.id.clone()));
                // D1: mint the NEUTRAL host seam over the request's live engine snapshot BEFORE
                // erasing the handle, so the plane reaches host capabilities by calling typed methods
                // on `ctx.host` rather than naming `busbar_core::plane_host::*_over`.
                let host = crate::plane_host::engine_host_from_handle(&handle);
                let engine: std::sync::Arc<dyn std::any::Any + Send + Sync> = handle;
                let ctx = busbar_substrate::plane_routes::PlaneReqCtx {
                    path: ctx_path,
                    uri,
                    method,
                    headers,
                    body,
                    path_params,
                    caller_principal,
                    gov,
                    principal: principal.map(|axum::extract::Extension(p)| p),
                    engine,
                    host,
                    slot,
                };
                handler(ctx).await
            }
        },
    )
}

/// Apply the shared middleware stack — auth chain, request-body cap, 413 reshaping, server-timing —
/// and bind the swappable `AppHandle` state. Identical for the single-listener router and each
/// split-plane router, so both planes get the SAME auth + limit posture and both see config-apply
/// hot-swaps (they share one `handle`).
pub(crate) fn apply_common_layers(
    router: Router<std::sync::Arc<state::AppHandle>>,
    core_routes: crate::core_routes::CoreRouteTable,
    handle: &std::sync::Arc<state::AppHandle>,
    request_body_max_bytes: usize,
    server_timing_enabled: bool,
) -> Router {
    // THIS ROUTER's core route-auth table, handed to the auth middleware as a `&'static`
    // borrow rather than through `axum::Extension`. The Extension form cost every request an
    // insert into its extensions map plus two `Arc` refcount round-trips (the layer's clone in,
    // the extractor's clone out) to deliver a value that never changes after this function runs:
    // routers are built ONCE at boot and a config apply only `swap`s the `AppHandle` snapshot, so
    // the table is process-immutable and the leak is one small allocation per router per process
    // lifetime — not per apply, and nothing at request rate. Per-router (not per-process) on
    // purpose, still: the data plane and the admin plane each leak THEIR OWN table, and a route's
    // bypass belongs to the plane that serves it.
    let core_routes: &'static crate::core_routes::CoreRouteTable = Box::leak(Box::new(core_routes));
    let router = router
        // The router's state is a swappable `AppHandle` (the config-apply hot-swap seam). Every
        // handler reads the CURRENT snapshot via the `CurrentApp` extractor; the auth middleware
        // loads it too. Until an admin apply calls `swap()`, this is identical to a fixed `Arc<App>`.
        .layer(axum::middleware::from_fn_with_state(
            handle.clone(),
            move |app: crate::state::CurrentApp,
                  req: axum::extract::Request,
                  next: axum::middleware::Next| {
                auth::auth_middleware(app, core_routes, req, next)
            },
        ))
        // Cap request body size (buffered before the handler) to bound per-request memory. Driven by
        // `limits.request_body_max_bytes` (default 32 MiB); COUPLED with the egress translate-body cap
        // (`limits::translate_body_max_bytes`) — both read the SAME knob so an accepted request is
        // always buffer-translatable on the cross-protocol path.
        .layer(axum::extract::DefaultBodyLimit::max(request_body_max_bytes))
        // Outermost: reshape the body-limit layer's bare-text 413 into a protocol-native JSON
        // envelope. Must wrap the `DefaultBodyLimit` layer above, so it is applied LAST (the last
        // `.layer()` is the outermost on the response path) and therefore sees that layer's 413.
        .layer(axum::middleware::from_fn_with_state(
            handle.clone(),
            reshape_body_limit_413,
        ));
    // THE PLANE INGRESS BOUNDARY. Outside the auth layer, which in axum means it observes the
    // FINAL response — including a 401 the auth chain issued before any handler ran, which on
    // a mounted plane is exactly the failure an operator has no other signal for. It emits for
    // a path a plane CLAIMS BY MOUNT and passes everything else straight through, so the
    // residual plane (every protocol endpoint, `/healthz`, `/metrics`, the admin surface) is
    // untouched and cannot be double-counted against `ingress::finish_inner`.
    //
    // COMPOSED IN ONLY WHEN A PLANE IS MOUNTED — the same composition rule as `server_timing`
    // below and for the same reason: a layer that is pure passthrough for every request this
    // deployment can ever receive is not free, it is a `handle.load()` + a mount-table walk per
    // request. Plane mounts are fixed at boot (`plane::registry::install_planes` registers once,
    // before the first request), so `has_mounts()` cannot change under a config apply and omitting
    // the layer is behaviour-identical to running its no-op arm. This is the plugins-cost-nothing
    // contract made structural: a deployment that configured no MCP/A2A plane carries NONE of the
    // plane machinery on its request path.
    let router = if handle.load().planes.has_mounts() {
        router.layer(axum::middleware::from_fn_with_state(
            handle.clone(),
            crate::plane::observe::observe,
        ))
    } else {
        router
    };
    // Always installed (cheap: one relaxed atomic add, no allocation) — the jemalloc idle-purge
    // activity ticker must keep incrementing whether or not `server_timing` below is installed.
    let router = router.layer(axum::middleware::from_fn(request_activity_tick));
    // Outermost, and COMPOSED IN ONLY WHEN ENABLED, for speed: an earlier version
    // installed this layer UNCONDITIONALLY and gated only the response header with a runtime `if`
    // inside `server_timing`, so every request paid an `Arc<AtomicU64>` allocation, an
    // `Instant::now()`, and a task-local `.scope()` even with the header suppressed. Gated on
    // `advanced.response_headers.server_timing` (default `false`): when `false` the layer is simply
    // NOT ADDED to the stack — zero per-request cost — mirroring
    // `apply_inbound_concurrency_limit`'s `max_inbound_concurrent > 0` composition gate below. Must
    // stay the LAST `.layer()` when present so it wraps (and times) everything inside it.
    let router = if server_timing_enabled {
        router.layer(axum::middleware::from_fn(server_timing))
    } else {
        router
    };
    router.with_state(handle.clone())
}

/// Build SEPARATE data-plane and admin-plane routers sharing ONE `AppHandle`, for the split-listener
/// deployment (`admin_listen` set). The admin surface is mounted ONLY on the admin router — it is
/// absent from the data router, so the data listener physically cannot serve `/api/v1/admin/*` (no
/// double-exposure: the whole point of splitting is that admin is not reachable on the public bind).
/// Both planes carry the identical middleware stack; the inbound-concurrency cap applies to the DATA
/// plane only (the low-volume admin plane is uncapped, matching today's default). Returns
/// `(data_router, admin_router, shared_handle)`.
pub fn build_split_routers_with_limits(
    app: std::sync::Arc<state::App>,
    request_body_max_bytes: usize,
    max_inbound_concurrent: usize,
    server_timing_enabled: bool,
) -> (Router, Router, std::sync::Arc<state::AppHandle>) {
    // Capture the plugin route table before `app` moves into the handle.
    let plugin_routes = app.plugin_routes.clone();
    let plane_slots = app.plane_slots.clone();
    let oauth_as = app.oauth_as.clone();
    let handle = std::sync::Arc::new(state::AppHandle::new(app));
    // DATA plane: protocols + health/metrics/stats + the `none`/`key`-auth plugin routes, NO admin
    // mount and NO admin-auth plugin routes (those are physically absent from the data listener).
    let (data, data_core_routes) =
        base_data_router(&plugin_routes, &plane_slots, oauth_as.as_ref());
    let data = apply_common_layers(
        data,
        data_core_routes,
        &handle,
        request_body_max_bytes,
        server_timing_enabled,
    );
    let data = apply_inbound_concurrency_limit(data, max_inbound_concurrent);
    // ADMIN plane: a liveness probe (unauthenticated, like the data plane's) + the admin surface +
    // the `admin`-auth plugin routes (confined to this listener exactly like `/api/v1/admin/*`).
    // `/healthz` bypasses auth so probes work on the admin port too; every `/api/v1/admin/*` route
    // stays behind the admin auth chain.
    let (admin, admin_core_routes) = crate::core_routes::CoreRouter::new()
        .route(
            crate::auth::HEALTHZ_PATH,
            busbar_plugin_loader::RouteMethod::Get,
            busbar_plugin_loader::RouteAuth::None,
            endpoints::healthz,
        )
        .into_parts();
    let admin = admin::transport::mount(admin, &admin::JsonV1);
    let admin = crate::plugin_routes::mount_plugin_routes(admin, &plugin_routes, true);
    let admin = apply_common_layers(
        admin,
        admin_core_routes,
        &handle,
        request_body_max_bytes,
        server_timing_enabled,
    );
    (data, admin, handle)
}

/// OUTERMOST inbound-concurrency cap. `max_inbound_concurrent == 0` disables the layer entirely (a
/// true no-op) — but `0` is NOT the default; `DEFAULT_MAX_INBOUND_CONCURRENT` is `8192`, so the layer
/// IS installed out of the box and an operator opts OUT with `0`, not in. When `> 0` (including the
/// default), [`limits::admission::InboundAdmissionLayer`] (one `AdmissionGate`, shared across ALL
/// requests) bounds in-flight inbound work: a request that arrives with the cap FULL is SHED with a
/// 503 immediately rather than queued for a permit (Bug 4). Applied as the last `.layer()` so it is
/// outermost (it must admission-control before any inner work, including body buffering). Factored
/// out so the add-only-when-`>0` rule is unit-testable in isolation.
/// Project the resolved `auth:` block onto [`state::App::auth_scope_caps`] — the per-PROVIDER admin
/// trust CEILING (`max_admin_scope:`) the admin authorization step floors every non-`admin-tokens`
/// verdict against.
///
/// KEYED BY PROVIDER NAME, not by the backing plugin MODULE. That is the whole point of the 1.5.3
/// named-definition pattern and the invariant [`crate::auth::ChainVerdict::Identified`] states
/// verbatim: two NAMED providers may share one plugin module and must get INDEPENDENT bindings and
/// ceilings. The lookup side (`auth::module_admin_scope_cap`) reads this map with the provider NAME
/// (the identity a chain verdict carries), and `role_bindings` is name-keyed too — so a module-keyed
/// build here disagreed with both. The dominant effect was fail-CLOSED (a miss floors to
/// `read-only`, silently ignoring an operator's explicit `max_admin_scope: full`), but a config in
/// which one provider's NAME equals a DIFFERENT provider's MODULE handed the first provider's
/// ceiling to the second — an escalation. Name-keying closes both.
pub(crate) fn project_auth_scope_caps(
    a: &config::AuthCfg,
) -> std::collections::HashMap<String, String> {
    a.chain
        .iter()
        .chain(a.admin_auth.iter())
        .filter_map(|e| {
            e.max_admin_scope
                .as_ref()
                .map(|sc| (e.name.clone(), sc.clone()))
        })
        .collect()
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
