// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin HTTP endpoint registration: the general primitive behind both `/metrics` (a
//! pull exporter's exposition) and a routing hook's inbound `/feedback`.
//!
//! A plugin DECLARES its routes at load (an export sink via its `routes` op, a hook via the same). The
//! engine, in the deterministic plugin scan order, **namespace-confines** each route ([`confine`]) and
//! **collision-checks** the `{path, method}` pair ([`build_route_table`]) — a second plugin claiming an
//! already-owned pair is a LOUD failure naming the owner, never last-writer-wins. The surviving table
//! ([`PluginRouteTable`]) is carried on the live [`crate::state::App`] snapshot; the mounted axum
//! handler ([`plugin_route_dispatch`]) resolves the owning plugin from the CURRENT snapshot on EVERY
//! request (scrape-time resolution), so a hot-swapped plugin never leaves a stale route.
//!
//! ## Confinement
//!
//! - A `hook` plugin's routes are confined under `/hooks/<name>/*` (`<name>` = its config name), so two
//!   hook instances can never collide and a hook can never shadow a core route.
//! - An `export` plugin may claim the well-known `/metrics` (a Prometheus/OpenMetrics convention);
//!   otherwise its routes are confined under `/exports/<name>/*`.
//! - No plugin route may collide with `/api/v1/admin/*`, `/healthz`, `/stats`, `/metrics/hooks`,
//!   `/v1/models`, `/v1beta/models`, or the auth-exchange path — and all plugin routes are reserved
//!   BEFORE the data-plane catch-all fallback (mounted in [`crate::base_data_router`]).
//!
//! ## Auth
//!
//! The declared [`RouteAuth`] is enforced by the EXISTING auth middleware chain (`auth::auth_middleware`
//! consults [`PluginRouteTable::declared_auth`]): `none` bypasses like `/healthz`, `key` takes the
//! data-plane bar, `admin` is routed through the operator chain AND the route is mounted ONLY on the
//! admin listener (physically absent from the data listener).

use crate::state::CurrentApp;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::Response;
use axum::routing::{on, MethodFilter, MethodRouter};
use busbar_plugin_loader::{
    HttpEndpointRequest, HttpEndpointResponse, Route, RouteAuth, RouteMethod,
};
use std::collections::HashMap;
use std::sync::Arc;

/// The header-count cap applied on BOTH directions of a plugin HTTP-endpoint route — the inbound
/// projection forwarded to the plugin ([`project_request_headers`]) and the plugin's response relayed
/// to the external client ([`relay_response`]) — mirroring the bounded-header posture every other
/// proxied response respects: a hostile/buggy plugin (this module's own framing) cannot flood either
/// side with unbounded headers.
///
/// Over-cap is NEVER a silent `.take(n)`: the OWNER PRINCIPLE for a security/audit product is that a
/// consumer relying on this data (the plugin deciding auth/governance/routing, or the external client
/// reading the response) must see either the WHOLE set or an explicit, counted, logged signal that it
/// did not — never a quietly-shortened one it cannot tell from complete. See [`relay_response`] (which
/// REJECTS with 502 over-cap — the response reaches an external client, so a partial header set must
/// never leave the process) and [`project_request_headers`] (which counts, warns, and marks the
/// projection over-cap — the request is still served, since a plugin route serving an inbound client
/// should not itself hard-fail on the client's own header count, but the plugin can never mistake the
/// cut set for a complete one).
const MAX_PLUGIN_HEADERS: usize = 64;

/// Synthetic header name [`project_request_headers`] appends to an over-cap projection so the
/// receiving plugin has an explicit, in-band signal that the header set it was handed is INCOMPLETE —
/// the same "never let an omission look complete" discipline `enforce_content_cap` uses for hook
/// content (see `crate::proxy::hooks::enforce_content_cap`).
const PLUGIN_REQUEST_HEADERS_TRUNCATED_MARKER: &str = "x-busbar-headers-truncated";

/// The core paths a plugin route may NEVER claim (exact match), independent of kind. `/metrics` is
/// deliberately ABSENT — it is the one well-known path a metrics `export` plugin MAY claim; a
/// `hook` still cannot, because the hook branch of [`confine`] requires `/hooks/<name>/*`.
fn reserved_exact_paths() -> [&'static str; 6] {
    [
        "/healthz",
        "/stats",
        "/metrics/hooks",
        "/v1/models",
        "/v1beta/models",
        crate::auth::exchange::AUTH_TOKEN_PATH,
    ]
}

/// The plugin KIND that declared a route — drives namespace confinement (a hook is confined more
/// tightly than an export sink, which alone may claim the well-known `/metrics`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum RouteKind {
    /// A `kind: export` sink (may claim `/metrics`; otherwise `/exports/<name>/*`).
    Export,
    /// A `kind: hook` policy (confined to `/hooks/<name>/*`).
    Hook,
}

/// A plugin that can serve a dispatched inbound HTTP request. Object-safe so the live table can hold
/// `Arc<dyn PluginHttpDispatch>` and resolve it at request time from the App snapshot. The production
/// implementor wraps a loader `DynExport`/hook handle; tests supply a fake.
pub(crate) trait PluginHttpDispatch: Send + Sync {
    /// Serve one inbound request the engine already auth-gated + matched to this plugin's route.
    fn handle_http(&self, req: &HttpEndpointRequest) -> HttpEndpointResponse;

    /// The app-aware serve arm: BUILT-IN export/hook dispatchers that need the LIVE `App` snapshot
    /// (the built-in `prometheus` exporter's scrape-time gauge refresh) override this; a
    /// loaded out-of-tree plugin (which cannot receive the app across the ABI) uses the default, which
    /// ignores the app and calls [`PluginHttpDispatch::handle_http`]. Called on a blocking thread (see
    /// [`plugin_route_dispatch`]), so a synchronous read (SQLite) inside an override cannot stall the
    /// async executor.
    fn handle_http_with_app(
        &self,
        _app: &crate::state::App,
        req: &HttpEndpointRequest,
    ) -> HttpEndpointResponse {
        self.handle_http(req)
    }
}

/// A loader `DynExport` presented as a [`PluginHttpDispatch`]: the production bridge from the engine's
/// route table to the ABI. A transport failure (the plugin panicked / returned an unexpected arm) is
/// relayed as a `502` rather than tearing anything down — the route is off the data-plane hot path.
///
/// Constructed once an export plugin is loaded INTO the App snapshot (a later wave); until then the
/// live table is empty and this bridge is exercised only by the route-dispatch tests.
#[allow(dead_code)]
pub(crate) struct ExportDispatch(pub(crate) Arc<busbar_plugin_loader::DynExport>);

impl PluginHttpDispatch for ExportDispatch {
    fn handle_http(&self, req: &HttpEndpointRequest) -> HttpEndpointResponse {
        match self.0.handle_http(req) {
            Ok(resp) => resp,
            Err(msg) => HttpEndpointResponse {
                status: 502,
                headers: Vec::new(),
                body: msg.into_bytes(),
            },
        }
    }
}

/// One plugin's route registration input, BEFORE collision + confinement resolution.
pub(crate) struct RouteDecl {
    /// The declaring plugin's config name (the namespace root for confinement + the collision owner).
    pub(crate) owner: String,
    /// The declaring plugin's kind (drives the confinement rule).
    pub(crate) kind: RouteKind,
    /// The declared route.
    pub(crate) route: Route,
    /// The live dispatcher for the owning plugin (resolved per request from the App snapshot).
    pub(crate) dispatch: Arc<dyn PluginHttpDispatch>,
}

/// A registered, collision-checked, confinement-validated route entry.
struct Registered {
    auth: RouteAuth,
    owner: String,
    dispatch: Arc<dyn PluginHttpDispatch>,
}

/// The live plugin route table: the {path, method} → owning-plugin index the mounted handler and the
/// auth middleware both read off the CURRENT App snapshot. Built once per config apply from the
/// collision-checked declaration set; empty when no plugin declared a route (the production default
/// until export/hook plugins are wired into the App snapshot).
#[derive(Default)]
pub(crate) struct PluginRouteTable {
    by_path_method: HashMap<(String, RouteMethod), Registered>,
}

impl PluginRouteTable {
    /// The EMPTY table — used by test harnesses that build an `App` with no exporters. Production
    /// builds the table from the built-in exporters (`crate::export::route_decls`), so this is
    /// test-only now.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn empty() -> Self {
        Self::default()
    }

    /// Every registered `{path, methods}` grouped by path, for the plane matching `admin` (admin-auth
    /// routes go to the admin listener; `none`/`key` routes to the data listener). Sorted for a stable
    /// mount order. Grouping by path is required because axum forbids two `.route(path, _)` calls for
    /// the same path — the methods on one path are combined into one `MethodRouter`.
    fn mounts_for_plane(&self, admin: bool) -> Vec<(String, Vec<RouteMethod>)> {
        let mut by_path: std::collections::BTreeMap<String, Vec<RouteMethod>> =
            std::collections::BTreeMap::new();
        for ((path, method), reg) in &self.by_path_method {
            if (reg.auth == RouteAuth::Admin) == admin {
                by_path.entry(path.clone()).or_default().push(*method);
            }
        }
        by_path
            .into_iter()
            .map(|(p, mut ms)| {
                ms.sort_by_key(|m| m.as_str());
                (p, ms)
            })
            .collect()
    }

    /// Every PATH this table owns (method-collapsed, deduplicated). The unit the axum router is keyed
    /// on: [`mount_plugin_routes`] registers one `.route(path, …)` per path (both planes mount from
    /// the same table), so this set — captured from the BOOT table onto [`crate::state::App`] as
    /// `boot_route_paths` — is exactly the set of plugin paths the running router can serve.
    pub(crate) fn paths(&self) -> std::collections::HashSet<String> {
        self.by_path_method
            .keys()
            .map(|(path, _)| path.clone())
            .collect()
    }

    /// The declared auth level for `(path, method)`, or `None` if not a registered plugin route. Read
    /// by the auth middleware to enforce the route's bar through the existing chain.
    pub(crate) fn declared_auth(&self, path: &str, method: &Method) -> Option<RouteAuth> {
        let rm = route_method_of(method)?;
        self.by_path_method
            .get(&(path.to_string(), rm))
            .map(|r| r.auth)
    }

    /// Resolve + dispatch a matched request to its owning plugin. `None` iff no plugin currently owns
    /// `(path, method)` — which, for a mounted route, means a hot-swap dropped it (→ the handler 404s),
    /// never a hot-path miss. Returns the OWNER alongside the response so a fail-closed reject on the
    /// relay side ([`relay_response`]) can name the offending plugin in its log line.
    fn dispatch(
        &self,
        path: &str,
        method: RouteMethod,
        app: &crate::state::App,
        req: &HttpEndpointRequest,
    ) -> Option<(String, HttpEndpointResponse)> {
        self.by_path_method
            .get(&(path.to_string(), method))
            .map(|reg| {
                (
                    reg.owner.clone(),
                    reg.dispatch.handle_http_with_app(app, req),
                )
            })
    }
}

/// Namespace-confine one declared `path` for a plugin of `kind` named `owner`. `Ok(())` iff the
/// path is inside the plugin's allowed namespace and collides with no reserved core route.
fn confine(kind: RouteKind, owner: &str, path: &str) -> Result<(), String> {
    // Never under the admin API surface — the whole `/api/*` root is reserved (the admin auth chain
    // keys on exactly this prefix; a plugin route here would shadow it or ride its auth).
    if path == "/api" || path.starts_with("/api/") {
        return Err(format!(
            "plugin {owner:?} cannot register {path} — the /api/* admin surface is reserved"
        ));
    }
    // Never a reserved core exposition/discovery/auth route.
    if reserved_exact_paths().contains(&path) {
        return Err(format!(
            "plugin {owner:?} cannot register {path} — it is a reserved core route"
        ));
    }
    match kind {
        RouteKind::Hook => {
            let root = format!("/hooks/{owner}");
            if path == root || path.starts_with(&format!("{root}/")) {
                Ok(())
            } else {
                Err(format!(
                    "hook plugin {owner:?} cannot register {path} — hook routes are confined to \
                     /hooks/{owner}/*"
                ))
            }
        }
        RouteKind::Export => {
            // The one well-known exception: a metrics-stream export sink may claim `/metrics`.
            if path == "/metrics" {
                return Ok(());
            }
            let root = format!("/exports/{owner}");
            if path == root || path.starts_with(&format!("{root}/")) {
                Ok(())
            } else {
                Err(format!(
                    "export plugin {owner:?} cannot register {path} — export routes are confined to \
                     /metrics or /exports/{owner}/*"
                ))
            }
        }
    }
}

/// Confinement-check the {path, method} tuples of a set of declarations WITHOUT their dispatchers — the
/// MANIFEST-LEVEL preflight: nothing is dlopened, deterministic scan order is the input
/// order, first-to-claim owns, and a second claim of the same `{path, method}` fails LOUD naming the
/// owning plugin. The SAME logic backs [`build_route_table`] (which additionally carries the live
/// dispatchers), so `--validate` and boot cannot diverge from what actually mounts.
pub(crate) fn preflight_route_collisions(
    decls: &[(String, RouteKind, Route)],
) -> Result<(), String> {
    let mut owned: HashMap<(String, RouteMethod), String> = HashMap::new();
    for (owner, kind, route) in decls {
        confine(*kind, owner, &route.path)?;
        let key = (route.path.clone(), route.method);
        if let Some(existing) = owned.get(&key) {
            return Err(format!(
                "plugin {owner:?} cannot register {} {} — already registered by {existing:?}",
                route.method.as_str(),
                route.path
            ));
        }
        owned.insert(key, owner.clone());
    }
    Ok(())
}

/// Build the live [`PluginRouteTable`] from the deterministic-order declaration set: confine every
/// route, first-to-claim owns each `{path, method}`, a second claim is a LOUD collision naming the
/// owner. This is the App-construction / config-apply path (invoked once export/hook plugins are
/// loaded into the snapshot — a later wave; exercised today by the route-dispatch + collision tests);
/// [`preflight_route_collisions`] is the manifest-only mirror that runs at `--validate` and boot with
/// the identical confinement + first-to-claim rules, so the two can never diverge.
#[allow(dead_code)]
pub(crate) fn build_route_table(decls: Vec<RouteDecl>) -> Result<PluginRouteTable, String> {
    let mut by_path_method: HashMap<(String, RouteMethod), Registered> = HashMap::new();
    for decl in decls {
        confine(decl.kind, &decl.owner, &decl.route.path)?;
        let key = (decl.route.path.clone(), decl.route.method);
        if let Some(existing) = by_path_method.get(&key) {
            return Err(format!(
                "plugin {:?} cannot register {} {} — already registered by {:?}",
                decl.owner,
                decl.route.method.as_str(),
                decl.route.path,
                existing.owner
            ));
        }
        by_path_method.insert(
            key,
            Registered {
                auth: decl.route.auth,
                owner: decl.owner,
                dispatch: decl.dispatch,
            },
        );
    }
    Ok(PluginRouteTable { by_path_method })
}

/// THE RESTART-TO-APPLY SIGNAL for plugin routes: the paths a just-applied config
/// declares that this process CANNOT serve, because they were never registered on the axum router.
///
/// Each declared path is registered ONCE, at boot ([`mount_plugin_routes`], `on(filter,
/// plugin_route_dispatch)`); a config apply swaps only `Arc<App>` and never rebuilds the router. So the
/// two directions are not symmetric — a REMOVED path keeps 404ing correctly (the dispatcher resolves
/// the owner from the current snapshot and finds nothing), while an ADDED path that was not mounted at
/// boot keeps 404ing however many times the operator applies it. `boot_mounted` is the boot table's
/// [`PluginRouteTable::paths`], carried forward unchanged on every rebuild (`App::boot_route_paths`).
///
/// Keyed on the DELTA (`installed` minus `previous`), the same discipline
/// `handlers::reload_to_apply_fields` uses in keying on the REQUEST: only a mutation that ITSELF
/// introduces an unmountable path is flagged, so a later unrelated edit does not re-flag an
/// already-restart-pending route. Sorted, so the reported list is stable.
pub(crate) fn paths_awaiting_restart(
    installed: &PluginRouteTable,
    previous: &PluginRouteTable,
    boot_mounted: &std::collections::HashSet<String>,
) -> Vec<String> {
    let previous = previous.paths();
    let mut out: Vec<String> = installed
        .paths()
        .into_iter()
        .filter(|p| !boot_mounted.contains(p) && !previous.contains(p))
        .collect();
    out.sort();
    out
}

/// Map an `http::Method` onto the declared [`RouteMethod`] set busbar supports. `None` for a method no
/// plugin route can declare (CONNECT/TRACE/OPTIONS/…).
///
/// HEAD maps onto `Get`, and it MUST: axum's [`MethodRouter`] already routes a HEAD to the GET arm
/// (stripping the response body), so a HEAD on a declared GET route reaches both
/// [`PluginRouteTable::declared_auth`] and [`plugin_route_dispatch`]. With no HEAD arm the two halves
/// disagreed — `declared_auth` returned `None`, so the route's DECLARED bar was not applied (an
/// `auth: none` route demanded a token; an `auth: admin` route was not forced down the admin chain,
/// reachable-in-principle and saved only by the dispatcher's matching gap), while the dispatcher 405'd
/// a request axum had already routed to the plugin. One arm closes both halves together, which is the
/// only safe way to close either.
pub(crate) fn route_method_of(method: &Method) -> Option<RouteMethod> {
    match *method {
        Method::GET | Method::HEAD => Some(RouteMethod::Get),
        Method::POST => Some(RouteMethod::Post),
        Method::PUT => Some(RouteMethod::Put),
        Method::PATCH => Some(RouteMethod::Patch),
        Method::DELETE => Some(RouteMethod::Delete),
        _ => None,
    }
}

/// The axum [`MethodFilter`] for a declared [`RouteMethod`].
pub(crate) fn method_filter_of(m: RouteMethod) -> MethodFilter {
    match m {
        RouteMethod::Get => MethodFilter::GET,
        RouteMethod::Post => MethodFilter::POST,
        RouteMethod::Put => MethodFilter::PUT,
        RouteMethod::Patch => MethodFilter::PATCH,
        RouteMethod::Delete => MethodFilter::DELETE,
    }
}

/// Mount every plugin route on the given plane onto `router`. `admin == false` mounts the `none`/`key`
/// routes (data listener, called from [`crate::base_data_router`] BEFORE the catch-all fallback);
/// `admin == true` mounts the `admin`-auth routes (admin listener). Each path's declared methods are
/// combined into one [`MethodRouter`] so a wrong-method hit still yields axum's native 405.
pub(crate) fn mount_plugin_routes(
    mut router: axum::Router<Arc<crate::state::AppHandle>>,
    table: &PluginRouteTable,
    admin: bool,
) -> axum::Router<Arc<crate::state::AppHandle>> {
    for (path, methods) in table.mounts_for_plane(admin) {
        let mut mr: Option<MethodRouter<Arc<crate::state::AppHandle>>> = None;
        for m in methods {
            let filter = method_filter_of(m);
            mr = Some(match mr {
                None => on(filter, plugin_route_dispatch),
                Some(existing) => existing.on(filter, plugin_route_dispatch),
            });
        }
        if let Some(mr) = mr {
            router = router.route(&path, mr);
        }
    }
    router
}

/// The ONE axum handler every mounted plugin route shares. It resolves the owning plugin from the
/// CURRENT App snapshot ([`CurrentApp`]) on every request (scrape-time resolution, no handle is
/// baked into the route closure), forwards a bounded projection of the request via `handle_http`, and
/// relays the plugin's response, REJECTING (502) rather than truncating if it exceeds the header-count
/// cap (see [`relay_response`]). The auth middleware already enforced the route's declared bar before
/// this runs.
async fn plugin_route_dispatch(
    CurrentApp(app): CurrentApp,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(rm) = route_method_of(&method) else {
        return StatusCode::METHOD_NOT_ALLOWED.into_response_stub();
    };
    let path = uri.path().to_string();
    let ep_req = HttpEndpointRequest {
        method: rm.as_str().to_string(),
        path: path.clone(),
        query: uri.query().unwrap_or("").to_string(),
        headers: project_request_headers(&headers),
        body: body.to_vec(),
    };
    // Resolve + serve on a BLOCKING thread: a plugin's `handle_http` (and the built-in prometheus
    // exporter's scrape-time SQLite gauge refresh) may block, and this is off the data-plane hot path,
    // so it must not run on an async worker. `app` is an `Arc<App>` moved into the closure; the table
    // + dispatcher are resolved from the CURRENT snapshot at serve time (no baked handle).
    let served = tokio::task::spawn_blocking(move || {
        app.plugin_routes
            .dispatch(&path, rm, &app, &ep_req)
            .map(|(owner, resp)| relay_response(&owner, &path, resp))
    })
    .await;
    match served {
        Ok(Some(resp)) => resp,
        // A mounted route with no current owner => a hot-swap dropped it. 404, never a stale handle.
        Ok(None) => StatusCode::NOT_FOUND.into_response_stub(),
        // The blocking task panicked — relay a 502 rather than tearing the listener down.
        Err(_) => StatusCode::BAD_GATEWAY.into_response_stub(),
    }
}

/// Project the inbound header set into the bounded, pre-filtered list forwarded to the plugin. The raw
/// `Authorization` header is NEVER forwarded — busbar enforced the grant before this point.
///
/// A plugin route may drive an auth/governance/routing decision (this module's own framing treats
/// plugins as potentially hostile/buggy, but the DECISION-MAKER here is the plugin — an incomplete
/// header set handed to it silently is itself audit-relevant). So an over-cap header set is never
/// quietly cut: [`PLUGIN_REQUEST_HEADERS_TRUNCATED_MARKER`] is appended so the plugin can see, in-band,
/// that what it was handed is incomplete, `busbar_plugin_request_headers_truncated_total` counts the
/// occurrence, and a warning names the route. The request is still SERVED (not fail-closed) — unlike
/// [`relay_response`], the truncation here never leaves the process to an external party, and hard-
/// failing every request from a client whose own header count is high (proxies/CDNs/tracing headers are
/// legitimate over-64 producers) would be a disproportionate response to a plugin-side decision-quality
/// concern; failing closed instead lives with [`relay_response`], where the withheld data would
/// otherwise reach an external client.
fn project_request_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    let mut projected: Vec<(String, String)> = headers
        .iter()
        .filter(|(name, _)| name.as_str() != "authorization")
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_string(), v.to_string()))
        })
        .collect();
    if projected.len() > MAX_PLUGIN_HEADERS {
        metrics::counter!(crate::metrics::PLUGIN_REQUEST_HEADERS_TRUNCATED_TOTAL).increment(1);
        tracing::warn!(
            header_count = projected.len(),
            cap = MAX_PLUGIN_HEADERS,
            "inbound request header count exceeded the plugin-route cap; truncating the projection \
             forwarded to the plugin and marking it with {PLUGIN_REQUEST_HEADERS_TRUNCATED_MARKER} so \
             the plugin cannot mistake an incomplete header set for a complete one"
        );
        projected.truncate(MAX_PLUGIN_HEADERS.saturating_sub(1));
        projected.push((
            PLUGIN_REQUEST_HEADERS_TRUNCATED_MARKER.to_string(),
            "true".to_string(),
        ));
    }
    projected
}

/// Relay a plugin's [`HttpEndpointResponse`] as an axum [`Response`], dropping any header name/value
/// that is not a valid HTTP header (a plugin cannot smuggle a malformed header onto the response path).
///
/// Over-cap headers are REJECTED WHOLE (a 502, never a truncated relay): this response reaches an
/// EXTERNAL client, so the OWNER PRINCIPLE leaves no fallback here — a silently-shortened header set
/// handed to an external party is exactly the failure mode this fix closes, and unlike the request
/// direction ([`project_request_headers`]) there is no in-band marker an arbitrary external HTTP client
/// is guaranteed to understand. `busbar_plugin_response_headers_rejected_total` counts the rejection and
/// an error log names the offending plugin/route, so an operator can tell a hostile/buggy plugin from a
/// cap that needs raising.
fn relay_response(owner: &str, path: &str, resp: HttpEndpointResponse) -> Response {
    use axum::http::{HeaderName, HeaderValue};
    if resp.headers.len() > MAX_PLUGIN_HEADERS {
        metrics::counter!(crate::metrics::PLUGIN_RESPONSE_HEADERS_REJECTED_TOTAL).increment(1);
        tracing::error!(
            plugin = owner,
            route = path,
            header_count = resp.headers.len(),
            cap = MAX_PLUGIN_HEADERS,
            "plugin response exceeded the header-count cap; rejecting with 502 rather than silently \
             relaying a truncated header set to the external client"
        );
        return StatusCode::BAD_GATEWAY.into_response_stub();
    }
    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut builder = Response::builder().status(status);
    for (name, value) in resp.headers {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            builder = builder.header(n, v);
        }
    }
    builder
        .body(Body::from(resp.body))
        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response_stub())
}

/// Tiny `IntoResponse`-free helper so this module does not pull the trait into scope just for a bare
/// status response.
trait StatusResponseExt {
    fn into_response_stub(self) -> Response;
}
impl StatusResponseExt for StatusCode {
    fn into_response_stub(self) -> Response {
        Response::builder()
            .status(self)
            .body(Body::empty())
            .expect("a bare-status response is always well-formed")
    }
}

#[cfg(test)]
#[path = "tests/plugin_routes_tests.rs"]
mod tests;
