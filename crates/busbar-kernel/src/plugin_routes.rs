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
//! - Export routes are confined under `/exports/<name>/*`. The first-party snapshot consumer
//!   may declare public paths through its Statement metadata ([`RouteDecl::scrape`]).
//! - No plugin route may collide with `/api/v1/admin/*`, `/healthz`, `/stats`, `/v1/models`,
//!   `/v1beta/models`, or the auth-exchange path — and all plugin routes are reserved
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
use busbar_contract::abi::mechanism::endpoint::*;
use busbar_contract::abi::mechanism::route::{Route, RouteAuth, RouteMethod};
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
fn reserved_exact_paths() -> [&'static str; 5] {
    [
        "/healthz",
        "/stats",
        "/v1/models",
        "/v1beta/models",
        crate::auth::exchange::AUTH_TOKEN_PATH,
    ]
}

/// The plugin KIND that declared a route — drives namespace confinement (a hook is confined more
/// tightly than an export sink, which alone may claim the well-known `/metrics`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RouteKind {
    /// A `kind: export` sink (may claim `/metrics`; otherwise `/exports/<name>/*`).
    Export,
    /// A `kind: hook` policy (confined to `/hooks/<name>/*`).
    Hook,
}

/// A plugin that can serve a dispatched inbound HTTP request. Object-safe so the live table can hold
/// `Arc<dyn PluginHttpDispatch>` and resolve it at request time from the App snapshot. The production
/// implementor wraps an export or hook door instance; tests supply a fake.
pub trait PluginHttpDispatch: Send + Sync {
    /// Serve one inbound request the engine already auth-gated + matched to this plugin's route.
    fn handle_http(&self, req: &EndpointRequest) -> EndpointResponse;

    /// The app-aware serve arm: a dispatcher that needs the LIVE `App` snapshot (the scrape sink's
    /// grant, which lends the host snapshot service that `App`) overrides this; a plugin route
    /// (which cannot receive the app across the ABI) uses the default, which ignores the app and
    /// calls [`PluginHttpDispatch::handle_http`]. Called on a blocking thread (see
    /// [`plugin_route_dispatch`]), so a synchronous read (SQLite) inside an override cannot stall the
    /// async executor.
    fn handle_http_with_app(
        &self,
        _app: &Arc<crate::state::App>,
        req: &EndpointRequest,
    ) -> EndpointResponse {
        self.handle_http(req)
    }
}

/// One plugin's route registration input, BEFORE collision + confinement resolution.
pub struct RouteDecl {
    /// The declaring plugin's config name (the namespace root for confinement + the collision owner).
    pub owner: String,
    /// The configured instance whose listener settings govern this route, independent of namespace.
    pub source_instance: String,
    /// An opened dispatcher exists; false marks a declaration awaiting a restart to open it.
    pub dispatch_available: bool,
    /// The declaring plugin's kind (drives the confinement rule).
    pub kind: RouteKind,
    /// The declared route.
    pub route: Route,
    /// Whether this route has the first-party snapshot consumer's public namespace grant.
    pub scrape: bool,
    /// The boot instance retains this route after configuration removal.
    pub persistent: bool,
    /// The live dispatcher for the owning plugin (resolved per request from the App snapshot).
    pub dispatch: Arc<dyn PluginHttpDispatch>,
}

/// A registered, collision-checked, confinement-validated route entry.
#[derive(Clone)]
struct Registered {
    kind: RouteKind,
    auth: RouteAuth,
    owner: String,
    source_instance: String,
    dispatch_available: bool,
    persistent: bool,
    dispatch: Arc<dyn PluginHttpDispatch>,
}

/// A read-only route policy of the completed application candidate.
#[derive(Debug, Clone, Copy)]
pub struct RouteDescriptor<'a> {
    /// The declaring instance.
    pub owner: &'a str,
    /// The exact configuration instance for placement (the boot instance for retained routes).
    pub source_instance: &'a str,
    /// Whether this candidate has an opened dispatcher for the declaration.
    pub dispatch_available: bool,
    /// This exact route retains its boot dispatcher after configuration removal.
    pub persistent: bool,
    /// The declaring kind.
    pub kind: RouteKind,
    /// The exact registered path.
    pub path: &'a str,
    /// The registered method.
    pub method: RouteMethod,
    /// The declared authentication policy.
    pub auth: RouteAuth,
}

/// The live plugin route table: the {path, method} → owning-plugin index the mounted handler and the
/// auth middleware both read off the CURRENT App snapshot. Built once per config apply from the
/// collision-checked declaration set; empty when no plugin declared a route (the production default
/// until export/hook plugins are wired into the App snapshot).
#[derive(Default)]
pub struct PluginRouteTable {
    /// Keyed by PATH with the (one- or two-entry) method list inline, NOT by `(String, RouteMethod)`
    /// pair: the pair key forced every per-request lookup ([`declared_auth`] from the auth
    /// middleware, [`dispatch`] from the mounted handler) to allocate a fresh `String` just to
    /// build a key it immediately dropped. A `HashMap<String, _>` answers a `&str` query through
    /// `Borrow`, so the hot-path lookups allocate nothing; the method walk inside one path's entry
    /// is over however many methods THAT path declared, which is one or two.
    by_path: HashMap<String, Vec<(RouteMethod, Registered)>>,
    persistent: std::collections::HashSet<String>,
}

impl PluginRouteTable {
    /// Replace a candidate's hook routes while retaining exact non-hook dispatchers and grants.
    /// Confinement and collision checks finish before the new table is returned.
    ///
    /// # Errors
    /// A replacement is not a hook route, escapes its namespace, or collides with a retained route.
    pub fn with_hook_routes(&self, declarations: Vec<RouteDecl>) -> Result<Self, String> {
        if declarations
            .iter()
            .any(|route| route.kind != RouteKind::Hook || route.scrape || route.persistent)
        {
            return Err(
                "a hook route replacement must contain only ungranted hook declarations".into(),
            );
        }
        let hooks = build_route_table(declarations)?;
        let mut by_path: HashMap<String, Vec<(RouteMethod, Registered)>> = self
            .by_path
            .iter()
            .filter_map(|(path, entries)| {
                let retained: Vec<_> = entries
                    .iter()
                    .filter(|(_, registered)| registered.kind != RouteKind::Hook)
                    .cloned()
                    .collect();
                (!retained.is_empty()).then(|| (path.clone(), retained))
            })
            .collect();
        for (path, entries) in hooks.by_path {
            let retained = by_path.entry(path.clone()).or_default();
            for (method, registered) in entries {
                if let Some((_, prior)) = retained.iter().find(|(existing, _)| *existing == method)
                {
                    return Err(format!(
                        "plugin {:?} cannot register {} {} — already registered by {:?}",
                        registered.owner,
                        method.as_str(),
                        path,
                        prior.owner
                    ));
                }
                retained.push((method, registered));
            }
        }
        Ok(Self {
            by_path,
            persistent: self.persistent.clone(),
        })
    }

    /// Project boot mounts to one physical listener; dispatch still reads the pinned App table.
    pub fn for_listener(&self, guests: &crate::guest::GuestList) -> Self {
        let mut by_path = HashMap::new();
        for (path, entries) in &self.by_path {
            let entries: Vec<_> = entries.iter().filter(|(method, registered)| {
                guests.lines().iter().any(|line| {
                    matches!(&line.claimant, crate::guest::Claimant::Need(owner, _) if owner == &registered.source_instance)
                        && line.route.path == *path
                        && line.route.methods & busbar_contract::abi::transport::route::method_bit(method.as_str()) != 0
                        && registered.auth != RouteAuth::Admin
                })
            }).cloned().collect();
            if !entries.is_empty() {
                by_path.insert(path.clone(), entries);
            }
        }
        Self {
            by_path,
            persistent: self.persistent.clone(),
        }
    }

    /// The actual candidate's route ownership and policy, without its dispatch handles.
    pub fn descriptors(&self) -> Vec<RouteDescriptor<'_>> {
        let mut routes: Vec<_> = self
            .by_path
            .iter()
            .flat_map(|(path, entries)| {
                entries
                    .iter()
                    .map(move |(method, registered)| RouteDescriptor {
                        path,
                        method: *method,
                        auth: registered.auth,
                        owner: &registered.owner,
                        source_instance: &registered.source_instance,
                        dispatch_available: registered.dispatch_available,
                        persistent: registered.persistent,
                        kind: registered.kind,
                    })
            })
            .collect();
        routes.sort_by_key(|route| (route.path, route.method.as_str()));
        routes
    }

    /// The EMPTY table — used by test harnesses that build an `App` with no exporters. Production
    /// builds the table from the built-in exporters (`crate::export::route_decls`), so this is
    /// test-only now.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Every registered `{path, methods}` grouped by path, for the plane matching `admin` (admin-auth
    /// routes go to the admin listener; `none`/`key` routes to the data listener). Sorted for a stable
    /// mount order. Grouping by path is required because axum forbids two `.route(path, _)` calls for
    /// the same path — the methods on one path are combined into one `MethodRouter`.
    fn mounts_for_plane(&self, admin: bool) -> Vec<(String, Vec<RouteMethod>)> {
        let mut by_path: std::collections::BTreeMap<String, Vec<RouteMethod>> =
            std::collections::BTreeMap::new();
        for (path, entries) in &self.by_path {
            for (method, reg) in entries {
                if (reg.auth == RouteAuth::Admin) == admin {
                    by_path.entry(path.clone()).or_default().push(*method);
                }
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
    pub fn paths(&self) -> std::collections::HashSet<String> {
        self.by_path.keys().cloned().collect()
    }

    /// The declared auth level for `(path, method)`, or `None` if not a registered plugin route. Read
    /// by the auth middleware to enforce the route's bar through the existing chain.
    pub fn declared_auth(&self, path: &str, method: &Method) -> Option<RouteAuth> {
        let rm = route_method_of(method)?;
        self.by_path
            .get(path)?
            .iter()
            .find(|(m, _)| *m == rm)
            .map(|(_, r)| r.auth)
    }

    /// Resolve + dispatch a matched request to its owning plugin. `None` iff no plugin currently owns
    /// `(path, method)` — which, for a mounted route, means a hot-swap dropped it (→ the handler 404s),
    /// never a hot-path miss. Returns the OWNER alongside the response so a fail-closed reject on the
    /// relay side ([`relay_response`]) can name the offending plugin in its log line.
    fn dispatch(
        &self,
        path: &str,
        method: RouteMethod,
        app: &Arc<crate::state::App>,
        req: &EndpointRequest,
    ) -> Option<(String, EndpointResponse)> {
        self.by_path
            .get(path)?
            .iter()
            .find(|(m, _)| *m == method)
            .map(|(_, reg)| {
                (
                    reg.owner.clone(),
                    reg.dispatch.handle_http_with_app(app, req),
                )
            })
    }
}

/// Namespace-confine one declared `path` for a plugin of `kind` named `owner` (`scrape`: it is the
/// scrape sink). `Ok(())` iff the path is inside the plugin's allowed namespace and collides with no
/// reserved core route.
fn confine(kind: RouteKind, owner: &str, path: &str, scrape: bool) -> Result<(), String> {
    // Never under the admin API surface — the whole `/api/*` root is reserved (the admin auth chain
    // keys on exactly this prefix; a plugin route here would shadow it or ride its auth).
    if path == "/api" || path.starts_with("/api/") {
        return Err(format!(
            "plugin {owner:?} cannot register {path} — the /api/* admin surface is reserved"
        ));
    }
    // Public namespace grants never include the host's reserved routes.
    if reserved_exact_paths().contains(&path) {
        return Err(format!(
            "plugin {owner:?} cannot register {path} — it is a reserved core route"
        ));
    }
    // A public namespace grant applies only to the declaring snapshot consumer's route.
    let (noun, root) = match kind {
        RouteKind::Hook => ("hook", format!("/hooks/{owner}")),
        RouteKind::Export if scrape => return Ok(()),
        RouteKind::Export => ("export", format!("/exports/{owner}")),
    };
    if path == root || path.starts_with(&format!("{root}/")) {
        return Ok(());
    }
    Err(format!(
        "{noun} plugin {owner:?} cannot register {path} — {noun} routes are confined to \
         {root}/*"
    ))
}

/// Build the live [`PluginRouteTable`] from the deterministic-order declaration set: confine every
/// route, first-to-claim owns each `{path, method}`, a second claim is a LOUD collision naming the
/// owner. The App-construction / config-apply path, and the boot/`--validate` preflight's check over
/// the same declaration set (`crate::preflight::plugins_preflight`), so the two can never diverge.
pub fn build_route_table(decls: Vec<RouteDecl>) -> Result<PluginRouteTable, String> {
    let mut by_path: HashMap<String, Vec<(RouteMethod, Registered)>> = HashMap::new();
    let mut persistent = std::collections::HashSet::new();
    for decl in decls {
        confine(decl.kind, &decl.owner, &decl.route.path, decl.scrape)?;
        if decl.persistent {
            if !decl.scrape || decl.kind != RouteKind::Export {
                return Err(format!(
                    "plugin {:?} cannot retain an ungranted route",
                    decl.owner
                ));
            }
            persistent.insert(decl.route.path.clone());
        }
        let entries = by_path.entry(decl.route.path.clone()).or_default();
        if let Some((_, existing)) = entries.iter().find(|(m, _)| *m == decl.route.method) {
            return Err(format!(
                "plugin {:?} cannot register {} {} — already registered by {:?}",
                decl.owner,
                decl.route.method.as_str(),
                decl.route.path,
                existing.owner
            ));
        }
        entries.push((
            decl.route.method,
            Registered {
                kind: decl.kind,
                auth: decl.route.auth,
                owner: decl.owner,
                source_instance: decl.source_instance,
                dispatch_available: decl.dispatch_available,
                persistent: decl.persistent,
                dispatch: decl.dispatch,
            },
        ));
    }
    Ok(PluginRouteTable {
        by_path,
        persistent,
    })
}

/// THE RESTART-TO-APPLY SIGNAL for plugin routes: the paths a just-applied config
/// declares that this process CANNOT serve, because they were never registered on the axum router.
///
/// A root with fixed routers carries its boot table's paths in `App::boot_route_paths`. A root
/// preparing actual physical routers for each candidate replaces that set through
/// [`crate::appbuild::RootRules::mounted_plugin_paths`] after its completed candidate checks. Only
/// a path absent from those real mounts needs a restart, including an unopened plugin's new route
/// or a new path on the fixed admin router.
///
/// Keyed on the DELTA (`installed` minus `previous`), the same discipline
/// `handlers::reload_to_apply_fields` uses in keying on the REQUEST: only a mutation that ITSELF
/// introduces an unmountable path is flagged, so a later unrelated edit does not re-flag an
/// already-restart-pending route. Sorted, so the reported list is stable.
pub fn paths_awaiting_restart(
    installed: &PluginRouteTable,
    previous: &PluginRouteTable,
    boot_mounted: &std::collections::HashSet<String>,
) -> Vec<String> {
    let previous = previous.paths();
    // Boot-lifetime routes already belong to the process's original instance.
    let mut out: Vec<String> = installed
        .paths()
        .into_iter()
        .filter(|p| {
            !boot_mounted.contains(p) && !previous.contains(p) && !installed.persistent.contains(p)
        })
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
pub fn route_method_of(method: &Method) -> Option<RouteMethod> {
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
pub fn method_filter_of(m: RouteMethod) -> MethodFilter {
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
pub fn mount_plugin_routes(
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
    consumed: Option<axum::extract::Extension<crate::auth::ConsumedCredentials>>,
    mut headers: HeaderMap,
    body: Bytes,
) -> Response {
    // No plugin sees the credential the gate consumed for this request (#40(b)).
    crate::auth::ConsumedCredentials::strip_from(consumed.as_deref(), &mut headers);
    let Some(rm) = route_method_of(&method) else {
        return StatusCode::METHOD_NOT_ALLOWED.into_response_stub();
    };
    let path = uri.path().to_string();
    let ep_req = EndpointRequest {
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
/// header set handed to it silently is itself audit-relevant). So an over-cap or non-text header set is never
/// quietly cut: [`PLUGIN_REQUEST_HEADERS_TRUNCATED_MARKER`] is appended so the plugin can see, in-band,
/// that what it was handed is incomplete, `busbar_plugin_request_headers_truncated_total` counts the
/// occurrence, and a warning names the route. The request is still SERVED (not fail-closed) — unlike
/// [`relay_response`], the truncation here never leaves the process to an external party, and hard-
/// failing every request from a client whose own header count is high (proxies/CDNs/tracing headers are
/// legitimate over-64 producers) would be a disproportionate response to a plugin-side decision-quality
/// concern; failing closed instead lives with [`relay_response`], where the withheld data would
/// otherwise reach an external client.
fn project_request_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    let mut non_text = false;
    let mut projected: Vec<(String, String)> = headers
        .iter()
        .filter(|(name, _)| name.as_str() != "authorization")
        .filter_map(|(name, value)| match value.to_str() {
            Ok(value) => Some((name.as_str().to_string(), value.to_string())),
            Err(_) => {
                non_text = true;
                None
            }
        })
        .collect();
    if non_text || projected.len() > MAX_PLUGIN_HEADERS {
        metrics::counter!(crate::snapshot::PLUGIN_REQUEST_HEADERS_TRUNCATED_TOTAL).increment(1);
        // Per-request on a client whose header count is legitimately high (proxies/CDNs/tracing
        // headers), so an unlatched warn spams. The PLUGIN_REQUEST_HEADERS_TRUNCATED_TOTAL counter
        // above is the operator signal; log the detail at `debug!`.
        tracing::debug!(
            header_count = projected.len(),
            cap = MAX_PLUGIN_HEADERS,
            non_text,
            "inbound request headers cannot be fully projected; truncating the projection \
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

/// The response's allocation follows every HTTP data-chunk clone until its last owner retires.
struct ResponseBytes {
    bytes: Vec<u8>,
    #[cfg(test)]
    retired: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl ResponseBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            #[cfg(test)]
            retired: None,
        }
    }
}

impl AsRef<[u8]> for ResponseBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for ResponseBytes {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.as_mut_slice().zeroize();
        #[cfg(test)]
        if let Some(retired) = &self.retired {
            // Observe the live initialized range after wiping, before Vec releases it.
            retired.store(
                self.bytes.iter().all(|b| *b == 0),
                std::sync::atomic::Ordering::SeqCst,
            );
        }
    }
}

/// Relay a plugin's [`EndpointResponse`] as an axum [`Response`], dropping any header name/value
/// that is not a valid HTTP header (a plugin cannot smuggle a malformed header onto the response path).
///
/// Over-cap headers are REJECTED WHOLE (a 502, never a truncated relay): this response reaches an
/// EXTERNAL client, so the OWNER PRINCIPLE leaves no fallback here — a silently-shortened header set
/// handed to an external party is exactly the failure mode this fix closes, and unlike the request
/// direction ([`project_request_headers`]) there is no in-band marker an arbitrary external HTTP client
/// is guaranteed to understand. `busbar_plugin_response_headers_rejected_total` counts the rejection and
/// an error log names the offending plugin/route, so an operator can tell a hostile/buggy plugin from a
/// cap that needs raising.
fn relay_response(owner: &str, path: &str, resp: EndpointResponse) -> Response {
    use axum::http::{HeaderName, HeaderValue};
    // Guard before every refusal, then transfer this exact allocation to the HTTP body.
    let body = ResponseBytes::new(resp.body);
    if resp.headers.len() > MAX_PLUGIN_HEADERS {
        metrics::counter!(crate::snapshot::PLUGIN_RESPONSE_HEADERS_REJECTED_TOTAL).increment(1);
        // Fail-closed 502 is UNCHANGED. Rate-limit the log to warn-once-per-(plugin,route): a
        // buggy/hostile plugin over-caps on every response, and the PLUGIN_RESPONSE_HEADERS_REJECTED
        // counter above carries the per-request volume. Warn on the first occurrence per key; log
        // `debug!` thereafter.
        static REJECT_WARNED: std::sync::LazyLock<
            std::sync::Mutex<std::collections::HashSet<String>>,
        > = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));
        let first = {
            let mut set = REJECT_WARNED.lock().unwrap_or_else(|e| e.into_inner());
            set.insert(format!("{owner}:{path}"))
        };
        if first {
            tracing::error!(
                plugin = owner,
                route = path,
                header_count = resp.headers.len(),
                cap = MAX_PLUGIN_HEADERS,
                "plugin response exceeded the header-count cap; rejecting with 502 rather than \
                 silently relaying a truncated header set to the external client"
            );
        } else {
            tracing::debug!(
                plugin = owner,
                route = path,
                header_count = resp.headers.len(),
                cap = MAX_PLUGIN_HEADERS,
                "plugin response again exceeded the header-count cap; rejecting with 502"
            );
        }
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
        .body(Body::from(Bytes::from_owner(body)))
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
