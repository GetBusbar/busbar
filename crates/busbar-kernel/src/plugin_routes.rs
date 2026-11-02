// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::state::CurrentApp;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::Response;
use axum::routing::{on, MethodFilter, MethodRouter};
use busbar_contract::abi::mechanism::endpoint::*;
use busbar_contract::abi::mechanism::route::{Route, RouteAuth, RouteMethod};
use std::collections::HashMap;
use std::sync::Arc;

const MAX_PLUGIN_HEADERS: usize = 64;

const PLUGIN_REQUEST_HEADERS_TRUNCATED_MARKER: &str = "x-busbar-headers-truncated";

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

pub trait PluginHttpDispatch: Send + Sync {
    fn handle_http(&self, req: &EndpointRequest) -> EndpointResponse;

    fn handle_http_with_app(
        &self,
        _app: &Arc<crate::state::App>,
        req: &EndpointRequest,
    ) -> EndpointResponse {
        self.handle_http(req)
    }
}

pub struct RouteDecl {
    pub owner: String,

    pub source_instance: String,

    pub dispatch_available: bool,

    pub kind: RouteKind,

    pub route: Route,

    pub scrape: bool,

    pub persistent: bool,

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

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn empty() -> Self {
        Self::default()
    }

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

    pub fn paths(&self) -> std::collections::HashSet<String> {
        self.by_path.keys().cloned().collect()
    }

    pub fn declared_auth(&self, path: &str, method: &Method) -> Option<RouteAuth> {
        let rm = route_method_of(method)?;
        self.by_path
            .get(path)?
            .iter()
            .find(|(m, _)| *m == rm)
            .map(|(_, r)| r.auth)
    }

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

fn confine(kind: RouteKind, owner: &str, path: &str, scrape: bool) -> Result<(), String> {
    if path == "/api" || path.starts_with("/api/") {
        return Err(format!(
            "plugin {owner:?} cannot register {path} — the /api/* admin surface is reserved"
        ));
    }

    if reserved_exact_paths().contains(&path) {
        return Err(format!(
            "plugin {owner:?} cannot register {path} — it is a reserved core route"
        ));
    }

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

pub fn paths_awaiting_restart(
    installed: &PluginRouteTable,
    previous: &PluginRouteTable,
    boot_mounted: &std::collections::HashSet<String>,
) -> Vec<String> {
    let previous = previous.paths();

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

pub fn method_filter_of(m: RouteMethod) -> MethodFilter {
    match m {
        RouteMethod::Get => MethodFilter::GET,
        RouteMethod::Post => MethodFilter::POST,
        RouteMethod::Put => MethodFilter::PUT,
        RouteMethod::Patch => MethodFilter::PATCH,
        RouteMethod::Delete => MethodFilter::DELETE,
    }
}

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

async fn plugin_route_dispatch(
    CurrentApp(app): CurrentApp,
    method: Method,
    uri: Uri,
    consumed: Option<axum::extract::Extension<crate::auth::ConsumedCredentials>>,
    mut headers: HeaderMap,
    body: Bytes,
) -> Response {
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

    let served = tokio::task::spawn_blocking(move || {
        app.plugin_routes
            .dispatch(&path, rm, &app, &ep_req)
            .map(|(owner, resp)| relay_response(&owner, &path, resp))
    })
    .await;
    match served {
        Ok(Some(resp)) => resp,

        Ok(None) => StatusCode::NOT_FOUND.into_response_stub(),

        Err(_) => StatusCode::BAD_GATEWAY.into_response_stub(),
    }
}

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
            retired.store(
                self.bytes.iter().all(|b| *b == 0),
                std::sync::atomic::Ordering::SeqCst,
            );
        }
    }
}

fn relay_response(owner: &str, path: &str, resp: EndpointResponse) -> Response {
    use axum::http::{HeaderName, HeaderValue};

    let body = ResponseBytes::new(resp.body);
    if resp.headers.len() > MAX_PLUGIN_HEADERS {
        metrics::counter!(crate::snapshot::PLUGIN_RESPONSE_HEADERS_REJECTED_TOTAL).increment(1);

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
