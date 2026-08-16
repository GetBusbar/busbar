// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE-PLUGIN SEAM — core's side of `busbar_api::plane`.
//!
//! This is the plane axis's [`crate::proto::registry::install_protocols`]: a plane crate exports a
//! `&'static PlaneDecl`, the composition root installs it, and core mounts what it declared. Core
//! reads the declaration and NOTHING ELSE — there is no `match` on a plane name in this file and
//! none above it.
//!
//! ## The direction, which is the whole point
//!
//! `busbar-plane-example` depends on `busbar-api` alone. It cannot name a `busbar-core` internal, so
//! it cannot require a widening; core depends on IT, exactly as `busbar-core` already depends on
//! `busbar-auth-admin-tokens` and calls it by name at `auth/mod.rs:951`. The decisive test —
//! could this crate be downloaded and dropped in? — is answered by its manifest.
//!
//! ## What this slice deliberately does NOT do
//!
//! Stated so its absence is not read as a claim. The config section is supplied through
//! [`install_plane_config`] (a composition-root write) rather than hydrated from `Config`: giving a
//! plane a real typed section means a type-erased section in `config/mod.rs` and its validator,
//! which is its own unit. [`CoreJournal`] is a REFUSAL, not a stub — a plane that calls it gets a
//! named error rather than a silent success, because a journal that quietly accepts and keeps
//! nothing is precisely the accept-and-do-nothing shape that hid two live security holes in the
//! store defaults. Wiring it to the audit chain is the follow-on unit.

use busbar_api::plane::{
    PlaneAuth, PlaneClock, PlaneCtx, PlaneDecl, PlaneError, PlaneJournal, PlaneMethod,
    PlaneRequest, PlaneResponse,
};
use std::sync::Arc;

/// Declarations the COMPOSITION ROOT installed. The plane axis's analogue of
/// `proto::registry`'s `INSTALLED`, with the same contract: one write, before first read.
static INSTALLED: std::sync::OnceLock<&'static [&'static PlaneDecl]> = std::sync::OnceLock::new();

/// Per-plane config section text, keyed by [`PlaneDecl::config_section`].
static SECTIONS: std::sync::OnceLock<Vec<(&'static str, Arc<str>)>> = std::sync::OnceLock::new();

/// INSTALL PLANE DECLARATIONS — the composition root's one write into the plane axis.
///
/// # Panics
/// - if called twice: two composition roots is a wiring bug, not a merge to attempt.
pub fn install_plane_plugins(decls: &'static [&'static PlaneDecl]) {
    assert!(
        INSTALLED.set(decls).is_ok(),
        "install_plane_plugins called twice: there is one composition root, and it registers once"
    );
}

/// Supply the operator's config-section text, per plane. Placeholder for the typed-section
/// hydration named in the module header; the SEAM it feeds ([`PlaneCtx::config`]) is final.
pub fn install_plane_config(sections: Vec<(&'static str, Arc<str>)>) {
    let _ = SECTIONS.set(sections);
}

/// The installed declarations, or an empty slice. **An empty slice is a supported state**: core
/// with no planes mounts no plane routes and serves the rest of its surface unchanged, which is
/// "core with no plugins compiles and runs, just does nothing" on this axis.
pub(crate) fn plane_decls() -> &'static [&'static PlaneDecl] {
    INSTALLED.get().copied().unwrap_or(&[])
}

/// A plane is ON when the operator wrote its config section. Absent section ⇒ the plane declares
/// itself and mounts nothing — the same rule `mcp:` and `a2a:` already follow.
fn section_for(decl: &PlaneDecl) -> Option<Arc<str>> {
    SECTIONS
        .get()?
        .iter()
        .find(|(name, _)| *name == decl.config_section)
        .map(|(_, text)| Arc::clone(text))
}

/// THE CLOCK, as a granted capability. The extracted dialects reach for `store::now` by module path
/// today; this is the shape that replaces it — grantable, mockable, and auditable by reading
/// [`PlaneCtx`]'s field list.
struct CoreClock;
impl PlaneClock for CoreClock {
    fn now_secs(&self) -> u64 {
        crate::store::now()
    }
}

/// The journal capability, UNWIRED IN THIS SLICE AND SAYING SO.
///
/// It refuses rather than accepting. An `Ok(())` here would be an accept-and-keep-nothing default —
/// the exact shape that let two absent security properties sit behind a green suite in the `Store`
/// contract. A plane that needs durability finds out at the first call, loudly.
struct CoreJournal;
impl PlaneJournal for CoreJournal {
    fn append(&self, _subject: &str, _payload: &str) -> Result<(), PlaneError> {
        Err(PlaneError::new(
            "unavailable",
            "plane journal is not wired to the audit chain in this build",
        ))
    }
    fn read(&self, _subject: &str, _limit: usize) -> Result<Vec<String>, PlaneError> {
        Err(PlaneError::new(
            "unavailable",
            "plane journal is not wired to the audit chain in this build",
        ))
    }
}

/// PLANE ROUTES RATIFIED AS UNAUTHENTICATED — the reviewed act, core-side.
///
/// Empty today, and its emptiness is the point. A route mounted `RouteAuth::None` answers everyone,
/// so opening one must be a deliberate decision recorded HERE, in core, where it is reviewable —
/// never a self-report a plugin makes about itself. The eventual real entry is MCP's RFC 9728
/// protected-resource metadata document, which a caller with no token must be able to read because
/// that caller is the entire population the document exists for.
const RATIFIED_PUBLIC_PLANE_ROUTES: &[&str] = &[];

/// Translate a declared [`PlaneAuth`] into the loader's route-auth vocabulary core's router already
/// enforces. One conversion, in one place: a plane's declared bar and the bar the middleware
/// applies cannot drift because there is no second statement of the mapping.
///
/// **A PLANE MAY NOT LOWER ITS OWN BAR.** `plugin_routes::confine` already refuses to let a plugin's
/// self-report place a route outside its namespace; this is the same rule on the other axis, and the
/// PoC discovered it the honest way — the example plane declared an unauthenticated route and core's
/// plane-boundary ratchet (`auth/tests/tests.rs`'s `DECLARED_PUBLIC`) failed the build. A declared
/// `None` that core has not ratified is raised to `Key`, loudly. Failing CLOSED (raising the bar)
/// rather than refusing the mount keeps a misdeclared route from silently disappearing, which would
/// be the harder failure to diagnose.
fn route_auth_of(auth: PlaneAuth, path: &str) -> busbar_plugin_loader::RouteAuth {
    match auth {
        PlaneAuth::None if RATIFIED_PUBLIC_PLANE_ROUTES.contains(&path) => {
            busbar_plugin_loader::RouteAuth::None
        }
        PlaneAuth::None => {
            tracing::warn!(
                path,
                "plane declared an unauthenticated route that core has not ratified; \
                 serving it behind the data-plane bar instead"
            );
            busbar_plugin_loader::RouteAuth::Key
        }
        PlaneAuth::Key => busbar_plugin_loader::RouteAuth::Key,
        PlaneAuth::Admin => busbar_plugin_loader::RouteAuth::Admin,
    }
}

fn route_method_of(method: PlaneMethod) -> busbar_plugin_loader::RouteMethod {
    match method {
        PlaneMethod::Get => busbar_plugin_loader::RouteMethod::Get,
        PlaneMethod::Post => busbar_plugin_loader::RouteMethod::Post,
        PlaneMethod::Put => busbar_plugin_loader::RouteMethod::Put,
        PlaneMethod::Patch => busbar_plugin_loader::RouteMethod::Patch,
        PlaneMethod::Delete => busbar_plugin_loader::RouteMethod::Delete,
    }
}

/// Build the context granted to a plane for one request.
fn ctx_for(config: Arc<str>) -> PlaneCtx {
    PlaneCtx::new(config, Arc::new(CoreClock), Arc::new(CoreJournal))
}

/// The same context the mount grants, for a test that drives a plane directly.
#[cfg(test)]
pub(crate) fn test_ctx(config: Arc<str>) -> PlaneCtx {
    ctx_for(config)
}

/// WHICH PATHS THIS PLANE MOUNTS, given the operator's section — the pure decision, extracted so
/// the test drives the REAL rule rather than a re-statement of it beside it.
///
/// [`mount_plane_routes`] reads this and nothing else, so "an unconfigured plane mounts nothing"
/// and "a streaming route is not served by the unary mount" are each stated exactly once.
pub(crate) fn mounted_paths_for(
    decl: &'static PlaneDecl,
    section: Option<Arc<str>>,
) -> Vec<&'static str> {
    // No section ⇒ the plane is off. Declared, not mounted.
    if section.is_none() || decl.handler.is_none() {
        return Vec::new();
    }
    decl.routes
        .iter()
        // A streaming route cannot be served through the unary adapter. Refusing beats buffering
        // silently: a quietly-buffered stream looks correct in a test and hangs a client in
        // production.
        .filter(|r| !r.streaming)
        .map(|r| r.path)
        .collect()
}

/// The header names forwarded to a plane. A BOUNDED ALLOWLIST, never the raw header map: core
/// already enforced the route's declared bar, so `Authorization` has done its job and must not
/// travel on. Mirrors the plugin wire's rule (`HttpEndpointRequest::headers`) so the linked and
/// loaded forms project the same request.
const FORWARDED_HEADERS: &[&str] = &["content-type", "accept", "user-agent"];

/// Convert an axum request into the plane's vocabulary. THE BOUNDARY: everything past this point is
/// `busbar-api` types, which is what lets the same handler serve the linked and the dlopen'd form.
pub(crate) async fn to_plane_request(
    method: &axum::http::Method,
    uri: &axum::http::Uri,
    headers: &axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> PlaneRequest {
    PlaneRequest {
        method: method.as_str().to_string(),
        path: uri.path().to_string(),
        query: uri.query().unwrap_or_default().to_string(),
        headers: FORWARDED_HEADERS
            .iter()
            .filter_map(|name| {
                headers
                    .get(*name)
                    .and_then(|v| v.to_str().ok())
                    .map(|v| ((*name).to_string(), v.to_string()))
            })
            .collect(),
        body: body.to_vec(),
    }
}

/// Convert the plane's answer back into an axum response, or its error into a status core chose.
/// THE FAULT TAXONOMY IS CORE'S: a plane classifies (`refused` / `invalid` / `unavailable`) and core
/// decides what the class MEANS on the wire, so a plane cannot mint its own status semantics.
pub(crate) fn to_axum_response(out: Result<PlaneResponse, PlaneError>) -> axum::response::Response {
    use axum::response::IntoResponse;
    match out {
        Ok(r) => {
            let status = axum::http::StatusCode::from_u16(r.status)
                .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
            let mut resp = (status, r.body).into_response();
            for (k, v) in r.headers {
                if let (Ok(name), Ok(value)) = (
                    axum::http::HeaderName::try_from(k.as_str()),
                    axum::http::HeaderValue::try_from(v.as_str()),
                ) {
                    resp.headers_mut().insert(name, value);
                }
            }
            resp
        }
        Err(e) => {
            let status = match e.class {
                "invalid" => axum::http::StatusCode::BAD_REQUEST,
                "refused" => axum::http::StatusCode::FORBIDDEN,
                "unavailable" => axum::http::StatusCode::SERVICE_UNAVAILABLE,
                _ => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            };
            (status, e.message).into_response()
        }
    }
}

/// MOUNT EVERY CONFIGURED PLANE'S DECLARED ROUTES onto the core router.
///
/// Core mounts exactly what each declaration lists. A plane serving a path it did not declare is
/// not a state this function can produce, which is what makes the route table a reviewable artifact.
pub(crate) fn mount_plane_routes(
    mut router: crate::core_routes::CoreRouter,
) -> crate::core_routes::CoreRouter {
    for decl in plane_decls() {
        let section = section_for(decl);
        // ONE statement of the mounting rule, read here and asserted by the tests.
        let mounted = mounted_paths_for(decl, section.clone());
        for route in decl.routes.iter().filter(|r| r.streaming) {
            tracing::error!(
                plane = decl.key,
                path = route.path,
                "plane declares a streaming route; the unary mount cannot serve it"
            );
        }
        let (Some(config), Some(handler)) = (section, decl.handler) else {
            continue;
        };
        for route in decl.routes.iter().filter(|r| mounted.contains(&r.path)) {
            let config = Arc::clone(&config);
            router = router.route(
                route.path,
                route_method_of(route.method),
                route_auth_of(route.auth, route.path),
                move |method: axum::http::Method,
                      uri: axum::http::Uri,
                      headers: axum::http::HeaderMap,
                      body: axum::body::Bytes| {
                    let config = Arc::clone(&config);
                    async move {
                        let req = to_plane_request(&method, &uri, &headers, body).await;
                        to_axum_response(handler.serve(&ctx_for(config), &req))
                    }
                },
            );
        }
    }
    router
}

#[cfg(test)]
#[path = "tests/plane_plugin_tests.rs"]
mod tests;
