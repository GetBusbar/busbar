// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for plugin HTTP endpoint registration (design §5): collision detection, namespace
//! confinement, end-to-end dispatch to `handle_http`, scrape-time (live-snapshot) resolution, and the
//! auth:admin route's confinement to the admin listener.

use super::*;
use axum::Router;
use busbar_plugin_loader::{
    HttpEndpointRequest, HttpEndpointResponse, Route, RouteAuth, RouteMethod,
};
use std::sync::Arc;

/// A fake plugin dispatcher that echoes its label + the request line, so a test can prove WHICH plugin
/// served a request (the scrape-time-resolution proof) and that `handle_http` ran end-to-end.
struct FakeDispatch {
    label: &'static str,
}
impl PluginHttpDispatch for FakeDispatch {
    fn handle_http(&self, req: &HttpEndpointRequest) -> HttpEndpointResponse {
        HttpEndpointResponse {
            status: 200,
            headers: vec![("x-served-by".into(), self.label.into())],
            body: format!("{} {} {}", self.label, req.method, req.path).into_bytes(),
        }
    }
}

/// Expect a build to FAIL with a collision/confinement error and return the message. A match rather
/// than `unwrap_err` because `PluginRouteTable` is not `Debug` (its dispatchers are trait objects) —
/// and this makes the RED case a clean assertion failure ("expected an Err"), not a compile error.
fn expect_err(r: Result<PluginRouteTable, String>) -> String {
    match r {
        Err(e) => e,
        Ok(_) => panic!("expected the registration to be REFUSED, but it succeeded"),
    }
}

fn decl(
    owner: &str,
    kind: RouteKind,
    path: &str,
    method: RouteMethod,
    auth: RouteAuth,
    label: &'static str,
) -> RouteDecl {
    RouteDecl {
        owner: owner.to_string(),
        kind,
        route: Route {
            path: path.to_string(),
            method,
            auth,
        },
        dispatch: Arc::new(FakeDispatch { label }),
    }
}

// ── Collision detection (§5.3, §5.5): deterministic first-to-claim, LOUD failure ────────────────────

/// Two plugins claiming the SAME {path, method} is a LOUD collision naming the OWNING (first) plugin,
/// never last-writer-wins — with the exact message shape the design specifies. Deterministic scan
/// order = declaration order, so `prometheus` (first) owns `GET /metrics` and `datadog` (second) is the
/// one refused.
///
/// RED-BEFORE-GREEN: this asserts the EXACT loud message; with `build_route_table` doing
/// last-writer-wins (no collision arm) the second claim would silently overwrite the first and this
/// test fails (no `Err`) — proven by removing the collision arm before wiring it.
#[test]
fn collision_is_a_loud_failure_naming_the_owner() {
    let decls = vec![
        decl(
            "prometheus",
            RouteKind::Export,
            "/metrics",
            RouteMethod::Get,
            RouteAuth::None,
            "prom",
        ),
        decl(
            "datadog",
            RouteKind::Export,
            "/metrics",
            RouteMethod::Get,
            RouteAuth::None,
            "dd",
        ),
    ];
    let err = expect_err(build_route_table(decls));
    assert_eq!(
        err,
        "plugin \"datadog\" cannot register GET /metrics — already registered by \"prometheus\""
    );

    // The manifest-only preflight (§5.5) uses the IDENTICAL logic + message, so `--validate` and boot
    // catch the same collision the live table would.
    let preflight = preflight_route_collisions(&[
        (
            "prometheus".to_string(),
            RouteKind::Export,
            Route {
                path: "/metrics".into(),
                method: RouteMethod::Get,
                auth: RouteAuth::None,
            },
        ),
        (
            "datadog".to_string(),
            RouteKind::Export,
            Route {
                path: "/metrics".into(),
                method: RouteMethod::Get,
                auth: RouteAuth::None,
            },
        ),
    ])
    .unwrap_err();
    assert_eq!(
        preflight,
        "plugin \"datadog\" cannot register GET /metrics — already registered by \"prometheus\""
    );
}

/// The SAME path with DIFFERENT methods is NOT a collision — the collision key is `{path, method}`.
#[test]
fn same_path_different_method_is_not_a_collision() {
    let decls = vec![
        decl(
            "sr",
            RouteKind::Hook,
            "/hooks/sr/feedback",
            RouteMethod::Get,
            RouteAuth::Key,
            "g",
        ),
        decl(
            "sr",
            RouteKind::Hook,
            "/hooks/sr/feedback",
            RouteMethod::Post,
            RouteAuth::Key,
            "p",
        ),
    ];
    assert!(build_route_table(decls).is_ok());
}

// ── Namespace confinement (§5.2) ─────────────────────────────────────────────────────────────────

/// A hook's routes are confined under `/hooks/<name>/*`; anything outside — a bid to shadow the admin
/// surface, the well-known `/metrics`, or a bare top-level path — is REJECTED by the registrar (the
/// plugin's self-report is never trusted to place a route outside its namespace).
#[test]
fn confinement_rejects_hook_out_of_namespace() {
    // In-namespace: accepted.
    assert!(build_route_table(vec![decl(
        "sr",
        RouteKind::Hook,
        "/hooks/sr/feedback",
        RouteMethod::Post,
        RouteAuth::Key,
        "ok",
    )])
    .is_ok());

    // Shadowing the admin surface: rejected.
    assert!(expect_err(build_route_table(vec![decl(
        "sr",
        RouteKind::Hook,
        "/api/v1/admin/keys",
        RouteMethod::Get,
        RouteAuth::Admin,
        "x",
    )]))
    .contains("/api/* admin surface is reserved"));

    // Claiming the well-known /metrics (an EXPORT-only exception): rejected for a hook.
    assert!(expect_err(build_route_table(vec![decl(
        "sr",
        RouteKind::Hook,
        "/metrics",
        RouteMethod::Get,
        RouteAuth::None,
        "x",
    )]))
    .contains("/hooks/sr/*"));

    // A bare top-level path outside the hook's namespace: rejected.
    assert!(expect_err(build_route_table(vec![decl(
        "sr",
        RouteKind::Hook,
        "/feedback",
        RouteMethod::Post,
        RouteAuth::Key,
        "x",
    )]))
    .contains("/hooks/sr/*"));
}

/// An export sink may claim the well-known `/metrics` but is otherwise confined to `/exports/<name>/*`;
/// a reserved core route (`/stats`, `/v1/models`, …) is refused to every kind.
#[test]
fn confinement_export_metrics_exception_and_reserved_routes() {
    // The well-known /metrics: accepted for an export sink.
    assert!(build_route_table(vec![decl(
        "prometheus",
        RouteKind::Export,
        "/metrics",
        RouteMethod::Get,
        RouteAuth::None,
        "ok",
    )])
    .is_ok());

    // Its own namespace: accepted.
    assert!(build_route_table(vec![decl(
        "datadog",
        RouteKind::Export,
        "/exports/datadog/push",
        RouteMethod::Post,
        RouteAuth::Key,
        "ok",
    )])
    .is_ok());

    // A reserved core route: refused even for an export sink.
    assert!(expect_err(build_route_table(vec![decl(
        "prometheus",
        RouteKind::Export,
        "/stats",
        RouteMethod::Get,
        RouteAuth::None,
        "x",
    )]))
    .contains("reserved core route"));

    // Out of the export namespace and not the /metrics exception: refused.
    assert!(expect_err(build_route_table(vec![decl(
        "datadog",
        RouteKind::Export,
        "/anywhere",
        RouteMethod::Get,
        RouteAuth::None,
        "x",
    )]))
    .contains("/exports/datadog/*"));
}

// ── End-to-end dispatch + scrape-time (live-snapshot) resolution (§5.4, §7.1) ────────────────────────

fn app_with_table(table: Arc<PluginRouteTable>) -> Arc<crate::state::App> {
    use crate::test_support::{LaneSpec, TestApp};
    let base = TestApp::new()
        .lane(LaneSpec::new(
            "m",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:1",
        ))
        .pool("pa", &[(0, 1)])
        .build();
    let mut app = (*base).clone();
    app.plugin_routes = table;
    Arc::new(app)
}

async fn get(router: Router, path: &str) -> (u16, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}{path}"))
        .send()
        .await
        .unwrap();
    let code = resp.status().as_u16();
    let body = resp.text().await.unwrap();
    server.abort();
    (code, body)
}

/// END-TO-END: a registered `none`-auth data-plane route dispatches to the plugin's `handle_http` and
/// relays its response verbatim; and after a hot-swap of the App snapshot to a DIFFERENT owner of the
/// SAME path, the SAME server resolves the NEW plugin (scrape-time resolution, §7.1 — no stale handle
/// baked into the route closure).
#[tokio::test]
async fn route_dispatches_to_handle_http_and_resolves_live_after_swap() {
    // An export-namespace path (not the built-in `/metrics`, which the process-wide metrics recorder
    // may already own in a shared test binary) — the dispatch + live-resolution mechanism is the same.
    const P: &str = "/exports/prometheus/scrape";
    // Snapshot A: the route owned by "prom".
    let table_a = Arc::new(
        build_route_table(vec![decl(
            "prometheus",
            RouteKind::Export,
            P,
            RouteMethod::Get,
            RouteAuth::None,
            "prom",
        )])
        .unwrap(),
    );
    let app_a = app_with_table(table_a);
    let (data_router, _admin_router, handle) = crate::build_split_routers_with_limits(
        app_a,
        crate::limits::translate_body_max_bytes(),
        crate::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        crate::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    );

    let (code, body) = get(data_router.clone(), P).await;
    assert_eq!(
        code, 200,
        "the none-auth plugin route dispatches (no token)"
    );
    assert_eq!(
        body,
        format!("prom GET {P}"),
        "handle_http response relayed verbatim"
    );

    // Hot-swap the live snapshot to snapshot B: the SAME path now owned by "next".
    let table_b = Arc::new(
        build_route_table(vec![decl(
            "prometheus",
            RouteKind::Export,
            P,
            RouteMethod::Get,
            RouteAuth::None,
            "next",
        )])
        .unwrap(),
    );
    handle.swap(app_with_table(table_b));

    let (code, body) = get(data_router, P).await;
    assert_eq!(code, 200);
    assert_eq!(
        body,
        format!("next GET {P}"),
        "the SAME server resolved the NEW plugin from the live snapshot — no stale route"
    );
}

// ── auth:admin confinement to the admin listener (§5.4) ──────────────────────────────────────────

/// Plane classification (feature-independent): an `auth: admin` plugin route is mounted ONLY on the
/// admin plane, never the data plane — the mount-level half of "confined to the admin listener".
#[test]
fn admin_auth_route_is_classified_to_the_admin_plane_only() {
    let table = build_route_table(vec![decl(
        "audit-sink",
        RouteKind::Export,
        "/exports/audit-sink/admin-op",
        RouteMethod::Get,
        RouteAuth::Admin,
        "audit",
    )])
    .unwrap();
    assert!(
        table.mounts_for_plane(false).is_empty(),
        "an auth:admin route is absent from the data plane"
    );
    assert_eq!(
        table.mounts_for_plane(true).len(),
        1,
        "an auth:admin route is on the admin plane"
    );
}

/// An `auth: admin` plugin route is physically ABSENT from the data listener — even WITH a valid admin
/// token it is a hard 404 there (route not mounted), exactly like `/api/v1/admin/*`; on the admin
/// listener it is served (dispatched to the plugin). Mirrors `split_admin_listener_no_double_exposure`.
#[cfg(feature = "auth-admin-tokens")]
#[tokio::test]
async fn admin_auth_route_is_absent_from_the_data_listener() {
    use crate::governance::{GovState, MemoryStore};
    use crate::test_support::{LaneSpec, TestApp};
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let base = TestApp::new()
        .lane(LaneSpec::new(
            "m",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:1",
        ))
        .pool("pa", &[(0, 1)])
        .governance(gov)
        .build();
    let table = Arc::new(
        build_route_table(vec![decl(
            "audit-sink",
            RouteKind::Export,
            "/exports/audit-sink/admin-op",
            RouteMethod::Get,
            RouteAuth::Admin,
            "audit",
        )])
        .unwrap(),
    );
    let mut app = (*base).clone();
    app.plugin_routes = table;
    let (data_router, admin_router, _handle) = crate::build_split_routers_with_limits(
        Arc::new(app),
        crate::limits::translate_body_max_bytes(),
        crate::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        crate::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    );

    async fn get_tok(router: Router, path: &str, token: &str) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let code = reqwest::Client::new()
            .get(format!("http://{addr}{path}"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16();
        server.abort();
        code
    }

    // DATA listener: absent — a valid admin token still 404s (route not mounted), not merely blocked.
    assert_eq!(
        get_tok(data_router, "/exports/audit-sink/admin-op", "admintok").await,
        404,
        "an auth:admin plugin route must be physically absent from the data listener"
    );
    // ADMIN listener: served (admin chain passes with the token, then the plugin dispatch runs → 200).
    assert_eq!(
        get_tok(admin_router, "/exports/audit-sink/admin-op", "admintok").await,
        200,
        "the admin listener serves the auth:admin plugin route"
    );
}

// ── HEAD on a declared GET route (the logged LOW) ────────────────────────────────────────────────

/// A HEAD request to a route a plugin declared as GET must be treated as that GET route by BOTH
/// halves of the seam — the auth middleware's [`PluginRouteTable::declared_auth`] lookup AND the
/// dispatcher's method mapping. axum already routes HEAD to the GET handler (its `MethodRouter`
/// falls back to the GET arm and strips the body), so a HEAD reaches `plugin_route_dispatch`; with
/// no HEAD arm in `route_method_of` the two halves DISAGREE:
///
/// * `declared_auth(path, HEAD)` returns `None`, so the route's DECLARED bar is not applied — an
///   `auth: none` route demands a token on HEAD, and an `auth: admin` route is not forced down the
///   admin chain (it is only saved from being reachable by the SECOND half of the same bug);
/// * the dispatcher then 405s a request axum had already routed to the plugin's GET handler.
///
/// Mapping `Method::HEAD` onto `RouteMethod::Get` fixes both halves together, which is the only safe
/// way to fix either: closing just the dispatch half would leave the auth half open.
#[test]
fn head_is_looked_up_as_the_declared_get_route() {
    let table = build_route_table(vec![decl(
        "prometheus",
        RouteKind::Export,
        "/exports/prometheus/scrape",
        RouteMethod::Get,
        RouteAuth::None,
        "prom",
    )])
    .unwrap();
    assert_eq!(
        table.declared_auth("/exports/prometheus/scrape", &axum::http::Method::HEAD),
        Some(RouteAuth::None),
        "a HEAD to a declared GET plugin route must resolve to that route's declared auth"
    );
    assert_eq!(
        route_method_of(&axum::http::Method::HEAD),
        Some(RouteMethod::Get),
        "HEAD maps onto the declared GET route (axum already routes HEAD to the GET handler)"
    );
    // Methods no plugin route can declare stay unmapped (the 405 arm is still reachable).
    assert_eq!(route_method_of(&axum::http::Method::OPTIONS), None);
    assert_eq!(route_method_of(&axum::http::Method::TRACE), None);
}

/// END-TO-END: a HEAD to an `auth: none` plugin route declared as GET is SERVED (200, empty body —
/// axum strips a HEAD response body), not rejected with 405. The GET arm of the same route is
/// unchanged.
#[tokio::test]
async fn head_dispatches_to_the_declared_get_route() {
    const P: &str = "/exports/prometheus/scrape";
    let table = Arc::new(
        build_route_table(vec![decl(
            "prometheus",
            RouteKind::Export,
            P,
            RouteMethod::Get,
            RouteAuth::None,
            "prom",
        )])
        .unwrap(),
    );
    let (data_router, _admin_router, _handle) = crate::build_split_routers_with_limits(
        app_with_table(table),
        crate::limits::translate_body_max_bytes(),
        crate::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        crate::config::DEFAULT_RESPONSE_HEADERS_SERVER_TIMING,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, data_router).await.unwrap() });
    let resp = reqwest::Client::new()
        .head(format!("http://{addr}{P}"))
        .send()
        .await
        .unwrap();
    let code = resp.status().as_u16();
    let served_by = resp
        .headers()
        .get("x-served-by")
        .map(|v| v.to_str().unwrap().to_string());
    server.abort();
    assert_eq!(
        code, 200,
        "HEAD on a declared GET plugin route is served, not 405'd"
    );
    assert_eq!(
        served_by.as_deref(),
        Some("prom"),
        "the owning plugin served the HEAD"
    );
}

// ── The RESTART-TO-APPLY signal (audit finding E1) ──────────────────────────────────────────────────

/// [`paths_awaiting_restart`] names exactly the paths a config apply cannot make servable, in every
/// direction the `export:` admin surface can move.
///
/// The asymmetry it encodes: the axum router registers each declared path ONCE, at boot, and an apply
/// swaps only `Arc<App>`. So an ADDED path that was not mounted at boot is unservable until a restart,
/// while a REMOVED one is genuinely live (the dispatcher resolves the owner per request and 404s), and
/// re-adding a path that WAS mounted at boot needs nothing — the mount never went away.
#[test]
fn paths_awaiting_restart_flags_only_newly_declared_unmounted_paths() {
    fn table(paths: &[&str]) -> PluginRouteTable {
        build_route_table(
            paths
                .iter()
                .map(|p| {
                    decl(
                        "prometheus",
                        RouteKind::Export,
                        p,
                        RouteMethod::Get,
                        RouteAuth::Key,
                        "x",
                    )
                })
                .collect(),
        )
        .expect("the fixture declares no colliding route")
    }
    fn boot(paths: &[&str]) -> std::collections::HashSet<String> {
        paths.iter().map(|p| p.to_string()).collect()
    }
    let empty = table(&[]);
    let metrics = table(&["/metrics"]);

    // ADDED, never mounted at boot ⇒ flagged. THE FINDING.
    assert_eq!(
        paths_awaiting_restart(&metrics, &empty, &boot(&[])),
        vec!["/metrics".to_string()],
    );
    // ADDED, but the boot router already has the mount (configured at boot, removed live, re-added)
    // ⇒ nothing to say.
    assert!(paths_awaiting_restart(&metrics, &empty, &boot(&["/metrics"])).is_empty());
    // REMOVED ⇒ live, nothing to say.
    assert!(paths_awaiting_restart(&empty, &metrics, &boot(&["/metrics"])).is_empty());
    // UNCHANGED (an edit touching no route) ⇒ nothing to say, even while `/metrics` is itself still
    // pending a restart from an EARLIER mutation: the signal is keyed on THIS delta, so an unrelated
    // later edit does not re-flag it.
    assert!(paths_awaiting_restart(&metrics, &metrics, &boot(&[])).is_empty());
}
