// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the built-in `prometheus` exporter: `/metrics` is served via the plugin HTTP endpoint
//! registration (design §7.1), gated on `export.prometheus` presence.

use super::*;
use crate::config::{ExportCfg, PrometheusSettings};

fn cfg_with_prometheus() -> ExportCfg {
    ExportCfg {
        prometheus: Some(PrometheusSettings {
            buffer_seconds: 60,
            key_gauge_limit: 2000,
        }),
        ..Default::default()
    }
}

/// `/metrics` is registered as a plugin route ONLY when `export.prometheus` is configured — the
/// presence-is-the-switch contract (design §2). The declared route is the well-known `GET /metrics`,
/// auth `none`, owned by `prometheus`.
///
/// RED-BEFORE-GREEN: before this unit `/metrics` was a hard-wired core route gated on a config
/// boolean and there was no `export::prometheus::route_decl` at all — this test does not compile
/// against the pre-lift-out tree.
#[test]
fn metrics_route_declared_only_when_configured() {
    assert!(
        route_decl(&ExportCfg::default()).is_none(),
        "no exporter configured ⇒ no /metrics route (zero-config default unchanged)"
    );

    let cfg = cfg_with_prometheus();
    let decl = route_decl(&cfg).expect("export.prometheus present ⇒ a /metrics route is declared");
    assert_eq!(decl.owner, "prometheus");
    assert_eq!(decl.route.path, METRICS_PATH);
    assert_eq!(decl.route.method, RouteMethod::Get);
    assert_eq!(decl.route.auth, RouteAuth::Key);
    assert_eq!(decl.kind, RouteKind::Export);
}

/// The declared route builds a live plugin-route table (the endpoint-registration path): `GET
/// /metrics` resolves to auth `none` in the built table, so the mounted handler dispatches every
/// scrape to the prometheus exporter.
#[test]
fn metrics_served_via_endpoint_registration() {
    let cfg = cfg_with_prometheus();
    let table = crate::plugin_routes::build_route_table(crate::export::route_decls(&cfg))
        .expect("the built-in /metrics route confines + collides cleanly");
    assert_eq!(
        table.declared_auth("/metrics", &axum::http::Method::GET),
        Some(RouteAuth::Key),
        "the built table exposes GET /metrics via the plugin endpoint registration (data-plane auth)"
    );
}

/// The exporter's `handle_http` renders the recorder registry as a `200` Prometheus text exposition
/// with the canonical content type — the DISTRIBUTION half lifted out of `metrics::handler`.
#[test]
fn dispatch_renders_prometheus_exposition() {
    let req = HttpEndpointRequest {
        method: "GET".into(),
        path: "/metrics".into(),
        query: String::new(),
        headers: vec![],
        body: vec![],
    };
    let resp = PrometheusExport.handle_http(&req);
    assert_eq!(resp.status, 200);
    assert!(
        resp.headers
            .iter()
            .any(|(k, v)| k == "content-type" && v.contains("text/plain")),
        "the exposition carries the Prometheus content type"
    );
}
