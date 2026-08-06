// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The built-in **prometheus** exporter (PULL).
//!
//! COLLECTION stays core: the recorder + emit sites + scrape-time gauge derivation live in
//! [`crate::metrics`]. This module is the DISTRIBUTION half — it serves the well-known `/metrics`
//! route through the plugin HTTP endpoint registration ([`crate::plugin_routes`]): when
//! `export.prometheus` is configured, [`route_decl`] hands a `GET /metrics` (auth `key` — the data-plane bar, preserving today's auth-gated /metrics)
//! registration to the route table, and every scrape is dispatched to [`PrometheusExport::handle_http_with_app`],
//! which refreshes the scrape-time gauges from the LIVE `App` snapshot (resolved at
//! scrape time, never a baked-in handle, so a hot-swap never leaves `/metrics` stale) and renders the
//! recorder registry.

use crate::plugin_routes::{PluginHttpDispatch, RouteDecl, RouteKind};
use busbar_plugin_loader::{
    HttpEndpointRequest, HttpEndpointResponse, Route, RouteAuth, RouteMethod,
};
use std::sync::Arc;

/// The well-known Prometheus/OpenMetrics scrape path — the one exception to "an export sink lives
/// under `/exports/<name>/*`" ([`crate::plugin_routes::confine`]), because external tooling expects
/// `/metrics` at a fixed path.
pub(crate) const METRICS_PATH: &str = "/metrics";

/// The built-in prometheus dispatcher. Zero-sized: it holds no state — the registry it renders is the
/// process-global recorder ([`crate::metrics`]) and the scrape-time gauges are refreshed from the
/// live `App` handed to [`PrometheusExport::handle_http_with_app`] per scrape.
pub(crate) struct PrometheusExport;

impl PluginHttpDispatch for PrometheusExport {
    /// The app-less arm (never reached in production — the route table always dispatches WITH the app
    /// via `handle_http_with_app` below). Renders the registry without a fresh gauge refresh so a
    /// direct call still yields a valid exposition rather than an empty body.
    fn handle_http(&self, _req: &HttpEndpointRequest) -> HttpEndpointResponse {
        ok_exposition(crate::metrics::render())
    }

    /// The production arm: refresh the scrape-time gauges from the CURRENT `App` snapshot, then render
    /// the recorder registry. Runs on a blocking thread (the route dispatch wraps it in
    /// `spawn_blocking`), so the synchronous SQLite reads in `refresh_scrape_gauges` do not stall the
    /// async executor — the same discipline the retired `metrics::handler` had.
    fn handle_http_with_app(
        &self,
        app: &crate::state::App,
        _req: &HttpEndpointRequest,
    ) -> HttpEndpointResponse {
        crate::metrics::refresh_scrape_gauges(app);
        ok_exposition(crate::metrics::render())
    }
}

/// The `GET /metrics` registration this exporter declares, or `None` when `export.prometheus` is
/// absent (⇒ the route is never mounted, exactly as `/metrics` was unmounted when metrics were off).
/// The owner name `"prometheus"` is what a colliding third-party export plugin is named against in the
/// `--validate` collision diagnostic.
pub(crate) fn route_decl(cfg: &crate::config::ExportCfg) -> Option<RouteDecl> {
    cfg.prometheus.as_ref().map(|_| RouteDecl {
        owner: "prometheus".to_string(),
        kind: RouteKind::Export,
        route: Route {
            path: METRICS_PATH.to_string(),
            method: RouteMethod::Get,
            auth: RouteAuth::Key,
        },
        dispatch: Arc::new(PrometheusExport),
    })
}

/// The manifest-level `(owner, kind, route)` tuple for the collision preflight (`--validate` / boot),
/// mirroring [`route_decl`] WITHOUT the live dispatcher so the two cannot diverge.
pub(crate) fn route_owner(cfg: &crate::config::ExportCfg) -> Option<(String, RouteKind, Route)> {
    cfg.prometheus.as_ref().map(|_| {
        (
            "prometheus".to_string(),
            RouteKind::Export,
            Route {
                path: METRICS_PATH.to_string(),
                method: RouteMethod::Get,
                auth: RouteAuth::Key,
            },
        )
    })
}

/// A `200 OK` Prometheus text exposition with the canonical content type.
fn ok_exposition(body: String) -> HttpEndpointResponse {
    HttpEndpointResponse {
        status: 200,
        headers: vec![(
            "content-type".to_string(),
            crate::metrics::PROMETHEUS_CONTENT_TYPE.to_string(),
        )],
        body: body.into_bytes(),
    }
}

#[cfg(test)]
#[path = "tests/prometheus_tests.rs"]
mod tests;
