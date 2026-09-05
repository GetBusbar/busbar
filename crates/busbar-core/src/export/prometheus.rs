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
pub struct PrometheusExport;

impl PluginHttpDispatch for PrometheusExport {
    /// The app-less arm (never reached in production — the route table always dispatches WITH the app
    /// via `handle_http_with_app` below). Renders the registry without a fresh gauge refresh; see
    /// [`render_or_refuse`] for why an uninstalled recorder is refused rather than rendered empty.
    fn handle_http(&self, _req: &HttpEndpointRequest) -> HttpEndpointResponse {
        render_or_refuse()
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
        // Refresh (and render) ONLY once the recorder is installed — see `render_or_refuse` for why
        // an uninstalled recorder must REFUSE rather than render an empty gauge-less exposition.
        if !crate::metrics::recorder_installed() {
            return refused();
        }
        crate::metrics::refresh_scrape_gauges(app);
        ok_exposition(crate::metrics::render())
    }
}

/// Render the exposition if the recorder is installed, else REFUSE the scrape rather than answer
/// `200` with an empty body.
///
/// The route is mounted only when `export.prometheus` is configured, which is exactly the condition
/// under which `metrics::configure` requested a recorder install — so by the time this route can be
/// hit, an install was always requested. But the install itself runs on a background thread (its
/// one-time clock calibration must not delay the listener bind), and on the thread-per-core data
/// plane EVERY worker's SO_REUSEPORT listener is live and accepting the instant its own bind
/// completes — independent of whether that background install has finished. A scrape landing in
/// that boot window (or, in the rarer permanent-install-failure case, at ANY time after) must not
/// come back as a `200` with an empty body: an operator wiring up Prometheus before traffic starts
/// would reasonably read that as "the endpoint has nothing to say" rather than "not ready yet, retry".
/// Refusing makes the two states distinguishable on the wire, matching the module contract that a
/// scrape is either FULL or REFUSED, never an empty success.
fn render_or_refuse() -> HttpEndpointResponse {
    if !crate::metrics::recorder_installed() {
        return refused();
    }
    ok_exposition(crate::metrics::render())
}

/// `503 Service Unavailable` with a `Retry-After` hint: the recorder install is a one-time,
/// sub-second background step (or, far more rarely, has permanently failed — logged at install
/// time), so a short retry is the correct operator action either way. No body: there is no
/// exposition to show, and a real one is not being padded.
fn refused() -> HttpEndpointResponse {
    HttpEndpointResponse {
        status: 503,
        headers: vec![("retry-after".to_string(), "1".to_string())],
        body: Vec::new(),
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
