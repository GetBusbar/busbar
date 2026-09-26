// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S SCRAPE — how the well-known `/metrics` is served now that the exposition is an export
//! sink's (`module: prometheus` is a row of the export axis, linked or dropped in).
//!
//! What stays the host's is what only the host can hold: the recorder every emit site writes
//! ([`crate::metrics`]), its scrape-time gauges, and the route. The SCRAPE SINK — the instance whose
//! sink carries the `metrics` stream and which subscribes to it ([`crate::config::PluginExportSettings`])
//! — is handed the recorder's SNAPSHOT (`ExportRequest::Scrape`) and the host serves the exposition
//! it renders. On every scrape, on the route's blocking thread: with the recorder installed, the
//! scrape-time gauges are refreshed from the LIVE `App` and every export-axis sink's `status` is
//! folded (the recorder then holds everything it will report); then
//! `busbar_plugin_loader::scrape::exposition` answers — the sink's rendering of the snapshot, the
//! recorder's own text when the sink cannot render, or `503` while the recorder is not installed
//! (its install runs on a background thread, and every data-plane listener accepts the moment its
//! own bind completes, so a scrape can land first).

use crate::config::ExportCfg;
use crate::plugin_routes::{PluginHttpDispatch, RouteDecl, RouteKind};
use busbar_plugin_loader::{EndpointRequest, EndpointResponse, Route, RouteAuth, RouteMethod};
use std::sync::Arc;

/// The well-known exposition path — the one export route outside `/exports/<name>/*`
/// ([`crate::plugin_routes`]'s confinement), because external tooling expects it at a fixed place.
pub(crate) const METRICS_PATH: &str = "/metrics";

/// The scrape dispatcher.
struct Scrape {
    /// The instance name of the sink that renders, looked up among the sinks opened at boot on
    /// every scrape; `None` when nothing renders but the recorder itself (a test app).
    sink: Option<String>,
}

impl Scrape {
    fn serve(&self, app: Option<&crate::state::App>) -> EndpointResponse {
        let installed = crate::metrics::recorder_installed();
        if let Some(app) = app.filter(|_| installed) {
            crate::metrics::refresh_scrape_gauges(app);
            super::plugin::status();
        }
        let sink = self.sink.as_deref().and_then(super::plugin::opened);
        let own = installed.then(crate::metrics::render);
        let own_type = crate::metrics::PROMETHEUS_CONTENT_TYPE;
        busbar_plugin_loader::scrape::exposition(sink.as_deref(), own, own_type)
    }
}

impl PluginHttpDispatch for Scrape {
    /// The app-less arm (the route table always dispatches WITH the app in production).
    fn handle_http(&self, _req: &EndpointRequest) -> EndpointResponse {
        self.serve(None)
    }

    /// The production arm, on a blocking thread (the route dispatch wraps it in `spawn_blocking`),
    /// so the synchronous reads the gauge refresh makes do not stall the executor.
    fn handle_http_with_app(
        &self,
        app: &crate::state::App,
        _req: &EndpointRequest,
    ) -> EndpointResponse {
        self.serve(Some(app))
    }
}

/// The scrape route `cfg` declares: owned by the MODULE its scrape sink's instance names (the name a
/// colliding sink is refused against), or `None` with no scrape sink (⇒ `/metrics` is never
/// mounted, as it was unmounted when metrics were off).
pub(crate) fn route_decl(cfg: &ExportCfg) -> Option<RouteDecl> {
    let sink = cfg.plugins.iter().find(|p| p.scrape)?;
    Some(decl(sink.def.module.trim(), Some(sink.name.clone())))
}

/// `GET /metrics` behind the data plane's key — the route 1.5.5 served — owned by `owner` and
/// rendered by the sink opened for the instance `sink`.
pub(crate) fn decl(owner: &str, sink: Option<String>) -> RouteDecl {
    let (path, method, auth) = (METRICS_PATH.to_string(), RouteMethod::Get, RouteAuth::Key);
    let route = Route { path, method, auth };
    let (owner, dispatch) = (owner.to_string(), Arc::new(Scrape { sink }));
    RouteDecl {
        owner,
        kind: RouteKind::Export,
        route,
        dispatch,
    }
}

#[cfg(test)]
#[path = "tests/scrape_tests.rs"]
pub(crate) mod tests;
