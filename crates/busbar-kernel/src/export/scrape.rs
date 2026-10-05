// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S SCRAPE — how the well-known `/metrics` is served: the exposition is an export
//! plugin's, a row of the export axis, linked or dropped in.
//!
//! What stays the host's is what only the host can hold: the recorder every emit site writes
//! ([`crate::snapshot`]), its scrape-time gauges, and the route. The SCRAPE SINK — the instance whose
//! sink carries the `metrics` stream and which subscribes to it ([`crate::config::PluginExportSettings`])
//! — is handed the recorder's SNAPSHOT ([`crate::snapshot::snapshot`]) and the host serves the
//! exposition it renders; the kernel renders none of its own. On every scrape, on the route's
//! blocking thread: with the recorder installed, the scrape-time gauges are refreshed from the LIVE
//! `App` and every export-axis sink's `status` is folded (the recorder then holds everything it will
//! report); then [`exposition`] answers — the sink's rendering, `502` when no sink renders, or `503`
//! while the recorder is not installed
//! (its install runs on a background thread, and every data-plane listener accepts the moment its
//! own bind completes, so a scrape can land first).

// D4 STAGED (TODO step 26): this route, and the content type below, leave the kernel for the scrape
// sink's own inbound listener need once boot serves a plugin's inbound need (THE DESIGN §3 "Inbound
// listeners"; QUESTIONS Q133).

use crate::config::ExportCfg;
use crate::plugin_routes::{PluginHttpDispatch, RouteDecl, RouteKind};
use busbar_contract::abi::cold::endpoint::*;
use busbar_contract::abi::mechanism::route::{Route, RouteAuth, RouteMethod};
use busbar_contract::export_calls::ExportCalls;
use std::sync::Arc;

/// The well-known exposition path — the one export route outside `/exports/<name>/*`
/// ([`crate::plugin_routes`]'s confinement), because external tooling expects it at a fixed place.
pub(crate) const METRICS_PATH: &str = "/metrics";

/// Which sink renders, asked on every scrape.
pub(crate) type SinkOf = Box<dyn Fn() -> Option<Arc<dyn ExportCalls>> + Send + Sync>;

/// The scrape dispatcher.
struct Scrape {
    /// The sink that renders: in production the one opened at boot for the scrape sink's instance;
    /// `None` = no sink renders (every scrape is a `502`).
    sink: SinkOf,
}

impl Scrape {
    fn serve(&self, app: Option<&crate::state::App>) -> EndpointResponse {
        let installed = crate::snapshot::recorder_installed();
        if let Some(app) = app.filter(|_| installed) {
            crate::snapshot::refresh_scrape_gauges(app);
            super::plugin::status();
        }
        exposition((self.sink)().as_deref(), crate::snapshot::snapshot())
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

/// The exposition's content type, 1.5.5's bytes.
pub(crate) const CONTENT_TYPE: &str = "text/plain; version=0.0.4";

/// THE HOST'S SCRAPE ANSWER (K9d): the recorder's `families` rendered by `sink` through the export
/// kind's `scrape`, served `200` as [`CONTENT_TYPE`]. No `families` (the recorder is not installed
/// yet, or its install failed) is REFUSED — `503`, `Retry-After: 1` — never answered `200` with
/// nothing: "not ready, retry" and "nothing to say" must be distinguishable on the wire. No sink, or
/// one that does not render, is a `502` with no body and a warning to the operator, as a plugin
/// route that cannot answer is: the host has no exposition of its own to fall back to.
pub(crate) fn exposition(
    sink: Option<&dyn ExportCalls>,
    families: Option<Vec<busbar_contract::export_calls::Family>>,
) -> EndpointResponse {
    let Some(families) = families else {
        let headers = vec![("retry-after".to_string(), "1".to_string())];
        return EndpointResponse {
            status: 503,
            headers,
            body: Vec::new(),
        };
    };
    let rendered = sink
        .ok_or_else(|| "no scrape sink is open".to_string())
        .and_then(|sink| sink.scrape(&families));
    match rendered {
        Ok(body) => EndpointResponse {
            status: 200,
            headers: vec![("content-type".to_string(), CONTENT_TYPE.to_string())],
            body,
        },
        Err(e) => {
            tracing::warn!(error = %e, "the scrape sink did not render");
            EndpointResponse {
                status: 502,
                headers: Vec::new(),
                body: Vec::new(),
            }
        }
    }
}

/// `/metrics/hooks`' content type, 1.5.5's bytes (its own: the hook exposition carried a charset).
pub(crate) const HOOKS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// `GET /metrics/hooks` — the hook-reported metrics, folded by the snapshot service
/// ([`crate::snapshot::hooks::families`]) and RENDERED BY THE SCRAPE SINK through the export kind's
/// `scrape` with `SCRAPE_FLAG_HOOK_FAMILIES` (P2 D4, ARCHITECT Q-D4-HOOKS 2026-10-04: `/metrics/hooks`
/// leaves core; the kernel writes no exposition). Governed by the auth chain exactly like `/metrics`
/// (both carry operational topology). Stale-while-revalidate: the fold reads the cache now and
/// refreshes stale hooks in the background; it never blocks on a hook. With no sink, or one that
/// does not render, a `502` with no body and a warning, as `/metrics` answers.
pub(crate) async fn hooks_handler(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let families = crate::snapshot::hooks::families(&app);
    let rendered = super::plugin::scrape_sink()
        .ok_or_else(|| "no scrape sink is open".to_string())
        .and_then(|sink| sink.scrape_hooks(&families));
    match rendered {
        Ok(body) => (
            axum::http::StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, HOOKS_CONTENT_TYPE)],
            String::from_utf8_lossy(&body).into_owned(),
        )
            .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "the scrape sink did not render the hook families");
            axum::http::StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// The scrape route `cfg` declares: owned by the MODULE its scrape sink's instance names (the name a
/// colliding sink is refused against), or `None` with no scrape sink (⇒ `/metrics` is never
/// mounted, as it was unmounted when metrics were off).
pub(crate) fn route_decl(cfg: &ExportCfg) -> Option<RouteDecl> {
    let sink = cfg.plugins.iter().find(|p| p.scrape)?;
    let name = sink.name.clone();
    let sink_of: SinkOf = Box::new(move || super::plugin::opened(&name));
    Some(decl(sink.def.module.trim(), sink_of))
}

/// `GET /metrics` behind the data plane's key — the route 1.5.5 served — owned by `owner` and
/// rendered by the sink `sink` answers with.
pub(crate) fn decl(owner: &str, sink: SinkOf) -> RouteDecl {
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
