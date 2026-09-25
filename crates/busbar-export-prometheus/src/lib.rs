// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROMETHEUS EXPORT SINK — `export.<name>.module: prometheus`.
//!
//! A PULL sink over the COLD export ABI. The host keeps what only the host can own: the recorder
//! every emit site writes, its scrape-time gauges, and the well-known `/metrics` route's dispatch.
//! This sink owns what an exposition IS: it declares the `metrics` stream and the `GET /metrics`
//! route, it validates the settings an operator writes for it, and on every scrape the host hands it
//! the recorder's snapshot (`ExportRequest::Scrape`, export ABI minor 6) and serves the text it
//! renders back.
//!
//! One crate, two doors (DECISIONS #2 rule (1)): the `rlib` is linked into the shipped binary
//! through the composition root's linked tables ([`linked::EXPORT`]), the `cdylib` can be packed
//! into a signed tarball and dropped into `plugins/`. Both are registered by the one admission and
//! loaded by the one load over [`BUSBAR_COLD_ENTRY`] or the library's symbols — the same functions.

use busbar_plugin_sdk::{
    render_exposition, ExportHandler, ExportStream, MetricFamily, Route, RouteAuth, RouteMethod,
    TEXT_EXPOSITION,
};

/// The module name an `export:` instance names this sink by — its name and its alias on either
/// door, as 1.5.5 spelled the built-in.
pub const NAME: &str = "prometheus";

/// The well-known scrape path external tooling expects at a fixed place.
pub const SCRAPE_PATH: &str = "/metrics";

/// The `settings:` an operator writes for this sink — the same shape, field for field, the
/// configuration grammar has frozen for it since 1.5.3, so a refusal reads exactly as it always has.
/// The VALUES are the host's to act on (the recorder's retention window, the scrape-time gauge
/// bound); this sink only says whether they are well formed.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PrometheusSettings {
    /// REQUIRED: the retention window of the rolling quantile summary, in seconds.
    #[allow(dead_code)]
    buffer_seconds: u64,
    /// The bound on per-key scrape-time gauges.
    #[serde(default)]
    #[allow(dead_code)]
    key_gauge_limit: usize,
}

/// The sink. It holds nothing: every scrape carries the whole snapshot it renders.
struct Prometheus;

impl ExportHandler for Prometheus {
    /// `metrics` — the one stream the host PULLS rather than pushes.
    fn streams(&self) -> Vec<ExportStream> {
        vec![ExportStream::Metrics]
    }

    /// `GET /metrics`, behind the data plane's key — the route 1.5.5 served there.
    fn routes(&self) -> Vec<Route> {
        vec![Route {
            path: SCRAPE_PATH.to_string(),
            method: RouteMethod::Get,
            auth: RouteAuth::Key,
        }]
    }

    /// The settings refusal, as one complete line: `export.<instance>.settings: <why>`.
    fn validate(&self, instance: &str, settings: &serde_json::Value) -> Vec<String> {
        match serde_json::from_value::<PrometheusSettings>(settings.clone()) {
            Ok(_) => Vec::new(),
            Err(e) => vec![format!("export.{instance}.settings: {e}")],
        }
    }

    /// The Prometheus text exposition of the snapshot: `# HELP`, `# TYPE`, the samples and the
    /// family-closing blank line, every label value and number exactly as the recorder wrote it.
    fn render(&self, families: &[MetricFamily]) -> (String, String) {
        (TEXT_EXPOSITION.to_string(), render_exposition(families))
    }
}

/// Open the sink. The settings are the host's to act on and were validated while the host
/// validated its configuration, so the open reads none of them and cannot fail on them.
pub fn open(_cfg: &str) -> Result<Box<dyn ExportHandler>, String> {
    Ok(Box::new(Prometheus))
}

busbar_plugin_sdk::export_export_plugin!(open);

/// THE LINKED DOOR's entry — what the composition root's linked tables name for this crate.
pub mod linked {
    /// The module name, and the boundary a linked build hands the loader in place of a library.
    pub const EXPORT: (&str, &busbar_plugin_sdk::ColdEntry) =
        (super::NAME, &super::BUSBAR_COLD_ENTRY);
}

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
