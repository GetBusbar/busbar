// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROMETHEUS EXPORT SINK — `export.<name>.module: prometheus`.
//!
//! A PULL sink over the COLD export ABI. The host keeps what only the host can own: the recorder
//! every emit site writes, its scrape-time gauges, and the well-known `/metrics` route it serves.
//! This sink owns what an exposition IS: it carries the `metrics` stream (the instance subscribed
//! to it is the one the host's scrape asks to render), it validates the settings an operator writes
//! for it, and on every scrape the host hands it the recorder's snapshot (`ExportRequest::Scrape`,
//! export ABI minor 6) and serves the text it renders back.
//!
//! One crate, two doors (DECISIONS #2 rule (1)): the `rlib` is linked into the shipped binary
//! through the composition root's linked tables ([`linked::EXPORT`]), the `cdylib` can be packed
//! into a signed tarball and dropped into `plugins/`. Both are registered by the one admission and
//! loaded by the one load over [`BUSBAR_COLD_ENTRY`] or the library's symbols — the same functions.

#![deny(unsafe_code)]

use busbar_plugin_sdk::{
    render_exposition, ExportHandler, ExportStream, MetricFamily, TEXT_EXPOSITION,
};

/// The row's canonical name.
pub const NAME: &str = "busbar-export-prometheus";

/// The `module:` an operator writes — the name 1.5.5 spelled the built-in by — the row's alias on
/// either door.
pub const ALIAS: &str = "prometheus";

/// What this sink DECLARES to the host (the manifest's `declares` section): nothing — it reports
/// no series and raises no code of its own, and it has no destination.
pub const DECLARES: &str = "{}";

/// The `settings:` an operator writes for this sink — the same shape, field for field, the
/// configuration grammar has frozen for it since 1.5.3, so a refusal reads exactly as it always has.
/// The VALUES are the host's to act on (the recorder's retention window, the scrape-time gauge
/// bound); this sink only says whether they are well formed.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PrometheusSettings {
    /// REQUIRED: the retention window of the rolling quantile summary, in seconds — positive.
    buffer_seconds: u64,
    /// The bound on per-key scrape-time gauges.
    #[serde(default)]
    #[allow(dead_code)]
    key_gauge_limit: usize,
}

/// The zero-retention refusal, word for word as the configuration has always reported it.
const ZERO_RETENTION: &str =
    "the `module: prometheus` export instance sets settings.buffer_seconds: 0, \
     which retains no observations — every scrape would report empty quantiles while still paying \
     the recording cost. Name a positive retention window in seconds, or remove the instance to \
     turn metrics off";

/// The sink. It holds nothing: every scrape carries the whole snapshot it renders.
struct Prometheus;

impl ExportHandler for Prometheus {
    /// `metrics` — the one stream the host PULLS rather than pushes.
    fn streams(&self) -> Vec<ExportStream> {
        vec![ExportStream::Metrics]
    }

    /// The settings refusal, as one complete line in the configuration's own words: a malformed
    /// bag is `export.<instance>.settings: <why>`; a zero retention window asks the recorder to keep
    /// nothing while still paying to record it, which is refused rather than served inert (omitting
    /// the instance is how collection is turned off).
    fn validate(&self, instance: &str, settings: &serde_json::Value) -> Vec<String> {
        match serde_json::from_value::<PrometheusSettings>(settings.clone()) {
            Err(e) => vec![format!("export.{instance}.settings: {e}")],
            Ok(s) if s.buffer_seconds == 0 => vec![ZERO_RETENTION.to_string()],
            Ok(_) => Vec::new(),
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
    /// `(name, alias, declares, boundary)` — the row's statement and the boundary the one cold load
    /// runs over, exactly what the dropped-in tarball states and exports.
    pub const EXPORT: (&str, &str, &str, &busbar_plugin_sdk::ColdEntry) = (
        super::NAME,
        super::ALIAS,
        super::DECLARES,
        &super::BUSBAR_COLD_ENTRY,
    );
}

#[cfg(test)]
#[path = "tests/lib_tests.rs"]
mod tests;
