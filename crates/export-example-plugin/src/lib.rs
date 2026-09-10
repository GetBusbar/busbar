// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A **hermetic trivial `kind: export` plugin** — a `cdylib` exporting the export C ABI. It declares
//! it carries the single [`ExportStream::Metrics`] stream and drops every delivered batch (the default
//! no-op `deliver`). It is the in-tree ABI-crossing coverage for the `kind: export` seam, the
//! export-seam analogue of `busbar-secret-example-plugin` (secret) and
//! `busbar-hook-test-plugin` (hook) — a real, loadable, signable export plugin for the `DynExport`
//! dlopen seam to round-trip through.
//!
//! It does NO real telemetry export: `streams()` reports `[Metrics]` and `deliver()` takes the trait
//! default (a no-op). Config JSON is ignored (this sink has no configurable shape), mirroring
//! `busbar-store-example-plugin`'s config-less posture.

use busbar_plugin_sdk::{export_catalog, export_export_plugin, Catalog};
use busbar_plugin_sdk::{ExportHandler, ExportStream};

/// The trivial sink: carries the metrics stream, drops batches (default `deliver`).
struct ExampleExport;

impl ExportHandler for ExampleExport {
    fn streams(&self) -> Vec<ExportStream> {
        vec![ExportStream::Metrics]
    }
    // `deliver` takes the trait's default no-op: a sink that reports a stream but drops its batches.
}

/// Construct the sink. No config is read; malformed JSON in `cfg` is accepted and ignored rather than
/// a load error, since there is nothing in this plugin's config shape that could be malformed.
/// This plugin's error catalog: EMPTY, and honestly so — this sink reports no failure today
/// (`deliver` is the no-op default). A host reads an empty catalog as "every code this plugin
/// emits is uncatalogued", which is exactly right for a plugin that emits none.
pub const CATALOG: &str = r#"{ "default_locale": "en", "entries": [] }"#;

/// This plugin's catalog, parsed: what the host reads at load, and what the tests check.
pub fn catalog() -> Catalog {
    serde_json::from_str(CATALOG).expect("the catalog is a catalog document")
}

fn open(_cfg: &str) -> Result<Box<dyn ExportHandler>, String> {
    Ok(Box::new(ExampleExport))
}

export_catalog!(CATALOG);
export_export_plugin!(open);

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
