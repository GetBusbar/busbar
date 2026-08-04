// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A **hermetic trivial `kind: export` plugin** — a `cdylib` exporting the export C ABI. It declares
//! it carries the single [`ExportStream::Metrics`] stream and drops every delivered batch (the default
//! no-op `deliver`). Before this crate existed, `kind: export` had zero in-tree ABI-crossing coverage;
//! it is the export-seam analogue of `busbar-secret-example-plugin` (secret) and
//! `busbar-hook-test-plugin` (hook) — a real, loadable, signable export plugin for the `DynExport`
//! dlopen seam to round-trip through.
//!
//! It does NO real telemetry export: `streams()` reports `[Metrics]` and `deliver()` takes the trait
//! default (a no-op). Config JSON is ignored (this sink has no configurable shape), mirroring
//! `busbar-store-example-plugin`'s config-less posture.

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
fn open(_cfg: &str) -> Result<Box<dyn ExportHandler>, String> {
    Ok(Box::new(ExampleExport))
}

busbar_plugin_sdk::export_export_plugin!(open);
