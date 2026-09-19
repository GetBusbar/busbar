// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A **hermetic trivial `kind: export` plugin** — a `cdylib` exporting the export C ABI. It declares
//! it carries the single [`ExportStream::Metrics`] stream and DROPS every delivered batch, answering
//! [`ExportAck::Retry`]. It is the in-tree ABI-crossing coverage for the `kind: export` seam, the
//! export-seam analogue of `busbar-secret-example-plugin` (secret) and
//! `busbar-hook-test-plugin` (hook) — a real, loadable, signable export plugin for the `DynExport`
//! dlopen seam to round-trip through.
//!
//! It does NO real telemetry export: `streams()` reports `[Metrics]`, and `deliver()` drops the batch
//! AND SAYS SO — it answers [`ExportAck::Retry`], the only honest word for a sink that took the record
//! nowhere. Reference coverage that overstated its acknowledgement would teach every plugin author who
//! reads it to overstate theirs. Config JSON is ignored (this sink has no configurable shape),
//! mirroring `busbar-store-example-plugin`'s config-less posture.

use busbar_plugin_sdk::{ExportAck, ExportHandler, ExportStream};

/// The trivial sink: carries the metrics stream, DROPS every batch and honestly says so.
struct ExampleExport;

impl ExportHandler for ExampleExport {
    fn streams(&self) -> Vec<ExportStream> {
        vec![ExportStream::Metrics]
    }

    /// DROP THE RECORD, AND SAY SO. [`ExportAck::Retry`] is the honest word and the other two are
    /// not: `Received`/`Durable` claim the sink HAS the record, and a sink that dropped it on the
    /// floor does not. A host's whole ability to act on an ack rests on a reference sink not lying.
    fn deliver(&self, _stream: ExportStream, _payload: &serde_json::Value) -> ExportAck {
        ExportAck::Retry
    }
}

/// Construct the sink. No config is read; malformed JSON in `cfg` is accepted and ignored rather than
/// a load error, since there is nothing in this plugin's config shape that could be malformed.
fn open(_cfg: &str) -> Result<Box<dyn ExportHandler>, String> {
    Ok(Box::new(ExampleExport))
}

busbar_plugin_sdk::export_export_plugin!(open);

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
