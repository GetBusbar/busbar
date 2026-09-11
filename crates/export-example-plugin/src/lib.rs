// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A **hermetic trivial `kind: export` plugin** — a `cdylib` exporting the export C ABI. It declares
//! it carries the single `metrics` stream and drops every record it is handed. It is the in-tree
//! ABI-crossing coverage for the `kind: export` seam, the
//! export-seam analogue of `busbar-secret-example-plugin` (secret) and
//! `busbar-hook-test-plugin` (hook) — a real, loadable, signable export plugin for the `DynExport`
//! dlopen seam to round-trip through.
//!
//! It does NO real telemetry export: it declares `metrics`, takes every record and drops it, and
//! declares no route. Config JSON is ignored (this sink has no configurable shape), mirroring
//! `busbar-store-example-plugin`'s config-less posture.
//!
//! IT IMPLEMENTS THE ONE EXPORT FACE — `busbar_contract::Export`, the same four methods the three
//! built-in sinks implement — and states all four itself, because that is what makes this crate
//! REFERENCE coverage: a plugin author reading it sees the whole of what an export sink is, with no
//! half inherited from a default they would never open.

use busbar_plugin_sdk::{
    export_export_plugin, AbiVersion, Ack, Export, ExportHost, ExportItem, Kind, Plugin,
    RouteStatement, ServeRequest, Served, EXPORT_ABI,
};

/// The trivial sink: carries the metrics stream, takes every record and drops it, serves nothing.
struct ExampleExport;

impl Plugin for ExampleExport {
    fn key(&self) -> &'static str {
        "export-example"
    }
    fn kind(&self) -> Kind {
        Kind::Export
    }
    fn abi(&self) -> AbiVersion {
        EXPORT_ABI
    }
}

impl Export for ExampleExport {
    fn streams(&self) -> &'static [&'static str] {
        &["metrics"]
    }

    /// Take the record and drop it. [`Ack::Received`] is the honest word for that and `Durable`
    /// would not be: this sink received it and put it nowhere a crash could not reach.
    fn receive(&self, _item: ExportItem<'_>, _host: &dyn ExportHost) -> Ack {
        Ack::Received
    }

    fn routes(&self) -> &'static [RouteStatement] {
        &[]
    }

    fn serve(&self, _req: &ServeRequest<'_>, _host: &dyn ExportHost) -> Served {
        Served {
            status: 404,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

/// Construct the sink. No config is read; malformed JSON in `cfg` is accepted and ignored rather than
/// a load error, since there is nothing in this plugin's config shape that could be malformed.
fn open(_cfg: &str) -> Result<Box<dyn Export>, String> {
    Ok(Box::new(ExampleExport))
}

export_export_plugin!(open);

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
