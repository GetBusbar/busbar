// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A **hermetic trivial `kind: export` plugin** — a `cdylib` exporting the export C ABI. It declares
//! it carries the single `metrics` stream and drops every record it is handed. It is the in-tree
//! ABI-crossing coverage for the `kind: export` seam, the
//! export-seam analogue of `busbar-secret-example-plugin` (secret) and
//! `busbar-hook-test-plugin` (hook) — a real, loadable, signable export plugin for the `DynExport`
//! dlopen seam to round-trip through.
//!
//! It does NO real telemetry export: it declares `metrics`, DROPS every record it is handed, and
//! declares no route. Config JSON is ignored (this sink has no configurable shape), mirroring
//! `busbar-store-example-plugin`'s config-less posture.
//!
//! AND IT SAYS SO. Reference coverage that lied about its acknowledgement would be teaching every
//! plugin author to lie about theirs — see [`Export::receive`] below.
//!
//! IT IMPLEMENTS THE ONE EXPORT FACE — `busbar_contract::Export`, the same four methods the three
//! built-in sinks implement — and states all four itself, because that is what makes this crate
//! REFERENCE coverage: a plugin author reading it sees the whole of what an export sink is, with no
//! half inherited from a default they would never open.

use busbar_plugin_sdk::{
    export_export_plugin, AbiVersion, Ack, Export, ExportHost, ExportItem, Kind, Plugin,
    RouteStatement, ServeRequest, Served, EXPORT_ABI,
};

/// The trivial sink: carries the metrics stream, DROPS every record it is handed, serves nothing.
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

    /// DROP THE RECORD, AND SAY SO. [`Ack::Retry`] is the honest word and the other two are not:
    /// `Received` means "the sink HAS the record and claims no durability for it", and a sink that
    /// dropped it on the floor does not have it. This plugin used to answer `Received` — which was
    /// wrong in the same way for the whole of its life and simply could not be seen, because before
    /// ABI v3 the acknowledgement did not cross the seam and no caller could ever have noticed.
    ///
    /// It matters here more than anywhere else in the tree: this crate is REFERENCE coverage, and a
    /// reference sink that overstates its own acknowledgement teaches every plugin author who reads
    /// it to overstate theirs. A host's whole ability to act on an ack rests on nobody doing that.
    fn receive(&self, _item: ExportItem<'_>, _host: &dyn ExportHost) -> Ack {
        Ack::Retry
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
