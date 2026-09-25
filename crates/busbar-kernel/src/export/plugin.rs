// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT AXIS — how an `export:` instance names a module that is not one of the built-ins, and
//! how the sink that module opens is fed (item 141; #2 rule (1): compiled in or dropped in, same
//! contract, same loading path).
//!
//! The axis is the plugin registry's `kind: export` rows (`busbar_plugin_loader::PluginRegistry`):
//! a row gets there through the registry's ONE registration — the dropped-in door (the plugins
//! directory's scan) and the linked door (`PluginRegistry::link`, the same boundary the plugin's
//! `cdylib` exports) both admit through it — and is opened by the registry's one load over either
//! image. The composition root [`install`]s that registry; the kernel names no module and never asks
//! which door a row came in by.
//!
//! From there an instance is an ordinary sink: `resolve_export` accepts its `module:` because the
//! axis holds it, [`open`] opens it once at boot (restart-to-apply, the posture every built-in PUSH
//! sink has), its projection is resolved against the streams the sink DECLARED, and the host feeds
//! it exactly as it feeds a built-in — the payload built to the sink's own projection, off the
//! request path, bounded and shed under pressure (the export kind's property 3), each hand-off
//! recorded as an access amendment. Its declared routes join the route table under the confinement
//! every export route gets, and its `status` is asked when the host renders `/metrics`.

use super::projection::{resolve_projection, Projection};
use super::PayloadCache;
use crate::config::ExportCfg;
use crate::limits::admission::AdmissionGate;
use crate::plugin_routes::{PluginHttpDispatch, RouteDecl, RouteKind};
use busbar_plugin_loader::PluginRegistry;
use busbar_plugin_loader::{DynExport, EndpointRequest, EndpointResponse, ExportStream};
use serde_json::Value;
use std::sync::{Arc, OnceLock};

/// How many deliveries ONE plugin sink may have in flight — the same floor the built-in file sink
/// holds ([`super::file`]): past it a line is shed and counted on the gate, never queued.
const MAX_INFLIGHT_PLUGIN_DELIVERIES: usize = 64;

/// The export axis: the registry the composition root installed, once, before the configuration
/// is resolved. Absent (no plugins directory, nothing linked) ⇒ only the built-ins resolve.
static AXIS: OnceLock<&'static PluginRegistry> = OnceLock::new();

/// Install the export axis — the composition root's one write, before the configuration is
/// resolved. The first install holds.
pub fn install(registry: &'static PluginRegistry) {
    let _ = AXIS.set(registry);
}

/// Whether `module` names a `kind: export` row on the axis (what `resolve_export` asks of a module
/// that is not a built-in) — and, when it does, the sink's own VALIDATION of the instance's
/// `settings` (K9a S2) joins `errs` verbatim, so a plugin sink's settings errors surface at the
/// same moment and in the same words a built-in module's do.
pub(crate) fn registered(name: &str, module: &str, cfg: &Value, errs: &mut Vec<String>) -> bool {
    let found = AXIS
        .get()
        .and_then(|a| a.validate_export(module, name, cfg));
    found.map(|problems| errs.extend(problems)).is_some()
}

/// One opened plugin sink.
struct PluginSink {
    name: String,
    module: String,
    sink: Arc<DynExport>,
    projection: Projection,
    gate: AdmissionGate,
}

/// The opened sinks, set once at boot by [`open`].
static SINKS: OnceLock<Vec<PluginSink>> = OnceLock::new();

fn sinks() -> impl Iterator<Item = &'static PluginSink> {
    SINKS.get().into_iter().flatten()
}

/// Open every export-axis instance `cfg` names, once, before the first app is built (so its routes
/// are in the boot route table). Every failure is collected and returned: a sink that will not
/// open, or an instance subscribing to a stream its sink does not carry, refuses the boot.
pub fn open(cfg: &ExportCfg) -> Result<(), String> {
    // No axis ⇒ no instance resolved through it, so there is nothing to open.
    let Some(axis) = AXIS.get() else {
        return Ok(());
    };
    let (mut errors, mut opened) = (Vec::new(), Vec::new());
    for p in &cfg.plugins {
        let (name, module, def) = (&p.name, p.def.module.trim(), &p.def);
        let settings = serde_json::Value::Object(def.settings.clone()).to_string();
        let opened_sink = axis.open_export(module, &settings);
        let Ok(sink) = opened_sink.map_err(|e| errors.push(format!("export.{name}: {e}"))) else {
            continue;
        };
        // Resolved again against the streams the sink DECLARED. `durable: true` never reaches
        // here: config resolution already refused it.
        let projection = resolve_projection(
            name,
            module,
            Some(sink.streams()),
            def.streams.as_deref(),
            def.fields.as_deref(),
            false,
            &mut errors,
        );
        opened.push(PluginSink {
            name: name.clone(),
            module: module.to_string(),
            sink: Arc::new(sink),
            projection,
            gate: AdmissionGate::new(MAX_INFLIGHT_PLUGIN_DELIVERIES, "export-plugin"),
        });
    }
    if !errors.is_empty() {
        return Err(errors.join("\n  - "));
    }
    let _ = SINKS.set(opened);
    Ok(())
}

/// Hand the request-log line to every opened sink subscribed to `logs`, built to that sink's own
/// projection, off the request path. A sink at its in-flight bound sheds the line (counted on its
/// gate); a sink that errors is logged. Neither reaches the request.
pub(crate) fn deliver_logs(cache: &mut PayloadCache<'_>) {
    let subscribed = |s: &&PluginSink| s.projection.wants_stream(ExportStream::Logs);
    for s in sinks().filter(subscribed) {
        if let Some(permit) = s.gate.try_enter() {
            let payload = cache.get(s.projection);
            crate::audit::amend::export_read(&s.module, cache.facts.ingress_protocol, &payload);
            s.sink.deliver_detached(ExportStream::Logs, payload, permit);
        }
    }
}

/// Ask every opened sink for its `status`, folded by the loader into this process's recorder —
/// called when `/metrics` renders, on the scrape's blocking thread.
pub(crate) fn status() {
    sinks().for_each(|s| s.sink.status());
}

/// The routes the opened sinks of `cfg`'s instances declared (an instance removed by a config apply
/// drops its routes on the next table build, as a removed built-in's do).
pub(crate) fn route_decls(cfg: &ExportCfg) -> impl Iterator<Item = RouteDecl> + '_ {
    let configured = |s: &&PluginSink| cfg.plugins.iter().any(|p| p.name == s.name);
    sinks().filter(configured).flat_map(|s| {
        s.sink.routes().iter().map(|route| RouteDecl {
            owner: s.name.clone(),
            kind: RouteKind::Export,
            route: route.clone(),
            dispatch: s.sink.clone(),
        })
    })
}

/// A plugin sink as a route dispatcher: the exchange crosses the ABI (see `DynExport::serve`).
impl PluginHttpDispatch for DynExport {
    fn handle_http(&self, req: &EndpointRequest) -> EndpointResponse {
        self.serve(req)
    }
}

#[cfg(test)]
#[path = "tests/plugin_tests.rs"]
mod tests;
