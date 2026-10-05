// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT AXIS — how an `export:` instance names a module that is not one of the built-ins, and
//! how the sink that module opens is fed (item 141; #2 rule (1): compiled in or dropped in, same
//! contract, same loading path).
//!
//! The axis is the contract's [`ExportAxis`]: every `kind: export` row the composition root
//! admitted, compiled in or dropped in through one registration, opened on the export kind's
//! memory ABI through the process's one dispatcher. The composition root installs it through its
//! root rows ([`crate::preflight::RootInstall`]); the kernel names no module and no export crate,
//! holds each opened instance as a contract [`ExportCalls`] handle, and never asks which door a row
//! came in by.
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
use busbar_contract::abi::cold::endpoint::*;
use busbar_contract::abi::export::{CheckPhase, ExportStream};
use busbar_contract::export_calls::{Delivered, ExportAxis, ExportCalls, ServeRequest};
use serde_json::Value;
use std::sync::{Arc, OnceLock};

/// How many deliveries ONE plugin sink may have in flight: past it a line is shed — counted on the
/// gate and on the sink's declared shed counter — never queued.
const MAX_INFLIGHT_PLUGIN_DELIVERIES: usize = 64;

/// The export axis the composition root installed through its root rows
/// ([`crate::preflight::RootInstall`]), before the configuration is resolved. Absent (no plugins
/// directory, nothing linked) ⇒ no export module resolves.
pub(super) fn axis() -> Option<&'static dyn ExportAxis> {
    crate::preflight::root_rows().export_axis
}

/// What the axis says of `module` for instance `name` (what `resolve_export` asks of a module that
/// is not a built-in): `None` when no `kind: export` row names it; else the streams its sink
/// declares (none when it will not open here) — the projection is resolved against them at
/// configuration time, as a built-in's is — and the sink's own VALIDATION of the instance's
/// `settings` (K9a S2), rendered under the instance, so a plugin sink's settings errors surface at
/// the same moment and in the same words a built-in's do.
pub(crate) fn probe(
    name: &str,
    module: &str,
    cfg: &Value,
) -> Option<(Option<Vec<ExportStream>>, Vec<String>)> {
    let (streams, problems) = axis()?.probe(module, name, cfg)?;
    let streams = streams.map(|b| streams_of(&b));
    Some((streams, problems))
}

/// Stream bytes as the vocabulary's streams (a byte outside it was refused at load).
fn streams_of(bytes: &[u8]) -> Vec<ExportStream> {
    bytes
        .iter()
        .filter_map(|&b| ExportStream::ALL.get(usize::from(b)).copied())
        .collect()
}

/// Whether `module` names a row this build LINKS on the export axis, as opposed to one a plugins
/// directory dropped in. The unknown-module diagnostic lists these beside the kernel's own modules.
pub(crate) fn linked(module: &str) -> bool {
    axis().is_some_and(|axis| axis.linked(module))
}

/// Whether `module` names a row the host grants FIRST-PARTY — linked, or dropped in signed by the
/// release key: the only kind of sink busbar's own `/metrics` is rendered by (#65).
pub(crate) fn first_party(module: &str) -> bool {
    axis().is_some_and(|axis| axis.first_party(module))
}

/// The sinks' own checks across every instance of each axis module `cfg` configures, in
/// configuration order (export ABI minors 8, 9) — run while the configuration is validated, at
/// `phase` (among its limits' checks, or after them); each line joins `errors` verbatim.
pub(crate) fn check(cfg: &ExportCfg, phase: CheckPhase, errors: &mut Vec<String>) {
    let Some(axis) = axis() else {
        return;
    };
    let phase = match phase {
        CheckPhase::Limits => busbar_contract::abi::export::CHECK_PHASE_LIMITS,
        CheckPhase::Instances => busbar_contract::abi::export::CHECK_PHASE_INSTANCES,
    };
    let mut modules: Vec<&str> = Vec::new();
    for p in &cfg.plugins {
        let module = p.def.module.trim();
        if modules.contains(&module) {
            continue;
        }
        modules.push(module);
        let instances: Vec<(String, Value)> = cfg
            .plugins
            .iter()
            .filter(|q| q.def.module.trim() == module)
            .map(|q| (q.name.clone(), Value::Object(q.def.settings.clone())))
            .collect();
        errors.extend(axis.check(module, phase, &instances).unwrap_or_default());
    }
}

/// One opened plugin sink.
pub(super) struct PluginSink {
    name: String,
    module: String,
    sink: Arc<dyn ExportCalls>,
    /// Whether this is the SCRAPE SINK's instance (the one subscribed to `metrics`), which renders
    /// `/metrics` and `/metrics/hooks`.
    scrape: bool,
    pub(super) projection: Projection,
    /// Its admission, as it stated it when started ([`start`]).
    admission: OnceLock<Admission>,
}

/// A started sink's admission: whether it takes deliveries this run, and its in-flight gate.
struct Admission {
    live: bool,
    gate: AdmissionGate,
}

impl Admission {
    /// The admission a sink of `module` is held to: as it `stated` when started — whether it takes
    /// deliveries, its in-flight bound (`0`: the host's) and its gate's name (empty: the module's)
    /// — or, stating none, the host's: live, [`MAX_INFLIGHT_PLUGIN_DELIVERIES`], the module's name.
    fn of(module: &str, stated: Option<(bool, u64, String)>) -> Admission {
        let (live, inflight, gate) = stated.unwrap_or((true, 0, String::new()));
        let bound = match inflight {
            0 => MAX_INFLIGHT_PLUGIN_DELIVERIES,
            n => usize::try_from(n).unwrap_or(usize::MAX),
        };
        let bound = bound.clamp(1, tokio::sync::Semaphore::MAX_PERMITS);
        let gate = if gate.is_empty() {
            module.to_string()
        } else {
            gate
        };
        Admission {
            live,
            gate: AdmissionGate::new(bound, gate),
        }
    }
}

impl PluginSink {
    /// The admission it stated when started; before then, or when it stated none, the host's.
    fn admission(&self) -> &Admission {
        self.admission
            .get_or_init(|| Admission::of(&self.module, None))
    }
}

/// The opened sinks, set once at boot by [`open`].
static SINKS: OnceLock<Vec<PluginSink>> = OnceLock::new();

pub(super) fn sinks() -> impl Iterator<Item = &'static PluginSink> {
    SINKS.get().into_iter().flatten()
}

/// Open every export-axis instance `cfg` names, once, before the first app is built (so its routes
/// are in the boot route table). Every failure is collected and returned: a sink that will not
/// open, or an instance subscribing to a stream its sink does not carry, refuses the boot.
pub fn open(cfg: &ExportCfg) -> Result<(), String> {
    // No axis ⇒ no instance resolved through it, so there is nothing to open.
    let Some(axis) = axis() else {
        return Ok(());
    };
    let (mut errors, mut opened) = (Vec::new(), Vec::new());
    for p in &cfg.plugins {
        let (name, module, def) = (&p.name, p.def.module.trim(), &p.def);
        let settings = serde_json::Value::Object(def.settings.clone());
        let opened_sink = axis.open(module, &format!("export.{name}"), &settings);
        let Ok(sink) = opened_sink.map_err(|e| errors.push(format!("export.{name}: {e}"))) else {
            continue;
        };
        // Resolved again against the streams the sink DECLARED. `durable: true` never reaches
        // here: config resolution already refused it.
        let projection = resolve_projection(
            name,
            module,
            Some(&streams_of(sink.streams())),
            def.streams.as_deref(),
            def.fields.as_deref(),
            false,
            &mut errors,
        );
        opened.push(PluginSink {
            name: name.clone(),
            module: module.to_string(),
            sink,
            scrape: p.scrape,
            projection,
            admission: OnceLock::new(),
        });
    }
    if !errors.is_empty() {
        return Err(errors.join("\n  - "));
    }
    let _ = SINKS.set(opened);
    // What a span CALLSITE's interest is depends on which sinks exist (`super::traces::layer`).
    tracing::callsite::rebuild_interest_cache();
    Ok(())
}

/// Hand the request-log line to every opened sink subscribed to `logs`, built to that sink's own
/// projection, off the request path.
pub(crate) fn deliver_logs(cache: &mut PayloadCache<'_>) {
    let op = cache.facts.ingress_protocol;
    deliver(ExportStream::Logs, op, |projection| cache.get(projection));
}

/// Hand `stream`'s payload — built by `f` to each sink's own projection — to every opened, live
/// sink subscribed to it. A sink at its in-flight bound sheds it (counted on its gate and on its
/// declared shed counter); a sink that errors is logged. Neither reaches the caller.
pub(super) fn deliver(stream: ExportStream, op: &str, mut f: impl FnMut(Projection) -> Arc<Value>) {
    for s in sinks().filter(|s| s.projection.wants_stream(stream)) {
        let admission = s.admission();
        if !admission.live {
            continue;
        }
        let Some(permit) = admission.gate.try_enter() else {
            s.sink.shed();
            continue;
        };
        let payload = f(s.projection);
        crate::audit::amend::export_read(&s.module, op, &payload);
        let line = serde_json::to_vec(&*payload).unwrap_or_default();
        if s.sink.deliver(stream as u8, line, Box::new(permit)) == Delivered::Shed {
            s.sink.shed();
        }
    }
}

/// START every opened sink — at the moment the host starts its PUSH sinks: each states its
/// admission (whether it takes deliveries this run, its in-flight bound, its gate's name), or none,
/// and is fed at the host's default admission.
pub fn start() {
    for s in sinks() {
        let stated = s.sink.admission();
        if stated.is_some() {
            let _ = s.admission.set(Admission::of(&s.module, stated));
        }
    }
}

/// The sink opened at boot for the instance `name`, if one was.
pub(crate) fn opened(name: &str) -> Option<Arc<dyn ExportCalls>> {
    sinks().find(|s| s.name == name).map(|s| s.sink.clone())
}

/// The scrape sink opened at boot (the instance subscribed to `metrics`), if one was: what renders
/// `/metrics/hooks`.
pub(crate) fn scrape_sink() -> Option<Arc<dyn ExportCalls>> {
    sinks().find(|s| s.scrape).map(|s| s.sink.clone())
}

/// Ask every opened sink for its `status` — its envelope folds into this process's recorder —
/// called when `/metrics` renders, on the scrape's blocking thread.
pub(crate) fn status() {
    sinks().for_each(|s| {
        let _ = s.sink.status();
    });
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
            dispatch: Arc::new(Served(s.sink.clone())),
        })
    })
}

/// A plugin sink as a route dispatcher: the exchange crosses the ABI through `serve`. A sink that
/// cannot answer is a `502` with no body to the client and a warning naming it to the operator —
/// the exchange never fails open into a partial response.
struct Served(Arc<dyn ExportCalls>);

impl PluginHttpDispatch for Served {
    fn handle_http(&self, req: &EndpointRequest) -> EndpointResponse {
        let request = ServeRequest {
            method: &req.method,
            path: &req.path,
            query: Some(req.query.as_str()).filter(|q| !q.is_empty()),
            headers: &req.headers,
            body: &req.body,
        };
        match self.0.serve(&request) {
            Ok(r) => EndpointResponse {
                status: r.status,
                headers: r.headers,
                body: r.body,
            },
            Err(e) => {
                tracing::warn!(error = %e, "export plugin route failed");
                EndpointResponse {
                    status: 502,
                    headers: Vec::new(),
                    body: Vec::new(),
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/plugin_tests.rs"]
mod tests;
