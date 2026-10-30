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
use busbar_contract::abi::export::{CheckPhase, ExportStream};
use busbar_contract::abi::mechanism::endpoint::*;
use busbar_contract::abi::mechanism::route::Route;
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
///
/// The sink validates its settings with each reference at a declared path resolved
/// ([`sink_settings`]); one that does not resolve is the instance's problem, in place of the
/// sink's verdict on a value it was never handed.
pub(crate) fn probe(
    name: &str,
    module: &str,
    settings: &serde_json::Map<String, Value>,
) -> Option<(Option<Vec<ExportStream>>, Vec<String>)> {
    let axis = axis()?;
    let (streams, problems) = match sink_settings(axis, module, settings) {
        Ok(cfg) => axis.probe(module, name, &cfg)?,
        Err(e) => {
            let (streams, _) = axis.probe(module, name, &Value::Object(settings.clone()))?;
            (streams, vec![format!("export.{name}.settings: {e}")])
        }
    };
    let streams = streams.map(|b| streams_of(&b));
    Some((streams, problems))
}

/// `settings` as the sink is handed them: each secret reference (`{env:}`, `{file:}`, `{module:}`)
/// at a path `module`'s Statement declares, secret (`secret_refs`) or reference-capable (its
/// extensions' `reference_fields`, lead ruling item 7a), RESOLVED IN PLACE to its string, as 1.5.5
/// resolved an exporter's `url` (the export host lends nothing, so a sink reads the value itself at
/// probe, check and open alike). A literal is handed as written. Resolved through the built-in
/// sources (`env`, `file`) at config time, fail-closed: an unresolvable reference is the `Err`,
/// naming the field, never a dangling reference handed to the sink. A reference at a path the
/// module did NOT declare leaves the settings as written: that is the undeclared-reference
/// refusal's to word (`config_validate`), not this.
///
/// The configuration keeps the reference; only the returned value carries what it resolved to, and
/// only for the one call it is handed to.
pub(crate) fn sink_settings(
    axis: &dyn ExportAxis,
    module: &str,
    settings: &serde_json::Map<String, Value>,
) -> Result<Value, String> {
    let declared = [axis.secret_refs(module), axis.reference_fields(module)].concat();
    let tree = Value::Object(settings.clone());
    if declared.is_empty()
        || busbar_contract::secret_fields::undeclared_reference(&tree, &declared).is_some()
    {
        return Ok(tree);
    }
    crate::config::secret::resolve_settings(
        settings,
        &[],
        &declared,
        module,
        &crate::config::secret::SecretResolver::builtins_only(),
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .map(|resolved| resolved.as_value().clone())
}

/// Stream bytes as the vocabulary's streams (a byte outside it was refused at load).
fn streams_of(bytes: &[u8]) -> Vec<ExportStream> {
    bytes
        .iter()
        .filter_map(|&b| ExportStream::ALL.get(usize::from(b)).copied())
        .collect()
}

/// The `module:` words of the export rows this build links, in the composition root's order.
pub(crate) fn linked_modules() -> Vec<String> {
    axis().map(|axis| axis.linked_modules()).unwrap_or_default()
}

/// Whether `module` names a row the host grants FIRST-PARTY — linked, or dropped in signed by the
/// release key: the only kind of sink busbar's own `/metrics` is rendered by (#65).
pub(crate) fn first_party(module: &str) -> bool {
    axis().is_some_and(|axis| axis.first_party(module))
}

/// Whether `module`'s row states the `one_instance` mark (at most one instance may be configured).
pub(crate) fn one_instance(module: &str) -> bool {
    axis().is_some_and(|axis| axis.one_instance(module))
}

/// `module`'s own check across `instances` at the LIMITS phase, its findings verbatim — asked while
/// the configuration is resolved, for a `one_instance` module configured more than once: the
/// plugin words its own refusal.
///
/// Each instance is handed as its sink reads it ([`sink_settings`]); one whose declared reference
/// does not resolve is already refused by [`probe`] and is left out.
pub(crate) fn check_one_instance(module: &str, instances: &[(String, Value)]) -> Vec<String> {
    axis()
        .and_then(|axis| {
            let instances: Vec<(String, Value)> = instances
                .iter()
                .filter_map(|(name, settings)| match settings {
                    Value::Object(map) => sink_settings(axis, module, map)
                        .ok()
                        .map(|v| (name.clone(), v)),
                    other => Some((name.clone(), other.clone())),
                })
                .collect();
            axis.check(
                module,
                busbar_contract::abi::export::CHECK_PHASE_LIMITS,
                &instances,
            )
        })
        .unwrap_or_default()
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
        // Each instance as its sink is handed it ([`sink_settings`]); one whose declared reference
        // does not resolve was already refused when the configuration was resolved ([`probe`]).
        let instances: Vec<(String, Value)> = cfg
            .plugins
            .iter()
            .filter(|q| q.def.module.trim() == module)
            .filter_map(|q| {
                sink_settings(axis, module, &q.def.settings)
                    .ok()
                    .map(|v| (q.name.clone(), v))
            })
            .collect();
        errors.extend(axis.check(module, phase, &instances).unwrap_or_default());
    }
}

/// One opened plugin sink.
pub(super) struct PluginSink {
    name: String,
    module: String,
    sink: Arc<dyn ExportCalls>,
    /// Whether this is the boot's SCRAPE SINK (the first-party instance subscribed to `metrics`):
    /// it serves `/metrics/hooks` for the process's life ([`route_decls`]).
    scrape: bool,
    pub(super) projection: Projection,
    /// It takes each `traces` line's full span record (`ExportCalls::takes_span_records`).
    pub(super) span_record: bool,
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
        // Each declared reference resolved in place, fail-closed ([`sink_settings`]).
        let settings = match sink_settings(axis, module, &def.settings) {
            Ok(settings) => settings,
            Err(e) => {
                errors.push(format!("export.{name}.settings: {e}"));
                continue;
            }
        };
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
        let span_record = sink.takes_span_records();
        opened.push(PluginSink {
            name: name.clone(),
            module: module.to_string(),
            span_record,
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
/// sink subscribed to it ([`deliver_to`]).
pub(super) fn deliver(stream: ExportStream, op: &str, mut f: impl FnMut(Projection) -> Arc<Value>) {
    deliver_to(stream, op, |projection, _| f(projection));
}

/// [`deliver`], `f` told also whether the sink takes full span records
/// ([`PluginSink::span_record`]).
pub(super) fn deliver_to(
    stream: ExportStream,
    op: &str,
    mut f: impl FnMut(Projection, bool) -> Arc<Value>,
) {
    for s in sinks().filter(|s| s.projection.wants_stream(stream)) {
        deliver_one(s, stream, op, &mut f);
    }
}

/// Hand `stream`'s payload to ONE sink, under the admission it stated when started ([`start`]). A
/// sink not yet started has stated nothing, so it is fed nothing: the delivery is shed, never let in
/// at a default that would then hold for the life of the process. A sink at its in-flight bound, or
/// whose queue refuses it, sheds it (counted on its gate and on its declared shed counter); a sink
/// that errors is logged. Neither reaches the caller. The access amendment records what the sink
/// QUEUED: a shed line never reached it, so it is never audited as read. `f` is told whether the
/// sink takes full span records ([`PluginSink::span_record`]).
fn deliver_one(
    s: &PluginSink,
    stream: ExportStream,
    op: &str,
    f: &mut impl FnMut(Projection, bool) -> Arc<Value>,
) {
    let Some(admission) = s.admission.get() else {
        s.sink.shed();
        return;
    };
    if !admission.live {
        return;
    }
    let Some(permit) = admission.gate.try_enter() else {
        s.sink.shed();
        return;
    };
    let payload = f(s.projection, s.span_record);
    let line = serde_json::to_vec(&*payload).unwrap_or_default();
    match s.sink.deliver(stream as u8, line, Box::new(permit)) {
        Delivered::Queued => crate::audit::amend::export_read(&s.module, op, &payload),
        Delivered::Shed => s.sink.shed(),
    }
}

/// START every opened sink — at the moment the host starts its PUSH sinks: each states its
/// admission (whether it takes deliveries this run, its in-flight bound, its gate's name), or none
/// and is fed at the host's default admission. Set exactly once, here: nothing is delivered before.
pub fn start() {
    sinks().for_each(start_one);
}

/// Start one sink: the admission it states, or the host's default when it states none.
fn start_one(s: &PluginSink) {
    let stated = s.sink.admission();
    let _ = s.admission.set(Admission::of(&s.module, stated));
}

/// Ask every opened sink for its `status` — its envelope folds into this process's recorder —
/// called when the WHOLE snapshot is read (`snapshot.read`), on the scrape's blocking thread.
pub(crate) fn status() {
    sinks().for_each(|s| {
        let _ = s.sink.status();
    });
}

/// The routes `cfg`'s instances declare (an instance removed by a config apply drops its routes on
/// the next table build, as a removed built-in's do), each opened sink's own. The SCRAPE SINK's
/// come first, owned by the module its instance names (the name a colliding sink is refused
/// against), marked [`RouteDecl::scrape`] and dispatched through the snapshot grant
/// ([`super::scrape::Granted`]): its `serve` reads the host snapshot service. Every other sink's are
/// owned by its instance name and lent nothing, and a well-known exposition path one of them
/// declares is not its to claim (only the first-party scrape sink serves `/metrics`, #65): it is
/// dropped, with a warning. A scrape instance a configuration apply added is served by the boot's
/// scrape sink of its module when the boot opened one; when it did not, the instance declares its
/// row's routes, so the apply reports the paths awaiting a restart, and nothing serves them until
/// then.
///
/// `/metrics/hooks` FOLLOWS 1.5.5, where it was a core route mounted with the recorder at boot and
/// answering for the process's life: it is the BOOT's scrape sink's, declared whether or not a
/// configuration apply still names that instance (ARCHITECT 2026-10-05, Q-U2-4 follow-up), while
/// `/metrics` follows the configuration, as 1.5.5's plugin route did (removed: `404`).
pub(crate) fn route_decls(cfg: &ExportCfg) -> Vec<RouteDecl> {
    let (scrape, rest): (Vec<_>, Vec<_>) = cfg.plugins.iter().partition(|p| p.scrape);
    let mut out = Vec::new();
    for p in scrape.into_iter().chain(rest) {
        let owner = if p.scrape {
            p.def.module.trim().to_string()
        } else {
            p.name.clone()
        };
        // A scrape instance this process did not open under its name (a configuration apply
        // renamed or re-added it) is served by the boot's scrape sink of the same module, as
        // 1.5.5's host-held recorder served `/metrics` whatever the instance was called.
        let module = p.def.module.trim();
        let opened = sinks().find(|s| s.name == p.name).or_else(|| {
            p.scrape
                .then(|| sinks().find(|s| s.scrape && s.module == module))
                .flatten()
        });
        let (routes, dispatch): (Vec<Route>, Arc<dyn PluginHttpDispatch>) = match opened {
            Some(s) => {
                let served: Arc<dyn PluginHttpDispatch> = Arc::new(Served(s.sink.clone()));
                let dispatch: Arc<dyn PluginHttpDispatch> = if p.scrape {
                    Arc::new(super::scrape::Granted(served))
                } else {
                    served
                };
                (s.sink.routes().to_vec(), dispatch)
            }
            None if p.scrape => {
                let routes = axis().map_or_else(Vec::new, |a| a.routes(module));
                (routes, Arc::new(Unopened))
            }
            None => continue,
        };
        for route in routes {
            if crate::plugin_routes::scrape_sink_path(&route.path) {
                // The boot's scrape sink's, below.
                continue;
            }
            if !p.scrape && crate::plugin_routes::well_known(&route.path) {
                tracing::warn!(
                    instance = %p.name,
                    path = %route.path,
                    "an export instance that is not the scrape sink declares a well-known \
                     exposition path; it is not mounted (only the first-party scrape sink serves it)"
                );
                continue;
            }
            out.push(RouteDecl {
                owner: owner.clone(),
                kind: RouteKind::Export,
                route,
                scrape: p.scrape,
                dispatch: dispatch.clone(),
            });
        }
    }
    if let Some(s) = sinks().find(|s| s.scrape) {
        let served: Arc<dyn PluginHttpDispatch> = Arc::new(Served(s.sink.clone()));
        let dispatch: Arc<dyn PluginHttpDispatch> = Arc::new(super::scrape::Granted(served));
        out.extend(
            s.sink
                .routes()
                .iter()
                .filter(|r| crate::plugin_routes::scrape_sink_path(&r.path))
                .map(|route| RouteDecl {
                    owner: s.module.clone(),
                    kind: RouteKind::Export,
                    route: route.clone(),
                    scrape: true,
                    dispatch: dispatch.clone(),
                }),
        );
    }
    out
}

/// The dispatcher of a route whose sink this process has not opened: a `502` with no body.
struct Unopened;

impl PluginHttpDispatch for Unopened {
    fn handle_http(&self, _: &EndpointRequest) -> EndpointResponse {
        EndpointResponse {
            status: 502,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

/// `sink` as a route dispatcher ([`Served`]) — a test app's scrape routes.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn served(sink: Arc<dyn ExportCalls>) -> Arc<dyn PluginHttpDispatch> {
    Arc::new(Served(sink))
}

/// A plugin sink as a route dispatcher: the exchange crosses the ABI through `serve`. A sink that
/// cannot answer is a `502` with no body to the client and a warning naming it to the operator —
/// the exchange never fails open into a partial response.
pub(super) struct Served(pub(super) Arc<dyn ExportCalls>);

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
