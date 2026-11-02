// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::projection::{resolve_projection, Projection};
use super::PayloadCache;
use crate::config::secret::ResolvedSettings;
use crate::config::ExportCfg;
use crate::limits::admission::AdmissionGate;
use crate::plugin_routes::{PluginHttpDispatch, RouteDecl, RouteKind};
use busbar_contract::abi::export::{CheckPhase, ExportStream};
use busbar_contract::abi::mechanism::endpoint::*;
use busbar_contract::abi::mechanism::route::Route;
use busbar_contract::export_calls::{Delivered, ExportAxis, ExportCalls, ServeRequest};
use serde_json::Value;
use std::sync::{Arc, OnceLock};

const MAX_INFLIGHT_PLUGIN_DELIVERIES: usize = 64;

pub(super) fn axis() -> Option<&'static dyn ExportAxis> {
    crate::preflight::root_rows().export_axis
}

pub(crate) fn probe(
    name: &str,
    module: &str,
    settings: &serde_json::Map<String, Value>,
) -> Option<(Option<Vec<ExportStream>>, Vec<String>)> {
    let axis = axis()?;
    let (streams, problems) = match sink_settings(axis, module, settings) {
        Ok(cfg) => axis.probe(module, name, cfg.as_value())?,
        Err(e) => {
            let written = ResolvedSettings::from_map(settings.clone());
            let (streams, _) = axis.probe(module, name, written.as_value())?;
            (streams, vec![format!("export.{name}.settings: {e}")])
        }
    };
    let streams = streams.map(|b| streams_of(&b));
    Some((streams, problems))
}

pub(crate) fn sink_settings(
    axis: &dyn ExportAxis,
    module: &str,
    settings: &serde_json::Map<String, Value>,
) -> Result<ResolvedSettings, String> {
    let secret = axis.secret_refs(module);
    let reference = axis.reference_fields(module);
    let declared = [secret.as_slice(), reference.as_slice()].concat();
    let tree = ResolvedSettings::from_map(settings.clone());
    if declared.is_empty()
        || busbar_contract::secret_fields::undeclared_reference(tree.as_value(), &declared)
            .is_some()
    {
        return Ok(tree);
    }
    crate::config::secret::resolve_export_settings(
        settings,
        &secret,
        &reference,
        module,
        &crate::config::secret::SecretResolver::builtins_only(),
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
}

fn streams_of(bytes: &[u8]) -> Vec<ExportStream> {
    bytes
        .iter()
        .filter_map(|&b| ExportStream::ALL.get(usize::from(b)).copied())
        .collect()
}

pub(crate) fn linked_modules() -> Vec<String> {
    axis().map(|axis| axis.linked_modules()).unwrap_or_default()
}

pub(crate) fn first_party(module: &str) -> bool {
    axis().is_some_and(|axis| axis.first_party(module))
}

pub(crate) fn one_instance(module: &str) -> bool {
    axis().is_some_and(|axis| axis.one_instance(module))
}

pub(crate) fn check_one_instance(module: &str, instances: &[(String, Value)]) -> Vec<String> {
    let names: Vec<String> = instances.iter().map(|(n, _)| n.clone()).collect();
    let found = axis()
        .and_then(|axis| {
            let held: Vec<_> = instances
                .iter()
                .map(|(_, settings)| {
                    settings
                        .as_object()
                        .map(|map| sink_settings(axis, module, map))
                })
                .collect();
            let instances: Vec<_> = instances
                .iter()
                .zip(&held)
                .filter_map(|((name, settings), resolved)| match resolved {
                    Some(Ok(value)) => Some((name.clone(), value.as_value())),
                    Some(Err(_)) => None,
                    None => Some((name.clone(), settings)),
                })
                .collect();
            axis.check(
                module,
                busbar_contract::abi::export::CHECK_PHASE_LIMITS,
                &instances,
            )
        })
        .unwrap_or_default();
    word_one_instance(module, &names, found)
}

const ONE_INSTANCE_WHY: &str = "The module runs as one instance, so a second instance could only \
                                be silently ignored — keep a single instance.";

pub(crate) fn word_one_instance(module: &str, names: &[String], found: Vec<String>) -> Vec<String> {
    if found.iter().any(|line| line.starts_with("export.")) {
        return found;
    }
    let Some((first, rest)) = names.split_first() else {
        return Vec::new();
    };
    let why = if found.is_empty() {
        ONE_INSTANCE_WHY.to_string()
    } else {
        found.join(" ")
    };
    rest.iter()
        .map(|name| {
            format!(
                "export.{name}: a second `module: {module}` instance (already defined as \
                 '{first}'). {why}"
            )
        })
        .collect()
}

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

        let held: Vec<(String, ResolvedSettings)> = cfg
            .plugins
            .iter()
            .filter(|q| q.def.module.trim() == module)
            .filter_map(|q| {
                sink_settings(axis, module, &q.def.settings)
                    .ok()
                    .map(|v| (q.name.clone(), v))
            })
            .collect();
        let instances: Vec<_> = held
            .iter()
            .map(|(name, settings)| (name.clone(), settings.as_value()))
            .collect();
        errors.extend(axis.check(module, phase, &instances).unwrap_or_default());
    }
}

pub(super) struct PluginSink {
    name: String,
    module: String,
    sink: Arc<dyn ExportCalls>,

    scrape: bool,
    pub(super) projection: Projection,

    pub(super) span_record: bool,

    admission: OnceLock<Admission>,

    reads: OnceLock<Arc<crate::audit::amend::NodeAmendments>>,
}

struct Admission {
    live: bool,
    gate: AdmissionGate,
}

impl Admission {
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

static SINKS: OnceLock<Vec<PluginSink>> = OnceLock::new();

pub(super) fn sinks() -> impl Iterator<Item = &'static PluginSink> {
    SINKS.get().into_iter().flatten()
}


pub fn requires_restart(name: &str, def: Option<&crate::config::ExportDefCfg>) -> bool {
    let boot = sinks()
        .find(|sink| sink.name == name)
        .map(|sink| (sink.module.as_str(), sink.projection, sink.sink.streams()));
    definition_requires_restart(name, boot, def)
}

fn definition_requires_restart(
    name: &str,
    boot: Option<(&str, Projection, &[u8])>,
    def: Option<&crate::config::ExportDefCfg>,
) -> bool {
    let (module, projection, streams, def) = match (boot, def) {
        (None, None) => return false,
        (None, Some(_)) | (Some(_), None) => return true,
        (Some((module, projection, streams)), Some(def)) => (module, projection, streams, def),
    };
    if def.module.trim() != module {
        return true;
    }
    let mut errors = Vec::new();
    let desired = resolve_projection(
        name,
        module,
        Some(&streams_of(streams)),
        def.streams.as_deref(),
        def.fields.as_deref(),
        false,
        &mut errors,
    );
    !errors.is_empty() || desired != projection
}

pub fn open(cfg: &ExportCfg) -> Result<(), String> {
    let Some(axis) = axis() else {
        return Ok(());
    };
    let (mut errors, mut opened) = (Vec::new(), Vec::new());
    for p in &cfg.plugins {
        let (name, module, def) = (&p.name, p.def.module.trim(), &p.def);

        let settings = match sink_settings(axis, module, &def.settings) {
            Ok(settings) => settings,
            Err(e) => {
                errors.push(format!("export.{name}.settings: {e}"));
                continue;
            }
        };
        let opened_sink = axis.open(module, &format!("export.{name}"), settings.as_value());
        let Ok(sink) = opened_sink.map_err(|e| errors.push(format!("export.{name}: {e}"))) else {
            continue;
        };

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
            reads: OnceLock::new(),
        });
    }
    if !errors.is_empty() {
        return Err(errors.join("\n  - "));
    }
    let _ = SINKS.set(opened);

    tracing::callsite::rebuild_interest_cache();
    Ok(())
}

#[derive(Default)]
struct Refreshes {
    running: bool,
    version: Option<u64>,
    next: Option<(crate::config::ExportDefs, u64)>,
}

static REFRESHES: std::sync::Mutex<Refreshes> = std::sync::Mutex::new(Refreshes {
    running: false,
    version: None,
    next: None,
});

pub(crate) fn queue_refresh(defs: &crate::config::ExportDefs, generation: u64) {
    let mut queued = REFRESHES.lock().unwrap_or_else(|p| p.into_inner());
    if queued.version.is_none_or(|version| generation > version) {
        queued.version = Some(generation);
        queued.next = Some((defs.clone(), generation));
    }
}

pub(crate) fn refresh_pending() {
    {
        let mut queued = REFRESHES.lock().unwrap_or_else(|p| p.into_inner());
        if queued.running {
            return;
        }
        queued.running = true;
    }
    loop {
        let next = {
            let mut queued = REFRESHES.lock().unwrap_or_else(|p| p.into_inner());
            let next = queued.next.take();
            if next.is_none() {
                queued.running = false;
            }
            next
        };
        let Some((defs, generation)) = next else {
            return;
        };
        refresh(&defs, generation);
    }
}

fn refresh(defs: &crate::config::ExportDefs, generation: u64) {
    let Some(axis) = axis() else {
        return;
    };
    let names: std::collections::BTreeSet<_> = sinks()
        .map(|sink| sink.name.as_str())
        .chain(defs.keys().map(String::as_str))
        .collect();
    for name in names {
        if requires_restart(name, defs.get(name)) {
            tracing::warn!(
                instance = %name,
                "export instance membership, module or projection differs from boot; restart is required for push delivery"
            );
        }
    }
    for sink in sinks() {
        let Some(def) = defs
            .get(&sink.name)
            .filter(|def| def.module.trim() == sink.module)
        else {
            continue;
        };
        let refreshed = sink_settings(axis, &sink.module, &def.settings)
            .and_then(|settings| sink.sink.refresh(settings.as_value(), generation));
        if let Err(error) = refreshed {
            tracing::warn!(
                instance = %sink.name,
                error = %error,
                "export refresh refused; the prior settings remain active"
            );
        }
    }
}

pub(crate) fn record_reads_on(amendments: &Arc<crate::audit::amend::NodeAmendments>) {
    for s in sinks() {
        let _ = s.reads.set(Arc::clone(amendments));
    }
}

pub(crate) fn deliver_logs(cache: &mut PayloadCache<'_>) {
    let op = cache.facts.ingress_protocol;
    deliver(ExportStream::Logs, op, |projection| cache.get(projection));
}

pub(crate) fn deliver(stream: ExportStream, op: &str, mut f: impl FnMut(Projection) -> Arc<Value>) {
    deliver_to(stream, op, |projection, _| f(projection));
}

pub(super) fn deliver_to(
    stream: ExportStream,
    op: &str,
    mut f: impl FnMut(Projection, bool) -> Arc<Value>,
) {
    for s in sinks().filter(|s| s.projection.wants_stream(stream)) {
        deliver_one(s, stream, op, &mut f);
    }
}

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
        Delivered::Queued => {
            if let Some(amendments) = s.reads.get() {
                crate::audit::amend::export_read(amendments, &s.module, op, &payload);
            }
        }
        Delivered::Shed => s.sink.shed(),
    }
}

pub fn start() -> Result<(), String> {
    let mut errors = Vec::new();
    for s in sinks() {
        if let Err(e) = s.sink.start() {
            errors.push(format!("export.{}: {e}", s.name));
            continue;
        }
        start_one(s);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n  - "))
    }
}

fn start_one(s: &PluginSink) {
    let stated = s.sink.admission();
    let _ = s.admission.set(Admission::of(&s.module, stated));
}

pub(crate) fn status() {
    sinks().for_each(|s| {
        let _ = s.sink.status();
    });
}

pub(crate) fn route_decls(cfg: &ExportCfg) -> Vec<RouteDecl> {
    route_decls_from(cfg, SINKS.get().map(Vec::as_slice).unwrap_or_default())
}

fn route_decls_from(cfg: &ExportCfg, boot_sinks: &[PluginSink]) -> Vec<RouteDecl> {
    let (scrape, rest): (Vec<_>, Vec<_>) = cfg.plugins.iter().partition(|p| p.scrape);
    let mut out = Vec::new();
    for p in scrape.into_iter().chain(rest) {
        let owner = if p.scrape {
            p.def.module.trim().to_string()
        } else {
            p.name.clone()
        };

        let module = p.def.module.trim();

        let opened = boot_sinks
            .iter()
            .find(|s| s.name == p.name && s.module == module && (!p.scrape || s.scrape))
            .or_else(|| {
                p.scrape
                    .then(|| boot_sinks.iter().find(|s| s.scrape && s.module == module))
                    .flatten()
            });
        let (public_routes, persistent_routes) = match opened {
            Some(s) => (
                s.sink.public_routes().to_vec(),
                s.sink.persistent_routes().to_vec(),
            ),
            None => axis().map_or_else(
                || (Vec::new(), Vec::new()),
                |a| (a.public_routes(module), a.persistent_routes(module)),
            ),
        };
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
            if persistent_routes.contains(&route.path) {
                continue;
            }
            if !p.scrape && public_routes.contains(&route.path) {
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
                source_instance: p.name.clone(),
                dispatch_available: opened.is_some(),
                kind: RouteKind::Export,
                scrape: p.scrape && public_routes.contains(&route.path),
                route,
                persistent: false,
                dispatch: dispatch.clone(),
            });
        }
    }
    if let Some(s) = boot_sinks.iter().find(|s| s.scrape) {
        let served: Arc<dyn PluginHttpDispatch> = Arc::new(Served(s.sink.clone()));
        let dispatch: Arc<dyn PluginHttpDispatch> = Arc::new(super::scrape::Granted(served));
        out.extend(
            s.sink
                .routes()
                .iter()
                .filter(|r| s.sink.persistent_routes().contains(&r.path))
                .map(|route| RouteDecl {
                    owner: s.module.clone(),
                    source_instance: s.name.clone(),
                    dispatch_available: true,
                    kind: RouteKind::Export,
                    route: route.clone(),
                    scrape: true,
                    persistent: true,
                    dispatch: dispatch.clone(),
                }),
        );
    }
    out
}

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

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn served(sink: Arc<dyn ExportCalls>) -> Arc<dyn PluginHttpDispatch> {
    Arc::new(Served(sink))
}

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
