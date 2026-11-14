// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::projection::{resolve_projection, Projection, Rendered};
use crate::config::secret::ResolvedSettings;
use crate::config::ExportCfg;
use crate::diagnostics::coded;
use crate::limits::admission::AdmissionGate;
use crate::plugin_routes::{PluginHttpDispatch, RouteDecl, RouteKind};
use busbar_contract::abi::export::{CheckPhase, ExportStream};
use busbar_contract::abi::mechanism::endpoint::*;
use busbar_contract::abi::mechanism::route::Route;
use busbar_contract::export_calls::{Delivered, ExportAxis, ExportCalls, ServeRequest};
use std::sync::{Arc, OnceLock};

const MAX_INFLIGHT_PLUGIN_DELIVERIES: usize = 64;

pub(super) fn axis() -> Option<&'static dyn ExportAxis> {
    crate::preflight::root_rows().export_axis
}

pub(crate) fn scrape_instance(
    projection: Projection,
    declared: Option<&[ExportStream]>,
    recorder: Option<busbar_contract::export_calls::RecorderRequirements>,
    already_scraping: bool,
) -> Result<
    (
        bool,
        Option<busbar_contract::export_calls::RecorderRequirements>,
    ),
    String,
> {
    let Some(recorder) = recorder else {
        return Ok((false, None));
    };
    recorder.validate()?;
    let metrics = ExportStream::Metrics;
    if !declared.is_some_and(|streams| streams.contains(&metrics)) {
        return Err("a recorder declaration requires the metrics stream".into());
    }
    if !projection.wants_stream(metrics) {
        return Ok((false, None));
    }
    if already_scraping {
        return Err("only one export instance may request the host recorder".into());
    }
    Ok((true, Some(recorder)))
}

pub(crate) fn configured_instance(
    name: &str,
    def: &crate::config::ExportDefCfg,
    projection: Projection,
    problems: Option<Vec<String>>,
    scrape: bool,
    linked_modules: impl FnOnce() -> Vec<String>,
    errors: &mut Vec<String>,
) -> Option<crate::config::PluginExportSettings> {
    match problems {
        Some(problems) => {
            errors.extend(problems);
            #[expect(
                clippy::disallowed_methods,
                reason = "config: an admitted export instance's settings, kept from config load"
            )]
            let settings = crate::config::PluginExportSettings {
                name: name.to_owned(),
                def: def.clone(),
                projection,
                scrape,
            };
            Some(settings)
        }
        None => {
            errors.push(
                coded::config_export_invalid(format!(
                    "export.{name}.module: unknown exporter '{}'; the built-in export modules are \
                 {}",
                    def.module.trim(),
                    linked_modules().join(" | ")
                ))
                .into(),
            );
            None
        }
    }
}

type Probed = (
    Option<Vec<ExportStream>>,
    Vec<String>,
    Option<busbar_contract::export_calls::RecorderRequirements>,
);

pub(crate) fn probe(
    name: &str,
    module: &str,
    settings: &busbar_contract::plugin_settings::Settings,
) -> Option<Probed> {
    let axis = axis()?;
    let (streams, problems, recorder) = match sink_settings(axis, module, settings) {
        Ok(cfg) => axis.probe(module, name, &cfg)?,
        Err(e) => {
            let written = settings.prepare();
            let (streams, _, _) = axis.probe(module, name, &written)?;
            #[expect(
                clippy::disallowed_methods,
                reason = "config: an export instance refused at config load"
            )]
            let refused = vec![format!("export.{name}.settings: {e}")];
            (streams, refused, None)
        }
    };
    let streams = streams.map(|b| declared_streams(&b));
    Some((streams, problems, recorder))
}

pub(crate) fn sink_settings(
    axis: &dyn ExportAxis,
    module: &str,
    settings: &busbar_contract::plugin_settings::Settings,
) -> Result<ResolvedSettings, String> {
    sink_settings_with_resolver(
        axis,
        module,
        settings,
        &crate::config::secret::SecretResolver::builtins_only(),
    )
}

fn sink_settings_with_resolver(
    axis: &dyn ExportAxis,
    module: &str,
    settings: &busbar_contract::plugin_settings::Settings,
    resolver: &dyn busbar_contract::secret::SecretResolve,
) -> Result<ResolvedSettings, String> {
    let secret = axis.secret_refs(module);
    let reference = axis.reference_fields(module);
    #[expect(
        clippy::disallowed_methods,
        reason = "config: an export module's declared settings slots, read at config load"
    )]
    let declared = [secret.as_slice(), reference.as_slice()].concat();
    let tree = settings.prepare();
    if declared.is_empty()
        || settings
            .undeclared_reference(&declared, &crate::config::secret::sugars())?
            .is_some()
    {
        return Ok(tree);
    }
    crate::config::secret::resolve_export_settings(
        settings,
        &secret,
        &reference,
        module,
        resolver,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
}

/// The streams a sink declares, by their byte codes.
fn streams_of(bytes: &[u8]) -> impl Iterator<Item = ExportStream> + '_ {
    bytes
        .iter()
        .filter_map(|&b| ExportStream::ALL.get(usize::from(b)).copied())
}

/// The streams a sink declares, held for config resolution.
fn declared_streams(bytes: &[u8]) -> Vec<ExportStream> {
    #[expect(
        clippy::disallowed_methods,
        reason = "config: a sink's declared streams resolve at config load"
    )]
    let streams = streams_of(bytes).collect();
    streams
}

pub(crate) fn linked_modules() -> Vec<String> {
    axis().map(|axis| axis.linked_modules()).unwrap_or_default()
}

pub(crate) fn one_instance(module: &str) -> bool {
    axis().is_some_and(|axis| axis.one_instance(module))
}

pub(crate) fn check_one_instance(
    module: &str,
    instances: &[(String, busbar_contract::plugin_settings::Settings)],
) -> Vec<String> {
    #[expect(
        clippy::disallowed_methods,
        reason = "config: a one-instance module's instances are checked at config load"
    )]
    let names: Vec<String> = instances.iter().map(|(n, _)| n.clone()).collect();
    #[expect(
        clippy::disallowed_methods,
        reason = "config: a one-instance module's instances are checked at config load"
    )]
    let found = axis()
        .and_then(|axis| {
            let held: Vec<_> = instances
                .iter()
                .map(|(_, settings)| sink_settings(axis, module, settings))
                .collect();
            let instances: Vec<_> = instances
                .iter()
                .zip(&held)
                .filter_map(|((name, _), resolved)| {
                    resolved.as_ref().ok().map(|value| (name.clone(), value))
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
    #[expect(
        clippy::disallowed_methods,
        reason = "config: an export instance refused at config load"
    )]
    let why = if found.is_empty() {
        ONE_INSTANCE_WHY.to_string()
    } else {
        found.join(" ")
    };
    #[expect(
        clippy::disallowed_methods,
        reason = "config: an export instance refused at config load"
    )]
    let refusals = rest
        .iter()
        .map(|name| {
            format!(
                "export.{name}: a second `module: {module}` instance (already defined as \
                 '{first}'). {why}"
            )
        })
        .collect();
    refusals
}

pub(crate) fn check(cfg: &ExportCfg, phase: CheckPhase, errors: &mut Vec<String>) {
    let Some(axis) = axis() else {
        return;
    };
    let phase = match phase {
        CheckPhase::Limits => busbar_contract::abi::export::CHECK_PHASE_LIMITS,
        CheckPhase::Instances => busbar_contract::abi::export::CHECK_PHASE_INSTANCES,
    };
    // busbar:expect(bp::fresh_buffer, reason = "config: each export module is checked once at config load")
    let mut modules: Vec<&str> = Vec::new();
    for p in &cfg.plugins {
        let module = p.def.module.trim();
        if modules.contains(&module) {
            continue;
        }
        modules.push(module);

        #[expect(
            clippy::disallowed_methods,
            reason = "config: each export module's instances are checked at config load"
        )]
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
        #[expect(
            clippy::disallowed_methods,
            reason = "config: each export module's instances are checked at config load"
        )]
        let instances: Vec<_> = held
            .iter()
            .map(|(name, settings)| (name.clone(), settings))
            .collect();
        errors.extend(axis.check(module, phase, &instances).unwrap_or_default());
    }
}

pub(super) struct PluginSink {
    name: String,
    module: Arc<str>,
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
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: a sink's admission gate is named once, when the sink starts"
        )]
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

/// Once OPEN completes, reloads cannot resize the live recorder's projection budget.
/// Outer None means startup admission has not happened yet; inner None means no recorder.
pub(crate) fn boot_recorder_requirements(
) -> Option<Option<busbar_contract::export_calls::RecorderRequirements>> {
    SINKS.get().map(|sinks| {
        sinks
            .iter()
            .find(|sink| sink.scrape)
            .and_then(|sink| sink.sink.recorder_requirements())
    })
}

pub fn requires_restart(name: &str, def: Option<&crate::config::ExportDefCfg>) -> bool {
    let sink = sinks().find(|sink| sink.name == name);
    let boot = sink.map(|sink| (&*sink.module, sink.projection, sink.sink.streams()));
    if definition_requires_restart(name, boot, def) {
        return true;
    }
    match (sink, def) {
        (Some(sink), Some(def)) => match probe(name, def.module.trim(), &def.settings) {
            Some((_, errors, recorder)) => {
                !errors.is_empty() || recorder != sink.sink.recorder_requirements()
            }
            None => true,
        },
        _ => false,
    }
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
    // busbar:expect(bp::fresh_buffer, reason = "config: a reload compares one instance's projection with its boot projection")
    let mut errors = Vec::new();
    let desired = resolve_projection(
        name,
        module,
        Some(&declared_streams(streams)),
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
    // busbar:expect(bp::fresh_buffer, reason = "boot: the export sinks open once, at boot")
    let mut errors = Vec::new();
    // busbar:expect(bp::fresh_buffer, reason = "boot: the export sinks open once, at boot")
    let mut opened = Vec::new();
    for p in &cfg.plugins {
        let (name, module, def) = (&p.name, p.def.module.trim(), &p.def);

        let settings = match sink_settings(axis, module, &def.settings) {
            Ok(settings) => settings,
            Err(e) => {
                errors.push(
                    coded::config_export_invalid(format!("export.{name}.settings: {e}")).into(),
                );
                continue;
            }
        };
        let admitted = busbar_contract::export_calls::ExportOpening::new(def.settings.clone());
        let prepared = admitted.with_settings(settings.clone());
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: an export sink is labelled once, when it opens"
        )]
        let opened_sink = axis.open(module, &format!("export.{name}"), &prepared);
        let Ok(sink) = instance_opened(name, opened_sink)
            .map_err(|e| errors.push(coded::config_export_invalid(e).into()))
        else {
            continue;
        };

        let projection = resolve_projection(
            name,
            module,
            Some(&declared_streams(sink.streams())),
            def.streams.as_deref(),
            def.fields.as_deref(),
            false,
            &mut errors,
        );
        let expected_recorder = if p.scrape { cfg.recorder } else { None };
        let opened_recorder = if projection.wants_stream(ExportStream::Metrics) {
            sink.recorder_requirements()
        } else {
            None
        };
        if opened_recorder != expected_recorder {
            errors.push(
                coded::config_export_invalid(format!(
                    "export.{name}: recorder declaration changed since configuration admission"
                ))
                .into(),
            );
            continue;
        }
        let span_record = sink.takes_span_records();
        opened.push(PluginSink {
            name: name.clone(),
            module: module.into(),
            span_record,
            sink,
            scrape: p.scrape,
            projection,
            admission: OnceLock::new(),
            reads: OnceLock::new(),
        });
    }
    if !errors.is_empty() {
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: the export sinks' refusals, reported once"
        )]
        return Err(errors.join("\n  - "));
    }
    let _ = SINKS.set(opened);
    super::traces::sinks_fixed();
    tracing::callsite::rebuild_interest_cache();
    Ok(())
}

fn instance_opened<T>(name: &str, opened: Result<T, String>) -> Result<T, String> {
    #[expect(
        clippy::disallowed_methods,
        reason = "boot: an export sink refused when it opens"
    )]
    let opened = opened.map_err(|error| format!("export.{name}: {error}"));
    opened
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
    #[expect(
        clippy::disallowed_methods,
        reason = "config: a config reload walks the boot and configured instance names once"
    )]
    let names: std::collections::BTreeSet<_> = sinks()
        .map(|sink| sink.name.as_str())
        .chain(defs.keys().map(String::as_str))
        .collect();
    for name in names {
        if requires_restart(name, defs.get(name)) {
            tracing::warn!(
                instance = %name,
                "export instance membership, module, projection or recorder requirements differ from boot; restart is required for push delivery"
            );
        }
    }
    for sink in sinks() {
        let Some(def) = defs
            .get(&sink.name)
            .filter(|def| def.module.trim() == &*sink.module)
        else {
            continue;
        };
        if requires_restart(&sink.name, Some(def)) {
            continue;
        }
        let refreshed = sink_settings(axis, &sink.module, &def.settings)
            .and_then(|settings| sink.sink.refresh(&settings, generation));
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

/// Hand each sink subscribed to `stream` its own record, rendered to its projection by `f`.
pub(crate) fn deliver(stream: ExportStream, op: &str, mut f: impl FnMut(Projection) -> Rendered) {
    deliver_to(stream, op, |projection, _| f(projection));
}

pub(super) fn deliver_to(
    stream: ExportStream,
    op: &str,
    mut f: impl FnMut(Projection, bool) -> Rendered,
) {
    let mut handed = Handed::default();
    for s in sinks().filter(|s| s.projection.wants_stream(stream)) {
        deliver_one(s, stream, &mut f, &mut handed);
    }
    handed.record(op);
}

/// The sinks of one event that queued their line and still owe a durable access amendment.
/// They are recorded together: one amendment per sink, one durable commit per event.
#[derive(Default)]
struct Handed {
    amendments: Option<Arc<crate::audit::amend::NodeAmendments>>,
    runtime: Option<tokio::runtime::Handle>,
    reads: Vec<(String, Arc<Value>)>,
    sinks: Vec<Arc<dyn ExportCalls>>,
    permits: Vec<Arc<tokio::sync::OwnedSemaphorePermit>>,
}

impl Handed {
    fn record(self, op: &str) {
        let Handed {
            amendments,
            runtime,
            reads,
            sinks,
            permits,
        } = self;
        let (Some(amendments), Some(runtime)) = (amendments, runtime) else {
            return;
        };
        if reads.is_empty() {
            return;
        }
        let op = op.to_owned();
        runtime.spawn(async move {
            // Retain every sink's admission through its durable access amendment, even if the
            // sink releases its delivery permit immediately.
            let _permits = permits;
            if crate::audit::amend::export_reads(&amendments, &op, &reads)
                .await
                .is_err()
            {
                // The original access facts remain in the shared native owner's queue; do not
                // report a durable audit success for any sink of the set.
                for sink in sinks {
                    sink.shed();
                }
            }
        });
    }
}

fn deliver_one(
    s: &PluginSink,
    stream: ExportStream,
    op: &str,
    f: &mut impl FnMut(Projection, bool) -> Rendered,
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
    let Rendered { line, members } = f(s.projection, s.span_record);
    let amendments = s.reads.get().cloned();
    let runtime = if amendments.is_some() {
        match handed
            .runtime
            .clone()
            .map_or_else(tokio::runtime::Handle::try_current, Ok)
        {
            Ok(runtime) => Some(runtime),
            Err(_) => {
                s.sink.shed();
                return;
            }
        }
    } else {
        None
    };
    // Retain admission through both actual delivery and its durable access
    // amendment, even if the sink releases its delivery permit immediately.
    let permit = Arc::new(permit);
    match s.sink.deliver(stream as u8, line, Box::new(permit.clone())) {
        Delivered::Queued => {
            let (Some(amendments), Some(runtime)) = (amendments, runtime) else {
                return;
            };
            let op = op.to_owned();
            let module = Arc::clone(&s.module);
            let sink = s.sink.clone();
            runtime.spawn(async move {
                let _permit = permit;
                if crate::audit::amend::export_read(&amendments, &module, &op, members)
                    .await
                    .is_err()
                {
                    // The original access fact remains in the shared native
                    // owner's queue; do not report a durable audit success.
                    sink.shed();
                }
            });
        }
        Delivered::Shed => s.sink.shed(),
    }
}

pub fn start() -> Result<(), String> {
    let mut errors: Vec<String> = Vec::new();
    for s in sinks() {
        if let Err(e) = s.sink.start() {
            errors.push(coded::config_export_invalid(format!("export.{}: {e}", s.name)).into());
            continue;
        }
        start_one(s);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: the export sinks' refusals, reported once"
        )]
        let refused = errors.join("\n  - ");
        Err(refused)
    }
}

fn start_one(s: &PluginSink) {
    let stated = s.sink.admission();
    let _ = s.admission.set(Admission::of(&s.module, stated));
}

/// How often a scrape crosses into every export sink's STATUS. A scrape arrives every few
/// seconds per scraper and its answer is not read here, so crossing on every scrape is waste.
pub(crate) const STATUS_REFRESH: std::time::Duration = std::time::Duration::from_secs(15);

static STATUS_AT: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);

/// Whether a STATUS round is due at `now` given the last one in `at`; marks `now` when it is.
fn status_due(at: &std::sync::Mutex<Option<std::time::Instant>>, now: std::time::Instant) -> bool {
    let mut at = at.lock().unwrap_or_else(|p| p.into_inner());
    if at.is_some_and(|last| now.saturating_duration_since(last) < STATUS_REFRESH) {
        return false;
    }
    *at = Some(now);
    true
}

/// Cross every export sink's STATUS, at most once per [`STATUS_REFRESH`].
pub(crate) fn status_if_stale() {
    if !status_due(&STATUS_AT, std::time::Instant::now()) {
        return;
    }
    sinks().for_each(|s| {
        let _ = s.sink.status();
    });
}

pub(crate) fn route_decls(cfg: &ExportCfg) -> Vec<RouteDecl> {
    route_projection(cfg).0
}

pub(crate) fn route_projection(
    cfg: &ExportCfg,
) -> (Vec<RouteDecl>, std::collections::HashSet<String>) {
    project_routes(cfg, SINKS.get().map(Vec::as_slice).unwrap_or_default())
}

#[cfg(test)]
fn route_decls_from(cfg: &ExportCfg, boot_sinks: &[PluginSink]) -> Vec<RouteDecl> {
    project_routes(cfg, boot_sinks).0
}

fn project_routes(
    cfg: &ExportCfg,
    boot_sinks: &[PluginSink],
) -> (Vec<RouteDecl>, std::collections::HashSet<String>) {
    let (scrape, rest): (Vec<_>, Vec<_>) = cfg.plugins.iter().partition(|p| p.scrape);
    // busbar:expect(bp::fresh_buffer, reason = "config: the export route table is built once per config generation")
    let mut out = Vec::new();
    #[expect(
        clippy::disallowed_types,
        reason = "config: the export route table is built once per config generation; the route table takes this set type"
    )]
    let mut withheld = std::collections::HashSet::new();
    for p in scrape.into_iter().chain(rest) {
        #[expect(
            clippy::disallowed_methods,
            reason = "config: the export route table is built once per config generation"
        )]
        let owner = if p.scrape {
            p.def.module.trim().to_string()
        } else {
            p.name.clone()
        };

        let module = p.def.module.trim();

        let opened = boot_sinks
            .iter()
            .find(|s| s.name == p.name && *s.module == *module && (!p.scrape || s.scrape))
            .or_else(|| {
                p.scrape
                    .then(|| boot_sinks.iter().find(|s| s.scrape && *s.module == *module))
                    .flatten()
            });
        #[expect(
            clippy::disallowed_methods,
            reason = "config: the export route table is built once per config generation"
        )]
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
        #[expect(
            clippy::disallowed_methods,
            reason = "config: the export route table is built once per config generation"
        )]
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

        let wholly_withheld = opened.is_some()
            && !p.scrape
            && routes
                .iter()
                .all(|route| public_routes.contains(&route.path))
            && routes
                .iter()
                .any(|route| !persistent_routes.contains(&route.path));
        for route in routes {
            if persistent_routes.contains(&route.path) {
                continue;
            }
            if !p.scrape && public_routes.contains(&route.path) {
                tracing::warn!(
                    instance = %p.name,
                    path = %route.path,
                    "an export instance that is not the scrape sink declares a well-known \
                     exposition path; it is not mounted (only the admitted recorder consumer serves it)"
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
        if wholly_withheld {
            withheld.insert(p.name.clone());
        }
    }
    if let Some(s) = boot_sinks.iter().find(|s| s.scrape) {
        let served: Arc<dyn PluginHttpDispatch> = Arc::new(Served(s.sink.clone()));
        let dispatch: Arc<dyn PluginHttpDispatch> = Arc::new(super::scrape::Granted(served));
        #[expect(
            clippy::disallowed_methods,
            reason = "config: the export route table is built once per config generation"
        )]
        out.extend(
            s.sink
                .routes()
                .iter()
                .filter(|r| s.sink.persistent_routes().contains(&r.path))
                .map(|route| RouteDecl {
                    owner: s.module.to_string(),
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
    (out, withheld)
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
