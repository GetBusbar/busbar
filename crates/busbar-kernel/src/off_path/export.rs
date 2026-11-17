// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `export`'s off-path code: the projection grammar's config-time resolution and its refusals, the
//! export sinks' admission, opening and start at boot, their reload refresh, the route table built
//! once per configuration generation, and the admin configuration schema. The request path only
//! reads what this builds (the opened sinks, their projections and the member order).

use crate::config::secret::ResolvedSettings;
use crate::config::ExportCfg;
use crate::diagnostics::coded;
use crate::export::plugin::{
    axis, Admission, Exports, PluginSink, Served, Unopened, MAX_INFLIGHT_PLUGIN_DELIVERIES,
};
use crate::export::projection::{
    produced_fields, stream_produced, Member, Projection, FIELDS, PRODUCED_STREAMS,
};
use crate::limits::admission::AdmissionGate;
use crate::plugin_routes::{PluginHttpDispatch, RouteDecl, RouteKind};
use busbar_contract::abi::export::{CheckPhase, ExportField};
use busbar_contract::abi::mechanism::route::Route;
use busbar_contract::export_calls::ExportAxis;
use busbar_contract::export_stream::ExportStream;
use std::sync::Arc;

// --- export (mod.rs) ---

/// Host-owned user configuration capabilities, derived from the same producer tables used by
/// export projection resolution. Module-specific carried streams remain an admission check.
#[cfg(feature = "openapi-schema")]
pub fn configuration_capabilities() -> serde_json::Value {
    serde_json::json!({
        "durable": false,
        "request_timing": {
            "profile": "observed-pump-v1",
            "stream": "traces",
            "record": "span.attributes",
            "requires": "enabled hot-path tracing and an exporter taking full span records",
            "coverage": "selected request-pump attempts, including normal, degraded and retry attempts; not pre-route refusals or session traffic outside the request pump",
            "identity": "trace_id/parent_span_id link the request; the request_attempts parent span scopes attempt ordinals, including separate session turns; retry_of_attempt names its predecessor",
            "clock": "monotonic elapsed microseconds from the attempt timing guard after member selection; route_wait_us is the preceding member selection duration",
            "intervals": {
                "route_wait_us": "member selection, including waits within selection; not an isolated queue duration",
                "response_ready_us": "first observed far-end status or nonempty bytes; not stream completion",
                "first_body_us": "first nonempty non-trailer far-end bytes; not a token event or TTFT",
                "far_end_last_us": "far-end terminal piece or end-of-pieces without cut/failover",
                "producer_complete_us": "pump completed its output writes; not proof of remote client consumption",
                "cancelled_us": "pump observed cancellation; cancel_reason is the engine reason code",
                "attempt_end_us": "pump attempt terminated, retried, or was abandoned"
            },
            "unknown": ["first_token", "provider_internal_cpu", "isolated_queue_wait", "client_consumption"],
            "missing_fields": "unobserved; never zero or inferred",
            "aggregation": "offsets overlap; never sum them as disjoint durations; busy_ns/idle_ns are span entry accounting, not CPU profiling",
            "sampling": "no producer probabilistic sampling; disabled/level-filtered tracing omits records; exporter sampling is exporter-specific",
            "loss": "bounded best-effort exporter admission and queue; host refusals call exporter shed; inspect exporter status for loss, absence is not zero loss or complete coverage",
            "privacy": "added timing fields contain generated identity, destination index, fixed outcomes and timings only; no body, headers, prompt, credential or provider error text; other span attributes retain the existing exporter policy",
            "metrics": "existing producer_drive and response_ready cumulative distributions are unchanged"
        },
        "streams": PRODUCED_STREAMS.iter().map(|stream| {
            let produced = produced_fields(*stream);
            serde_json::json!({
                "name": stream.as_token(),
                "default_fields": if *stream == ExportStream::Traces {
                    stream.default_fields()
                } else { produced }.iter().map(|field| field.as_token()).collect::<Vec<_>>(),
                "produced_fields": produced.iter().map(|field| field.as_token()).collect::<Vec<_>>(),
                "pinned_fields": stream.pinned_fields().iter().map(|field| field.as_token()).collect::<Vec<_>>(),
                "fields_override": !stream.default_fields().is_empty()
                    && stream.pinned_fields().iter().all(|field| produced.contains(field))
            })
        }).collect::<Vec<_>>()
    })
}

/// Exercise the owning projection resolver without loading an exporter in focused schema tests.
#[cfg(all(feature = "openapi-schema", any(test, feature = "test-support")))]
pub fn validate_configuration_projection(
    def: &crate::config::ExportDefCfg,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    resolve_projection(
        "schema-test",
        &def.module,
        None,
        def.streams.as_deref(),
        def.fields.as_deref(),
        def.durable,
        &mut errors,
    );
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// --- export::projection ---

/// Every member, ordered by name (as a JSON object map orders its keys), with each member's rank in
/// that order: built once, for `projection::MEMBER_ORDER`.
pub(crate) fn member_order() -> ([Member; FIELDS + 1], [u8; FIELDS + 1]) {
    let mut order = [Member::Span; FIELDS + 1];
    for (bit, (slot, field)) in order.iter_mut().zip(ExportField::ALL).enumerate() {
        *slot = Member::Field(*field, bit as u32);
    }
    order.sort_by_key(|member| member.name());
    let mut rank = [0u8; FIELDS + 1];
    for (at, member) in order.iter().enumerate() {
        let index = match *member {
            Member::Field(_, bit) => bit as usize,
            Member::Span => FIELDS,
        };
        rank[index] = at as u8;
    }
    (order, rank)
}

pub(crate) fn resolve_projection(
    name: &str,
    module: &str,
    module_carries: Option<&[ExportStream]>,
    stream_tokens: Option<&[String]>,
    fields: Option<&[String]>,
    durable: bool,
    errors: &mut Vec<String>,
) -> Projection {
    let before = errors.len();

    if durable {
        errors.push(
            coded::config_export_invalid(format!(
            "export.{name}.durable: `true` is NOT YET IMPLEMENTED in this release — core does not \
             spool this sink's records, so accepting it would promise a completeness guarantee \
             nothing delivers. The key is reserved and the spool arrives in a later release; set \
             `durable: false` (or omit it) meanwhile."
        ))
            .into(),
        );
    }

    let subscribed: Vec<ExportStream> = match stream_tokens {
        None => {
            let produced: Vec<ExportStream> = module_carries
                .unwrap_or(PRODUCED_STREAMS)
                .iter()
                .copied()
                .filter(|s| stream_produced(*s))
                .collect();
            if produced.is_empty() {
                errors.push(
                    coded::config_export_invalid(format!(
                        "export.{name}.streams: omitted, and `module: {module}` carries only \
                         streams this release has NO PRODUCER for ({}), so the sink would \
                         deliver nothing while reporting success. The streams this release \
                         produces are: {}.",
                        tokens(module_carries.unwrap_or(&[])),
                        tokens(PRODUCED_STREAMS)
                    ))
                    .into(),
                );
            }
            produced
        }
        Some([]) => {
            errors.push(
                coded::config_export_invalid(format!(
                "export.{name}.streams: is EMPTY — a sink that subscribes to no stream receives \
                 nothing at all. Omit the key to take the module's own streams ({}), or name the \
                 streams you want.",
                tokens(module_carries.unwrap_or(&[]))
            ))
                .into(),
            );
            Vec::new()
        }
        Some(list) => {
            let mut out = Vec::new();
            for tok in list {
                let Some(stream) = ExportStream::from_token(tok) else {
                    if tok == "audit" {
                        errors.push(
                            coded::config_export_invalid(format!(
                            "export.{name}.streams: `audit` is NOT a stream — it was a use case, \
                             not a data type. An auditor is a SINK whose projection includes the \
                             right streams (e.g. `streams: [logs, identity, decisions, events, \
                             costs]`), which is strictly more expressive. The streams are: {}.",
                            ExportStream::vocabulary()
                        ))
                            .into(),
                        );
                    } else {
                        errors.push(
                            coded::config_export_invalid(format!(
                            "export.{name}.streams: unknown stream `{tok}`; the streams are: {}.",
                            ExportStream::vocabulary()
                        ))
                            .into(),
                        );
                    }
                    continue;
                };
                if !stream_produced(stream) {
                    errors.push(
                        coded::config_export_invalid(format!(
                        "export.{name}.streams: `{}` HAS NO PRODUCER in this release — nothing \
                         generates those records yet, so subscribing would deliver nothing while \
                         reporting success. It arrives in a later release. The streams this \
                         release produces are: {}.",
                        stream.as_token(),
                        tokens(PRODUCED_STREAMS)
                    ))
                        .into(),
                    );
                    continue;
                }
                if let Some(carried) = module_carries {
                    if !carried.contains(&stream) {
                        errors.push(
                            coded::config_export_invalid(format!(
                                "export.{name}.streams: `module: {module}` cannot carry the `{}` \
                             stream (it carries: {}), so this subscription would deliver nothing. \
                             Point a different module at this stream, or drop it from `streams:`.",
                                stream.as_token(),
                                tokens(carried)
                            ))
                            .into(),
                        );
                        continue;
                    }
                }
                if out.contains(&stream) {
                    errors.push(
                        coded::config_export_invalid(format!(
                            "export.{name}.streams: `{}` is listed twice.",
                            stream.as_token()
                        ))
                        .into(),
                    );
                    continue;
                }
                out.push(stream);
            }
            out
        }
    };

    let granted: Vec<ExportField> = match fields {
        None => subscribed
            .iter()
            .flat_map(|s| match s {
                ExportStream::Traces => s.default_fields(),
                other => produced_fields(*other),
            })
            .copied()
            .collect(),
        Some(list) => resolve_fields_override(name, list, &subscribed, errors),
    };

    if errors.len() != before {
        return Projection::default();
    }
    Projection::from_parts(&subscribed, &granted)
}

fn resolve_fields_override(
    name: &str,
    list: &[String],
    subscribed: &[ExportStream],
    errors: &mut Vec<String>,
) -> Vec<ExportField> {
    if list.is_empty() {
        errors.push(coded::config_export_invalid(format!(
            "export.{name}.fields: is EMPTY — `fields:` is an EXHAUSTIVE OVERRIDE, so an empty list \
             means a record with no fields at all. Omit the key to take each subscribed stream's \
             default fields."
        )).into());
        return Vec::new();
    }

    let mut blocked = false;
    for s in subscribed {
        if s.default_fields().is_empty() {
            errors.push(
                coded::config_export_invalid(format!(
                "export.{name}.fields: the `{}` stream has no per-record fields to project (its \
                 unit is the documented metric catalog — families, not record fields), so \
                 `fields:` cannot apply to it.",
                s.as_token()
            ))
                .into(),
            );
            blocked = true;
            continue;
        }
        let produced = produced_fields(*s);
        if let Some(missing) = s
            .pinned_fields()
            .iter()
            .find(|p| !produced.contains(p))
            .copied()
        {
            errors.push(
                coded::config_export_invalid(format!(
                "export.{name}.fields: the `{}` stream cannot be projected with `fields:` in this \
                 release — its PINNED field `{}` (which `fields:` may never omit, because it is \
                 what makes the records joinable) HAS NO PRODUCER yet and arrives in a later \
                 release. Omit `fields:` to receive the stream's produced default set.",
                s.as_token(),
                missing.as_token()
            ))
                .into(),
            );
            blocked = true;
        }
    }

    let mut granted: Vec<ExportField> = Vec::new();
    for tok in list {
        let Some(field) = ExportField::from_token(tok) else {
            errors.push(
                coded::config_export_invalid(format!(
                "export.{name}.fields: unknown field `{tok}`. The fields of the subscribed streams \
                 are: {}.",
                subscribed_field_tokens(subscribed)
            ))
                .into(),
            );
            continue;
        };
        if !subscribed
            .iter()
            .any(|s| s.default_fields().contains(&field))
        {
            errors.push(
                coded::config_export_invalid(format!(
                "export.{name}.fields: `{tok}` is not a field of any subscribed stream ({}), so it \
                 would never arrive. The fields of the subscribed streams are: {}.",
                tokens(subscribed),
                subscribed_field_tokens(subscribed)
            ))
                .into(),
            );
            continue;
        }
        if !blocked
            && !subscribed
                .iter()
                .any(|s| produced_fields(*s).contains(&field))
        {
            errors.push(coded::config_export_invalid(format!(
                "export.{name}.fields: `{tok}` HAS NO PRODUCER in this release — it is a documented \
                 field of a subscribed stream but nothing fills it in yet, so asking for it \
                 explicitly would leave a permanently-absent key. It arrives in a later release."
            )).into());
            continue;
        }
        if granted.contains(&field) {
            errors.push(
                coded::config_export_invalid(format!(
                    "export.{name}.fields: `{tok}` is listed twice."
                ))
                .into(),
            );
            continue;
        }
        granted.push(field);
    }

    if !blocked {
        for s in subscribed {
            for pinned in s.pinned_fields() {
                if !granted.contains(pinned) {
                    errors.push(
                        coded::config_export_invalid(format!(
                        "export.{name}.fields: omits `{}`, which is PINNED on the `{}` stream. \
                         `fields:` bounds what a sink is DISCLOSED, but it must not break the \
                         records' STRUCTURE: {} Add `{}` to `fields:`, or omit `fields:` to take \
                         the stream's defaults.",
                        pinned.as_token(),
                        s.as_token(),
                        pinned_reason(*pinned),
                        pinned.as_token()
                    ))
                        .into(),
                    );
                }
            }
        }
    }
    granted
}

fn pinned_reason(field: ExportField) -> &'static str {
    match field {
        ExportField::CorrelationId => {
            "one request is split across several streams, and `correlation_id` is the join key that \
             reassembles them — without it the records are unjoinable."
        }
        ExportField::PrevHash => {
            "it is the link in the event hash chain — without it the chain cannot be verified."
        }
        ExportField::Seq => "it is the event's position in the chain.",
        ExportField::Ts => "it is when the event happened, and part of what the chain hashes.",
        ExportField::TraceId | ExportField::SpanId => {
            "it is the span tree's own identity — without it a span cannot be placed in a trace."
        }
        _ => "it is structural to the stream's records.",
    }
}

/// Tokens separated by ` | `, written straight into the message they appear in.
struct Joined<I>(I);

impl<I: Iterator<Item = &'static str> + Clone> std::fmt::Display for Joined<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, token) in self.0.clone().enumerate() {
            if i > 0 {
                f.write_str(" | ")?;
            }
            f.write_str(token)?;
        }
        Ok(())
    }
}

fn tokens(streams: &[ExportStream]) -> impl std::fmt::Display + '_ {
    Joined(streams.iter().map(|s| s.as_token()))
}

fn subscribed_field_tokens(subscribed: &[ExportStream]) -> impl std::fmt::Display + '_ {
    Joined(
        ExportField::ALL
            .iter()
            .filter(|f| subscribed.iter().any(|s| s.default_fields().contains(f)))
            .map(|f| f.as_token()),
    )
}

// --- export::plugin: config admission ---

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
            Some(crate::config::PluginExportSettings {
                name: name.to_owned(),
                def: def.clone(),
                projection,
                scrape,
            })
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
            (streams, vec![format!("export.{name}.settings: {e}")], None)
        }
    };
    let streams = streams.map(|b| declared_streams(&b));
    Some((streams, problems, honoured(module, recorder)))
}

/// The host recorder backs busbar's own `/metrics`, so only a FIRST-PARTY row (linked, or dropped in
/// signed by the release key) may request it. A third party's recorder declaration is not honoured:
/// its instance is an ordinary `metrics` subscriber and never the scrape sink (#65).
fn honoured(
    module: &str,
    recorder: Option<busbar_contract::export_calls::RecorderRequirements>,
) -> Option<busbar_contract::export_calls::RecorderRequirements> {
    recorder.filter(|_| axis().is_some_and(|axis| axis.first_party(module)))
}

pub(crate) fn sink_settings(
    axis: &dyn ExportAxis,
    module: &str,
    settings: &busbar_contract::plugin_settings::Settings,
) -> Result<ResolvedSettings, String> {
    // Export sinks are process-lifetime and hold no generation of their own: their settings read
    // the shorthand admission last published (SECRET-SHORTHAND-BOOT OQ3).
    sink_settings_with_resolver(
        axis,
        module,
        settings,
        &crate::config::secret::SecretResolver::builtins_only()
            .with_sources(crate::config::secret::admitted_sugars()),
    )
}

pub(crate) fn sink_settings_with_resolver(
    axis: &dyn ExportAxis,
    module: &str,
    settings: &busbar_contract::plugin_settings::Settings,
    resolver: &dyn busbar_contract::secret::SecretResolve,
) -> Result<ResolvedSettings, String> {
    let secret = axis.secret_refs(module);
    let reference = axis.reference_fields(module);
    let declared = [secret.as_slice(), reference.as_slice()].concat();
    let tree = settings.prepare();
    let none = busbar_contract::secret_ref::Sugars::default();
    let sources = resolver.sources().unwrap_or(&none);
    if declared.is_empty() || settings.undeclared_reference(&declared, sources)?.is_some() {
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

/// The streams a sink declares, held for config resolution.
pub(crate) fn declared_streams(bytes: &[u8]) -> Vec<ExportStream> {
    bytes
        .iter()
        .filter_map(|&b| ExportStream::ALL.get(usize::from(b)).copied())
        .collect()
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
    let names: Vec<String> = instances.iter().map(|(n, _)| n.clone()).collect();
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
            .map(|(name, settings)| (name.clone(), settings))
            .collect();
        errors.extend(axis.check(module, phase, &instances).unwrap_or_default());
    }
}

// --- export::plugin: boot (open, start) and reload ---

impl Admission {
    pub(crate) fn of(module: &str, stated: Option<(bool, u64, String)>) -> Admission {
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

pub fn requires_restart(
    exports: &Exports,
    name: &str,
    def: Option<&crate::config::ExportDefCfg>,
) -> bool {
    let sink = exports.sinks.iter().find(|sink| sink.name == name);
    let boot = sink.map(|sink| (&*sink.module, sink.projection, sink.sink.streams()));
    if definition_requires_restart(name, boot, def) {
        return true;
    }
    match (sink, def) {
        (Some(sink), Some(def)) => match probe(name, def.module.trim(), &def.settings) {
            Some((_, errors, recorder)) => {
                !errors.is_empty()
                    || recorder != honoured(&sink.module, sink.sink.recorder_requirements())
            }
            None => true,
        },
        _ => false,
    }
}

pub(crate) fn definition_requires_restart(
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
        Some(&declared_streams(streams)),
        def.streams.as_deref(),
        def.fields.as_deref(),
        false,
        &mut errors,
    );
    !errors.is_empty() || desired != projection
}

/// Compose the kernel projections over instances already opened by the process root.
/// This path never opens another instance or resolves settings through the legacy axis.
pub fn open_prepared(
    cfg: &ExportCfg,
    prepared: &std::collections::BTreeMap<
        String,
        Arc<dyn busbar_contract::export_calls::ExportCalls>,
    >,
    amendments: Arc<crate::audit::amend::NodeAmendments>,
) -> Result<Exports, String> {
    if prepared
        .keys()
        .any(|name| !cfg.plugins.iter().any(|plugin| &plugin.name == name))
    {
        return Err("opened export has no effective configuration projection".into());
    }
    open_with(cfg, amendments, |name, _| {
        prepared
            .get(name)
            .cloned()
            .ok_or_else(|| format!("export.{name}: no opened MIN3 export instance"))
    })
}

fn open_with(
    cfg: &ExportCfg,
    amendments: Arc<crate::audit::amend::NodeAmendments>,
    mut open: impl FnMut(
        &str,
        &crate::config::ExportDefCfg,
    ) -> Result<Arc<dyn busbar_contract::export_calls::ExportCalls>, String>,
) -> Result<Exports, String> {
    let mut errors = Vec::new();
    let mut opened = Vec::new();
    for p in &cfg.plugins {
        let (name, module, def) = (&p.name, p.def.module.trim(), &p.def);

        let opened_sink = open(name, def);
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
            honoured(module, sink.recorder_requirements())
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
        let admission = Admission::of(module, sink.admission());
        opened.push(PluginSink {
            name: name.clone(),
            module: module.into(),
            span_record,
            sink,
            scrape: p.scrape,
            projection,
            admission,
            started: std::sync::atomic::AtomicBool::new(false),
            reads: Some(Arc::clone(&amendments)),
        });
    }
    if !errors.is_empty() {
        return Err(errors.join("\n  - "));
    }
    Ok(Exports {
        sinks: opened,
        ..Exports::default()
    })
}

pub(crate) fn instance_opened<T>(name: &str, opened: Result<T, String>) -> Result<T, String> {
    opened.map_err(|error| format!("export.{name}: {error}"))
}

#[derive(Default)]
pub(crate) struct Refreshes {
    running: bool,
    version: Option<u64>,
    next: Option<(crate::config::ExportDefs, u64)>,
}

pub(crate) fn queue_refresh(exports: &Exports, defs: &crate::config::ExportDefs, generation: u64) {
    let mut queued = exports.refreshes.lock().unwrap_or_else(|p| p.into_inner());
    if queued.version.is_none_or(|version| generation > version) {
        queued.version = Some(generation);
        queued.next = Some((defs.clone(), generation));
    }
}

pub(crate) fn refresh_pending(exports: &Exports) {
    {
        let mut queued = exports.refreshes.lock().unwrap_or_else(|p| p.into_inner());
        if queued.running {
            return;
        }
        queued.running = true;
    }
    loop {
        let next = {
            let mut queued = exports.refreshes.lock().unwrap_or_else(|p| p.into_inner());
            let next = queued.next.take();
            if next.is_none() {
                queued.running = false;
            }
            next
        };
        let Some((defs, generation)) = next else {
            return;
        };
        refresh(exports, &defs, generation);
    }
}

fn refresh(exports: &Exports, defs: &crate::config::ExportDefs, generation: u64) {
    let Some(axis) = axis() else {
        return;
    };
    let names: std::collections::BTreeSet<_> = exports
        .sinks
        .iter()
        .map(|sink| sink.name.as_str())
        .chain(defs.keys().map(String::as_str))
        .collect();
    for name in names {
        if requires_restart(exports, name, defs.get(name)) {
            tracing::warn!(
                instance = %name,
                "export instance membership, module, projection or recorder requirements differ from boot; restart is required for push delivery"
            );
        }
    }
    for sink in &exports.sinks {
        let Some(def) = defs
            .get(&sink.name)
            .filter(|def| def.module.trim() == &*sink.module)
        else {
            continue;
        };
        if requires_restart(exports, &sink.name, Some(def)) {
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

pub fn start(exports: &Exports) -> Result<(), String> {
    let mut errors: Vec<String> = Vec::new();
    for s in &exports.sinks {
        if let Err(e) = s.sink.start() {
            errors.push(coded::config_export_invalid(format!("export.{}: {e}", s.name)).into());
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

pub(crate) fn start_one(s: &PluginSink) {
    s.started.store(true, std::sync::atomic::Ordering::Release);
}

// --- export::plugin: the route table, once per configuration generation ---

pub(crate) fn route_decls(cfg: &ExportCfg) -> Vec<RouteDecl> {
    route_projection(cfg, None).0
}

pub(crate) fn route_projection(
    cfg: &ExportCfg,
    exports: Option<&Exports>,
) -> (Vec<RouteDecl>, std::collections::HashSet<String>) {
    project_routes(
        cfg,
        exports
            .map(|exports| exports.sinks.as_slice())
            .unwrap_or_default(),
    )
}

#[cfg(test)]
pub(crate) fn route_decls_from(cfg: &ExportCfg, boot_sinks: &[PluginSink]) -> Vec<RouteDecl> {
    project_routes(cfg, boot_sinks).0
}

pub(crate) fn project_routes(
    cfg: &ExportCfg,
    boot_sinks: &[PluginSink],
) -> (Vec<RouteDecl>, std::collections::HashSet<String>) {
    let (scrape, rest): (Vec<_>, Vec<_>) = cfg.plugins.iter().partition(|p| p.scrape);
    let mut out = Vec::new();
    let mut withheld = std::collections::HashSet::new();
    for p in scrape.into_iter().chain(rest) {
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
                    Arc::new(crate::export::scrape::Granted(served))
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
        let dispatch: Arc<dyn PluginHttpDispatch> =
            Arc::new(crate::export::scrape::Granted(served));
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
