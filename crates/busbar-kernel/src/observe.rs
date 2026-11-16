// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

/// The label core writes on every plugin metric: the instance's kind word (IF §12.17). There is no `plugin` label:
/// no metric names a stamp name, module or former name (I2).
pub const KIND_LABEL: &str = "kind";
/// The label core writes on every MIN-3 plugin metric: the configured instance name (IF §12.17).
pub const INSTANCE_LABEL: &str = "instance";

/// An opaque budget group. The composition root reuses one owner for every
/// instance of an implementation, including replacements. This is not authority.
#[derive(Clone, Debug)]
pub struct ObservationOwner(std::sync::Arc<()>);
impl Default for ObservationOwner {
    fn default() -> Self {
        Self(std::sync::Arc::new(()))
    }
}
impl PartialEq for ObservationOwner {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for ObservationOwner {}
impl std::hash::Hash for ObservationOwner {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&std::sync::Arc::as_ptr(&self.0), state);
    }
}

/// Output only: metadata decoration belongs to the composition root. Policy
/// cannot retrieve an implementation name or use this sink to dispatch work.
pub trait ObservationSink {
    fn metric(&self, metric: &busbar_contract::hook_wire::reply::HookMetric, canonical: bool);
    fn diagnostic(
        &self,
        diagnostic: &'static crate::diagnostics::Diagnostic,
        level: tracing::Level,
        message: &str,
        fields: &[(String, String)],
        canonical: bool,
    );
    fn cardinality(&self, series: &str, max_series: usize, max_label_sets: usize);
    /// `count` values of `field` this plugin sent were over `cap` and were cut; the longest was
    /// `max_sanitised` chars after sanitising. Required: a sink cannot drop the fact silently.
    fn text_cut(
        &self,
        field: busbar_contract::hook_wire::reply::TextField,
        cap: usize,
        count: u32,
        max_sanitised: usize,
    );
}

const RESERVED_PREFIX: &str = "busbar_";

pub(crate) fn admits_metric_name(name: &str) -> bool {
    busbar_contract::hook_wire::reply::valid_metric_name(name) && !name.starts_with(RESERVED_PREFIX)
}

pub(crate) const MAX_SERIES_PER_PLUGIN: usize = 64;

pub(crate) const MAX_LABEL_SETS_PER_SERIES: usize = 32;

/// One plugin's registered series and, per series, the label sets seen under it.
#[derive(Default)]
struct Budget {
    series: std::collections::HashMap<String, SeriesBudget>,
}

struct SeriesBudget {
    kind: String,
    labels: std::collections::HashSet<u64>,
}

enum MetricRefusal {
    Cardinality,
    Type,
}

static LEDGER: std::sync::RwLock<Option<std::collections::HashMap<ObservationOwner, Budget>>> =
    std::sync::RwLock::new(None);

fn fingerprint(bytes: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

fn fingerprint_pairs(labels: Option<&std::collections::BTreeMap<String, String>>) -> u64 {
    let Some(labels) = labels else {
        return fingerprint(&[]);
    };
    let mut canonical = String::new();
    for (k, v) in labels {
        canonical.push_str(k);
        canonical.push('\u{1}');
        canonical.push_str(v);
        canonical.push('\u{2}');
    }
    fingerprint(canonical.as_bytes())
}

#[cfg(test)]
pub(crate) fn admits_cardinality(
    owner: &ObservationOwner,
    series: &str,
    label_fingerprint: u64,
) -> bool {
    admit_metric(owner, series, "", label_fingerprint).is_ok()
}

fn admit_metric(
    owner: &ObservationOwner,
    series: &str,
    kind: &str,
    label_fingerprint: u64,
) -> Result<(), MetricRefusal> {
    let mut guard = LEDGER.write().unwrap_or_else(|e| e.into_inner());
    let ledger = guard.get_or_insert_with(std::collections::HashMap::new);
    if !kind.is_empty()
        && ledger
            .values()
            .filter_map(|budget| budget.series.get(series))
            .any(|held| !held.kind.is_empty() && held.kind != kind)
    {
        return Err(MetricRefusal::Type);
    }

    let budget = ledger.entry(owner.clone()).or_default();
    match budget.series.get_mut(series) {
        Some(held) => {
            if held.labels.contains(&label_fingerprint) {
                return Ok(());
            }
            if held.labels.len() >= MAX_LABEL_SETS_PER_SERIES {
                return Err(MetricRefusal::Cardinality);
            }
            held.labels.insert(label_fingerprint);
            Ok(())
        }
        None => {
            if budget.series.len() >= MAX_SERIES_PER_PLUGIN {
                return Err(MetricRefusal::Cardinality);
            }
            budget.series.insert(
                series.to_string(),
                SeriesBudget {
                    kind: kind.to_string(),
                    labels: std::iter::once(label_fingerprint).collect(),
                },
            );
            Ok(())
        }
    }
}

#[cfg(test)]
pub(crate) fn forget_cardinality(owner: &ObservationOwner) {
    let mut guard = LEDGER.write().unwrap_or_else(|e| e.into_inner());
    if let Some(ledger) = guard.as_mut() {
        ledger.remove(owner);
    }
}

/// The kernel's observer: validates what a plugin reported, bounds it, and folds it into THIS
/// process's recorder and diagnostics path.
///
/// It holds one thing, lent: the catalogue a reported code resolves against, the composition root's
/// fold ([`crate::diagnostics::Catalogue`]). The recorder it writes to is the process-global one
/// ([`crate::snapshot`]).
#[derive(Clone, Copy, Debug)]
pub struct KernelPluginObserver {
    catalogue: crate::diagnostics::Catalogue,
}

/// Verified declarations bound by the root to one opaque budget owner.
pub trait Grants: Send + Sync {
    fn owner(&self) -> &ObservationOwner;
    fn first_party(&self) -> bool;
    fn first_party_series(&self, name: &str, kind: &str) -> bool;
}

impl KernelPluginObserver {
    #[must_use]
    pub const fn lent(catalogue: crate::diagnostics::Catalogue) -> KernelPluginObserver {
        KernelPluginObserver { catalogue }
    }

    pub fn dropped(&self, observations: u64) {
        metrics::counter!(crate::snapshot::PLUGIN_OBSERVATIONS_DROPPED_TOTAL)
            .increment(observations);
    }

    pub fn observe(
        &self,
        grants: &dyn Grants,
        sink: &dyn ObservationSink,
        kind: busbar_contract::abi::mechanism::KindCode,
        metrics: &[serde_json::Value],
        diagnostics: &[serde_json::Value],
    ) {
        fold_diagnostics(grants, sink, self.catalogue, diagnostics);
        if kind == busbar_contract::abi::mechanism::KindCode::Hook {
            return;
        }
        fold_metrics(grants, sink, metrics);
    }
}

fn fold_metrics(grants: &dyn Grants, sink: &dyn ObservationSink, raw: &[serde_json::Value]) {
    if raw.is_empty() {
        return;
    }

    let (parsed, cuts) = busbar_contract::hook_wire::reply::parse_status_metrics_counted(raw);
    text_cuts(sink, &cuts);
    for mut m in parsed {
        let granted = grants.first_party_series(&m.name, &m.kind);
        if !granted && !admits_metric_name(&m.name) {
            continue;
        }

        if let Some(labels) = &mut m.labels {
            labels.retain(|k, _| {
                k != KIND_LABEL
                    && k != INSTANCE_LABEL
                    && !(m.kind == "histogram" && k == super::source::QUANTILE_LABEL)
            });
        }

        if let Err(refusal) = admit_metric(
            grants.owner(),
            &m.name,
            &m.kind,
            fingerprint_pairs(m.labels.as_ref()),
        ) {
            if matches!(refusal, MetricRefusal::Cardinality) {
                warn_cardinality_once(grants.owner(), sink, &m.name);
            }
            continue;
        }
        if m.kind == "counter" && m.value < 0.0 {
            continue;
        }
        sink.metric(&m, granted);
    }
}

static WARNED: std::sync::RwLock<Option<std::collections::HashSet<ObservationOwner>>> =
    std::sync::RwLock::new(None);

fn warn_cardinality_once(owner: &ObservationOwner, sink: &dyn ObservationSink, series: &str) {
    let mut guard = WARNED.write().unwrap_or_else(|e| e.into_inner());
    let warned = guard.get_or_insert_with(std::collections::HashSet::new);
    if !warned.insert(owner.clone()) {
        return;
    }
    drop(guard);
    sink.cardinality(series, MAX_SERIES_PER_PLUGIN, MAX_LABEL_SETS_PER_SERIES);
}

fn fold_diagnostics(
    grants: &dyn Grants,
    sink: &dyn ObservationSink,
    catalogue: crate::diagnostics::Catalogue,
    raw: &[serde_json::Value],
) {
    use busbar_contract::hook_wire::reply::{TextCuts, TextField};
    if raw.is_empty() {
        return;
    }
    let mut cuts = TextCuts::default();
    for entry in raw.iter().take(MAX_PLUGIN_DIAGNOSTICS) {
        let Ok(d) = serde_json::from_value::<
            busbar_contract::abi::mechanism::observe::PluginDiagnostic,
        >(entry.clone()) else {
            continue;
        };
        let Some(diag) = resolve_code(catalogue, &d.code) else {
            continue;
        };

        let level = clamp_level(d.level, diag.severity);

        if grants.first_party() {
            let fields: Vec<(String, String)> = d
                .ordered_fields()
                .into_iter()
                .take(MAX_DIAG_FIELDS)
                .collect();
            sink.diagnostic(diag, tracing_level(level), &d.message, &fields, true);
            continue;
        }
        let (message, cut) = busbar_contract::hook_wire::reply::sanitize_cap_counted(
            &d.message,
            MAX_DIAG_MESSAGE_CHARS,
        );
        if let Some(sanitised_chars) = cut {
            cuts.record(TextField::DiagMessage, sanitised_chars);
        }
        let fields = d
            .fields
            .iter()
            .take(MAX_DIAG_FIELDS)
            .filter(|(k, _)| busbar_contract::hook_wire::reply::valid_metric_name(k))
            .map(|(k, v)| {
                let (value, cut) = busbar_contract::hook_wire::reply::sanitize_cap_counted(
                    v,
                    MAX_DIAG_FIELD_CHARS,
                );
                if let Some(sanitised_chars) = cut {
                    cuts.record(TextField::DiagField, sanitised_chars);
                }
                (k.clone(), value)
            })
            .collect::<Vec<_>>();
        sink.diagnostic(diag, tracing_level(level), &message, &fields, false);
    }
    text_cuts(sink, &cuts);
}

/// One `text_cut` per field the reply's parse cut, summed over the reply.
fn text_cuts(sink: &dyn ObservationSink, cuts: &busbar_contract::hook_wire::reply::TextCuts) {
    for (field, count, max_sanitised) in cuts.iter() {
        sink.text_cut(
            field,
            crate::hooks::text_cut::cap_of(field),
            count,
            max_sanitised,
        );
    }
}

const MAX_PLUGIN_DIAGNOSTICS: usize = 16;

pub(crate) const MAX_DIAG_MESSAGE_CHARS: usize = 300;

pub(crate) const MAX_DIAG_FIELD_CHARS: usize = 64;

const MAX_DIAG_FIELDS: usize = 8;

fn resolve_code(
    catalogue: crate::diagnostics::Catalogue,
    code: &str,
) -> Option<&'static crate::diagnostics::Diagnostic> {
    let n: u16 = code.strip_prefix("BUSBAR-")?.parse().ok()?;
    catalogue.by_code(n)
}

fn tracing_level(level: busbar_contract::abi::mechanism::observe::DiagLevel) -> tracing::Level {
    use busbar_contract::abi::mechanism::observe::DiagLevel;
    match level {
        DiagLevel::Error => tracing::Level::ERROR,
        DiagLevel::Warn => tracing::Level::WARN,
        DiagLevel::Info => tracing::Level::INFO,
        DiagLevel::Debug => tracing::Level::DEBUG,
    }
}

fn clamp_level(
    claimed: busbar_contract::abi::mechanism::observe::DiagLevel,
    severity: crate::diagnostics::Severity,
) -> busbar_contract::abi::mechanism::observe::DiagLevel {
    use crate::diagnostics::Severity;
    use busbar_contract::abi::mechanism::observe::DiagLevel;
    match severity {
        Severity::BenignRecurring => DiagLevel::Debug,
        Severity::Actionable | Severity::Fatal => claimed,
    }
}

#[cfg(test)]
#[path = "tests/observe_tests.rs"]
mod tests;
