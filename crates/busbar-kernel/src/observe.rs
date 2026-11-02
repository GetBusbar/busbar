// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub const PLUGIN_LABEL: &str = "plugin";

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

static LEDGER: std::sync::RwLock<Option<std::collections::HashMap<String, Budget>>> =
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
pub(crate) fn admits_cardinality(plugin: &str, series: &str, label_fingerprint: u64) -> bool {
    admit_metric(plugin, series, "", label_fingerprint).is_ok()
}

fn admit_metric(
    plugin: &str,
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

    let budget = ledger.entry(plugin.to_string()).or_default();
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
pub(crate) fn forget_cardinality(plugin: &str) {
    let mut guard = LEDGER.write().unwrap_or_else(|e| e.into_inner());
    if let Some(ledger) = guard.as_mut() {
        ledger.remove(plugin);
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

pub trait Grants: Send + Sync {
    fn first_party(&self, plugin: &str) -> bool;

    fn first_party_series(&self, plugin: &str, name: &str, kind: &str) -> bool;
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
        plugin: &str,
        kind: &str,
        metrics: &[serde_json::Value],
        diagnostics: &[serde_json::Value],
    ) {
        fold_diagnostics(grants, self.catalogue, plugin, diagnostics);
        if kind == busbar_contract::abi::mechanism::kind::HOOK {
            return;
        }
        fold_metrics(grants, plugin, metrics);
    }
}

fn fold_metrics(grants: &dyn Grants, plugin: &str, raw: &[serde_json::Value]) {
    if raw.is_empty() {
        return;
    }

    for mut m in busbar_contract::hook_wire::reply::parse_status_metrics(raw) {
        let granted = grants.first_party_series(plugin, &m.name, &m.kind);
        if !granted && !admits_metric_name(&m.name) {
            continue;
        }

        if let Some(labels) = &mut m.labels {
            labels.retain(|k, _| {
                k != PLUGIN_LABEL && !(m.kind == "histogram" && k == super::source::QUANTILE_LABEL)
            });
        }

        if let Err(refusal) = admit_metric(
            plugin,
            &m.name,
            &m.kind,
            fingerprint_pairs(m.labels.as_ref()),
        ) {
            if matches!(refusal, MetricRefusal::Cardinality) {
                warn_cardinality_once(plugin, &m.name);
            }
            continue;
        }
        let labels = labels_for((!granted).then_some(plugin), &m);
        match m.kind.as_str() {
            "counter" => {
                if m.value < 0.0 {
                    continue;
                }

                metrics::counter!(m.name.clone(), labels).increment(m.value as u64);
            }
            "gauge" => metrics::gauge!(m.name.clone(), labels).set(m.value),
            "histogram" => metrics::histogram!(m.name.clone(), labels).record(m.value),

            _ => {}
        }
    }
}

static WARNED: std::sync::RwLock<Option<std::collections::HashSet<String>>> =
    std::sync::RwLock::new(None);

fn warn_cardinality_once(plugin: &str, series: &str) {
    let mut guard = WARNED.write().unwrap_or_else(|e| e.into_inner());
    let warned = guard.get_or_insert_with(std::collections::HashSet::new);
    if !warned.insert(plugin.to_string()) {
        return;
    }
    tracing::warn!(
        plugin = %plugin,
        series = %series,
        max_series = MAX_SERIES_PER_PLUGIN,
        max_label_sets = MAX_LABEL_SETS_PER_SERIES,
        "plugin exceeded its metric cardinality budget; further new series or label sets from it \
         are refused (established ones keep reporting)"
    );
}

fn labels_for(
    plugin: Option<&str>,
    m: &busbar_contract::hook_wire::reply::HookMetric,
) -> Vec<metrics::Label> {
    let provenance = plugin.map(|p| metrics::Label::new(PLUGIN_LABEL, p.to_string()));
    let mut labels: Vec<metrics::Label> = provenance.into_iter().collect();
    if let Some(own) = &m.labels {
        for (k, v) in own {
            if k == PLUGIN_LABEL {
                continue;
            }
            labels.push(metrics::Label::new(k.clone(), v.clone()));
        }
    }
    labels
}

fn fold_diagnostics(
    grants: &dyn Grants,
    catalogue: crate::diagnostics::Catalogue,
    plugin: &str,
    raw: &[serde_json::Value],
) {
    if raw.is_empty() {
        return;
    }
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

        if grants.first_party(plugin) {
            let fields: Vec<(String, String)> = d
                .ordered_fields()
                .into_iter()
                .take(MAX_DIAG_FIELDS)
                .collect();
            crate::diagnostics::emit(diag, tracing_level(level), &d.message, &fields);
            continue;
        }
        let message =
            busbar_contract::hook_wire::reply::sanitize_cap(&d.message, MAX_DIAG_MESSAGE_CHARS);
        let fields = d
            .fields
            .iter()
            .take(MAX_DIAG_FIELDS)
            .filter(|(k, _)| busbar_contract::hook_wire::reply::valid_metric_name(k))
            .map(|(k, v)| {
                format!(
                    "{k}={}",
                    busbar_contract::hook_wire::reply::sanitize_cap(v, MAX_DIAG_FIELD_CHARS)
                )
            })
            .collect::<Vec<_>>()
            .join(" ");

        let banner = diag.banner();
        match level {
            busbar_contract::abi::mechanism::observe::DiagLevel::Error => {
                tracing::error!(diag = %banner, plugin = %plugin, fields = %fields, "{message}")
            }
            busbar_contract::abi::mechanism::observe::DiagLevel::Warn => {
                tracing::warn!(diag = %banner, plugin = %plugin, fields = %fields, "{message}")
            }
            busbar_contract::abi::mechanism::observe::DiagLevel::Info => {
                tracing::info!(diag = %banner, plugin = %plugin, fields = %fields, "{message}")
            }
            busbar_contract::abi::mechanism::observe::DiagLevel::Debug => {
                tracing::debug!(diag = %banner, plugin = %plugin, fields = %fields, "{message}")
            }
        }
    }
}

const MAX_PLUGIN_DIAGNOSTICS: usize = 16;

const MAX_DIAG_MESSAGE_CHARS: usize = 300;

const MAX_DIAG_FIELD_CHARS: usize = 64;

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
