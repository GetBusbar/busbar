// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::mechanism::KindCode;
use busbar_kernel::snapshot::observe::{
    Grants, KernelPluginObserver, ObservationOwner, ObservationSink, INSTANCE_LABEL, KIND_LABEL,
};
use foldhash::HashMap;
use std::sync::{Arc, Mutex};

use busbar_kernel::audit::auditlog::{record_plugin_refusal, PluginRefusal};

use crate::root::loader::observe::{first_party, first_party_series, BindRefusal, PluginObserver};

/// Each plugin's observation owner and its shared name, keyed by that name.
pub(crate) type Owners = HashMap<Arc<str>, (ObservationOwner, Arc<str>)>;

struct Observer {
    policy: KernelPluginObserver,
    /// Each plugin's observation owner and its name, shared into every metric label it reports.
    owners: Mutex<Owners>,
}
impl Observer {
    fn owner(&self, plugin: &str) -> (ObservationOwner, Arc<str>) {
        let mut owners = self.owners.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(known) = owners.get(plugin) {
            return known.clone();
        }
        crate::root::cold::first_observed(&mut owners, plugin)
    }
}

impl PluginObserver for Observer {
    fn observe(
        &self,
        plugin: &str,
        kind: &str,
        metrics: &[serde_json::Value],
        diagnostics: &[serde_json::Value],
    ) {
        let Some(kind) = KindCode::ALL.into_iter().find(|code| code.word() == kind) else {
            return;
        };
        let (owner, name) = self.owner(plugin);
        self.policy.observe(
            &LoaderGrants {
                plugin,
                owner: &owner,
            },
            &Output(&name, kind.word()),
            kind,
            metrics,
            diagnostics,
        );
    }

    fn dropped(&self, observations: u64) {
        self.policy.dropped(observations);
    }

    fn refused(&self, kind: &str, instance: &str, refusal: BindRefusal<'_>) {
        match refusal {
            BindRefusal::Need { need, reason } => {
                let code = crate::root::cold::need_refusal_code(need, reason);
                record_plugin_refusal(PluginRefusal::Need, kind, instance, &code);
            }
            BindRefusal::Open { code } => {
                record_plugin_refusal(PluginRefusal::Open, kind, instance, code);
            }
            BindRefusal::Op { code } => {
                record_plugin_refusal(PluginRefusal::Op, kind, instance, code);
            }
        }
    }
}

struct LoaderGrants<'a> {
    plugin: &'a str,
    owner: &'a ObservationOwner,
}
impl Grants for LoaderGrants<'_> {
    fn owner(&self) -> &ObservationOwner {
        self.owner
    }
    fn first_party(&self) -> bool {
        first_party(self.plugin)
    }
    fn first_party_series(&self, name: &str, kind: &str) -> bool {
        first_party_series(self.plugin, name, kind)
    }
}

/// A diagnostic's fields as `k=v` pairs joined by single spaces, written straight into the log
/// line when (and only when) the event is recorded.
struct Fields<'a>(&'a [(String, String)]);
impl std::fmt::Display for Fields<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, (k, v)) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{k}={v}")?;
        }
        Ok(())
    }
}

/// A plugin's observation output: its name (for log lines only) and its kind word, the one label core writes on
/// its metrics (IF §12.17: no `plugin` label).
struct Output<'a>(&'a Arc<str>, &'static str);
impl ObservationSink for Output<'_> {
    fn metric(&self, m: &busbar_contract::hook_wire::reply::HookMetric, canonical: bool) {
        let labels = labels_for((!canonical).then_some(self.1), m);
        match m.kind.as_str() {
            "counter" => metrics::counter!(m.name.clone(), &labels).increment(m.value as u64),
            "gauge" => metrics::gauge!(m.name.clone(), &labels).set(m.value),
            "histogram" => metrics::histogram!(m.name.clone(), &labels).record(m.value),
            _ => {}
        }
    }
    fn diagnostic(
        &self,
        diag: &'static busbar_kernel::diagnostics::Diagnostic,
        level: tracing::Level,
        message: &str,
        fields: &[(String, String)],
        canonical: bool,
    ) {
        if canonical {
            busbar_kernel::diagnostics::emit(diag, level, message, fields);
            return;
        }
        let plugin = self.0;
        let banner = diag.banner();
        let fields = Fields(fields);
        match level {
            tracing::Level::ERROR => {
                tracing::error!(diag = %banner, plugin = %plugin, fields = %fields, "{message}")
            }
            tracing::Level::WARN => {
                tracing::warn!(diag = %banner, plugin = %plugin, fields = %fields, "{message}")
            }
            tracing::Level::INFO => {
                tracing::info!(diag = %banner, plugin = %plugin, fields = %fields, "{message}")
            }
            _ => tracing::debug!(diag = %banner, plugin = %plugin, fields = %fields, "{message}"),
        }
    }
    fn cardinality(&self, series: &str, max_series: usize, max_label_sets: usize) {
        tracing::warn!(plugin = %self.0, series = %series, max_series, max_label_sets,
            "plugin exceeded its metric cardinality budget; further new series or label sets from it \
             are refused (established ones keep reporting)");
    }
    fn text_cut(
        &self,
        field: busbar_contract::hook_wire::reply::TextField,
        cap: usize,
        count: u32,
        max_sanitised: usize,
    ) {
        busbar_kernel::hooks::text_cut::report(self.0, field, cap, count, max_sanitised);
    }
}

/// The labels one metric carries. The metrics macros take it by reference and build the key's
/// label set themselves, so this module hands over borrowed fields and allocates no label list.
struct LabelsOf<'a> {
    kind: Option<&'static str>,
    own: Option<&'a std::collections::BTreeMap<String, String>>,
}

impl<'a> IntoIterator for &LabelsOf<'a> {
    type Item = metrics::Label;
    type IntoIter = std::iter::Chain<std::option::IntoIter<metrics::Label>, OwnLabels<'a>>;

    fn into_iter(self) -> Self::IntoIter {
        let provenance = self.kind.map(|k| metrics::Label::new(KIND_LABEL, k));
        provenance
            .into_iter()
            .chain(OwnLabels(self.own.map(|own| own.iter())))
    }
}

/// A metric's own labels, less any that claims a label core writes (`kind`, `instance`).
struct OwnLabels<'a>(Option<std::collections::btree_map::Iter<'a, String, String>>);

impl Iterator for OwnLabels<'_> {
    type Item = metrics::Label;

    fn next(&mut self) -> Option<metrics::Label> {
        let (k, v) = self
            .0
            .as_mut()?
            .find(|(k, _)| k.as_str() != KIND_LABEL && k.as_str() != INSTANCE_LABEL)?;
        Some(metrics::Label::new(k.clone(), v.clone()))
    }
}

fn labels_for<'a>(
    kind: Option<&'static str>,
    m: &'a busbar_contract::hook_wire::reply::HookMetric,
) -> LabelsOf<'a> {
    LabelsOf {
        kind,
        own: m.labels.as_ref(),
    }
}

pub fn install(catalogue: busbar_kernel::diagnostics::Catalogue) {
    let observer: &'static Observer = Box::leak(Box::new(Observer {
        policy: KernelPluginObserver::lent(catalogue),
        owners: Mutex::new(HashMap::default()),
    }));
    let _ = crate::root::dispatch::dispatcher()
        .observing()
        .install_observer(observer);
}

#[cfg(test)]
#[path = "tests/observe.rs"]
mod tests;
