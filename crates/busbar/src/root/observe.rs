// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::mechanism::KindCode;
use busbar_kernel::snapshot::observe::{
    Grants, KernelPluginObserver, ObservationOwner, ObservationSink, PLUGIN_LABEL,
};
use foldhash::HashMap;
use std::sync::{Arc, Mutex};

use busbar_kernel::audit::auditlog::{record_plugin_refusal, PluginRefusal};

use crate::root::loader::observe::{first_party, first_party_series, BindRefusal, PluginObserver};

/// Each plugin's observation owner and its shared name, keyed by that name.
type Owners = HashMap<Arc<str>, (ObservationOwner, Arc<str>)>;

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
        // busbar:expect(bp::into_alloc, reason = "config: a plugin's name is spelled once, on its first observation, then shared")
        let name: Arc<str> = Arc::from(plugin);
        let known = (ObservationOwner::default(), name.clone());
        owners.insert(name, known.clone());
        known
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
            &Output(&name),
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
                #[expect(
                    clippy::disallowed_methods,
                    reason = "error: the refusal code is spelled only when a plugin's bind is refused"
                )]
                let code = format!("need.{need}.{reason}");
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

struct Output<'a>(&'a Arc<str>);
impl ObservationSink for Output<'_> {
    fn metric(&self, m: &busbar_contract::hook_wire::reply::HookMetric, canonical: bool) {
        let labels = labels_for((!canonical).then_some(self.0), m);
        match m.kind.as_str() {
            "counter" => metrics::counter!(m.name.clone(), labels).increment(m.value as u64),
            "gauge" => metrics::gauge!(m.name.clone(), labels).set(m.value),
            "histogram" => metrics::histogram!(m.name.clone(), labels).record(m.value),
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
}

fn labels_for(
    plugin: Option<&Arc<str>>,
    m: &busbar_contract::hook_wire::reply::HookMetric,
) -> Vec<metrics::Label> {
    let provenance = plugin.map(|p| metrics::Label::new(PLUGIN_LABEL, Arc::clone(p)));
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

pub fn install(catalogue: busbar_kernel::diagnostics::Catalogue) {
    let observer: &'static Observer = Box::leak(Box::new(Observer {
        policy: KernelPluginObserver::lent(catalogue),
        owners: Mutex::new(HashMap::default()),
    }));
    let _ = crate::root::dispatch::dispatcher()
        .observing()
        .install_observer(observer);
}
