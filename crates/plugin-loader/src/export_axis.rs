// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::abi::mechanism::lifecycle::refusal_lines;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::conn::DeclaredConns;
use busbar_contract::export_calls::{ExportCalls, Probed, DEFAULT_INFLIGHT, INFLIGHT_KEY};

use crate::dispatch::kinds::export::{Export, ExportFacts};
use crate::dispatch::{
    load_dropped_bytes, load_linked, Bind, ConnTable, Dispatcher, EnvelopeSink, LinkedRow, NoSink,
    Plugin, PluginLogConfig,
};
use crate::export_door::{self, ExportInstance};
use crate::registry::LoadablePlugin;
use crate::PluginRegistry;

const SECTION: &str = busbar_contract::plugin::Kind::Export.root();

enum Image {
    Linked(LinkedRow),
    Dropped(Vec<u8>),
}

pub const NO_DOOR: &str = "it states no export door (the 1.5.5 JSON export contract, which this host does not load) — rebuild the plugin against the 1.6.0 SDK";

pub struct ExportRows<'r> {
    registry: &'r PluginRegistry,
    dispatcher: Arc<Dispatcher>,

    logs: Option<&'r PluginLogConfig>,

    conns: Option<Arc<dyn DeclaredConns>>,

    envelope: Option<Arc<dyn EnvelopeSink>>,
}

impl std::fmt::Debug for ExportRows<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportRows").finish_non_exhaustive()
    }
}

impl<'r> ExportRows<'r> {
    #[must_use]
    pub fn new(registry: &'r PluginRegistry, dispatcher: Arc<Dispatcher>) -> Self {
        Self {
            registry,
            dispatcher,
            logs: None,
            conns: None,
            envelope: None,
        }
    }

    #[must_use]
    pub fn with_logs(mut self, logs: &'r PluginLogConfig) -> Self {
        self.logs = Some(logs);
        self
    }

    #[must_use]
    pub fn with_conns(mut self, conns: Arc<dyn DeclaredConns>) -> Self {
        self.conns = Some(conns);
        self
    }

    #[must_use]
    pub fn with_envelope(mut self, envelope: Arc<dyn EnvelopeSink>) -> Self {
        self.envelope = Some(envelope);
        self
    }

    fn row(&self, module: &str) -> Option<&'r LoadablePlugin> {
        self.registry
            .resolve(module)
            .filter(|p| p.manifest.kind == busbar_contract::abi::mechanism::kind::EXPORT)
    }

    fn load(
        &self,
        row: &LoadablePlugin,
        label: &str,
        opening: Option<&serde_json::Value>,
    ) -> Result<Plugin<Export>, String> {
        let name = &row.manifest.name;
        let refused = |e: crate::dispatch::LoadError| format!("export plugin '{name}': {e}");
        let image = match row.door() {
            Some(door) => Image::Linked(LinkedRow::of_raw(door).map_err(refused)?),
            None => match row.manifest.stated_rendering()? {
                Some(stated) => Image::Dropped(stated),
                None => return Err(format!("export plugin '{name}': {NO_DOOR}")),
            },
        };

        let sink: Arc<dyn EnvelopeSink> = match opening {
            None => Arc::new(NoSink),
            Some(_) => {
                let envelope = self.envelope.clone().unwrap_or_else(|| Arc::new(NoSink));
                match self.logs {
                    Some(logs) => Arc::new(logs.sink(label, KindCode::Export, envelope)?),
                    None => envelope,
                }
            }
        };
        let max_inflight_cap = opening
            .and_then(|settings| settings.get(INFLIGHT_KEY))
            .and_then(serde_json::Value::as_u64)
            .map_or(DEFAULT_INFLIGHT, |n| {
                u32::try_from(n).unwrap_or(u32::MAX).max(1)
            });
        let bind = Bind {
            instance: Arc::from(label),
            max_inflight_cap,
            sink,
            dispatcher: self.dispatcher.adopter(),

            conns: if opening.is_some() {
                ConnTable::serving(self.conns.clone())
            } else {
                ConnTable::Probe
            },
        };
        let loaded = match &image {
            Image::Linked(r) => load_linked::<Export>(r, bind),
            Image::Dropped(stated) => {
                load_dropped_bytes::<Export>(&row.lib_bytes, name, stated, bind)
            }
        };
        loaded.map_err(refused)
    }

    #[must_use]
    pub fn probe(
        &self,
        module: &str,
        instance: &str,
        settings: &serde_json::Value,
    ) -> Option<Probed> {
        let row = self.row(module)?;
        match self.load(row, &label(instance), None) {
            Ok(p) => {
                let streams = p.context::<ExportFacts>().map(|f| f.streams.clone());
                let text = zeroize::Zeroizing::new(settings.to_string());
                let problems = match export_door::validate(&p, text.as_bytes()) {
                    Ok(()) => Vec::new(),
                    Err(text) => refusal_lines(SECTION, instance, &text),
                };
                Some((streams, problems))
            }

            Err(_) => Some((None, Vec::new())),
        }
    }

    #[must_use]
    pub fn linked_modules(&self) -> Vec<String> {
        self.registry
            .linked()
            .iter()
            .filter(|p| p.manifest.kind == SECTION)
            .map(|p| p.manifest.alias.clone())
            .collect()
    }

    #[must_use]
    pub fn one_instance(&self, module: &str) -> bool {
        let Some(row) = self.row(module) else {
            return false;
        };
        self.load(row, &label(module), None)
            .is_ok_and(|p| p.context::<ExportFacts>().is_some_and(|f| f.one_instance))
    }

    #[must_use]
    pub fn routes(&self, module: &str) -> Vec<busbar_contract::abi::mechanism::route::Route> {
        let Some(row) = self.row(module) else {
            return Vec::new();
        };
        self.load(row, &label(module), None)
            .ok()
            .and_then(|p| p.context::<ExportFacts>().map(|f| f.routes.clone()))
            .unwrap_or_default()
    }

    #[must_use]
    pub fn public_routes(&self, module: &str) -> Vec<String> {
        let Some(row) = self.row(module) else {
            return Vec::new();
        };
        self.load(row, &label(module), None)
            .ok()
            .and_then(|p| p.context::<ExportFacts>().map(|f| f.public_routes.clone()))
            .unwrap_or_default()
    }

    #[must_use]
    pub fn persistent_routes(&self, module: &str) -> Vec<String> {
        let Some(row) = self.row(module) else {
            return Vec::new();
        };
        self.load(row, &label(module), None)
            .ok()
            .and_then(|p| {
                p.context::<ExportFacts>()
                    .map(|f| f.persistent_routes.clone())
            })
            .unwrap_or_default()
    }

    #[must_use]
    pub fn check(
        &self,
        module: &str,
        phase: u32,
        instances: &[(String, &serde_json::Value)],
    ) -> Option<Vec<String>> {
        let row = self.row(module)?;
        let listed: zeroize::Zeroizing<Vec<(String, Vec<u8>)>> = zeroize::Zeroizing::new(
            instances
                .iter()
                .map(|(n, s)| (n.clone(), s.to_string().into_bytes()))
                .collect(),
        );
        let none = [(module.to_string(), b"{}".to_vec())];
        let candidates = if listed.is_empty() {
            &none[..]
        } else {
            &listed[..]
        };
        let unchecked = |why: String| Some(vec![format!("export `module: {module}`: {why}")]);
        let mut unopened = None;
        for (named, settings) in candidates {
            let p = match self.load(row, &label(named), None) {
                Ok(p) => p,
                Err(why) => return unchecked(why),
            };
            if export_door::validate(&p, settings).is_err() {
                continue;
            }
            match ExportInstance::open(p, self.dispatcher.clone(), settings) {
                Ok(opened) => {
                    return Some(
                        export_door::check(opened.plugin(), phase, &listed)
                            .unwrap_or_else(|e| vec![format!("export `module: {module}`: {e}")]),
                    )
                }
                Err(why) => unopened = Some(why),
            }
        }
        unopened.map_or_else(|| Some(Vec::new()), unchecked)
    }

    pub fn open(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
    ) -> Result<Arc<dyn ExportCalls>, String> {
        let row =
            self.row(module)
                .ok_or_else(|| match self.registry.unresolved_reason(module) {
                    Some(s) => format!(
                        "export plugin '{module}' is present ({}) but was not loaded: {}",
                        s.file, s.reason
                    ),
                    None => format!("no `kind: export` plugin answers to '{module}'"),
                })?;
        let text = zeroize::Zeroizing::new(settings.to_string());
        let p = self.load(row, label, Some(settings))?;

        let grant = crate::observe::grant_series(
            self.dispatcher.observing(),
            &row.manifest.name,
            row.first_party(),
            &row.manifest.declares.metrics,
        )?;

        p.grant_destinations(&row.manifest.declares);

        let opened =
            ExportInstance::open(p, self.dispatcher.clone(), text.as_bytes())?.holding(grant);
        Ok(Arc::new(opened))
    }

    #[must_use]
    pub fn linked(&self, module: &str) -> bool {
        self.registry
            .linked()
            .iter()
            .any(|p| p.manifest.config_names().any(|n| n == module))
    }

    #[must_use]
    pub fn first_party(&self, module: &str) -> bool {
        self.registry
            .resolve(module)
            .is_some_and(LoadablePlugin::first_party)
    }
}

fn label(instance: &str) -> String {
    format!("{SECTION}.{instance}")
}

#[cfg(test)]
#[path = "tests/export_axis_tests.rs"]
mod tests;
