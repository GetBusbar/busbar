// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::abi::mechanism::lifecycle::refusal_lines;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::conn::admissions::AdmissionAuthority;
use busbar_contract::export_calls::{ExportCalls, PreparedExport, Probed, DEFAULT_INFLIGHT};
use busbar_contract::secure::SecureVec;

use crate::dispatch::kinds::export::{Export, ExportFacts};
use crate::dispatch::{Bind, ConnTable, Dispatcher, EnvelopeSink, NoSink, Plugin, PluginLogConfig};
use crate::export_door::{self, ExportInstance};
use crate::registry::{open_loadable, LoadablePlugin, RowRefusal};
use crate::PluginRegistry;

const SECTION: &str = busbar_contract::plugin::Kind::Export.root();

pub const NO_DOOR: &str = "it states no export door (the 1.5.5 JSON export contract, which this host does not load) — rebuild the plugin against the 1.6.0 SDK";

pub struct ExportRows<'r> {
    registry: &'r PluginRegistry,
    dispatcher: Arc<Dispatcher>,

    logs: Option<&'r PluginLogConfig>,

    conns: Option<AdmissionAuthority>,
    disk: Option<busbar_contract::services::disk_admission::DiskAuthority>,

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
            disk: None,
            envelope: None,
        }
    }

    #[must_use]
    pub fn with_logs(mut self, logs: &'r PluginLogConfig) -> Self {
        self.logs = Some(logs);
        self
    }

    #[must_use]
    pub fn with_conns(mut self, conns: AdmissionAuthority) -> Self {
        self.conns = Some(conns);
        self
    }

    #[must_use]
    pub fn with_disk(
        mut self,
        authority: busbar_contract::services::disk_admission::DiskAuthority,
    ) -> Self {
        self.disk = Some(authority);
        self
    }

    #[cfg(any(test, feature = "test-support"))]
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
        opening: Option<u32>,
    ) -> Result<Plugin<Export>, String> {
        let name = &row.manifest.name;
        let bind = || -> Result<Bind, String> {
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
            // busbar:expect(bp::into_alloc, reason = "boot: a loaded export instance keeps its label")
            Ok(Bind {
                instance: Arc::from(label),
                max_inflight_cap: opening.unwrap_or(DEFAULT_INFLIGHT),
                sink,
                dispatcher: self.dispatcher.adopter(),

                conns: if opening.is_some() {
                    ConnTable::serving(self.conns.clone())
                } else {
                    ConnTable::Probe
                },
            })
        };
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: names the export plugin that did not load"
        )]
        let refused = |e: RowRefusal| match e {
            RowRefusal::Stated(e) | RowRefusal::Bind(e) => e,
            RowRefusal::NoDoor => format!("export plugin '{name}': {NO_DOOR}"),
            RowRefusal::Load(e) => format!("export plugin '{name}': {e}"),
        };
        open_loadable::<Export>(row, name, bind).map_err(refused)
    }

    #[must_use]
    pub fn probe(
        &self,
        module: &str,
        instance: &str,
        settings: &busbar_contract::plugin_settings::ResolvedSettings,
    ) -> Option<Probed> {
        let row = self.row(module)?;
        match self.load(row, &label(instance), None) {
            Ok(p) => {
                let streams = p.context::<ExportFacts>().map(|f| f.streams.clone());
                #[expect(
                    clippy::disallowed_methods,
                    reason = "config: an export probe's settings did not render"
                )]
                let text = match settings.encode() {
                    Ok(text) => text,
                    Err(error) => return Some((streams, vec![error.to_string()], None)),
                };
                let Some(seal) = self.dispatcher.seal() else {
                    return Some((
                        streams,
                        vec!["export probe requires the host settings seal".into()],
                        None,
                    ));
                };
                let text = text.expose(seal);
                let declaration = export_door::validate(&p, text).and_then(|()| {
                    if p.context::<ExportFacts>().is_some_and(|f| f.recorder) {
                        ExportInstance::open(p, self.dispatcher.clone(), text)
                            .map(|opened| opened.recorder_requirements())
                    } else {
                        Ok(None)
                    }
                });
                let (recorder, problems) = match declaration {
                    Ok(recorder) => (recorder, Vec::new()),
                    Err(text) => (None, refusal_lines(SECTION, instance, &text)),
                };
                Some((streams, problems, recorder))
            }

            Err(error) => Some((None, refusal_lines(SECTION, instance, &error), None)),
        }
    }

    #[must_use]
    pub fn linked_modules(&self) -> Vec<String> {
        // busbar:expect(bp::clone_alloc, reason = "config: lists the linked export modules config may name")
        #[expect(
            clippy::disallowed_methods,
            reason = "config: lists the linked export modules config may name"
        )]
        let modules = self
            .registry
            .linked()
            .iter()
            .filter(|p| p.manifest.kind == SECTION)
            .map(|p| p.manifest.alias.clone())
            .collect();
        modules
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
        // busbar:expect(bp::clone_alloc, reason = "config: an export module's routes, read when config names it")
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
        // busbar:expect(bp::clone_alloc, reason = "config: an export module's public routes, read when config names it")
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
                // busbar:expect(bp::clone_alloc, reason = "config: an export module's persistent routes, read when config names it")
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
        instances: &[(String, &busbar_contract::plugin_settings::ResolvedSettings)],
    ) -> Option<Vec<String>> {
        let row = self.row(module)?;
        let seal = match self.dispatcher.seal() {
            Some(seal) => seal,
            None => return Some(vec!["export check requires the host settings seal".into()]),
        };
        let mut listed: Vec<(String, SecureVec)> = Vec::with_capacity(instances.len());
        for (name, settings) in instances {
            #[expect(
                clippy::disallowed_methods,
                reason = "config: an export check's instance settings did not render"
            )]
            let bytes = match settings.encode() {
                Ok(bytes) => bytes,
                Err(error) => return Some(vec![error.to_string()]),
            };
            listed.push((name.clone(), SecureVec::from(bytes.expose(seal).as_slice())));
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "config: an export check with no instances checks the empty settings"
        )]
        let none = [(module.to_string(), SecureVec::from(&b"{}"[..]))];
        let candidates = if listed.is_empty() {
            &none[..]
        } else {
            &listed[..]
        };
        #[expect(
            clippy::disallowed_methods,
            reason = "config: names the export module a check could not run"
        )]
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
            #[expect(
                clippy::disallowed_methods,
                reason = "config: names the export module whose check failed"
            )]
            match ExportInstance::open(p, self.dispatcher.clone(), settings) {
                Ok(opened) => {
                    return Some(
                        export_door::check(opened.plugin(), phase, &listed)
                            .unwrap_or_else(|e| vec![format!("export `module: {module}`: {e}")]),
                    );
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
        settings: &PreparedExport,
    ) -> Result<Arc<dyn ExportCalls>, String> {
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: names a configured export module that did not load"
        )]
        let row =
            self.row(module)
                .ok_or_else(|| match self.registry.unresolved_reason(module) {
                    Some(s) => format!(
                        "export plugin '{module}' is present ({}) but was not loaded: {}",
                        s.file, s.reason
                    ),
                    None => format!("no `kind: export` plugin answers to '{module}'"),
                })?;
        let text = settings
            .settings()
            .encode()
            .map_err(|_| "cannot encode exporter settings")?;
        let seal = self
            .dispatcher
            .seal()
            .ok_or("export opening requires the host settings seal")?;
        let p = self.load(row, label, Some(settings.max_inflight()))?;

        let grant = crate::observe::grant_series(
            self.dispatcher.observing(),
            &row.manifest.name,
            row.first_party(),
            &row.manifest.declares.metrics,
        )?;

        if !row.manifest.declares.destinations.is_empty() {
            let authority = self
                .disk
                .as_ref()
                .ok_or("export disk destinations require kernel admission authority")?;
            p.grant_destinations(authority, &row.manifest.declares);
        }

        let opened =
            ExportInstance::open(p, self.dispatcher.clone(), text.expose(seal))?.holding(grant);
        Ok(Arc::new(opened))
    }

    #[must_use]
    pub fn linked(&self, module: &str) -> bool {
        self.registry
            .linked()
            .iter()
            .filter(|p| p.manifest.kind == busbar_contract::abi::mechanism::kind::EXPORT)
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
    #[expect(
        clippy::disallowed_methods,
        reason = "config: an export instance's label, named when config loads it"
    )]
    let label = format!("{SECTION}.{instance}");
    label
}

#[cfg(test)]
pub(crate) fn test_opening(settings: &serde_json::Value) -> PreparedExport {
    let admitted: busbar_contract::export_calls::ExportOpening =
        serde_json::from_value(settings.clone()).expect("export settings object");
    admitted.prepare()
}

#[cfg(test)]
#[path = "tests/export_axis_tests.rs"]
mod tests;
