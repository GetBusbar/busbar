// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT ROWS (WIRE-EXPORT): [`ExportRows`] probes, checks and opens the plugin registry's
//! `kind: export` rows on the process's one dispatcher. The composition root implements the
//! contract's `ExportAxis` over it, with the registry it scanned and linked, and installs that axis
//! through the kernel's `RootInstall` (ARCHITECT ruling 2026-09-29, the opener seam: impl in the
//! root, installed via `RootInstall`) — so the kernel probes, checks and opens export instances
//! naming neither this crate nor the root.
//!
//! A row opens on the export kind's MEMORY ABI (`abi::export`, through [`ExportInstance`]) when it
//! is a linked door ([`crate::registry::LinkedEntry::Door`]) or a dropped-in library whose signed
//! manifest states its Statement: both bind through the one load ([`load_linked`] /
//! [`load_dropped_bytes`]), each opened instance under the host's instance label, to its own log
//! sink and declaring its needs on the host's one connection table. A validate refusal renders
//! line by line under the instance (`lifecycle::refusal_lines`), 1.5.5's
//! `export.<instance>.settings: …`. A 1.5.5 JSON-contract export plugin (manifest `abi_version` 2)
//! is refused at scan naming the rebuild; a row that states no door is refused at its open, naming
//! the same rebuild ([`NO_DOOR`]).

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

/// The export kind's configuration section, read off the contract's kind list: a refusal's line
/// renders under it.
const SECTION: &str = busbar_contract::plugin::Kind::Export.root();

/// The image a row binds: a linked door's row, or a dropped library's stated rendering.
enum Image {
    Linked(LinkedRow),
    Dropped(Vec<u8>),
}

/// Why a row that states no door does not open: a 1.5.5 JSON-contract export plugin.
pub const NO_DOOR: &str = "it states no export door (the 1.5.5 JSON export contract, which this host does not load) — rebuild the plugin against the 1.6.0 SDK";

/// The export rows of a registry, opening instances on a dispatcher.
pub struct ExportRows<'r> {
    registry: &'r PluginRegistry,
    dispatcher: Arc<Dispatcher>,
    /// `plugins.logs`: each OPENED instance's own log sink; `None` = its records are discarded.
    logs: Option<&'r PluginLogConfig>,
    /// The host's one connection table: an OPENED instance's needs are declared on it.
    conns: Option<Arc<dyn DeclaredConns>>,
    /// A sink an OPENED instance's #85 envelope is also handed to (the host observes it at the bind
    /// regardless); `None` = none. Under `plugins.logs` it is the log sink's own downstream.
    envelope: Option<Arc<dyn EnvelopeSink>>,
}

impl std::fmt::Debug for ExportRows<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportRows").finish_non_exhaustive()
    }
}

impl<'r> ExportRows<'r> {
    /// The rows of `registry`, bound on `dispatcher`: an opened instance discards its log records and
    /// declares no need until [`Self::with_logs`] / [`Self::with_conns`] say where they go.
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

    /// Each opened instance logs to its own sink under `logs`.
    #[must_use]
    pub fn with_logs(mut self, logs: &'r PluginLogConfig) -> Self {
        self.logs = Some(logs);
        self
    }

    /// Each opened instance declares its needs on `conns`.
    #[must_use]
    pub fn with_conns(mut self, conns: Arc<dyn DeclaredConns>) -> Self {
        self.conns = Some(conns);
        self
    }

    /// Each opened instance's #85 envelope is also handed to `envelope` (behind its log sink, when
    /// [`Self::with_logs`] gave one); the host's observability has it either way.
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

    /// Bind `row`'s door under `label`: an instance only probed or checked (`opening` is `None`)
    /// binds with no log sink, no envelope and no connection table (nothing is opened to the network
    /// or the disk while a configuration is judged); one opened to deliver over its settings binds
    /// with all three — its #85 envelope observed by the host at the bind, as every door's is, and
    /// handed to its log sink and to [`Self::with_envelope`]'s sink when one is set — and its in-flight bound
    /// the one its settings state ([`INFLIGHT_KEY`], [`DEFAULT_INFLIGHT`] when they state none),
    /// within the plugin's declared `max_inflight` (ARCHITECT ruling MAX-INFLIGHT 2026-10-03).
    fn load(
        &self,
        row: &LoadablePlugin,
        label: &str,
        opening: Option<&serde_json::Value>,
    ) -> Result<Plugin<Export>, String> {
        let name = &row.manifest.name;
        let refused = |e: crate::dispatch::LoadError| format!("export plugin '{name}': {e}");
        let image = match row.door() {
            Some(door) => Image::Linked(LinkedRow::of(door).map_err(refused)?),
            None => match row.manifest.stated_rendering()? {
                Some(stated) => Image::Dropped(stated),
                None => return Err(format!("export plugin '{name}': {NO_DOOR}")),
            },
        };
        // The dispatcher stands the host's observability before whatever sink is bound here
        // (every kind's envelope is observed at its bind, ARCHITECT ruling ENVELOPE-ALL).
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
            // Opened to deliver: the host's table (an axis handed none serves only doors that
            // declare no need). Probed or checked: a probe, bound with no table.
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

    /// `None` when no `kind: export` row names `module`; else its streams and `instance`'s
    /// settings problems, each rendered by `lifecycle::refusal_lines`.
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
                let problems = match export_door::validate(&p, settings.to_string().as_bytes()) {
                    Ok(()) => Vec::new(),
                    Err(text) => refusal_lines(SECTION, instance, &text),
                };
                Some((streams, problems))
            }
            // It will not load here: its open refuses the boot naming the instance.
            Err(_) => Some((None, Vec::new())),
        }
    }

    /// The sink's own checks across `instances` of `module` at `phase`; `None` when `module` is
    /// not an export row.
    #[must_use]
    pub fn check(
        &self,
        module: &str,
        phase: u32,
        instances: &[(String, serde_json::Value)],
    ) -> Option<Vec<String>> {
        let row = self.row(module)?;
        let first = instances
            .first()
            .map_or_else(|| "{}".to_string(), |(_, s)| s.to_string());
        let named = instances.first().map_or(module, |(n, _)| n.as_str());
        match self.load(row, &label(named), None) {
            Ok(p) => {
                let Ok(opened) = ExportInstance::open(p, self.dispatcher.clone(), first.as_bytes())
                else {
                    return Some(Vec::new());
                };
                let listed: Vec<(String, Vec<u8>)> = instances
                    .iter()
                    .map(|(n, s)| (n.clone(), s.to_string().into_bytes()))
                    .collect();
                Some(
                    export_door::check(opened.plugin(), phase, &listed)
                        .unwrap_or_else(|e| vec![format!("export `module: {module}`: {e}")]),
                )
            }
            Err(_) => Some(Vec::new()),
        }
    }

    /// OPEN one instance of `module` with `settings` under the host's instance `label`.
    ///
    /// # Errors
    /// Why it will not open, naming the module.
    pub fn open(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
    ) -> Result<Arc<dyn ExportCalls>, String> {
        let row = self.row(module).ok_or_else(|| {
            match self.registry.unresolved_reason(module) {
                // A dropped plugin the scan refused: its refusal, named.
                Some(s) => format!(
                    "export plugin '{module}' is present ({}) but was not loaded: {}",
                    s.file, s.reason
                ),
                None => format!("no `kind: export` plugin answers to '{module}'"),
            }
        })?;
        let text = settings.to_string();
        let p = self.load(row, label, Some(settings))?;
        crate::observe::grant_series(
            &row.manifest.name,
            row.first_party(),
            &row.manifest.declares.metrics,
        )?;
        // The destinations its manifest declares: `open` binds each to the path the operator's
        // settings give it, and `disk.append` serves the instance those only.
        p.grant_destinations(&row.manifest.declares.destinations);
        let opened = ExportInstance::open(p, self.dispatcher.clone(), text.as_bytes())?;
        Ok(Arc::new(opened))
    }

    /// Whether `module` names a row this build LINKS.
    #[must_use]
    pub fn linked(&self, module: &str) -> bool {
        self.registry
            .linked()
            .iter()
            .any(|p| p.manifest.alias == module)
    }

    /// Whether `module` names a FIRST-PARTY row: linked, or dropped in signed by the release key.
    #[must_use]
    pub fn first_party(&self, module: &str) -> bool {
        self.registry
            .resolve(module)
            .is_some_and(LoadablePlugin::first_party)
    }
}

/// The host's label for the instance the operator named `instance` under `export:`.
fn label(instance: &str) -> String {
    format!("{SECTION}.{instance}")
}

#[cfg(test)]
#[path = "tests/export_axis_tests.rs"]
mod tests;
