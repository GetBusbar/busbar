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
//! is refused at scan naming the rebuild.
//!
//! M6-COLD-DELETE (TRANSITIONAL, drained by the request-log sinks' door re-pins: the file sink on
//! the host's disk lane, the webhook sink on the connector's admission): a row still on the COLD
//! export lane — a linked `BUSBAR_COLD_ENTRY`, or a dropped-in library stating no Statement — opens
//! through [`ColdExport`] (ARCHITECT ruling 2026-09-29, WIRE-EXPORT Q4: the auth kind's
//! arrangement). It and `crate::export` are deleted with the last such row.

use std::sync::{Arc, OnceLock};

use busbar_contract::abi::export::{CheckPhase, ExportStream, CHECK_PHASE_LIMITS};
use busbar_contract::abi::mechanism::lifecycle::refusal_lines;
use busbar_contract::abi::mechanism::route::Route;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::conn::DeclaredConns;
use busbar_contract::export_calls::{Delivered, ExportCalls, Family, Probed, ServeRequest, Served};

use crate::dispatch::kinds::export::{Export, ExportFacts};
use crate::dispatch::{
    load_dropped_bytes, load_linked, Bind, Dispatcher, EnvelopeSink, LinkedRow, NoSink, Plugin,
    PluginLogConfig,
};
use crate::export::DynExport;
use crate::export_door::{self, ExportInstance};
use crate::registry::LoadablePlugin;
use crate::PluginRegistry;

/// The export kind's name in the registry.
const EXPORT: &str = busbar_contract::abi::cold::kind::EXPORT;

/// The export kind's configuration section, read off the contract's kind list: a refusal's line
/// renders under it.
const SECTION: &str = busbar_contract::plugin::Kind::Export.root();

/// The host's clamp on an export Statement's `max_inflight`.
const MAX_INFLIGHT_CAP: u32 = 64;

/// How a row opens.
enum Door {
    /// On the memory ABI: the bound plugin.
    Memory(Plugin<Export>),
    /// M6-COLD-DELETE: on the cold lane.
    Cold,
}

/// The export rows of a registry, opening instances on a dispatcher.
pub struct ExportRows<'r> {
    registry: &'r PluginRegistry,
    dispatcher: Arc<Dispatcher>,
    /// `plugins.logs`: each OPENED instance's own log sink; `None` = its records are discarded.
    logs: Option<&'r PluginLogConfig>,
    /// The host's one connection table: an OPENED instance's needs are declared on it.
    conns: Option<Arc<dyn DeclaredConns>>,
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

    fn row(&self, module: &str) -> Option<&'r LoadablePlugin> {
        self.registry
            .resolve(module)
            .filter(|p| p.manifest.kind == EXPORT)
    }

    /// Bind `row`'s door under `label`: an instance only probed or checked binds with no log sink
    /// and no connection table (nothing is opened to the network or the disk while a configuration
    /// is judged); one opened to deliver binds with both.
    fn load(&self, row: &LoadablePlugin, label: &str, opening: bool) -> Result<Door, String> {
        let name = &row.manifest.name;
        let sink: Arc<dyn EnvelopeSink> = match (opening, self.logs) {
            (true, Some(logs)) => Arc::new(logs.sink(label, KindCode::Export, Arc::new(NoSink))?),
            _ => Arc::new(NoSink),
        };
        let bind = Bind {
            instance: Arc::from(label),
            max_inflight_cap: MAX_INFLIGHT_CAP,
            sink,
            dispatcher: self.dispatcher.adopter(),
            conns: if opening { self.conns.clone() } else { None },
        };
        let loaded = match row.door() {
            Some(door) => LinkedRow::of(door).and_then(|r| load_linked::<Export>(&r, bind)),
            None if row.image_is_cold_linked() => return Ok(Door::Cold),
            None => {
                // M6-COLD-DELETE: a dropped-in cold sink states no Statement rendering.
                let Some(stated) = row.manifest.stated_rendering()? else {
                    return Ok(Door::Cold);
                };
                load_dropped_bytes::<Export>(&row.lib_bytes, name, &stated, bind)
            }
        };
        loaded
            .map(Door::Memory)
            .map_err(|e| format!("export plugin '{name}': {e}"))
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
        match self.load(row, &label(instance), false) {
            Ok(Door::Memory(p)) => {
                let streams = p.context::<ExportFacts>().map(|f| f.streams.clone());
                let problems = match export_door::validate(&p, settings.to_string().as_bytes()) {
                    Ok(()) => Vec::new(),
                    Err(text) => refusal_lines(SECTION, instance, &text),
                };
                Some((streams, problems))
            }
            Ok(Door::Cold) => {
                self.registry
                    .probe_export(module, instance, settings)
                    .map(|(streams, problems)| {
                        let streams = streams.map(|s| s.into_iter().map(|s| s as u8).collect());
                        (streams, problems)
                    })
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
        match self.load(row, &label(named), false) {
            Ok(Door::Memory(p)) => {
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
            Ok(Door::Cold) => {
                let phase = match phase {
                    CHECK_PHASE_LIMITS => CheckPhase::Limits,
                    _ => CheckPhase::Instances,
                };
                self.registry.check_export(module, phase, instances)
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
        let row = self
            .row(module)
            .ok_or_else(|| format!("no `kind: export` plugin answers to '{module}'"))?;
        let text = settings.to_string();
        match self.load(row, label, true)? {
            Door::Memory(p) => {
                crate::observe::grant_series(
                    &row.manifest.name,
                    row.first_party(),
                    &row.manifest.declares.metrics,
                )?;
                let opened = ExportInstance::open(p, self.dispatcher.clone(), text.as_bytes())?;
                Ok(Arc::new(opened))
            }
            Door::Cold => Ok(Arc::new(ColdExport::open(
                self.registry.open_export(module, &text)?,
            ))),
        }
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

/// M6-COLD-DELETE: a not-yet-ported sink on the cold export lane, as [`ExportCalls`].
pub struct ColdExport {
    sink: Arc<DynExport>,
    streams: Vec<u8>,
    started: OnceLock<Option<(bool, u64, String)>>,
}

impl std::fmt::Debug for ColdExport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ColdExport")
            .field("sink", &self.sink.name())
            .finish_non_exhaustive()
    }
}

impl ColdExport {
    /// The adapter over an opened cold sink.
    #[must_use]
    pub fn open(sink: DynExport) -> Self {
        let streams = sink.streams().iter().map(|s| *s as u8).collect();
        Self {
            sink: Arc::new(sink),
            streams,
            started: OnceLock::new(),
        }
    }
}

impl ExportCalls for ColdExport {
    fn streams(&self) -> &[u8] {
        &self.streams
    }

    fn routes(&self) -> &[Route] {
        self.sink.routes()
    }

    fn deliver(&self, stream: u8, line: Vec<u8>, hold: Box<dyn Send>) -> Delivered {
        let (Some(stream), Ok(payload)) = (
            ExportStream::ALL.get(usize::from(stream)).copied(),
            serde_json::from_slice::<serde_json::Value>(&line),
        ) else {
            return Delivered::Shed;
        };
        self.sink.deliver_detached(stream, Arc::new(payload), hold);
        Delivered::Queued
    }

    fn scrape(&self, families: &[Family]) -> Result<Vec<u8>, String> {
        self.sink
            .scrape(crate::scrape::cold_families(families))
            .map(|(_, body)| body.into_bytes())
    }

    fn status(&self) -> Option<Vec<u8>> {
        self.sink.status();
        None
    }

    fn serve(&self, req: &ServeRequest<'_>) -> Result<Served, String> {
        use busbar_contract::abi::cold::endpoint::EndpointRequest;
        let request = EndpointRequest {
            method: req.method.to_string(),
            path: req.path.to_string(),
            query: req.query.unwrap_or_default().to_string(),
            headers: req.headers.to_vec(),
            body: req.body.to_vec(),
        };
        let r = self.sink.serve(&request);
        Ok(Served {
            status: r.status,
            headers: r.headers,
            body: r.body,
        })
    }

    fn admission(&self) -> Option<(bool, u64, String)> {
        self.started
            .get_or_init(|| {
                self.sink.start().unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "export plugin start failed");
                    None
                })
            })
            .clone()
    }

    fn shed(&self) {
        self.sink.shed();
    }
}

#[cfg(test)]
#[path = "tests/export_axis_tests.rs"]
mod tests;
