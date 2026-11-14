// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::abi::auth::{FACT_DEFAULT_INBOUND_STYLE, FACT_READS_CREDENTIALS};
use busbar_contract::abi::mechanism::door::REWRITE_ALIAS;
use busbar_contract::abi::mechanism::rendering::read;
use busbar_contract::auth_calls::AuthCalls;
use busbar_contract::conn::admissions::AdmissionAuthority;

use crate::auth_door::{AuthInstance, AuthSink};
use crate::dispatch::kinds::auth::{Auth, AuthFacts};
use crate::dispatch::{Bind, ConnTable, Dispatcher, LinkedRow, Plugin};
use crate::registry::{open_loadable, LoadablePlugin, RowRefusal};
use crate::PluginRegistry;

const AUTH: &str = "auth";

const MAX_INFLIGHT_CAP: u32 = 64;

enum Door {
    Memory(Plugin<Auth>, AuthSink),
}

pub const NO_DOOR: &str = "it speaks the 1.5.5 JSON auth contract, which this host does not load — rebuild the plugin against the 1.6.0 SDK";

pub struct AuthRows {
    registry: Arc<PluginRegistry>,
    dispatcher: Arc<Dispatcher>,

    conns: Option<fn() -> AdmissionAuthority>,

    held: Option<AdmissionAuthority>,

    logs: Option<fn() -> crate::dispatch::PluginLogConfig>,

    #[cfg(test)]
    bound: std::sync::Mutex<Vec<String>>,
}

impl std::fmt::Debug for AuthRows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthRows").finish_non_exhaustive()
    }
}

impl AuthRows {
    #[must_use]
    pub fn new(registry: Arc<PluginRegistry>, dispatcher: Arc<Dispatcher>) -> Self {
        Self {
            registry,
            dispatcher,
            conns: None,
            held: None,
            logs: None,
            #[cfg(test)]
            bound: std::sync::Mutex::default(),
        }
    }

    #[must_use]
    pub fn with_logs(mut self, logs: fn() -> crate::dispatch::PluginLogConfig) -> Self {
        self.logs = Some(logs);
        self
    }

    #[must_use]
    pub fn with_conns(mut self, conns: fn() -> AdmissionAuthority) -> Self {
        self.conns = Some(conns);
        self
    }

    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn with_table(mut self, table: AdmissionAuthority) -> Self {
        self.held = Some(table);
        self
    }

    fn row(&self, module: &str) -> Option<&LoadablePlugin> {
        self.registry
            .resolve(module)
            .filter(|p| p.manifest.kind == AUTH)
            .or_else(|| {
                let rows = self
                    .registry
                    .linked()
                    .iter()
                    .chain(self.registry.loadable());
                rows.filter(|p| p.manifest.kind == AUTH)
                    .find(|p| stated_aliases(p).iter().any(|a| a == module))
            })
    }

    fn load(&self, row: &LoadablePlugin, label: &str, serving: bool) -> Result<Door, String> {
        let name = row.key();
        #[cfg(test)]
        self.bound
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(name.to_string());
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: names the auth plugin that did not load"
        )]
        let refused = |e: String| format!("auth plugin '{name}': {e}");
        let sink = AuthSink::new(name);

        let envelope = match self.logs.filter(|_| serving) {
            Some(logs) => sink.to_file(&logs(), label).map_err(refused)?,
            None => sink.bind(),
        };
        // busbar:expect(bp::into_alloc, reason = "boot: a loaded auth instance keeps its label")
        let bind = Bind {
            instance: Arc::from(label),
            max_inflight_cap: MAX_INFLIGHT_CAP,
            sink: envelope,
            dispatcher: self.dispatcher.adopter(),

            conns: if serving {
                ConnTable::serving(self.conns.map(|c| c()).or_else(|| self.held.clone()))
            } else {
                ConnTable::Probe
            },
        };
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: names why the auth plugin did not load"
        )]
        let plugin = open_loadable::<Auth>(row, name, move || Ok(bind)).map_err(|e| {
            refused(match e {
                RowRefusal::Stated(e) | RowRefusal::Bind(e) => e,
                RowRefusal::NoDoor => NO_DOOR.to_string(),
                RowRefusal::Load(e) => e.to_string(),
            })
        })?;
        Ok(Door::Memory(plugin, sink))
    }

    fn stated_read(&self, row: &LoadablePlugin) -> Result<Option<AuthFacts>, String> {
        match row.door() {
            Some(door) => crate::dispatch::kinds::auth::stated_facts_raw(door).map(Some),
            None => match row.manifest.stated_rendering()? {
                Some(r) => crate::dispatch::kinds::auth::rendered_facts(&r).map(Some),
                None => Ok(None),
            },
        }
    }

    fn stated(&self, row: &LoadablePlugin) -> Option<AuthFacts> {
        self.stated_read(row).ok().flatten()
    }

    #[must_use]
    pub fn linked_names(&self) -> Vec<String> {
        // busbar:expect(bp::clone_alloc, reason = "config: lists the linked auth modules config may name")
        #[expect(
            clippy::disallowed_methods,
            reason = "config: lists the linked auth modules config may name"
        )]
        let names = self
            .registry
            .linked()
            .iter()
            .filter(|p| p.manifest.kind == AUTH)
            .map(|p| p.manifest.alias.clone())
            .collect();
        names
    }

    #[must_use]
    pub fn answers(&self, module: &str) -> bool {
        self.row(module).is_some()
    }

    #[must_use]
    pub fn linked(&self, module: &str) -> bool {
        self.registry
            .linked()
            .iter()
            .filter(|p| p.manifest.kind == AUTH)
            .any(|p| p.manifest.answers_to(module) || stated_aliases(p).iter().any(|a| a == module))
    }

    #[must_use]
    pub fn operator(&self) -> Option<(String, String)> {
        let rows = self
            .registry
            .linked()
            .iter()
            .chain(self.registry.loadable());
        rows.filter(|p| p.manifest.kind == AUTH).find_map(|row| {
            let principal = self.stated(row)?.operator_principal?;
            // busbar:expect(bp::clone_alloc, reason = "config: names the operator auth plugin when config is read")
            Some((row.manifest.alias.clone(), principal))
        })
    }

    #[must_use]
    pub fn credential_readers(&self) -> Vec<String> {
        let rows = self
            .registry
            .linked()
            .iter()
            .chain(self.registry.loadable());
        #[expect(
            clippy::disallowed_methods,
            reason = "config: lists the credential-reading auth plugins when config is read"
        )]
        let readers = rows
            .filter(|p| p.manifest.kind == AUTH)
            .filter_map(|row| {
                let facts = self.stated(row)?;
                // busbar:expect(bp::clone_alloc, reason = "config: lists the credential-reading auth plugins when config is read")
                (facts.facts & FACT_READS_CREDENTIALS != 0).then(|| row.manifest.alias.clone())
            })
            .collect();
        readers
    }

    #[must_use]
    pub fn issued_credential(&self) -> Option<(String, busbar_contract::auth_calls::IssuedShape)> {
        let rows = self
            .registry
            .linked()
            .iter()
            .chain(self.registry.loadable());
        rows.filter(|p| p.manifest.kind == AUTH).find_map(|row| {
            let facts = self.stated(row)?;
            if facts.facts & FACT_READS_CREDENTIALS == 0 {
                return None;
            }
            let kind = facts.credential_kinds.first()?.clone();
            facts.issued.map(|shape| (kind, shape))
        })
    }

    #[must_use]
    pub fn carriers(&self, module: &str) -> Vec<String> {
        let Some(row) = self.row(module) else {
            return Vec::new();
        };
        self.stated(row).map(|f| f.carriers).unwrap_or_default()
    }

    pub fn inbound_style(&self, module: &str) -> Option<busbar_contract::auth_calls::InboundStyle> {
        use busbar_contract::abi::auth::{CAP_INBOUND, FACT_OPERATOR};
        let row = self.row(module)?;
        let facts = self.stated(row)?;
        if facts.caps & CAP_INBOUND == 0
            || facts.facts & (FACT_OPERATOR | FACT_READS_CREDENTIALS) != 0
        {
            return None;
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "config: names an inbound auth style when config is read"
        )]
        let mut names = vec![
            row.manifest.name.clone(),
            row.key().to_string(),
            row.manifest.alias.clone(),
        ];
        names.extend(stated_aliases(row));
        names.sort_unstable();
        names.dedup();
        Some(busbar_contract::auth_calls::InboundStyle {
            module: row.manifest.name.clone(),
            names,
            points: facts.inbound_points,
        })
    }

    pub fn default_inbound_style(&self) -> Result<Vec<String>, String> {
        let rows = self
            .registry
            .linked()
            .iter()
            .chain(self.registry.loadable());
        #[expect(
            clippy::disallowed_methods,
            reason = "config: finds the default inbound style when config is read"
        )]
        let stating: Vec<(String, Vec<String>)> = rows
            .filter(|p| p.manifest.kind == AUTH)
            .filter_map(|row| {
                let facts = self.stated(row)?;
                // busbar:expect(bp::clone_alloc, reason = "config: finds the default inbound style when config is read")
                (facts.facts & FACT_DEFAULT_INBOUND_STYLE != 0)
                    .then(|| (row.manifest.alias.clone(), facts.carriers))
            })
            .collect();
        match stating.as_slice() {
            [] => Ok(Vec::new()),
            [(_, carriers)] => Ok(carriers.clone()),
            many => {
                #[expect(
                    clippy::disallowed_methods,
                    reason = "config: names every auth plugin stating the default inbound style"
                )]
                let rows = many.iter().map(|(a, _)| a.as_str()).collect::<Vec<_>>();
                Err(two_default_inbound_styles(&rows))
            }
        }
    }

    fn one_reader_per_kind(&self, row: &LoadablePlugin, mine: &[String]) -> Result<(), String> {
        if mine.is_empty() {
            return Ok(());
        }
        let rows = self
            .registry
            .linked()
            .iter()
            .chain(self.registry.loadable());
        let alias = &row.manifest.alias;
        for other in rows.filter(|p| p.manifest.kind == AUTH && p.manifest.alias != *alias) {
            let f = match self.stated_read(other) {
                Ok(Some(f)) => f,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(
                        plugin = %other.manifest.alias,
                        error = %e,
                        "an auth plugin's Statement does not read back; the one-reader check skips it"
                    );
                    continue;
                }
            };
            if let Some(kind) = mine.iter().find(|k| f.credential_kinds.contains(k)) {
                #[expect(
                    clippy::disallowed_methods,
                    reason = "boot: two auth plugins read the same credential kind"
                )]
                let refused = format!(
                    "auth plugins '{alias}' and '{}' both declare they read the credential kind \
                     '{kind}'; one verifier reads a credential kind",
                    other.manifest.alias
                );
                return Err(refused);
            }
        }
        Ok(())
    }

    pub fn open(
        &self,
        module: &str,
        label: &str,
        settings: &busbar_contract::plugin_settings::ResolvedSettings,
    ) -> Result<Arc<dyn AuthCalls>, String> {
        self.open_instance(module, label, settings)
            .map(|opened| opened as Arc<dyn AuthCalls>)
    }

    fn open_instance(
        &self,
        module: &str,
        label: &str,
        settings: &busbar_contract::plugin_settings::ResolvedSettings,
    ) -> Result<Arc<AuthInstance>, String> {
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: names a configured auth module no plugin answers to"
        )]
        let row = self
            .row(module)
            .ok_or_else(|| format!("no `kind: auth` plugin answers to '{module}'"))?;
        let name = row.manifest.name.clone();
        let Door::Memory(plugin, sink) = self.load(row, label, true)?;
        let kinds = plugin
            .context::<AuthFacts>()
            .map(|f| f.credential_kinds.clone())
            .unwrap_or_default();
        self.one_reader_per_kind(row, &kinds)?;
        let (settings, secrets) = crate::auth_door::split_secrets(&plugin, settings);
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: an auth instance's settings render once, when it opens"
        )]
        let text = settings.encode().map_err(|error| error.to_string())?;
        let seal = self
            .dispatcher
            .seal()
            .ok_or("auth opening requires the host settings seal")?;
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: names the auth plugin that did not open"
        )]
        let opened = AuthInstance::open(
            plugin,
            sink,
            self.dispatcher.clone(),
            label,
            text.expose(seal),
            secrets,
        )
        .map_err(|e| format!("plugin '{name}' open failed: {e}"))?;
        Ok(Arc::new(opened))
    }

    pub fn serving(
        &self,
        style: &str,
        settings: &serde_json::Value,
    ) -> Result<Option<busbar_contract::auth_calls::OutboundServing>, String> {
        use crate::dispatch::auth_outbound::{outbound_styles, OutboundInstance};
        let rows = self
            .registry
            .linked()
            .iter()
            .chain(self.registry.loadable());
        let mut unloaded = None;
        for row in rows.filter(|p| p.manifest.kind == AUTH) {
            let plugin = match self.load(row, &row.manifest.alias, true) {
                Ok(Door::Memory(plugin, _)) => plugin,
                Err(e) => {
                    unloaded.get_or_insert(e);
                    continue;
                }
            };
            let Some((flags, points)) = outbound_styles(&plugin)
                .iter()
                .find(|s| s.name == style)
                .map(|s| (s.flags, s.points))
            else {
                continue;
            };
            #[expect(
                clippy::disallowed_methods,
                reason = "config: binding an outbound style renders its settings once"
            )]
            let settings = serde_json::to_vec(settings).map_err(|e| e.to_string())?;
            let auth =
                OutboundInstance::open_with(plugin, Arc::clone(&self.dispatcher), 0, &settings)?;
            return Ok(Some(busbar_contract::auth_calls::OutboundServing {
                auth: Arc::new(auth),
                flags,
                points,
            }));
        }
        unloaded.map_or(Ok(None), Err)
    }
}

fn stated_aliases(row: &LoadablePlugin) -> Vec<String> {
    let stated = match row.door() {
        Some(door) => LinkedRow::of_raw(door).ok().map(|r| r.statement),
        None => row.manifest.stated_rendering().ok().flatten(),
    };
    #[expect(
        clippy::disallowed_methods,
        reason = "config: an auth plugin's stated aliases, read when config names a module"
    )]
    let aliases = stated
        .and_then(|s| read(&s).ok())
        .map(|r| crate::boot::rewrites(&r, REWRITE_ALIAS).collect())
        .unwrap_or_default();
    aliases
}

impl busbar_contract::auth_calls::AuthAxis for AuthRows {
    fn linked_names(&self) -> Vec<String> {
        AuthRows::linked_names(self)
    }

    fn answers(&self, module: &str) -> bool {
        AuthRows::answers(self, module)
    }

    fn linked(&self, module: &str) -> bool {
        AuthRows::linked(self, module)
    }

    fn operator(&self) -> Option<(String, String)> {
        AuthRows::operator(self)
    }

    fn credential_readers(&self) -> Vec<String> {
        AuthRows::credential_readers(self)
    }

    fn issued_credential(&self) -> Option<(String, busbar_contract::auth_calls::IssuedShape)> {
        AuthRows::issued_credential(self)
    }

    fn carriers(&self, module: &str) -> Vec<String> {
        AuthRows::carriers(self, module)
    }

    fn inbound_style(&self, module: &str) -> Option<busbar_contract::auth_calls::InboundStyle> {
        AuthRows::inbound_style(self, module)
    }

    fn default_inbound_style(&self) -> Result<Vec<String>, String> {
        AuthRows::default_inbound_style(self)
    }

    fn open(
        &self,
        module: &str,
        label: &str,
        settings: &busbar_contract::plugin_settings::ResolvedSettings,
    ) -> Result<Arc<dyn AuthCalls>, String> {
        AuthRows::open(self, module, label, settings)
    }
}

#[must_use]
pub fn two_default_inbound_styles(rows: &[&str]) -> String {
    #[expect(
        clippy::disallowed_methods,
        reason = "config: names every auth plugin stating the default inbound style"
    )]
    let refused = format!(
        "more than one auth plugin states the default inbound style ({}): at most one may; \
         remove all but one",
        rows.join(", ")
    );
    refused
}

#[cfg(test)]
#[path = "tests/auth_axis_tests.rs"]
mod tests;
