// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::abi::auth::{FACT_DEFAULT_INBOUND_STYLE, FACT_READS_CREDENTIALS};
use busbar_contract::abi::mechanism::door::REWRITE_ALIAS;
use busbar_contract::abi::mechanism::rendering::read;
use busbar_contract::auth_calls::AuthCalls;
use busbar_contract::conn::DeclaredConns;

use crate::auth_door::{AuthInstance, AuthSink};
use crate::dispatch::kinds::auth::{Auth, AuthFacts};
use crate::dispatch::{
    load_dropped_bytes, load_linked, Bind, ConnTable, Dispatcher, LinkedRow, Plugin,
};
use crate::registry::LoadablePlugin;
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

    conns: Option<fn() -> Arc<dyn DeclaredConns>>,

    held: Option<Arc<dyn DeclaredConns>>,

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
    pub fn with_conns(mut self, conns: fn() -> Arc<dyn DeclaredConns>) -> Self {
        self.conns = Some(conns);
        self
    }

    #[must_use]
    pub fn with_table(mut self, table: Arc<dyn DeclaredConns>) -> Self {
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
        let refused = |e: String| format!("auth plugin '{name}': {e}");
        let sink = AuthSink::new(name);

        let envelope = match self.logs.filter(|_| serving) {
            Some(logs) => sink.to_file(&logs(), label).map_err(refused)?,
            None => sink.bind(),
        };
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
        let loaded = match row.door() {
            Some(door) => LinkedRow::of_raw(door).and_then(|r| load_linked::<Auth>(&r, bind)),
            None => match row.manifest.stated_rendering().map_err(refused)? {
                None => return Err(refused(NO_DOOR.to_string())),
                Some(stated) => load_dropped_bytes::<Auth>(&row.lib_bytes, name, &stated, bind),
            },
        };
        let plugin = loaded.map_err(|e| refused(e.to_string()))?;
        Ok(Door::Memory(plugin, sink))
    }

    fn stated(&self, row: &LoadablePlugin) -> Option<AuthFacts> {
        match row.door() {
            Some(door) => crate::dispatch::kinds::auth::stated_facts_raw(door).ok(),
            None => row
                .manifest
                .stated_rendering()
                .ok()
                .flatten()
                .and_then(|r| crate::dispatch::kinds::auth::rendered_facts(&r).ok()),
        }
    }

    #[must_use]
    pub fn linked_names(&self) -> Vec<String> {
        self.registry
            .linked()
            .iter()
            .filter(|p| p.manifest.kind == AUTH)
            .map(|p| p.manifest.alias.clone())
            .collect()
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
        rows.filter(|p| p.manifest.kind == AUTH)
            .filter_map(|row| {
                let facts = self.stated(row)?;
                (facts.facts & FACT_READS_CREDENTIALS != 0).then(|| row.manifest.alias.clone())
            })
            .collect()
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
        let mut names = vec![
            row.manifest.name.clone(),
            row.key().to_string(),
            row.manifest.alias.clone(),
        ];
        names.extend(stated_aliases(row));
        names.sort();
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
        let stating: Vec<(String, Vec<String>)> = rows
            .filter(|p| p.manifest.kind == AUTH)
            .filter_map(|row| {
                let facts = self.stated(row)?;
                (facts.facts & FACT_DEFAULT_INBOUND_STYLE != 0)
                    .then(|| (row.manifest.alias.clone(), facts.carriers))
            })
            .collect();
        match stating.as_slice() {
            [] => Ok(Vec::new()),
            [(_, carriers)] => Ok(carriers.clone()),
            many => Err(two_default_inbound_styles(
                &many.iter().map(|(a, _)| a.as_str()).collect::<Vec<_>>(),
            )),
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
            let Some(f) = self.stated(other) else {
                continue;
            };
            if let Some(kind) = mine.iter().find(|k| f.credential_kinds.contains(k)) {
                return Err(format!(
                    "auth plugins '{alias}' and '{}' both declare they read the credential kind \
                     '{kind}'; one verifier reads a credential kind",
                    other.manifest.alias
                ));
            }
        }
        Ok(())
    }

    pub fn open(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
    ) -> Result<Arc<dyn AuthCalls>, String> {
        self.open_instance(module, label, settings)
            .map(|opened| opened as Arc<dyn AuthCalls>)
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
    ) -> Result<Arc<AuthInstance>, String> {
        self.open_instance(module, label, settings)
    }

    fn open_instance(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
    ) -> Result<Arc<AuthInstance>, String> {
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
        let text = settings.to_string();
        let opened = AuthInstance::open(
            plugin,
            sink,
            self.dispatcher.clone(),
            label,
            text.as_bytes(),
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
        for row in rows.filter(|p| p.manifest.kind == AUTH) {
            let Ok(Door::Memory(plugin, _)) = self.load(row, &row.manifest.alias, true) else {
                continue;
            };
            let Some(decl) = outbound_styles(&plugin)
                .into_iter()
                .find(|s| s.name == style)
            else {
                continue;
            };
            let settings = serde_json::to_vec(settings).map_err(|e| e.to_string())?;
            let auth =
                OutboundInstance::open_with(plugin, Arc::clone(&self.dispatcher), 0, &settings)?;
            return Ok(Some(busbar_contract::auth_calls::OutboundServing {
                auth: Arc::new(auth),
                flags: decl.flags,
                points: decl.points,
            }));
        }
        Ok(None)
    }
}

fn stated_aliases(row: &LoadablePlugin) -> Vec<String> {
    let stated = match row.door() {
        Some(door) => LinkedRow::of_raw(door).ok().map(|r| r.statement),
        None => row.manifest.stated_rendering().ok().flatten(),
    };
    stated
        .and_then(|s| read(&s).ok())
        .map(|r| crate::boot::rewrites(&r, REWRITE_ALIAS).collect())
        .unwrap_or_default()
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
        settings: &serde_json::Value,
    ) -> Result<Arc<dyn AuthCalls>, String> {
        AuthRows::open(self, module, label, settings)
    }
}

#[must_use]
pub fn two_default_inbound_styles(rows: &[&str]) -> String {
    format!(
        "more than one auth plugin states the default inbound style ({}): at most one may; \
         remove all but one",
        rows.join(", ")
    )
}

#[cfg(test)]
#[path = "tests/auth_axis_tests.rs"]
mod tests;
