// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::auth_calls::codes::FACT_READS_CREDENTIALS;
use busbar_contract::auth_calls::AuthCalls;
use busbar_contract::conn::admissions::AdmissionAuthority;

use crate::auth_door::{AuthInstance, AuthSink};
use crate::cold::auth_axis as cold;
use crate::dispatch::kinds::auth::{Auth, AuthFacts};
use crate::dispatch::{Bind, ConnTable, Dispatcher, Plugin};
use crate::registry::{open_loadable, LoadablePlugin};
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
                    .find(|p| cold::stated_aliases(p).iter().any(|a| a == module))
            })
    }

    /// The auth rows this build links, in registration order.
    pub(crate) fn linked_rows(&self) -> impl Iterator<Item = &LoadablePlugin> + '_ {
        self.registry
            .linked()
            .iter()
            .filter(|p| p.manifest.kind == AUTH)
    }

    /// Every auth row: the linked ones, then the dropped-in ones.
    pub(crate) fn auth_rows(&self) -> impl Iterator<Item = &LoadablePlugin> + '_ {
        self.registry
            .linked()
            .iter()
            .chain(self.registry.loadable())
            .filter(|p| p.manifest.kind == AUTH)
    }

    /// Tests only: remember that `name` was bound.
    #[cfg(test)]
    fn record_bound(&self, name: &str) {
        self.bound
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(name.to_string());
    }

    fn load(&self, row: &LoadablePlugin, label: &str, serving: bool) -> Result<Door, String> {
        let name = row.key();
        #[cfg(test)]
        self.record_bound(name);
        let sink = AuthSink::new(name);

        let envelope = match self.logs.filter(|_| serving) {
            Some(logs) => sink
                .to_file(&logs(), label)
                .map_err(|e| cold::load_refused(name, &e))?,
            None => sink.bind(),
        };
        let bind = Bind {
            accept: Default::default(),
            instance: cold::instance(label),
            max_inflight_cap: MAX_INFLIGHT_CAP,
            sink: envelope,
            dispatcher: self.dispatcher.adopter(),

            conns: if serving {
                ConnTable::serving(self.conns.map(|c| c()).or_else(|| self.held.clone()))
            } else {
                ConnTable::Probe
            },
        };
        let plugin = open_loadable::<Auth>(row, name, move || Ok(bind))
            .map_err(|e| cold::row_refused(name, e))?;
        Ok(Door::Memory(plugin, sink))
    }

    fn stated_read(&self, row: &LoadablePlugin) -> Result<Option<AuthFacts>, String> {
        stated_of(row)
    }

    pub(crate) fn stated(&self, row: &LoadablePlugin) -> Option<AuthFacts> {
        self.stated_read(row).ok().flatten()
    }

    #[must_use]
    pub fn linked_names(&self) -> Vec<String> {
        cold::linked_names(self)
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
            .any(|p| {
                p.manifest.answers_to(module) || cold::stated_aliases(p).iter().any(|a| a == module)
            })
    }

    #[must_use]
    pub fn operator_claims(&self) -> busbar_contract::auth_calls::OperatorClaims {
        cold::operator_claims(self.auth_rows())
    }

    #[must_use]
    pub fn credential_readers(&self) -> Vec<String> {
        cold::credential_readers(self)
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
        use busbar_contract::auth_calls::codes::{CAP_INBOUND, FACT_OPERATOR};
        let row = self.row(module)?;
        let facts = self.stated(row)?;
        if facts.caps & CAP_INBOUND == 0
            || facts.facts & (FACT_OPERATOR | FACT_READS_CREDENTIALS) != 0
        {
            return None;
        }
        Some(cold::inbound_style(row, facts.inbound_points))
    }

    pub fn default_inbound_style(&self) -> Result<Vec<String>, String> {
        cold::default_inbound_style(self)
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
                return Err(cold::two_readers(alias, &other.manifest.alias, kind));
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
        let row = self.row(module).ok_or_else(|| cold::no_plugin(module))?;
        let name = row.manifest.name.clone();
        let Door::Memory(plugin, sink) = self.load(row, label, true)?;
        let kinds = plugin
            .context::<AuthFacts>()
            .map(|f| f.credential_kinds.clone())
            .unwrap_or_default();
        self.one_reader_per_kind(row, &kinds)?;
        let (settings, secrets) = crate::auth_door::split_secrets(&plugin, settings);
        let text = settings
            .encode()
            .map_err(|error| cold::settings_unrendered(&error))?;
        let seal = self
            .dispatcher
            .seal()
            .ok_or("auth opening requires the host settings seal")?;
        let opened = AuthInstance::open(
            plugin,
            sink,
            self.dispatcher.clone(),
            label,
            text.expose(seal),
            secrets,
        )
        .map_err(|e| cold::open_failed(&name, &e))?;
        Ok(Arc::new(opened))
    }

    pub fn serving<S: serde::Serialize + ?Sized>(
        &self,
        style: &str,
        settings: &S,
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
            let settings = cold::outbound_settings(settings)?;
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

    fn operator_claims(&self) -> busbar_contract::auth_calls::OperatorClaims {
        AuthRows::operator_claims(self)
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

/// The facts one auth row's Statement states: the linked door's, or the signed manifest's rendering
/// (the signature covers it), with no dlopen. `Err` when the Statement does not decode.
pub(crate) fn stated_of(row: &LoadablePlugin) -> Result<Option<AuthFacts>, String> {
    match row.door() {
        Some(door) => crate::dispatch::kinds::auth::stated_facts_raw(door).map(Some),
        None => match row.manifest.stated_rendering()? {
            Some(r) => crate::dispatch::kinds::auth::rendered_facts(&r).map(Some),
            None => Ok(None),
        },
    }
}

/// THE OPERATOR CLAIMS among `rows` (linked rows first, then the dropped-in ones): every `kind:
/// auth` row stating the operator fact, and every auth row whose Statement does not read
/// (OPERATOR-FROM-ADMITTED-AUTH §3.2). Process start reads them from the start scan's rows; every
/// build reads them again from its registry.
#[must_use]
pub fn operator_claims<'a>(
    rows: impl Iterator<Item = &'a LoadablePlugin>,
) -> busbar_contract::auth_calls::OperatorClaims {
    cold::operator_claims(rows.filter(|p| p.manifest.kind == AUTH))
}

#[must_use]
pub fn two_default_inbound_styles(rows: &[&str]) -> String {
    cold::two_default_inbound_styles(rows)
}

#[cfg(test)]
#[path = "tests/auth_axis_tests.rs"]
mod tests;
