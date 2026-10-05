// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH ROWS (WIRE-AUTH): [`AuthRows`] answers and opens the plugin registry's `kind: auth` rows
//! on the process's one dispatcher. The composition root implements the contract's `AuthAxis` over
//! it and installs that axis on the kernel (`install_auth_axis`, ARCHITECT ruling 2026-09-29: the
//! opener seam, impl in the root), so the kernel's identity chain opens auth instances naming
//! neither this crate nor the root.
//!
//! A row opens on the auth kind's MEMORY ABI (`abi::auth`, through [`AuthInstance`]) when it is a
//! linked door ([`crate::registry::LinkedEntry::Door`]) or a dropped-in library exporting
//! `busbar_plugin_door`. A dropped-in library that states no door (a 1.5.5 JSON-contract auth
//! plugin) is refused at its load, naming the rebuild ([`NO_DOOR`]).

use std::sync::Arc;

use busbar_contract::abi::mechanism::door::REWRITE_ALIAS;
use busbar_contract::abi::mechanism::rendering::read;
use busbar_contract::auth_calls::AuthCalls;
use busbar_contract::conn::DeclaredConns;

use crate::auth_door::{AuthInstance, AuthSink};
use crate::dispatch::kinds::auth::{Auth, AuthFacts};
use crate::dispatch::{load_dropped_bytes, load_linked, Bind, Dispatcher, LinkedRow, Plugin};
use crate::registry::LoadablePlugin;
use crate::PluginRegistry;

/// The auth kind's word in a registry row's manifest (`kind: auth`).
const AUTH: &str = "auth";

/// The host's clamp on an auth Statement's `max_inflight`.
const MAX_INFLIGHT_CAP: u32 = 64;

/// How a row opens.
enum Door {
    /// On the memory ABI: the bound plugin and its envelope sink.
    Memory(Plugin<Auth>, AuthSink),
}

/// Why a row that states no door does not open: a 1.5.5 JSON-contract auth plugin.
pub const NO_DOOR: &str = "it speaks the 1.5.5 JSON auth contract, which this host does not load — rebuild the plugin against the 1.6.0 SDK";

/// The auth rows of `registry`, opening instances on `dispatcher`. One per build: the kernel builds
/// its registry per boot or apply and opens that build's auth instances over it, on the process's
/// one dispatcher (ARCHITECT ruling 2026-09-30, AUTH-DOOR Q1).
pub struct AuthRows {
    registry: Arc<PluginRegistry>,
    dispatcher: Arc<Dispatcher>,
    /// The host's one connection table, read when an instance OPENS to serve: it declares its needs
    /// on it (a row only read for its facts binds with none).
    conns: Option<fn() -> Arc<dyn DeclaredConns>>,
    /// A connection table held by the axis itself (a test's stand-in for the connector, with far
    /// ends of its own), used the same way when no `conns` is read.
    held: Option<Arc<dyn DeclaredConns>>,
}

impl std::fmt::Debug for AuthRows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthRows").finish_non_exhaustive()
    }
}

impl AuthRows {
    /// The axis over `registry`'s auth rows, on `dispatcher`.
    #[must_use]
    pub fn new(registry: Arc<PluginRegistry>, dispatcher: Arc<Dispatcher>) -> Self {
        Self {
            registry,
            dispatcher,
            conns: None,
            held: None,
        }
    }

    /// Each instance opened to serve declares its needs on the table `conns` answers when it opens
    /// (the process's one connector): a networked auth door (a directory over `tcp`) dials through
    /// it.
    #[must_use]
    pub fn with_conns(mut self, conns: fn() -> Arc<dyn DeclaredConns>) -> Self {
        self.conns = Some(conns);
        self
    }

    /// [`Self::with_conns`] over a table the axis holds: a test's stand-in for the process's
    /// connector (an IdP's far ends in process). Never a shipped build's: the root hands the
    /// connector through [`Self::with_conns`].
    #[must_use]
    pub fn with_table(mut self, table: Arc<dyn DeclaredConns>) -> Self {
        self.held = Some(table);
        self
    }

    /// The `kind: auth` row config names by `module`: the registry's name or manifest alias, else
    /// an alias the row's Statement states (its alias rewrites).
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

    /// Load `row`'s door for the instance `label`, bound to the dispatcher and admitted against
    /// the Statement the row states (a linked door's own rendering, a dropped plugin's signed one).
    /// `serving`: the instance is opened to serve, and declares its needs on the host's table; one
    /// only read for its facts binds with no table.
    fn load(&self, row: &LoadablePlugin, label: &str, serving: bool) -> Result<Door, String> {
        let name = &row.manifest.name;
        let refused = |e: String| format!("auth plugin '{name}': {e}");
        let sink = AuthSink::new(name);
        let bind = Bind {
            instance: Arc::from(label),
            max_inflight_cap: MAX_INFLIGHT_CAP,
            sink: sink.bind(),
            dispatcher: self.dispatcher.adopter(),
            conns: if serving {
                self.conns.map(|c| c()).or_else(|| self.held.clone())
            } else {
                None
            },
        };
        let loaded = match row.door() {
            Some(door) => LinkedRow::of(door).and_then(|r| load_linked::<Auth>(&r, bind)),
            None => match row.manifest.stated_rendering().map_err(refused)? {
                None => return Err(refused(NO_DOOR.to_string())),
                Some(stated) => load_dropped_bytes::<Auth>(&row.lib_bytes, name, &stated, bind),
            },
        };
        let plugin = loaded.map_err(|e| refused(e.to_string()))?;
        Ok(Door::Memory(plugin, sink))
    }

    /// The config keys of the auth rows this build LINKS, in registration order.
    #[must_use]
    pub fn linked_names(&self) -> Vec<String> {
        self.registry
            .linked()
            .iter()
            .filter(|p| p.manifest.kind == AUTH)
            .map(|p| p.manifest.alias.clone())
            .collect()
    }

    /// Whether a `kind: auth` row answers `module`.
    #[must_use]
    pub fn answers(&self, module: &str) -> bool {
        self.row(module).is_some()
    }

    /// Whether `module` names a row this build LINKS.
    #[must_use]
    pub fn linked(&self, module: &str) -> bool {
        self.registry
            .linked()
            .iter()
            .filter(|p| p.manifest.kind == AUTH)
            .any(|p| p.manifest.alias == module || stated_aliases(p).iter().any(|a| a == module))
    }

    /// THE OPERATOR CREDENTIAL'S ROW: the auth row whose Statement states `FACT_OPERATOR`, as its
    /// config key and the principal id it names; linked rows first, then the plugins directory's.
    /// A row whose door will not load states nothing here (its own open reports why).
    #[must_use]
    pub fn operator(&self) -> Option<(String, String)> {
        let rows = self
            .registry
            .linked()
            .iter()
            .chain(self.registry.loadable());
        rows.filter(|p| p.manifest.kind == AUTH).find_map(|row| {
            let alias = &row.manifest.alias;
            let Ok(Door::Memory(plugin, _)) = self.load(row, alias, false) else {
                return None;
            };
            let principal = plugin.context::<AuthFacts>()?.operator_principal.clone()?;
            Some((alias.clone(), principal))
        })
    }

    /// ONE VERIFIER PER CREDENTIAL KIND: a row whose Statement declares it reads a credential kind
    /// refuses to open while another auth row declares the same kind (1.5.5 had one built-in
    /// inbound verifier per credential kind and no way to declare a second, so there is no 1.5.5
    /// equivalent to keep).
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
            let Ok(Door::Memory(theirs, _)) = self.load(other, &other.manifest.alias, false) else {
                continue;
            };
            let Some(f) = theirs.context::<AuthFacts>() else {
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

    /// OPEN one instance of `module` over `settings` under the host's instance `label`.
    ///
    /// # Errors
    /// Why it will not open, naming the module.
    pub fn open(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
    ) -> Result<Arc<dyn AuthCalls>, String> {
        let row = self
            .row(module)
            .ok_or_else(|| format!("no `kind: auth` plugin answers to '{module}'"))?;
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
        .map_err(|e| format!("auth plugin '{module}': {e}"))?;
        Ok(Arc::new(opened))
    }
}

/// The aliases `row`'s Statement states (its [`REWRITE_ALIAS`] rewrites; the design's One
/// Statement): a linked door's own rendering, a dropped plugin's signed one.
/// A rendering that does not read back names nothing here; the load refuses it.
fn stated_aliases(row: &LoadablePlugin) -> Vec<String> {
    let stated = match row.door() {
        Some(door) => LinkedRow::of(door).ok().map(|r| r.statement),
        None => row.manifest.stated_rendering().ok().flatten(),
    };
    stated
        .and_then(|s| read(&s).ok())
        .map(|r| crate::boot::rewrites(&r, REWRITE_ALIAS).collect())
        .unwrap_or_default()
}

/// TEST STAND-IN: one build's auth axis over `registry` on a dispatcher of its own, for a build
/// with no composition root to hold the process's one dispatcher (a test binary). Never shipped.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn stand_in(registry: Arc<PluginRegistry>) -> Arc<dyn busbar_contract::auth_calls::AuthAxis> {
    static DISPATCHER: std::sync::OnceLock<Arc<Dispatcher>> = std::sync::OnceLock::new();
    let dispatcher = DISPATCHER
        .get_or_init(|| Arc::new(Dispatcher::new(crate::dispatch::DispatchConfig::default())));
    let rows = AuthRows::new(registry, dispatcher.clone());
    let table = STAND_IN_CONNS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    Arc::new(match table {
        Some(table) => rows.with_table(table),
        None => rows,
    })
}

/// The connection table the TEST STAND-IN's opened instances are bound to, when a test installed
/// one ([`stand_in_conns`]).
#[cfg(any(test, feature = "test-support"))]
static STAND_IN_CONNS: std::sync::Mutex<Option<Arc<dyn DeclaredConns>>> =
    std::sync::Mutex::new(None);

/// TEST STAND-IN: bind every instance the stand-in axis opens from now on to `conns` (a test's
/// stand-in for the process's connector, e.g. [`crate::https_conns::HttpsConns`]). Never shipped.
#[cfg(any(test, feature = "test-support"))]
pub fn stand_in_conns(conns: Arc<dyn DeclaredConns>) {
    *STAND_IN_CONNS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(conns);
}

/// The contract's auth axis over one build's rows: what the kernel's identity chain opens auth
/// instances through, naming neither this crate nor the root.
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

    fn open(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
    ) -> Result<Arc<dyn AuthCalls>, String> {
        AuthRows::open(self, module, label, settings)
    }
}

#[cfg(test)]
#[path = "tests/auth_axis_tests.rs"]
mod tests;
