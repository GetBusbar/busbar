// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH ROWS (WIRE-AUTH): [`AuthRows`] answers and opens the plugin registry's `kind: auth`
//! rows on the process's one dispatcher. The composition root implements the contract's `AuthAxis`
//! over it and hands that axis to the kernel on its install record (`RootInstall::auth_axis`, impl
//! in the root), so the kernel's identity chain opens auth instances naming neither this crate nor
//! the root.
//!
//! A row opens on the auth kind's MEMORY ABI (`abi::auth`, through [`AuthInstance`]) when it is a
//! linked door ([`crate::registry::LinkedEntry::Door`]) or a dropped-in library exporting
//! `busbar_plugin_door`. A dropped-in library that states no door (a 1.5.5 JSON-contract auth
//! plugin) is refused at its load, naming the rebuild ([`NO_DOOR`]).

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
/// one dispatcher.
pub struct AuthRows {
    registry: Arc<PluginRegistry>,
    dispatcher: Arc<Dispatcher>,
    /// The host's one connection table, read when an instance OPENS to serve: it declares its needs
    /// on it (a row only read for its facts binds with none).
    conns: Option<fn() -> Arc<dyn DeclaredConns>>,
    /// A connection table held by the axis itself (a test's stand-in for the connector, with far
    /// ends of its own), used the same way when no `conns` is read.
    held: Option<Arc<dyn DeclaredConns>>,
    /// Where each instance opened to serve writes its plugin log (THE DESIGN §11.2).
    logs: Option<fn() -> crate::dispatch::PluginLogConfig>,
    /// TEST PROBE: every row [`Self::load`] was asked to bind, by key, in order (a row the
    /// configuration does not use is never bound).
    #[cfg(test)]
    bound: std::sync::Mutex<Vec<String>>,
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
            logs: None,
            #[cfg(test)]
            bound: std::sync::Mutex::default(),
        }
    }

    /// Each instance opened to serve writes its log records and diagnostics to its own plugin log
    /// file under the configured `plugins.logs` that `logs` answers when it opens.
    #[must_use]
    pub fn with_logs(mut self, logs: fn() -> crate::dispatch::PluginLogConfig) -> Self {
        self.logs = Some(logs);
        self
    }

    /// Each instance opened to serve declares its needs on the table `conns` answers when it opens
    /// (the process's one connector): a networked auth door (a directory over a stream transport)
    /// dials through it.
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
        let name = row.key();
        #[cfg(test)]
        self.bound
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(name.to_string());
        let refused = |e: String| format!("auth plugin '{name}': {e}");
        let sink = AuthSink::new(name);
        // Opened to serve: its own plugin log file (THE DESIGN §11.2). A fact read binds no file.
        let envelope = match self.logs.filter(|_| serving) {
            Some(logs) => sink.to_file(&logs(), label).map_err(refused)?,
            None => sink.bind(),
        };
        let bind = Bind {
            instance: Arc::from(label),
            max_inflight_cap: MAX_INFLIGHT_CAP,
            sink: envelope,
            dispatcher: self.dispatcher.adopter(),
            // Serving: the host's table (else a table the axis holds), or (none) a door that
            // declares no need. A fact read: a probe, bound with no table whatever it declares.
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

    /// The facts `row` states, READ, never bound (reading a row's static declaration, its kind tail
    /// included, is reading, not loading; and the canonical rendering carries the whole kind tail,
    /// audit root#7 / loader#9): a linked door's `'static` Statement, a dropped-in row's SIGNED
    /// MANIFEST rendering, with no `dlopen` (admitting that row compares its door's Statement with
    /// the same rendering, tail included). `None` when the row's Statement is one a bind refuses.
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
            .any(|p| p.manifest.answers_to(module) || stated_aliases(p).iter().any(|a| a == module))
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
            let principal = self.stated(row)?.operator_principal?;
            Some((row.manifest.alias.clone(), principal))
        })
    }

    /// THE CREDENTIAL READERS: the config keys of the auth rows whose Statement states
    /// `FACT_READS_CREDENTIALS` (a row whose door will not load states nothing here), linked rows
    /// first, then the plugins directory's.
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

    /// THE CREDENTIAL THE HOST ISSUES beside a signed-token key: the first credential reader, in
    /// [`Self::credential_readers`]' order, whose Statement states an issued shape (its
    /// `MARK_WORD_ISSUED_*` marks, checked at load), as its first credential kind and that shape.
    /// Read from the Statements ([`Self::stated`]), binding no linked row: the build's fact,
    /// whatever the chain names.
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

    /// The carriers the auth row answering `module` states (its Statement's carrier word marks, in
    /// order); none when no row answers it, its door will not load, or it states none.
    #[must_use]
    pub fn carriers(&self, module: &str) -> Vec<String> {
        let Some(row) = self.row(module) else {
            return Vec::new();
        };
        self.stated(row).map(|f| f.carriers).unwrap_or_default()
    }

    /// THE HOST'S DEFAULT INBOUND STYLE: the carriers of the one auth row whose Statement states
    /// `FACT_DEFAULT_INBOUND_STYLE` (a row whose door will not load states nothing here), linked
    /// rows first, then the plugins directory's; none when no row states it.
    ///
    /// # Errors
    /// Two or more rows state it: [`two_default_inbound_styles`] names them, and boot is refused.
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

    /// TEST STAND-IN: the auth row serving the outbound `style`, its instance opened for its
    /// outbound styles over `settings` (as the composition root's `OutboundAuths::serving` opens
    /// one, without its instance cache or its tick schedule); `None` when no row this build reaches
    /// states the style. Never shipped: the root serves outbound styles.
    ///
    /// # Errors
    /// The serving row would not open for its outbound styles.
    #[cfg(any(test, feature = "test-support"))]
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

/// The aliases `row`'s Statement states (its [`REWRITE_ALIAS`] rewrites; the design's One
/// Statement): a linked door's own rendering, a dropped plugin's signed one.
/// A rendering that does not read back names nothing here; the load refuses it.
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

/// TEST STAND-IN: one build's auth axis over `registry` on a dispatcher of its own, for a build
/// with no composition root to hold the process's one dispatcher (a test binary), lent `seal` (the
/// kernel's, so a verify reveals the credential it lends the plugin as a booted node's does). The
/// first call's seal is the one lent. Never shipped.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn stand_in(
    registry: Arc<PluginRegistry>,
    seal: impl busbar_contract::plugin::KernelSeal + Send + Sync + 'static,
) -> Arc<dyn busbar_contract::auth_calls::AuthAxis> {
    static DISPATCHER: std::sync::OnceLock<Arc<Dispatcher>> = std::sync::OnceLock::new();
    let dispatcher = DISPATCHER.get_or_init(|| {
        let d = Dispatcher::new(crate::dispatch::DispatchConfig::default());
        let _ = d.lend_seal(seal);
        Arc::new(d)
    });
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

    fn credential_readers(&self) -> Vec<String> {
        AuthRows::credential_readers(self)
    }

    fn issued_credential(&self) -> Option<(String, busbar_contract::auth_calls::IssuedShape)> {
        AuthRows::issued_credential(self)
    }

    fn carriers(&self, module: &str) -> Vec<String> {
        AuthRows::carriers(self, module)
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

/// THE REFUSAL when more than one auth row states the host's default inbound style
/// (`FACT_DEFAULT_INBOUND_STYLE`): where a caller's credential sits on a line the config leaves
/// without a style would be two answers, so boot names the rows and stops.
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
