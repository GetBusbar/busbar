// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PLUGIN SETTING RENAMES: a plugin renames one of its own settings keys the way core renames one of
//! its own, through migration (owner ruling 2026-10-27).
//!
//! A plugin declares each rename in its packed declaration (`declares.renamed_settings`, each
//! `{from, to, since}`). The composition root hands the kernel the renames of every plugin it can
//! load ([`install`]), before the first configuration is read, as it hands in the root legacy
//! table ([`super::legacy`]). Then the one rule applies on both paths:
//!
//! - **on load** ([`apply`], run by every parse of a configuration document): a settings block of
//!   an instance whose `module:` declares the rename has its `from` key moved to `to`, the
//!   instance opens exactly as if the operator had written `to`, and one deprecation line names
//!   the old key, the new key, the release that renamed it and the command that rewrites it. The
//!   old name keeps working until the next major version;
//! - **in `busbar --migrate-config`** ([`migrate`]): the same move, written into the document, one
//!   change line each.
//!
//! A block that sets both `from` and `to` is refused on either path, naming both: there is no
//! precedence to guess. A rename only ever moves a TOP-LEVEL key of the instance's `settings`.

use std::collections::BTreeSet;
use std::sync::{Mutex, OnceLock};

use busbar_contract::plugin::Kind;

/// One declared rename of a plugin's settings key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingRename {
    /// The key's former name, still accepted.
    pub from: String,
    /// The key's name now.
    pub to: String,
    /// The release that renamed it (the plugin's version, as its declaration states it).
    pub since: String,
}

/// The renames of every plugin a build can load, by kind and `module:` word (a plugin's name or
/// one of its aliases).
pub trait SettingRenames: Send + Sync {
    /// The renames the plugin `module` of `kind` declares; empty when it declares none or no
    /// plugin answers to `module`.
    fn renames(&self, kind: Kind, module: &str) -> Vec<SettingRename>;
}

/// The root's table, installed once before the first configuration is read; the first install
/// stands. None installed: no plugin renames anything.
static TABLE: OnceLock<&'static dyn SettingRenames> = OnceLock::new();

/// Install the root's renames.
pub fn install(table: &'static dyn SettingRenames) {
    let _ = TABLE.set(table);
}

/// One rename made on load, for its deprecation line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Renamed {
    /// The settings block, as an operator spells its path (`export.audit.settings`).
    pub at: String,
    /// The rename made.
    pub rename: SettingRename,
}

impl Renamed {
    /// The deprecation line.
    #[must_use]
    pub fn deprecation(&self) -> String {
        let r = &self.rename;
        format!(
            "{at}.{from} is deprecated: the plugin renamed it `{to}` in {since}. The old name \
             keeps working until the next major version; `busbar --migrate-config` rewrites it.",
            at = self.at,
            from = r.from,
            to = r.to,
            since = r.since
        )
    }

    /// The migrator's change line.
    #[must_use]
    pub fn change(&self) -> String {
        let r = &self.rename;
        format!(
            "{}: `{}` -> `{}` (renamed by the plugin in {})",
            self.at, r.from, r.to, r.since
        )
    }
}

/// The refusal of a block that sets both names.
fn both(at: &str, r: &SettingRename) -> String {
    format!(
        "{at}: `{from}` was renamed `{to}` in {since}; set `{to}` alone, not both",
        from = r.from,
        to = r.to,
        since = r.since
    )
}

/// Move each of `renames` in `settings` (one instance's settings block at `at`).
///
/// # Errors
/// A block that sets both a rename's names.
pub fn rename_in<V>(
    settings: &mut impl SettingsMap<V>,
    at: &str,
    renames: &[SettingRename],
) -> Result<Vec<Renamed>, String> {
    let mut made = Vec::new();
    for r in renames {
        if !settings.has(&r.from) {
            continue;
        }
        if settings.has(&r.to) {
            return Err(both(at, r));
        }
        settings.rename(&r.from, &r.to);
        made.push(Renamed {
            at: at.to_string(),
            rename: r.clone(),
        });
    }
    Ok(made)
}

/// A settings block a rename moves a key in: the typed configuration's JSON map, or the
/// migrator's YAML mapping.
pub trait SettingsMap<V> {
    /// Whether the block sets `key`.
    fn has(&self, key: &str) -> bool;
    /// Move `from`'s value to `to` (the caller checked `to` is not set).
    fn rename(&mut self, from: &str, to: &str);
}

impl SettingsMap<serde_json::Value> for serde_json::Map<String, serde_json::Value> {
    fn has(&self, key: &str) -> bool {
        self.contains_key(key)
    }
    fn rename(&mut self, from: &str, to: &str) {
        if let Some(v) = self.remove(from) {
            self.insert(to.to_string(), v);
        }
    }
}

impl SettingsMap<serde_yaml::Value> for serde_yaml::Mapping {
    fn has(&self, key: &str) -> bool {
        self.contains_key(serde_yaml::Value::from(key))
    }
    fn rename(&mut self, from: &str, to: &str) {
        if let Some(v) = self.remove(serde_yaml::Value::from(from)) {
            self.insert(serde_yaml::Value::from(to), v);
        }
    }
}

/// The renames `module` of `kind` declares, from the installed table.
fn renames_of(table: &dyn SettingRenames, kind: Kind, module: &str) -> Vec<SettingRename> {
    table.renames(kind, module.trim())
}

/// Apply every installed rename to the plugin instances `deploy` configures, over `table`.
///
/// # Errors
/// A settings block that sets both names of one rename.
pub fn apply_with(
    deploy: &mut super::DeployCfg,
    table: &dyn SettingRenames,
) -> Result<Vec<Renamed>, String> {
    let mut made = Vec::new();
    let root = |k: Kind| k.root();
    for (name, def) in &mut deploy.identity_providers {
        let at = format!("{}.{name}.settings", root(Kind::Auth));
        let rs = renames_of(table, Kind::Auth, &def.module);
        made.extend(rename_in(&mut def.settings, &at, &rs)?);
    }
    for (name, def) in &mut deploy.hooks {
        let at = format!("{}.{name}.settings", root(Kind::Hook));
        let rs = renames_of(table, Kind::Hook, &def.module);
        made.extend(rename_in(&mut def.settings, &at, &rs)?);
    }
    for (name, def) in &mut deploy.export {
        let at = format!("{}.{name}.settings", root(Kind::Export));
        let rs = renames_of(table, Kind::Export, &def.module);
        made.extend(rename_in(&mut def.settings, &at, &rs)?);
    }
    if let Some(store) = &mut deploy.store {
        let at = format!("{}.settings", root(Kind::Store));
        let rs = renames_of(table, Kind::Store, &store.module);
        made.extend(rename_in(&mut store.settings, &at, &rs)?);
    }
    for (module, def) in &mut deploy.secrets {
        let at = format!("{}.{module}.settings", root(Kind::Secret));
        let rs = renames_of(table, Kind::Secret, module);
        made.extend(rename_in(&mut def.settings, &at, &rs)?);
    }
    Ok(made)
}

/// The deprecation lines this process has said already: each once.
static SAID: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// THE LOAD PATH: [`apply_with`] over the installed table, each deprecation line said once per
/// process. Run by every parse of a configuration document ([`super::prepass`]).
///
/// # Errors
/// A settings block that sets both names of one rename.
pub fn apply(deploy: &mut super::DeployCfg) -> Result<(), String> {
    let Some(table) = TABLE.get() else {
        return Ok(());
    };
    for r in apply_with(deploy, *table)? {
        let line = r.deprecation();
        let first = SAID
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(line.clone());
        if first {
            tracing::warn!(target: "busbar::config", "{line}");
        }
    }
    Ok(())
}

/// THE MIGRATOR PATH: the same renames, written into the raw document `root`, over `table`.
///
/// # Errors
/// A settings block that sets both names of one rename.
pub fn migrate_with(
    root: &mut serde_yaml::Mapping,
    table: &dyn SettingRenames,
) -> Result<Vec<Renamed>, String> {
    use serde_yaml::Value;
    let mut made = Vec::new();
    let module_of = |entry: &serde_yaml::Mapping| {
        entry
            .get(Value::from("module"))
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    for kind in [Kind::Auth, Kind::Hook, Kind::Export] {
        let Some(Value::Mapping(defs)) = root.get_mut(Value::from(kind.root())) else {
            continue;
        };
        for (name, entry) in defs.iter_mut() {
            let Value::Mapping(entry) = entry else {
                continue;
            };
            let Some(module) = module_of(entry) else {
                continue;
            };
            let rs = renames_of(table, kind, &module);
            if let Some(Value::Mapping(settings)) = entry.get_mut(Value::from("settings")) {
                let at = format!("{}.{}.settings", kind.root(), name.as_str().unwrap_or("?"));
                made.extend(rename_in(settings, &at, &rs)?);
            }
        }
    }
    if let Some(Value::Mapping(store)) = root.get_mut(Value::from(Kind::Store.root())) {
        if let Some(module) = module_of(store) {
            let rs = renames_of(table, Kind::Store, &module);
            if let Some(Value::Mapping(settings)) = store.get_mut(Value::from("settings")) {
                let at = format!("{}.settings", Kind::Store.root());
                made.extend(rename_in(settings, &at, &rs)?);
            }
        }
    }
    if let Some(Value::Mapping(secrets)) = root.get_mut(Value::from(Kind::Secret.root())) {
        for (module, entry) in secrets.iter_mut() {
            let (Some(module), Value::Mapping(entry)) = (module.as_str(), entry) else {
                continue;
            };
            let rs = renames_of(table, Kind::Secret, module);
            if let Some(Value::Mapping(settings)) = entry.get_mut(Value::from("settings")) {
                let at = format!("{}.{module}.settings", Kind::Secret.root());
                made.extend(rename_in(settings, &at, &rs)?);
            }
        }
    }
    Ok(made)
}

/// [`migrate_with`] over the installed table (none installed: nothing renamed).
///
/// # Errors
/// A settings block that sets both names of one rename.
pub fn migrate(root: &mut serde_yaml::Mapping) -> Result<Vec<Renamed>, String> {
    TABLE
        .get()
        .map_or(Ok(Vec::new()), |t| migrate_with(root, *t))
}

#[cfg(test)]
#[path = "tests/plugin_renames_tests.rs"]
mod tests;
