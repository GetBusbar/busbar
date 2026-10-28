// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EACH PLUGIN MIGRATES ITS OWN SETTINGS (owner ruling 2026-10-27).
//!
//! `busbar --migrate-config` migrates core's own keys and nothing inside a plugin's settings
//! section: core knows no plugin's keys, old or new. For each plugin the configuration selects,
//! this step hands the section to that plugin's own `migrate` (through the composition root's
//! [`MigrateHost`], which loads the plugin's current build) and then:
//!
//! - writes the section the plugin answered in place of the old one;
//! - applies the needs the plugin raised, to keys CORE owns and nothing else (a destination to
//!   allow joins `advanced.allow_destinations`, exactly that host);
//! - prints every report line under the plugin's name.
//!
//! A plugin whose build states no `migrate` passes through unchanged. A plugin no build answers is
//! left as written, with a TODO naming it. The composition root also answers which release of a
//! plugin matches this core (`plugins.fetch` pins are rewritten through that lookup, and a plugin
//! no build here serves gains a pin), by asking the release index: no plugin name is written here.

use busbar_contract::abi::sdk::migrate::{MigrateNeed, Migrated};
use busbar_contract::plugin::Kind;
use serde_yaml::{Mapping, Value};

/// The busbar version a configuration is migrated from when nothing says otherwise: the release
/// before this one.
pub const FROM_DEFAULT: &str = "1.5.5";

/// What the composition root answers for the migration: the plugins, and the release index.
pub trait MigrateHost {
    /// The busbar version the configuration came from.
    fn from_version(&self) -> &str {
        FROM_DEFAULT
    }

    /// Migrate one plugin's section: the plugin `module` names on `kind`'s axis (`kind` is the
    /// kind's word, `plane` for a plane, whose `module` is its registry key). `Ok(None)` when no
    /// build of it states a `migrate`; otherwise the plugin's name (the word its report lines are
    /// printed under) and its answer.
    ///
    /// # Errors
    /// No build of the plugin is at hand, or its `migrate` refused (the reason).
    fn migrate(
        &self,
        kind: &str,
        module: &str,
        settings: &serde_json::Value,
        from: &str,
    ) -> Result<Option<(String, Migrated)>, String>;

    /// The `plugins.fetch` GitHub reference (`org/repo@tag`) that names the release of the same
    /// plugin matching this core, when `github` names another one. `Ok(None)`: it already matches,
    /// or the index does not know the plugin.
    ///
    /// # Errors
    /// The release index could not be read.
    fn repin(&self, github: &str) -> Result<Option<String>, String>;

    /// The `plugins.fetch` GitHub reference for the plugin `module` names on `kind`'s axis, when no
    /// build here serves it (not linked, not in the plugins directory) and the release index names
    /// one matching this core. `Ok(None)` otherwise.
    ///
    /// # Errors
    /// The release index could not be read.
    fn release_for(&self, kind: &str, module: &str) -> Result<Option<String>, String>;
}

/// The host of a migration with no plugins at hand (`migrate_config`): every plugin passes through
/// unchanged, and no pin is rewritten.
pub struct NoPlugins;

impl MigrateHost for NoPlugins {
    fn migrate(
        &self,
        _: &str,
        _: &str,
        _: &serde_json::Value,
        _: &str,
    ) -> Result<Option<(String, Migrated)>, String> {
        Ok(None)
    }
    fn repin(&self, _: &str) -> Result<Option<String>, String> {
        Ok(None)
    }
    fn release_for(&self, _: &str, _: &str) -> Result<Option<String>, String> {
        Ok(None)
    }
}

/// The ledgers a migration step writes.
pub(super) struct Ledger<'a> {
    pub changes: &'a mut Vec<String>,
    pub todos: &'a mut Vec<String>,
}

/// One plugin section the configuration selects: where it is, which kind and module, and its
/// settings as written.
struct Site {
    /// The path an operator reads (`store.settings`, `export.audit.settings`, `<plane section>`).
    path: String,
    /// Where the section sits, key by key from the document root (empty for a plane's sections,
    /// which sit at the root under their own names).
    at: Vec<String>,
    kind: String,
    module: String,
    settings: serde_json::Value,
}

/// Run every plugin's own migration over `root`, then the release lookups.
pub(super) fn migrate(root: &mut Mapping, host: &dyn MigrateHost, ledger: &mut Ledger<'_>) {
    let from = host.from_version().to_string();
    let mut wanted: Vec<(String, String)> = Vec::new();
    for site in sites(root) {
        wanted.push((site.kind.clone(), site.module.clone()));
        match host.migrate(&site.kind, &site.module, &site.settings, &from) {
            Ok(None) => {}
            Ok(Some((plugin, migrated))) => apply(root, &site, &plugin, migrated, ledger),
            Err(why) => ledger.todos.push(format!(
                "{}: the {} plugin '{}' could not migrate its settings ({why}); they were left as \
                 written",
                site.path, site.kind, site.module
            )),
        }
    }
    repin_fetch(root, host, ledger);
    pin_unserved(root, host, &wanted, ledger);
}

/// Every plugin section the configuration selects, in document order: the store, each named
/// instance of the named-map kinds, and each plane's sections.
fn sites(root: &Mapping) -> Vec<Site> {
    let mut out = Vec::new();
    let json = |v: Option<&Value>| -> serde_json::Value {
        v.and_then(|v| serde_json::to_value(v).ok())
            .unwrap_or(serde_json::Value::Null)
    };
    for kind in [
        Kind::Store,
        Kind::Secret,
        Kind::Auth,
        Kind::Hook,
        Kind::Export,
    ] {
        let key = kind.root();
        let word = kind_word(kind);
        let Some(Value::Mapping(section)) = root.get(Value::from(key)) else {
            continue;
        };
        if kind == Kind::Store {
            if let Some(module) = section.get(Value::from("module")).and_then(Value::as_str) {
                out.push(Site {
                    path: format!("{key}.settings"),
                    at: vec![key.to_string(), "settings".to_string()],
                    kind: word.to_string(),
                    module: module.to_string(),
                    settings: json(section.get(Value::from("settings"))),
                });
            }
            continue;
        }
        for (name, entry) in section {
            let (Some(name), Value::Mapping(entry)) = (name.as_str(), entry) else {
                continue;
            };
            let Some(module) = entry.get(Value::from("module")).and_then(Value::as_str) else {
                continue;
            };
            out.push(Site {
                path: format!("{key}.{name}.settings"),
                at: vec![key.to_string(), name.to_string(), "settings".to_string()],
                kind: word.to_string(),
                module: module.to_string(),
                settings: json(entry.get(Value::from("settings"))),
            });
        }
    }
    for d in crate::plane::registry::plane_decls() {
        let mut sections = serde_json::Map::new();
        for s in plane_sections(d) {
            if let Some(v) = root.get(Value::from(s)) {
                sections.insert(s.to_string(), json(Some(v)));
            }
        }
        if sections.is_empty() {
            continue;
        }
        out.push(Site {
            path: plane_sections(d).join(", "),
            at: Vec::new(),
            kind: "plane".to_string(),
            module: d.key.to_string(),
            settings: serde_json::Value::Object(sections),
        });
    }
    out
}

/// The sections a plane's migration is handed and may answer: the one that declares it and the
/// ones it owns.
fn plane_sections(d: &crate::plane::registry::PlaneDecl) -> Vec<&'static str> {
    let mut all = vec![d.config_section];
    for s in d.owned_config_sections {
        if !all.contains(s) {
            all.push(s);
        }
    }
    all
}

/// The word a kind's plugins are named by in the migration (`store`, `auth`, ...).
fn kind_word(kind: Kind) -> &'static str {
    match kind {
        Kind::Plane => "plane",
        Kind::Transport => "transport",
        Kind::Auth => "auth",
        Kind::Store => "store",
        Kind::Secret => "secret",
        Kind::Hook => "hook",
        Kind::Export => "export",
    }
}

/// Write `migrated` for `site`: its section, its needs on core's keys, its report lines.
fn apply(
    root: &mut Mapping,
    site: &Site,
    plugin: &str,
    migrated: Migrated,
    ledger: &mut Ledger<'_>,
) {
    let Migrated {
        settings,
        report,
        needs,
    } = migrated;
    if settings != site.settings {
        if let Err(why) = write_back(root, site, settings) {
            ledger.todos.push(format!(
                "{}: the plugin '{plugin}' answered a migration that cannot be written ({why}); \
                 the settings were left as written",
                site.path
            ));
            return;
        }
    }
    for line in report {
        ledger.changes.push(format!("{plugin}: {line}"));
    }
    for need in needs {
        match need {
            MigrateNeed::AllowDestination(host) => allow_destination(root, plugin, &host, ledger),
        }
    }
}

/// Put `settings` where `site` read its section from.
fn write_back(root: &mut Mapping, site: &Site, settings: serde_json::Value) -> Result<(), String> {
    let value = |v: &serde_json::Value| serde_yaml::to_value(v).map_err(|e| e.to_string());
    if site.kind == "plane" {
        let serde_json::Value::Object(sections) = settings else {
            return Err("a plane answers its sections as one object".into());
        };
        for (name, v) in &sections {
            if site.settings.get(name).is_none() {
                return Err(format!("`{name}` is not a section it was handed"));
            }
            root.insert(Value::from(name.as_str()), value(v)?);
        }
        return Ok(());
    }
    let new = value(&settings)?;
    let Some((last, parents)) = site.at.split_last() else {
        return Err("no place to write".into());
    };
    let mut at: &mut Mapping = root;
    for seg in parents {
        at = match at.get_mut(Value::from(seg.as_str())) {
            Some(Value::Mapping(m)) => m,
            _ => return Err(format!("`{seg}` is no longer a mapping")),
        };
    }
    if settings.is_null() {
        at.remove(Value::from(last.as_str()));
    } else {
        at.insert(Value::from(last.as_str()), new);
    }
    Ok(())
}

/// Add `host` to `advanced.allow_destinations`, once, reporting it.
fn allow_destination(root: &mut Mapping, plugin: &str, host: &str, ledger: &mut Ledger<'_>) {
    let host = host.trim();
    if host.is_empty() {
        return;
    }
    let advanced = root
        .entry(Value::from("advanced"))
        .or_insert_with(|| Value::Mapping(Mapping::new()));
    let Value::Mapping(advanced) = advanced else {
        ledger.todos.push(format!(
            "advanced: is not a mapping, so '{host}', which the plugin '{plugin}' needs allowed, \
             was not added to advanced.allow_destinations; add it by hand"
        ));
        return;
    };
    let list = advanced
        .entry(Value::from("allow_destinations"))
        .or_insert_with(|| Value::Sequence(Vec::new()));
    let Value::Sequence(list) = list else {
        ledger.todos.push(format!(
            "advanced.allow_destinations: is not a list, so '{host}', which the plugin '{plugin}' \
             needs allowed, was not added; add it by hand"
        ));
        return;
    };
    if list.iter().any(|e| e.as_str() == Some(host)) {
        return;
    }
    list.push(Value::from(host));
    ledger.changes.push(format!(
        "advanced.allow_destinations: added '{host}' (the plugin '{plugin}' reached it before \
         this upgrade, and 1.6.0 refuses a private or loopback destination unless it is allowed; \
         only this host is allowed, not every private address)"
    ));
}

/// The `plugins.fetch` list, when the configuration has one.
fn fetch_list(root: &mut Mapping) -> Option<&mut Vec<Value>> {
    let Some(Value::Mapping(plugins)) = root.get_mut(Value::from("plugins")) else {
        return None;
    };
    match plugins.get_mut(Value::from("fetch")) {
        Some(Value::Sequence(list)) => Some(list),
        _ => None,
    }
}

/// Rewrite each `plugins.fetch` GitHub pin that names another release of a plugin than the one
/// matching this core (a 1.5.5-era build would be refused at boot), dropping its now-wrong
/// `sha256`, one change line each.
fn repin_fetch(root: &mut Mapping, host: &dyn MigrateHost, ledger: &mut Ledger<'_>) {
    let Some(list) = fetch_list(root) else {
        return;
    };
    for entry in list.iter_mut() {
        let Value::Mapping(entry) = entry else {
            continue;
        };
        let Some(old) = entry
            .get(Value::from("github"))
            .and_then(Value::as_str)
            .map(str::to_string)
        else {
            continue;
        };
        match host.repin(&old) {
            Ok(Some(new)) if new != old => {
                entry.insert(Value::from("github"), Value::from(new.as_str()));
                let pinned = entry.remove(Value::from("sha256")).is_some();
                ledger.changes.push(format!(
                    "plugins.fetch: '{old}' -> '{new}' (the release the old pin names was built \
                     for an earlier busbar and is refused at boot; this is the release of the same \
                     plugin that matches this busbar{})",
                    if pinned {
                        "; its sha256 pinned the old build, so it was removed"
                    } else {
                        ""
                    }
                ));
            }
            Ok(_) => {}
            Err(why) => ledger.todos.push(format!(
                "plugins.fetch: '{old}' could not be checked against the release index ({why}); \
                 make sure it names a release built for this busbar"
            )),
        }
    }
}

/// The `org/repo` of a GitHub pin (`org/repo@tag`), lower-cased for comparison.
fn repo_of(github: &str) -> String {
    github
        .split_once('@')
        .map_or(github, |(repo, _)| repo)
        .to_ascii_lowercase()
}

/// Pin, in `plugins.fetch`, each selected plugin no build here serves, at the release the index
/// names for this core, unless a pin for that repository is already there.
fn pin_unserved(
    root: &mut Mapping,
    host: &dyn MigrateHost,
    wanted: &[(String, String)],
    ledger: &mut Ledger<'_>,
) {
    let mut pins: Vec<String> = Vec::new();
    for (kind, module) in wanted {
        match host.release_for(kind, module) {
            Ok(Some(pin)) if !pins.contains(&pin) => pins.push(pin),
            Ok(_) => {}
            Err(why) => ledger.todos.push(format!(
                "the {kind} plugin '{module}': no build of it is here, and the release index could \
                 not be read ({why}); install its build for this busbar in plugins.dir, or add a \
                 plugins.fetch pin for it"
            )),
        }
    }
    if pins.is_empty() {
        return;
    }
    let have: Vec<String> = fetch_list(root)
        .map(|list| {
            list.iter()
                .filter_map(|e| e.get("github").and_then(Value::as_str).map(repo_of))
                .collect()
        })
        .unwrap_or_default();
    for pin in pins {
        if have.contains(&repo_of(&pin)) {
            continue;
        }
        let plugins = root
            .entry(Value::from("plugins"))
            .or_insert_with(|| Value::Mapping(Mapping::new()));
        let Value::Mapping(plugins) = plugins else {
            return;
        };
        let list = plugins
            .entry(Value::from("fetch"))
            .or_insert_with(|| Value::Sequence(Vec::new()));
        let Value::Sequence(list) = list else {
            return;
        };
        let mut entry = Mapping::new();
        entry.insert(Value::from("github"), Value::from(pin.as_str()));
        list.push(Value::Mapping(entry));
        ledger.changes.push(format!(
            "plugins.fetch: added '{pin}' (the configuration uses this plugin, no build of it is \
             in this binary or plugins.dir, and a build made for an earlier busbar is refused at \
             boot; this is its release for this busbar. A host with no network needs the tarball \
             copied into plugins.dir instead)"
        ));
    }
}

#[cfg(test)]
#[path = "tests/migrate_plugins_tests.rs"]
mod tests;
