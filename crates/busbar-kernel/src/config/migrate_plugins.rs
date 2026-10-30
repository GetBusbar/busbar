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
//!   allow joins `advanced.allow_destinations`, exactly that host; a destination to allow only if
//!   it is private is resolved here, at migrate time, and judged with the destination guard's own
//!   predicates first);
//! - prints every report line under the plugin's name.
//!
//! A plane is handed the sections it owns and, beside them, the sections it CONSUMES, read-only:
//! an answer that rewrites a consumed section is refused whole. A plane that consumes the
//! transport kind's root is handed the providers catalog merged under the deployment's entries,
//! as boot merges them.
//!
//! A plugin whose build states no `migrate` passes through unchanged. A plugin no build answers is
//! left as written, with a TODO naming it. The composition root also answers which release of a
//! plugin matches this core (`plugins.fetch` pins are rewritten through that lookup, and a plugin
//! no build here serves gains a pin), by asking the release index: no plugin name is written here.

use std::net::IpAddr;

use busbar_contract::abi::sdk::migrate::{MigrateNeed, Migrated};
use busbar_contract::plugin::Kind;
use serde_yaml::{Mapping, Value};

/// The busbar version a configuration is migrated from when nothing says otherwise: the release
/// before this one.
pub const FROM_DEFAULT: &str = "1.5.5";

/// What the composition root answers for the migration: the plugins, and the release index.
pub trait MigrateHost {
    /// The busbar version the configuration came from.
    fn migrating_from(&self) -> &str {
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

    /// The providers catalog the configuration reads, rewritten without the keys its entries'
    /// grammar does not read ([`super::migrate_catalog`]): `Ok(None)` when there is no catalog or
    /// nothing to remove; otherwise the `providers_file:` value that names the rewritten catalog
    /// and one change line per removed key.
    ///
    /// # Errors
    /// The catalog could not be read or the rewritten one written.
    fn rewrite_catalog(&self) -> Result<Option<(String, Vec<String>)>, String> {
        Ok(None)
    }

    /// The providers catalog the configuration reads (the file boot reads, found as boot finds
    /// it), as written: each entry's table by its name. `Ok(None)` when there is none.
    ///
    /// # Errors
    /// The catalog could not be read, or is not a map of entries.
    fn providers_catalog(
        &self,
    ) -> Result<Option<serde_json::Map<String, serde_json::Value>>, String> {
        Ok(None)
    }

    /// Every address the name `host` answers on this machine, now (the migration's one
    /// resolution of a host a plugin raised to allow only if it is private).
    ///
    /// # Errors
    /// The name did not resolve (the reason).
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        Err(format!("no resolver is at hand for '{host}'"))
    }
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
    // settings-leak-lint: allow — the operator's own section as written, handed to its plugin's
    // migrate and written back into the operator's file; no admin read serves it.
    settings: serde_json::Value,
    /// The sections in `settings` the plugin reads but does not own (a plane's consumed
    /// sections): handed read-only, never written back.
    read_only: Vec<String>,
}

/// What the migration reads of one plane: its registry key, the sections it owns (its declaring
/// section first) and the sections it consumes.
pub(super) struct PlaneFacts {
    pub key: &'static str,
    pub owns: Vec<&'static str>,
    pub consumes: &'static [&'static str],
}

/// Every plane the registry holds, as the migration reads it.
fn registry_planes() -> Vec<PlaneFacts> {
    crate::plane_driver::registry::plane_decls()
        .iter()
        .map(|d| PlaneFacts {
            key: d.key,
            owns: plane_sections(d),
            consumes: crate::plane_driver::door::consumed_sections(d),
        })
        .collect()
}

/// Run every plugin's own migration over `root`, then the release lookups.
pub(super) fn migrate(root: &mut Mapping, host: &dyn MigrateHost, ledger: &mut Ledger<'_>) {
    migrate_over(root, host, ledger, &registry_planes());
}

/// [`migrate`] over the planes `planes`.
pub(super) fn migrate_over(
    root: &mut Mapping,
    host: &dyn MigrateHost,
    ledger: &mut Ledger<'_>,
    planes: &[PlaneFacts],
) {
    let from = host.migrating_from().to_string();
    let mut wanted: Vec<(String, String)> = Vec::new();
    for site in sites(root, planes, host, ledger) {
        wanted.push((site.kind.clone(), site.module.clone()));
        match host.migrate(&site.kind, &site.module, &site.settings, &from) {
            Ok(None) => {}
            Ok(Some((plugin, migrated))) => apply(root, host, &site, &plugin, migrated, ledger),
            Err(why) => ledger.todos.push(format!(
                "{}: the {} plugin '{}' could not migrate its settings ({why}); they were left as \
                 written",
                site.path, site.kind, site.module
            )),
        }
    }
    repin_fetch(root, host, ledger);
    pin_unserved(root, host, &wanted, ledger);
    match host.rewrite_catalog() {
        Ok(None) => {}
        Ok(Some((file, lines))) => {
            ledger.changes.extend(lines);
            root.insert(Value::from("providers_file"), Value::from(file.as_str()));
            ledger.changes.push(format!(
                "providers_file: '{file}' (the providers catalog without the keys 1.6.0 refuses, \
                 written beside the old one, which is left as it was; a `--providers` flag still \
                 names the old catalog, so drop it or point it here)"
            ));
        }
        Err(why) => ledger.todos.push(format!(
            "the providers catalog could not be checked for keys 1.6.0 refuses ({why}); remove any \
             key a catalog entry does not read before starting 1.6.0"
        )),
    }
}

/// Every plugin section the configuration selects, in document order: the store, each named
/// instance of the named-map kinds, and each plane's sections (with the ones it consumes,
/// read-only).
fn sites(
    root: &Mapping,
    planes: &[PlaneFacts],
    host: &dyn MigrateHost,
    ledger: &mut Ledger<'_>,
) -> Vec<Site> {
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
                    read_only: Vec::new(),
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
                read_only: Vec::new(),
            });
        }
    }
    let mut providers: Option<Option<serde_json::Value>> = None;
    for plane in planes {
        let mut sections = serde_json::Map::new();
        for s in &plane.owns {
            if let Some(v) = root.get(Value::from(*s)) {
                sections.insert((*s).to_string(), json(Some(v)));
            }
        }
        // A plane none of whose own sections is written is not configured: nothing to migrate.
        if sections.is_empty() {
            continue;
        }
        let mut read_only = Vec::new();
        for s in plane.consumes {
            if plane.owns.contains(s) {
                continue;
            }
            let value = if *s == Kind::Transport.root() {
                providers
                    .get_or_insert_with(|| merged_providers(root, host, ledger))
                    .clone()
            } else {
                root.get(Value::from(*s)).map(|v| json(Some(v)))
            };
            if let Some(v) = value {
                sections.insert((*s).to_string(), v);
                read_only.push((*s).to_string());
            }
        }
        out.push(Site {
            path: plane.owns.join(", "),
            at: Vec::new(),
            kind: "plane".to_string(),
            module: plane.key.to_string(),
            settings: serde_json::Value::Object(sections),
            read_only,
        });
    }
    out
}

/// THE PROVIDERS A PLANE READS: the catalog the configuration reads, merged under the
/// deployment's `providers:` entries as boot merges them (`super::providers::merge_tables`: a key
/// the deployment sets wins, a string map merges member by member), so an entry only the catalog
/// states is there too. `None` when neither states any. A catalog that cannot be read leaves the
/// deployment's entries alone, with a TODO.
fn merged_providers(
    root: &Mapping,
    host: &dyn MigrateHost,
    ledger: &mut Ledger<'_>,
) -> Option<serde_json::Value> {
    let key = Kind::Transport.root();
    let deployment = root
        .get(Value::from(key))
        .and_then(|v| serde_json::to_value(v).ok());
    let catalog = match host.providers_catalog() {
        Ok(catalog) => catalog,
        Err(why) => {
            ledger.todos.push(format!(
                "{key}: the providers catalog could not be read for the plane migrations ({why}); \
                 each plane was handed the configuration's own `{key}:` entries only, so check \
                 that every private upstream a catalog entry names is in \
                 advanced.allow_destinations"
            ));
            None
        }
    };
    let Some(mut merged) = catalog else {
        return deployment;
    };
    let Some(serde_json::Value::Object(entries)) = deployment else {
        return Some(serde_json::Value::Object(merged));
    };
    for (name, entry) in entries {
        let entry = match (merged.remove(&name), entry) {
            (Some(serde_json::Value::Object(cat)), serde_json::Value::Object(dep)) => {
                serde_json::Value::Object(super::providers::merge_tables(cat, dep))
            }
            (_, entry) => entry,
        };
        merged.insert(name, entry);
    }
    Some(serde_json::Value::Object(merged))
}

/// The sections a plane's migration is handed and may answer: the one that declares it and the
/// ones it owns.
fn plane_sections(d: &crate::plane_driver::registry::PlaneDecl) -> Vec<&'static str> {
    let mut all = vec![d.config_section];
    for s in d.owned_config_sections {
        if !all.contains(s) {
            all.push(*s);
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
    host: &dyn MigrateHost,
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
    let mut decided: Vec<String> = Vec::new();
    for need in needs {
        match need {
            MigrateNeed::AllowDestination(host) => allow_destination(root, plugin, &host, ledger),
            // One decision per host, however many times the plugin raised it.
            MigrateNeed::AllowDestinationIfPrivate(h) => {
                let h = h.trim().to_string();
                if !decided.contains(&h) {
                    allow_if_private(root, host, plugin, &h, ledger);
                    decided.push(h);
                }
            }
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
        // Judged whole before anything is written: a refused answer writes none of itself.
        let mut writes = Vec::new();
        for (name, v) in &sections {
            let Some(handed) = site.settings.get(name) else {
                return Err(format!("`{name}` is not a section it was handed"));
            };
            if site.read_only.contains(name) {
                if handed != v {
                    return Err(format!(
                        "`{name}` is a section it reads but does not own: it was handed it \
                         read-only, and a plugin's migration rewrites only the sections it owns"
                    ));
                }
                continue;
            }
            writes.push((Value::from(name.as_str()), value(v)?));
        }
        for (name, v) in writes {
            root.insert(name, v);
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
    match push_allowed(root, plugin, host) {
        Ok(false) => {}
        Ok(true) => ledger.changes.push(format!(
            "advanced.allow_destinations: added '{host}' (the plugin '{plugin}' reached it before \
             this upgrade, and 1.6.0 refuses a private or loopback destination unless it is \
             allowed; only this host is allowed, not every private address)"
        )),
        Err(todo) => ledger.todos.push(todo),
    }
}

/// Add `host` to `advanced.allow_destinations` (made when it is not there): `Ok(true)` when it
/// was added, `Ok(false)` when it was there already, or the TODO naming what is in its way.
fn push_allowed(root: &mut Mapping, plugin: &str, host: &str) -> Result<bool, String> {
    let advanced = root
        .entry(Value::from("advanced"))
        .or_insert_with(|| Value::Mapping(Mapping::new()));
    let Value::Mapping(advanced) = advanced else {
        return Err(format!(
            "advanced: is not a mapping, so '{host}', which the plugin '{plugin}' needs allowed, \
             was not added to advanced.allow_destinations; add it by hand"
        ));
    };
    let list = advanced
        .entry(Value::from("allow_destinations"))
        .or_insert_with(|| Value::Sequence(Vec::new()));
    let Value::Sequence(list) = list else {
        return Err(format!(
            "advanced.allow_destinations: is not a list, so '{host}', which the plugin '{plugin}' \
             needs allowed, was not added; add it by hand"
        ));
    };
    if list.iter().any(|e| e.as_str() == Some(host)) {
        return Ok(false);
    }
    list.push(Value::from(host));
    Ok(true)
}

/// Whether `advanced.allow_destinations` already names `name` (as the guard folds an entry:
/// unbracketed, one trailing dot dropped, case-blind). Nothing is made.
fn already_allowed(root: &Mapping, name: &str) -> bool {
    let Some(Value::Mapping(advanced)) = root.get(Value::from("advanced")) else {
        return false;
    };
    let Some(Value::Sequence(list)) = advanced.get(Value::from("allow_destinations")) else {
        return false;
    };
    list.iter().filter_map(Value::as_str).any(|e| {
        let e = e.trim().trim_start_matches('[').trim_end_matches(']');
        e.strip_suffix('.').unwrap_or(e).eq_ignore_ascii_case(name)
    })
}

/// THE ALLOW-IF-PRIVATE DECISION (`MigrateNeed::AllowDestinationIfPrivate`): the host the plugin
/// `plugin` raised, read as the destination guard reads it, with the guard's own predicates
/// (`busbar_contract::net`) in the guard's order: a host it cannot judge, a cloud-metadata name
/// and an alternate IPv4 spelling are decided first; an address literal is its own answer; a
/// `localhost` name is loopback; any other name is resolved here, now, through `host`, and every
/// answer is judged. Exactly the host is added only when every answer is private or loopback and
/// none is cloud metadata (nor IPv6 link-local, which the guard refuses as it refuses metadata,
/// and which a host entry never admits). Every decision gets a line: what the host resolved to,
/// and that it was resolved at migrate time. A decision only the operator can make is a TODO.
fn allow_if_private(
    root: &mut Mapping,
    host: &dyn MigrateHost,
    plugin: &str,
    raised: &str,
    ledger: &mut Ledger<'_>,
) {
    use busbar_contract::net::{
        embedded_ipv4, host_ip, ip_is_cloud_metadata, ip_is_internal, is_alternate_ipv4_encoding,
        is_link_local_v6, judged_host, METADATA_HOSTS,
    };
    let todo = |why: &str| {
        format!("advanced.allow_destinations: '{raised}', which the plugin '{plugin}' dials, {why}")
    };
    let never = "a migration never allows it (the 1.5.5 `allow_metadata_hosts` carve-outs keep \
                 working as they did)";
    // The one form the guard compares every name in.
    let name = match judged_host(raised) {
        Ok(name) if !name.is_empty() => name,
        _ => {
            ledger.todos.push(todo(
                "is not a host the destination guard can judge, so it was not added; write the \
                 plain host name or address",
            ));
            return;
        }
    };
    if already_allowed(root, &name) {
        ledger.changes.push(format!(
            "advanced.allow_destinations: '{name}' for the plugin '{plugin}' is already listed, so \
             it was left as it is (not resolved)"
        ));
        return;
    }
    if METADATA_HOSTS.contains(&name.as_str()) {
        ledger.changes.push(format!(
            "advanced.allow_destinations: not added '{name}' for the plugin '{plugin}': it is a \
             cloud metadata name, so it was not resolved at migrate time, and {never}"
        ));
        return;
    }
    if is_alternate_ipv4_encoding(&name) {
        ledger.todos.push(todo(
            "is an alternate IPv4 spelling, which the destination guard refuses whatever the \
             allowlist says, so it was not added; write the address in dotted-quad form",
        ));
        return;
    }
    let (answers, resolved) = if let Some(ip) = host_ip(&name) {
        (vec![ip], format!("{ip} (an address literal)"))
    } else if name == "localhost" || name.ends_with(".localhost") {
        (
            Vec::new(),
            "loopback (a `localhost` name is loopback by definition)".to_string(),
        )
    } else {
        match host.resolve(&name) {
            Ok(answers) if !answers.is_empty() => {
                let shown: Vec<String> = answers.iter().map(ToString::to_string).collect();
                let resolved = format!(
                    "{} (this machine's DNS; where busbar runs it may answer differently)",
                    shown.join(", ")
                );
                (answers, resolved)
            }
            Ok(_) => {
                ledger.todos.push(todo(
                    "answered no address at migrate time, so it was not added; if it is a \
                     private or loopback host where busbar runs, add it to \
                     advanced.allow_destinations by hand",
                ));
                return;
            }
            Err(why) => {
                ledger.todos.push(todo(&format!(
                    "did not resolve at migrate time ({why}), so it was not added; if it is a \
                     private or loopback host where busbar runs, add it to \
                     advanced.allow_destinations by hand"
                )));
                return;
            }
        }
    };
    let link_local = |ip: &IpAddr| matches!(ip, IpAddr::V6(v6) if embedded_ipv4(v6).is_none() && is_link_local_v6(v6));
    if let Some(ip) = answers
        .iter()
        .find(|ip| ip_is_cloud_metadata(ip) || link_local(ip))
    {
        let what = if ip_is_cloud_metadata(ip) {
            "cloud metadata"
        } else {
            "IPv6 link-local, which the destination guard refuses as it refuses cloud metadata"
        };
        ledger.changes.push(format!(
            "advanced.allow_destinations: not added '{name}' for the plugin '{plugin}': resolved at \
             migrate time to {resolved}, and {ip} is {what}, so {never}"
        ));
        return;
    }
    let public = answers.iter().filter(|ip| !ip_is_internal(ip)).count();
    if public > 0 && public == answers.len() {
        ledger.changes.push(format!(
            "advanced.allow_destinations: not added '{name}' for the plugin '{plugin}': resolved at \
             migrate time to {resolved}, every answer public, so it needs no entry"
        ));
        return;
    }
    if public > 0 {
        ledger.todos.push(todo(&format!(
            "resolved at migrate time to {resolved}: some answers private and some public, so it \
             was not added; 1.6.0 refuses such an answer unless the host is allowed, so add it to \
             advanced.allow_destinations by hand if every address it answers is yours"
        )));
        return;
    }
    match push_allowed(root, plugin, &name) {
        Ok(_) => ledger.changes.push(format!(
            "advanced.allow_destinations: added '{name}' for the plugin '{plugin}': resolved at \
             migrate time to {resolved}, every answer private or loopback and none cloud metadata \
             (1.6.0 refuses a private or loopback destination unless it is allowed; only this host \
             is allowed, not every private address)"
        )),
        Err(todo) => ledger.todos.push(todo),
    }
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
