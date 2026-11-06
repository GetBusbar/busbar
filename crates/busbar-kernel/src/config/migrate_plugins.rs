// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::net::IpAddr;

use busbar_contract::abi::sdk::migrate::{MigrateNeed, Migrated};
use busbar_contract::plugin::Kind;
use serde_yaml::{Mapping, Value};

use super::migrate::vocabulary::field;

const FETCH_GITHUB_PIN_KEY: &str = "github";

const LOCALHOST_NAME: &str = "localhost";
const LOCALHOST_SUFFIX: &str = ".localhost";

pub const FROM_DEFAULT: &str = "1.5.5";

pub trait MigrateHost {
    /// Additional config sections whose presence selects this admitted plane for use.
    /// Consuming a section alone does not select the plane; its Statement must say so.
    fn plane_selecting_sections(&self, _module: &str) -> Vec<String> {
        Vec::new()
    }

    /// Cold migration only: save an old literal and return its private absolute file path.
    /// The default refuses rather than printing a purportedly migrated literal credential.
    fn externalize_secret(
        &self,
        _site: &str,
        _path: &[String],
        _bytes: &[u8],
    ) -> Result<String, String> {
        Err("this migration host cannot externalize historical literal secrets".into())
    }

    /// Validate converted current settings before emitting them. No instance is opened.
    fn validate_migrated(
        &self,
        _kind: &str,
        _module: &str,
        _settings: &serde_json::Value,
    ) -> Result<(), String> {
        Ok(())
    }

    fn migrating_from(&self) -> &str {
        FROM_DEFAULT
    }

    fn migrate(
        &self,
        kind: &str,
        module: &str,
        settings: &serde_json::Value,
        from: &str,
    ) -> Result<Option<(String, Migrated)>, String>;

    fn repin(&self, github: &str) -> Result<Option<String>, String>;

    fn release_for(&self, kind: &str, module: &str) -> Result<Option<String>, String>;

    fn rewrite_catalog(&self) -> Result<Option<(String, Vec<String>)>, String> {
        Ok(None)
    }

    fn providers_catalog(
        &self,
    ) -> Result<Option<serde_json::Map<String, serde_json::Value>>, String> {
        Ok(None)
    }

    /// Resolve the released 1.5.5 JWT credential filename convention once, without
    /// returning credential material to the configuration migrator. None means inline JSON.
    fn legacy_jwt_credential_file(
        &self,
        _credential: &busbar_contract::secret_ref::SecretRef,
    ) -> Result<Option<busbar_contract::secret_ref::SecretRef>, String> {
        Err("credential resolution is unavailable during migration".into())
    }

    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        Err(format!("no resolver is at hand for '{host}'"))
    }
}

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

pub(super) struct Ledger<'a> {
    pub changes: &'a mut Vec<String>,
    pub todos: &'a mut Vec<String>,
    pub failures: &'a mut Vec<String>,
}

struct Site {
    path: String,

    at: Vec<String>,
    kind: String,
    module: String,

    // settings-leak-lint: allow — the operator's own section as written, handed to its plugin's
    settings: serde_json::Value,

    read_only: Vec<String>,
}

pub(super) struct PlaneFacts {
    pub key: &'static str,
    pub owns: Vec<&'static str>,
    pub consumes: &'static [&'static str],
}

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

pub(super) fn migrate(root: &mut Mapping, host: &dyn MigrateHost, ledger: &mut Ledger<'_>) {
    migrate_over(root, host, ledger, &registry_planes());
}

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
            Ok(None) => {
                if host
                    .validate_migrated(&site.kind, &site.module, &site.settings)
                    .is_err()
                {
                    ledger.failures.push(format!("{}: current plugin validation refused unchanged settings; install the current plugin or resolve its migration prerequisites before retrying", site.path));
                }
            }
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
            root.insert(
                Value::from(field::PROVIDERS_FILE),
                Value::from(file.as_str()),
            );
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

fn migration_json(
    value: Option<&Value>,
    path: &str,
    ledger: &mut Ledger<'_>,
) -> Result<serde_json::Value, ()> {
    match value {
        None => Ok(serde_json::Value::Null),
        Some(value) => serde_json::to_value(value).map_err(|_| {
            ledger.todos.push(format!("{path}: cannot be represented as plugin JSON; the original YAML was preserved and the affected plugin migration was not called"));
        }),
    }
}

fn sites(
    root: &Mapping,
    planes: &[PlaneFacts],
    host: &dyn MigrateHost,
    ledger: &mut Ledger<'_>,
) -> Vec<Site> {
    let mut out = Vec::new();
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
            if let Some(module) = section
                .get(Value::from(field::MODULE))
                .and_then(Value::as_str)
            {
                let path = format!("{key}.settings");
                let Ok(settings) =
                    migration_json(section.get(Value::from(field::SETTINGS)), &path, ledger)
                else {
                    continue;
                };
                out.push(Site {
                    path,
                    at: vec![key.to_string(), field::SETTINGS.to_string()],
                    kind: word.to_string(),
                    module: module.to_string(),
                    settings,
                    read_only: Vec::new(),
                });
            }
            continue;
        }
        for (name, entry) in section {
            let (Some(name), Value::Mapping(entry)) = (name.as_str(), entry) else {
                continue;
            };
            let Some(module) = entry
                .get(Value::from(field::MODULE))
                .and_then(Value::as_str)
            else {
                continue;
            };
            let path = format!("{key}.{name}.settings");
            let Ok(settings) =
                migration_json(entry.get(Value::from(field::SETTINGS)), &path, ledger)
            else {
                continue;
            };
            out.push(Site {
                path,
                at: vec![
                    key.to_string(),
                    name.to_string(),
                    field::SETTINGS.to_string(),
                ],
                kind: word.to_string(),
                module: module.to_string(),
                settings,
                read_only: Vec::new(),
            });
        }
    }
    let mut providers: Option<Result<Option<serde_json::Value>, ()>> = None;
    'planes: for plane in planes {
        let mut sections = serde_json::Map::new();
        for s in &plane.owns {
            if let Some(v) = root.get(Value::from(*s)) {
                let Ok(value) = migration_json(Some(v), s, ledger) else {
                    continue 'planes;
                };
                sections.insert((*s).to_string(), value);
            }
        }

        if sections.is_empty()
            && !host
                .plane_selecting_sections(plane.key)
                .iter()
                .any(|section| root.contains_key(Value::from(section.as_str())))
        {
            continue;
        }
        let mut read_only = Vec::new();
        for s in plane.consumes {
            if plane.owns.contains(s) {
                continue;
            }
            let value = if *s == Kind::Transport.root() {
                match providers
                    .get_or_insert_with(|| merged_providers(root, host, ledger))
                    .clone()
                {
                    Ok(value) => value,
                    Err(()) => continue 'planes,
                }
            } else {
                match root.get(Value::from(*s)) {
                    None => None,
                    Some(v) => match migration_json(Some(v), s, ledger) {
                        Ok(value) => Some(value),
                        Err(()) => continue 'planes,
                    },
                }
            };
            if let Some(v) = value {
                sections.insert((*s).to_string(), v);
                read_only.push((*s).to_string());
            }
        }
        out.push(Site {
            path: plane.owns.join(", "),
            at: Vec::new(),
            kind: busbar_contract::abi::mechanism::kind::PLANE.to_string(),
            module: plane.key.to_string(),
            settings: serde_json::Value::Object(sections),
            read_only,
        });
    }
    out
}

fn merged_providers(
    root: &Mapping,
    host: &dyn MigrateHost,
    ledger: &mut Ledger<'_>,
) -> Result<Option<serde_json::Value>, ()> {
    let key = Kind::Transport.root();
    let deployment = root
        .get(Value::from(key))
        .map(|value| migration_json(Some(value), key, ledger))
        .transpose()?;
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
        return Ok(deployment);
    };
    let Some(serde_json::Value::Object(entries)) = deployment else {
        return Ok(Some(serde_json::Value::Object(merged)));
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
    Ok(Some(serde_json::Value::Object(merged)))
}

fn plane_sections(d: &crate::plane_driver::registry::PlaneDecl) -> Vec<&'static str> {
    let mut all = vec![d.config_section];
    for s in d.owned_config_sections {
        if !all.contains(s) {
            all.push(*s);
        }
    }
    all
}

fn kind_word(kind: Kind) -> &'static str {
    match kind {
        Kind::Plane => busbar_contract::abi::mechanism::kind::PLANE,
        Kind::Transport => busbar_contract::abi::mechanism::kind::TRANSPORT,
        Kind::Auth => busbar_contract::abi::mechanism::kind::AUTH,
        Kind::Store => busbar_contract::abi::mechanism::kind::STORE,
        Kind::Secret => busbar_contract::abi::mechanism::kind::SECRET,
        Kind::Hook => busbar_contract::abi::mechanism::kind::HOOK,
        Kind::Export => busbar_contract::abi::mechanism::kind::EXPORT,
    }
}

fn apply(
    root: &mut Mapping,
    host: &dyn MigrateHost,
    site: &Site,
    plugin: &str,
    migrated: Migrated,
    ledger: &mut Ledger<'_>,
) {
    let Migrated {
        mut settings,
        mut report,
        needs,
    } = migrated;
    let lifted_secret = needs
        .iter()
        .any(|need| matches!(need, MigrateNeed::ExternalizeSecret { .. }));
    // Complete secret lifting before any configuration is emitted. An unsuccessful lift is a
    // failed migration, not a TODO beside a literal that current runtime cannot safely consume.
    for need in &needs {
        let MigrateNeed::ExternalizeSecret { path } = need else {
            continue;
        };
        let result = externalize_secret(&mut settings, &mut report, path, host, &site.path);
        if result.is_err() {
            ledger.failures.push(format!(
                "{}: the plugin '{plugin}' requires secure literal-secret migration; ensure the old credential is nonempty without trailing CR/LF and the private migration directory is writable, or supply an explicit private file SecretRef; no converted configuration was emitted",
                site.path
            ));
            return;
        }
    }
    if host
        .validate_migrated(&site.kind, &site.module, &settings)
        .is_err()
    {
        ledger.failures.push(format!("{}: current plugin validation refused the migrated settings; no converted configuration was emitted", site.path));
        return;
    }
    if settings != site.settings {
        if let Err(why) = write_back(root, site, settings) {
            if lifted_secret {
                ledger.failures.push(format!("{}: migrated secret settings could not be installed; no converted configuration was emitted", site.path));
                return;
            }
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
            MigrateNeed::ExternalizeSecret { .. } => {}
            MigrateNeed::AllowDestination(host) => allow_destination(root, plugin, &host, ledger),

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

fn externalize_secret(
    settings: &mut serde_json::Value,
    report: &mut [String],
    path: &[String],
    host: &dyn MigrateHost,
    site: &str,
) -> Result<(), String> {
    use zeroize::Zeroize;
    if path.is_empty() || path.len() > 32 || path.iter().any(|p| p.is_empty() || p.len() > 256) {
        return Err("invalid migration secret path".into());
    }
    let mut slot = settings;
    for part in path {
        slot = slot
            .as_object_mut()
            .and_then(|map| map.get_mut(part))
            .ok_or("migration secret path is not an existing settings field")?;
    }
    let serde_json::Value::String(secret) = slot else {
        return Err("migration secret path is not a historical literal".into());
    };
    if secret.is_empty() || secret.ends_with(['\r', '\n']) {
        return Err("the current text secret resolver cannot preserve this literal exactly".into());
    }
    let file = host.externalize_secret(site, path, secret.as_bytes())?;
    for line in report {
        if !secret.is_empty() && line.contains(secret.as_str()) {
            *line = line.replace(secret.as_str(), "[REDACTED]");
        }
    }
    secret.zeroize();
    *slot = serde_json::json!({"file": file});
    Ok(())
}

/// Convert plugin JSON into real YAML scalars. serde_json arbitrary_precision exposes a
/// private map marker through generic serializers, which would corrupt numeric settings.
/// Refuse integers outside YAML's exact range instead of silently rounding their value.
pub fn yaml_value(value: &serde_json::Value) -> Result<Value, String> {
    use serde_json::Value as Json;
    Ok(match value {
        Json::Null => Value::Null,
        Json::Bool(value) => Value::Bool(*value),
        Json::String(value) => Value::String(value.clone()),
        Json::Number(value) => {
            if let Some(value) = value.as_u64() {
                Value::Number(value.into())
            } else if let Some(value) = value.as_i64() {
                Value::Number(value.into())
            } else {
                let text = value.to_string();
                if !text.contains(['.', 'e', 'E']) {
                    return Err("plugin migration integer exceeds the exact YAML range".into());
                }
                let value = value
                    .as_f64()
                    .filter(|value| value.is_finite())
                    .ok_or("plugin migration number is not a finite YAML scalar")?;
                let replay = serde_json::Number::from_f64(value)
                    .ok_or("plugin migration number is not finite")?
                    .to_string();
                if decimal_value(&text) != decimal_value(&replay) {
                    return Err(
                        "plugin migration decimal cannot be represented exactly in YAML".into(),
                    );
                }
                Value::Number(value.into())
            }
        }
        Json::Array(values) => {
            Value::Sequence(values.iter().map(yaml_value).collect::<Result<_, _>>()?)
        }
        Json::Object(values) => Value::Mapping(
            values
                .iter()
                .map(|(key, value)| Ok((Value::String(key.clone()), yaml_value(value)?)))
                .collect::<Result<_, String>>()?,
        ),
    })
}

fn decimal_value(text: &str) -> Option<(bool, String, i64)> {
    let (negative, text) = text
        .strip_prefix('-')
        .map_or((false, text), |text| (true, text));
    let (coefficient, exponent) =
        text.split_once(['e', 'E'])
            .map_or(Some((text, 0_i64)), |(coefficient, exponent)| {
                exponent
                    .parse()
                    .ok()
                    .map(|exponent| (coefficient, exponent))
            })?;
    let decimals = coefficient
        .split_once('.')
        .map_or(0, |(_, fraction)| fraction.len());
    let mut digits = coefficient.replace('.', "");
    digits = digits.trim_start_matches('0').to_owned();
    if digits.is_empty() {
        return Some((false, "0".into(), 0));
    }
    let trailing = digits.len() - digits.trim_end_matches('0').len();
    digits.truncate(digits.len() - trailing);
    let exponent = exponent
        .checked_sub(i64::try_from(decimals).ok()?)?
        .checked_add(i64::try_from(trailing).ok()?)?;
    Some((negative, digits, exponent))
}

fn write_back(root: &mut Mapping, site: &Site, settings: serde_json::Value) -> Result<(), String> {
    let value = yaml_value;
    if site.kind == busbar_contract::abi::mechanism::kind::PLANE {
        let serde_json::Value::Object(sections) = settings else {
            return Err("a plane answers its sections as one object".into());
        };

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

fn push_allowed(root: &mut Mapping, plugin: &str, host: &str) -> Result<bool, String> {
    let advanced = root
        .entry(Value::from(field::ADVANCED))
        .or_insert_with(|| Value::Mapping(Mapping::new()));
    let Value::Mapping(advanced) = advanced else {
        return Err(format!(
            "advanced: is not a mapping, so '{host}', which the plugin '{plugin}' needs allowed, \
             was not added to advanced.allow_destinations; add it by hand"
        ));
    };
    let list = advanced
        .entry(Value::from(field::ALLOW_DESTINATIONS))
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

fn already_allowed(root: &Mapping, name: &str) -> bool {
    let Some(Value::Mapping(advanced)) = root.get(Value::from(field::ADVANCED)) else {
        return false;
    };
    let Some(Value::Sequence(list)) = advanced.get(Value::from(field::ALLOW_DESTINATIONS)) else {
        return false;
    };
    list.iter().filter_map(Value::as_str).any(|e| {
        let e = e.trim().trim_start_matches('[').trim_end_matches(']');
        e.strip_suffix('.').unwrap_or(e).eq_ignore_ascii_case(name)
    })
}

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
    } else if name == LOCALHOST_NAME || name.ends_with(LOCALHOST_SUFFIX) {
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

fn fetch_list(root: &mut Mapping) -> Option<&mut Vec<Value>> {
    let Some(Value::Mapping(plugins)) = root.get_mut(Value::from(field::PLUGINS)) else {
        return None;
    };
    match plugins.get_mut(Value::from(field::FETCH)) {
        Some(Value::Sequence(list)) => Some(list),
        _ => None,
    }
}

fn repin_fetch(root: &mut Mapping, host: &dyn MigrateHost, ledger: &mut Ledger<'_>) {
    let Some(list) = fetch_list(root) else {
        return;
    };
    for entry in list.iter_mut() {
        let Value::Mapping(entry) = entry else {
            continue;
        };
        let Some(old) = entry
            .get(Value::from(FETCH_GITHUB_PIN_KEY))
            .and_then(Value::as_str)
            .map(str::to_string)
        else {
            continue;
        };
        match host.repin(&old) {
            Ok(Some(new)) if new != old => {
                entry.insert(Value::from(FETCH_GITHUB_PIN_KEY), Value::from(new.as_str()));
                let pinned = entry.remove(Value::from(field::SHA256)).is_some();
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

fn repo_of(github: &str) -> String {
    github
        .split_once('@')
        .map_or(github, |(repo, _)| repo)
        .to_ascii_lowercase()
}

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
                .filter_map(|e| {
                    e.get(FETCH_GITHUB_PIN_KEY)
                        .and_then(Value::as_str)
                        .map(repo_of)
                })
                .collect()
        })
        .unwrap_or_default();
    for pin in pins {
        if have.contains(&repo_of(&pin)) {
            continue;
        }
        let plugins = root
            .entry(Value::from(field::PLUGINS))
            .or_insert_with(|| Value::Mapping(Mapping::new()));
        let Value::Mapping(plugins) = plugins else {
            ledger.todos.push("plugins: is not a mapping; required plugin pins could not be added. The original value was preserved; fix plugins and re-run migration".into());
            return;
        };
        let list = plugins
            .entry(Value::from(field::FETCH))
            .or_insert_with(|| Value::Sequence(Vec::new()));
        let Value::Sequence(list) = list else {
            ledger.todos.push("plugins.fetch: is not a list; required plugin pins could not be added. The original value was preserved; fix plugins.fetch and re-run migration".into());
            return;
        };
        let mut entry = Mapping::new();
        entry.insert(Value::from(FETCH_GITHUB_PIN_KEY), Value::from(pin.as_str()));
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
