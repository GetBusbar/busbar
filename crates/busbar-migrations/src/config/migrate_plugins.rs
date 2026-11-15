// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::net::IpAddr;

use busbar_contract::abi::sdk::migrate::{MigrateNeed, MigrationAnswer};
use busbar_contract::plugin::Kind;
use busbar_contract::yaml::prelude::*;

use super::migrate::vocabulary::field;

const FETCH_GITHUB_PIN_KEY: &str = "github";

const LOCALHOST_NAME: &str = "localhost";
const LOCALHOST_SUFFIX: &str = ".localhost";

/// Frozen plugin-settings migration vocabulary understood by the released Migrate ABI.
/// Source-aware startup selects this only after native profile admission; it does
/// not assert that the physical schema uniquely identifies a product binary release.
pub(crate) const FROM_DEFAULT: &str = "1.5.5";

/// Why converted settings could not be checked by their current plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unvalidated {
    /// The host could not obtain the current plugin. Closed set; the host writes the Display text.
    Unavailable(Unobtainable),
    /// The current plugin refused the settings. Its text is NOT carried, because it may echo
    /// settings.
    Refused,
}

/// Why the host could not obtain a current plugin. Holds no free text: every operator- or
/// index-derived value is a [`Shown`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unobtainable {
    /// Reading or downloading the plugin index failed.
    IndexUnreachable { source: Shown },
    /// The plugin index's bytes are not a release index.
    NotAnIndex { source: Shown },
    /// The plugin index has no row for this kind and module.
    NoSuchPlugin { source: Shown },
    /// The plugin index names no release of `repo` built for this busbar.
    NoReleaseForAbi { repo: Shown },
    /// The plugin index's release is not an `org/repo@tag` pin.
    BadPin,
    /// Downloading the plugin asset failed.
    AssetUnreachable { asset: Shown },
    /// The temporary staging directory could not be created or written.
    Staging,
    /// The plugin trust policy refused the fetched plugin.
    NotAdmitted,
    /// The fetched plugin serves no plugin of this kind and module.
    NotServed,
}

impl std::fmt::Display for Unobtainable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IndexUnreachable { source } => {
                write!(f, "the plugin index {source} could not be read")
            }
            Self::NotAnIndex { source } => {
                write!(f, "the plugin index {source} is not a release index")
            }
            Self::NoSuchPlugin { source } => {
                write!(f, "the plugin index {source} names no such plugin")
            }
            Self::NoReleaseForAbi { repo } => write!(
                f,
                "the plugin index names no release of {repo} built for this busbar"
            ),
            Self::BadPin => {
                f.write_str("the plugin index names a release that is not an org/repo@tag pin")
            }
            Self::AssetUnreachable { asset } => {
                write!(f, "the plugin asset {asset} could not be downloaded")
            }
            Self::Staging => {
                f.write_str("the migration staging directory could not be created or written")
            }
            Self::NotAdmitted => {
                f.write_str("the fetched plugin was not admitted by the plugin trust policy")
            }
            Self::NotServed => {
                f.write_str("the fetched plugin serves no plugin of this kind and module")
            }
        }
    }
}

/// Index-derived or operator-supplied text as the host shows it. The only constructor is
/// [`Shown::of`], which keeps at most a scheme, host, port and path, or a fixed placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shown(String);

const SHOWN_UNPRINTABLE: &str = "<unprintable source>";
const SHOWN_REDACTED: &str = "<redacted>";
const SHOWN_SCHEME_END: &str = "://";

impl Shown {
    /// Show `s` without userinfo, query or fragment, refusing any byte outside printable ASCII.
    #[must_use]
    pub fn of(s: &str) -> Self {
        if s.bytes().any(|b| !(0x21..=0x7E).contains(&b)) {
            return Self(SHOWN_UNPRINTABLE.to_owned());
        }
        let mut rest = s.to_owned();
        // Drop userinfo by the last `@` before any other cut, so no character inside a raw
        // password can hide it.
        if let Some(last_at) = s.rfind('@') {
            let start = match s.find(SHOWN_SCHEME_END) {
                Some(at) if at + SHOWN_SCHEME_END.len() <= last_at && is_scheme(&s[..at]) => {
                    at + SHOWN_SCHEME_END.len()
                }
                _ => 0,
            };
            if s[start..=last_at].contains(['?', '#']) {
                // A password holding `?`/`#` and a query or fragment holding `@` look the same.
                return Self(format!("{}{SHOWN_REDACTED}", &s[..start]));
            }
            rest = format!("{}{}", &s[..start], &s[last_at + 1..]);
        }
        if let Some(cut) = rest.find(['?', '#']) {
            rest.truncate(cut);
        }
        Self(rest)
    }
}

/// RFC 3986 `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`.
fn is_scheme(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_alphabetic())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

impl std::fmt::Display for Shown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub trait MigrateHost {
    /// The migration's grammar: the source shorthand the modules the migrated document's own
    /// `plugins:` block admits declare ([`Self::bind_grammar`]), never the live secret axis. No
    /// source is inferred when absent.
    fn source_declarations(&self) -> Result<busbar_contract::secret_ref::Sugars, String> {
        Ok(Default::default())
    }

    /// The migrated document's `plugins:` block after the structural steps (SECRET-SHORTHAND-BOOT
    /// §3.13): what [`Self::source_declarations`] is computed from for the rest of this migration.
    /// A host with fixed declarations ignores it.
    fn bind_grammar(&self, _plugins: Option<&busbar_contract::yaml::Value>) {}

    /// Accept opaque grammar/settings evidence for in-memory migration custody only.
    fn admit_config_profile(&self, _: &super::HistoricalConfigProof) -> Result<(), String> {
        Ok(())
    }

    /// Resolve a scalar solely for validation/probing; authored output retains its template.
    fn resolved_authored_scalar(&self, _: &str) -> Result<Option<serde_json::Value>, String> {
        Ok(None)
    }

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

    /// Validate converted current settings as [`Self::validate_migrated`] does, saying whether the
    /// current plugin could not be obtained or refused them. The default reads every
    /// [`Self::validate_migrated`] refusal as [`Unvalidated::Refused`] and drops its text, which
    /// may echo settings. A host that fetches current plugins overrides this to say why one could
    /// not be obtained.
    fn validate_current(
        &self,
        kind: &str,
        module: &str,
        settings: &serde_json::Value,
    ) -> Result<(), Unvalidated> {
        self.validate_migrated(kind, module, settings)
            .map_err(|_| Unvalidated::Refused)
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
    ) -> Result<Option<(String, MigrationAnswer)>, String>;

    /// Cold reference discovery, distinct from selecting an owner for settings migration.
    fn migrate_references(
        &self,
        _kind: &str,
        _module: &str,
        _settings: &serde_json::Value,
        _from: &str,
    ) -> Result<Option<(String, MigrationAnswer)>, String> {
        Ok(None)
    }

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

    /// Resolve and lend a reference to the auth owner selected by a plugin migration.
    /// The host never interprets credential text or the owner's historical format.
    fn migrate_credential(
        &self,
        _module: &str,
        _credential: &busbar_contract::secret_ref::SecretRef,
        _from: &str,
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
    ) -> Result<Option<(String, MigrationAnswer)>, String> {
        Ok(None)
    }
    fn repin(&self, _: &str) -> Result<Option<String>, String> {
        Ok(None)
    }
    fn release_for(&self, _: &str, _: &str) -> Result<Option<String>, String> {
        Ok(None)
    }
}

/// A host that answers every `kind: auth` settings check `Ok` and delegates every other kind and
/// method to `0`. Pass 1 of the startup upgrade (see
/// [`super::normalize_plugins_view`]) uses it before the operator words are bound, when the
/// startup host cannot yet tell the operator module from any other auth module.
pub struct ViewOnly<'a>(pub &'a dyn MigrateHost);

impl MigrateHost for ViewOnly<'_> {
    fn source_declarations(&self) -> Result<busbar_contract::secret_ref::Sugars, String> {
        self.0.source_declarations()
    }
    fn admit_config_profile(&self, proof: &super::HistoricalConfigProof) -> Result<(), String> {
        self.0.admit_config_profile(proof)
    }
    fn resolved_authored_scalar(&self, scalar: &str) -> Result<Option<serde_json::Value>, String> {
        self.0.resolved_authored_scalar(scalar)
    }
    fn plane_selecting_sections(&self, module: &str) -> Vec<String> {
        self.0.plane_selecting_sections(module)
    }
    fn externalize_secret(
        &self,
        site: &str,
        path: &[String],
        bytes: &[u8],
    ) -> Result<String, String> {
        self.0.externalize_secret(site, path, bytes)
    }
    fn validate_migrated(
        &self,
        kind: &str,
        module: &str,
        settings: &serde_json::Value,
    ) -> Result<(), String> {
        if kind == busbar_contract::abi::mechanism::kind::AUTH {
            return Ok(());
        }
        self.0.validate_migrated(kind, module, settings)
    }
    fn validate_current(
        &self,
        kind: &str,
        module: &str,
        settings: &serde_json::Value,
    ) -> Result<(), Unvalidated> {
        if kind == busbar_contract::abi::mechanism::kind::AUTH {
            return Ok(());
        }
        self.0.validate_current(kind, module, settings)
    }
    fn migrating_from(&self) -> &str {
        self.0.migrating_from()
    }
    fn migrate(
        &self,
        kind: &str,
        module: &str,
        settings: &serde_json::Value,
        from: &str,
    ) -> Result<Option<(String, MigrationAnswer)>, String> {
        self.0.migrate(kind, module, settings, from)
    }
    fn migrate_references(
        &self,
        kind: &str,
        module: &str,
        settings: &serde_json::Value,
        from: &str,
    ) -> Result<Option<(String, MigrationAnswer)>, String> {
        self.0.migrate_references(kind, module, settings, from)
    }
    fn repin(&self, github: &str) -> Result<Option<String>, String> {
        self.0.repin(github)
    }
    fn release_for(&self, kind: &str, module: &str) -> Result<Option<String>, String> {
        self.0.release_for(kind, module)
    }
    fn rewrite_catalog(&self) -> Result<Option<(String, Vec<String>)>, String> {
        self.0.rewrite_catalog()
    }
    fn providers_catalog(
        &self,
    ) -> Result<Option<serde_json::Map<String, serde_json::Value>>, String> {
        self.0.providers_catalog()
    }
    fn migrate_credential(
        &self,
        module: &str,
        credential: &busbar_contract::secret_ref::SecretRef,
        from: &str,
    ) -> Result<Option<busbar_contract::secret_ref::SecretRef>, String> {
        self.0.migrate_credential(module, credential, from)
    }
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        self.0.resolve(host)
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

    /// The section as written, encoded and held in guarded custody. It is read back into a wiping
    /// tree only while this site is being migrated ([`Site::handed`]).
    settings: busbar_contract::Secret<Vec<u8>>,

    read_only: Vec<String>,
    references_only: bool,
    browser_client_id: Option<String>,
}

/// Seal a section for a [`Site`]: guarded encoded bytes, never a readable tree at rest.
fn sealed(settings: serde_json::Value) -> Result<busbar_contract::Secret<Vec<u8>>, String> {
    busbar_contract::plugin_settings::ResolvedSettings::from(settings)
        .encode()
        .map_err(|_| "its settings could not be held for migration (values not echoed)".to_owned())
}

impl Site {
    /// The section as written, read back from guarded custody for this site's migration only.
    fn handed(&self) -> Result<busbar_contract::abi::sdk::cred::SettingsValue, String> {
        busbar_contract::abi::sdk::cred::settings_document(
            self.settings.expose(&busbar_kernel::seal::lend()),
        )
        .map_err(|_| {
            format!(
                "{}: its settings could not be read back for migration (values not echoed); \
                 they were left as written",
                self.path
            )
        })
    }

    fn owns_reference_scope(&self, path: &[String]) -> bool {
        self.kind == busbar_contract::abi::mechanism::kind::PLANE
            && path.len() > 1
            && path.first().is_some_and(|section| {
                section != busbar_contract::abi::sdk::migrate::SOURCE_DOCUMENTS
                    && self.read_only.contains(section)
            })
    }

    fn validate(
        &self,
        host: &dyn MigrateHost,
        settings: &serde_json::Value,
    ) -> Result<(), Unvalidated> {
        let Some(client_id) = &self.browser_client_id else {
            return host.validate_current(&self.kind, &self.module, settings);
        };
        if settings.get("client_id").is_some() {
            return host.validate_current(&self.kind, &self.module, settings);
        }
        // Match login opening: browser configuration supplies a fallback only.
        // Keep this projection out of authored settings and migration write-back.
        let mut effective =
            busbar_contract::abi::sdk::cred::SettingsValue::from(if settings.is_null() {
                serde_json::json!({})
            } else {
                settings.clone()
            });
        if let Some(map) = effective
            .pointer_mut("")
            .and_then(serde_json::Value::as_object_mut)
        {
            map.entry("client_id")
                .or_insert_with(|| client_id.clone().into());
        }
        host.validate_current(&self.kind, &self.module, &effective)
    }
}

/// The failure line for a site whose current plugin the host could not obtain. Only host-written
/// text ([`Unobtainable`]'s Display) is shown.
fn unobtainable(site: &Site, why: &Unobtainable) -> String {
    format!(
        "{}: the current {} plugin '{}' could not be obtained to check these settings ({why}); \
         install it in a plugins directory and set `plugins: {{enabled: true, dir: <dir>}}` in \
         this config, or make BUSBAR_PLUGIN_INDEX and the plugin's GitHub release reachable, \
         then retry",
        site.path, site.kind, site.module
    )
}

pub(super) struct PlaneFacts {
    pub key: &'static str,
    pub owns: Vec<&'static str>,
    pub consumes: &'static [&'static str],
}

fn registry_planes() -> Vec<PlaneFacts> {
    busbar_kernel::plane_driver::registry::plane_decls()
        .iter()
        .map(|d| PlaneFacts {
            key: d.key,
            owns: plane_sections(d),
            consumes: busbar_kernel::plane_driver::door::consumed_sections(d),
        })
        .collect()
}

/// Only registered owners whose current validator refuses a payload may convert it
/// without native format provenance. This never changes Store bootstrap bindings,
/// repins plugins, rewrites catalogs or applies implicit historical access grants.
pub(super) fn migrate_recognized(
    root: &mut Pairs,
    host: &dyn MigrateHost,
    ledger: &mut Ledger<'_>,
) {
    super::migrate_tls::apply(root, ledger);
    let from = host.migrating_from().to_owned();
    // Current plane payloads are validated by ordinary admission. Do not construct
    // historical plane envelopes or read their consumed catalogs on this path.
    for site in sites(root, &[], host, ledger) {
        if site.kind == busbar_contract::abi::mechanism::kind::STORE
            || site.kind == busbar_contract::abi::mechanism::kind::PLANE
        {
            continue;
        }
        let handed = match site.handed() {
            Ok(handed) => handed,
            Err(failure) => {
                ledger.failures.push(failure);
                continue;
            }
        };
        if site.validate(host, &handed).is_ok() {
            continue;
        }
        match host.migrate(&site.kind, &site.module, &handed, &from) {
            Ok(Some((plugin, migrated))) if serde_json::to_value(migrated.authoring(&busbar_kernel::seal::acquire()))
                .map(busbar_contract::abi::sdk::cred::SettingsValue::from)
                .is_ok_and(|settings| *settings != *handed) => {
                let proof = match super::provenance::HistoricalConfigProof::settings(&site.path, &handed) {
                    Ok(proof) => proof,
                    Err(error) => { ledger.failures.push(error); continue; }
                };
                if host.admit_config_profile(&proof).is_err() {
                    ledger.failures.push("historical settings evidence was refused".into()); continue;
                }
                apply(root, host, &site, &handed, &plugin, migrated, ledger);
            }
            _ => ledger.todos.push(format!("{}: current settings were refused and the registered owner established no supported historical conversion", site.path)),
        }
    }
}

pub(super) fn migrate(root: &mut Pairs, host: &dyn MigrateHost, ledger: &mut Ledger<'_>) {
    migrate_over(root, host, ledger, &registry_planes());
}

pub(super) fn migrate_over(
    root: &mut Pairs,
    host: &dyn MigrateHost,
    ledger: &mut Ledger<'_>,
    planes: &[PlaneFacts],
) {
    super::migrate_tls::apply(root, ledger);
    let from = host.migrating_from().to_string();
    let mut wanted: Vec<(String, String)> = Vec::new();
    for site in sites(root, planes, host, ledger) {
        let handed = match site.handed() {
            Ok(handed) => handed,
            Err(failure) => {
                ledger.failures.push(failure);
                continue;
            }
        };
        if site.references_only {
            match host.migrate_references(&site.kind, &site.module, &handed, &from) {
                Ok(Some((_, answer))) => {
                    for need in answer.needs {
                        match need {
                            MigrateNeed::MigrateCredential {path, module} if site.owns_reference_scope(&path) =>
                                super::migrate_credentials::migrate(root, host, &path, &module, ledger.changes, ledger.todos),
                            MigrateNeed::Review {path, reason} if site.owns_reference_scope(&path) =>
                                ledger.todos.push(format!("{}: {reason}", path.join("."))),
                            _ => {}
                        }
                    }
                }
                Ok(None) => {}
                Err(_) => ledger.todos.push(format!("{}: its owner could not inspect original credential references; they were preserved", site.path)),
            }
            continue;
        }
        wanted.push((site.kind.clone(), site.module.clone()));
        match host.migrate(&site.kind, &site.module, &handed, &from) {
            Ok(None) => match site.validate(host, &handed) {
                Ok(()) => {}
                Err(Unvalidated::Unavailable(why)) => {
                    ledger.failures.push(unobtainable(&site, &why));
                }
                Err(Unvalidated::Refused) => {
                    ledger.failures.push(format!("{}: current plugin validation refused unchanged settings; install the current plugin or resolve its migration prerequisites before retrying", site.path));
                }
            },
            Ok(Some((plugin, migrated))) => {
                apply(root, host, &site, &handed, &plugin, migrated, ledger);
            }
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
            root.insert_key(field::PROVIDERS_FILE, Value::from(file.as_str()));
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
    root: &Pairs,
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
        let Some(Value::Map(section)) = root.get_key(key) else {
            continue;
        };
        if kind == Kind::Store {
            if let Some(module) = section.get_key(field::MODULE).and_then(Value::as_str) {
                let path = format!("{key}.settings");
                let Ok(settings) = migration_json(section.get_key(field::SETTINGS), &path, ledger)
                else {
                    continue;
                };
                let settings = match sealed(settings) {
                    Ok(settings) => settings,
                    Err(why) => {
                        ledger.failures.push(format!("{path}: {why}"));
                        continue;
                    }
                };
                out.push(Site {
                    path,
                    at: vec![key.to_string(), field::SETTINGS.to_string()],
                    kind: word.to_string(),
                    module: module.to_string(),
                    settings,
                    read_only: Vec::new(),
                    references_only: false,
                    browser_client_id: None,
                });
            }
            continue;
        }
        for (name, entry) in section {
            let (Some(name), Value::Map(entry)) = (name.as_str(), entry) else {
                continue;
            };
            let Some(module) = entry.get_key(field::MODULE).and_then(Value::as_str) else {
                continue;
            };
            // `token:` on an identity-provider definition is core's 1.5 operator field, not plugin
            // settings: it passes through untouched, with no host check and no plugin migrate.
            if kind == Kind::Auth && entry.contains_key(field::TOKEN) {
                continue;
            }
            let path = format!("{key}.{name}.settings");
            let Ok(settings) = migration_json(entry.get_key(field::SETTINGS), &path, ledger) else {
                continue;
            };
            let settings = match sealed(settings) {
                Ok(settings) => settings,
                Err(why) => {
                    ledger.failures.push(format!("{path}: {why}"));
                    continue;
                }
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
                references_only: false,
                browser_client_id: (kind == Kind::Auth)
                    .then(|| {
                        entry
                            .get_key(field::BROWSER_LOGIN)
                            .and_then(|login| login.get("client_id"))
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .flatten(),
            });
        }
    }
    let mut providers: Option<Result<ProviderDocuments, ()>> = None;
    'planes: for plane in planes {
        let mut sections = serde_json::Map::new();
        for s in &plane.owns {
            if let Some(v) = root.get_key(*s) {
                let Ok(value) = migration_json(Some(v), s, ledger) else {
                    continue 'planes;
                };
                sections.insert((*s).to_string(), value);
            }
        }

        let selected = !sections.is_empty()
            || host
                .plane_selecting_sections(plane.key)
                .iter()
                .any(|section| root.contains_key(section.as_str()));
        if !selected
            && !plane
                .consumes
                .iter()
                .any(|section| root.contains_key(*section))
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
                    Ok(value) => {
                        let source_key = busbar_contract::abi::sdk::migrate::SOURCE_DOCUMENTS;
                        sections.insert(
                            source_key.to_owned(),
                            serde_json::json!({*s: value.sources}),
                        );
                        read_only.push(source_key.to_owned());
                        value.effective
                    }
                    Err(()) => continue 'planes,
                }
            } else {
                match root.get_key(*s) {
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
        let path = plane.owns.join(", ");
        let settings = match sealed(serde_json::Value::Object(sections)) {
            Ok(settings) => settings,
            Err(why) => {
                ledger.failures.push(format!("{path}: {why}"));
                continue;
            }
        };
        out.push(Site {
            path,
            at: Vec::new(),
            kind: busbar_contract::abi::mechanism::kind::PLANE.to_string(),
            module: plane.key.to_string(),
            settings,
            read_only,
            references_only: !selected,
            browser_client_id: None,
        });
    }
    out
}

#[derive(Clone)]
struct ProviderDocuments {
    effective: Option<serde_json::Value>,
    sources: busbar_contract::abi::sdk::migrate::SourceDocuments,
}

fn merged_providers(
    root: &Pairs,
    host: &dyn MigrateHost,
    ledger: &mut Ledger<'_>,
) -> Result<ProviderDocuments, ()> {
    let key = Kind::Transport.root();
    let deployment = root
        .get_key(key)
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
    let sources = busbar_contract::abi::sdk::migrate::SourceDocuments {
        authored: deployment.clone().unwrap_or_default(),
        catalog: catalog
            .clone()
            .map(serde_json::Value::Object)
            .unwrap_or_default(),
    };
    let Some(mut merged) = catalog else {
        return Ok(ProviderDocuments {
            effective: deployment,
            sources,
        });
    };
    let Some(serde_json::Value::Object(entries)) = deployment else {
        return Ok(ProviderDocuments {
            effective: Some(serde_json::Value::Object(merged)),
            sources,
        });
    };
    for (name, entry) in entries {
        let entry = match (merged.remove(&name), entry) {
            (Some(serde_json::Value::Object(cat)), serde_json::Value::Object(dep)) => {
                serde_json::Value::Object(busbar_kernel::config::providers::merge_tables(cat, dep))
            }
            (_, entry) => entry,
        };
        merged.insert(name, entry);
    }
    Ok(ProviderDocuments {
        effective: Some(serde_json::Value::Object(merged)),
        sources,
    })
}

fn plane_sections(d: &busbar_kernel::plane_driver::registry::PlaneDecl) -> Vec<&'static str> {
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
    root: &mut Pairs,
    host: &dyn MigrateHost,
    site: &Site,
    handed: &serde_json::Value,
    plugin: &str,
    migrated: MigrationAnswer,
    ledger: &mut Ledger<'_>,
) {
    let seal = busbar_kernel::seal::acquire();
    let Ok(settings) = serde_json::to_value(migrated.authoring(&seal)) else {
        ledger.failures.push(format!(
            "{}: migrated settings could not be authored; no converted configuration was emitted",
            site.path
        ));
        return;
    };
    let mut settings = busbar_contract::abi::sdk::cred::SettingsValue::from(settings);
    let mut report = migrated.report;
    let needs = migrated.needs;
    let lifted_secret = needs
        .iter()
        .any(|need| matches!(need, MigrateNeed::ExternalizeSecret { .. }));
    // Complete secret lifting before any configuration is emitted. An unsuccessful lift is a
    // failed migration, not a TODO beside a literal that current runtime cannot safely consume.
    for need in &needs {
        let MigrateNeed::ExternalizeSecret { path } = need else {
            continue;
        };
        let result = externalize_secret(
            settings.pointer_mut("").expect("document root"),
            &mut report,
            path,
            host,
            &site.path,
        );
        if result.is_err() {
            ledger.failures.push(format!(
                "{}: the plugin '{plugin}' requires secure literal-secret migration; ensure the old credential is nonempty without trailing CR/LF and the private migration directory is writable, or supply an explicit private file SecretRef; no converted configuration was emitted",
                site.path
            ));
            return;
        }
    }
    match site.validate(host, &settings) {
        Ok(()) => {}
        Err(Unvalidated::Unavailable(why)) => {
            ledger.failures.push(unobtainable(site, &why));
            return;
        }
        Err(Unvalidated::Refused) => {
            ledger.failures.push(format!("{}: current plugin validation refused the migrated settings; no converted configuration was emitted", site.path));
            return;
        }
    }
    if *settings != *handed {
        if let Err(why) = write_back(root, site, handed, &settings) {
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
            MigrateNeed::Review { path, reason } => {
                ledger.todos.push(format!("{}: {reason}", path.join(".")));
            }
            MigrateNeed::MigrateCredential { path, module } => {
                if !site.owns_reference_scope(&path) {
                    ledger.todos.push(format!("{plugin}: credential migration requested a reference outside its consumed sections; the original was preserved"));
                    continue;
                }
                super::migrate_credentials::migrate(
                    root,
                    host,
                    &path,
                    &module,
                    &mut *ledger.changes,
                    &mut *ledger.todos,
                );
            }
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
    if secret.contains("${") && host.resolved_authored_scalar(secret)?.is_some() {
        if let Some(variable) = secret
            .strip_prefix("${")
            .and_then(|v| v.strip_suffix('}'))
            .filter(|v| !v.is_empty() && !v.contains(['{', '}']))
        {
            let reference = host.source_declarations()?.reference_for_role(
                busbar_contract::abi::mechanism::door::SUGAR_ROLE_FILL,
                variable,
            )?;
            let reference =
                serde_json::to_value(reference.authoring(&busbar_kernel::seal::acquire()))
                    .map_err(|_| "source reference encoding failed")?;
            secret.zeroize();
            *slot = reference;
            return Ok(());
        }
        let reference = serde_json::to_value(
            busbar_contract::secret_ref::SecretRef::template(
                secret.clone(),
                &host.source_declarations()?,
            )?
            .authoring(&busbar_kernel::seal::acquire()),
        )
        .map_err(|_| "authored secret template could not be encoded")?;
        secret.zeroize();
        *slot = reference;
        return Ok(());
    }
    if secret.is_empty() || secret.ends_with(['\r', '\n']) {
        return Err("the current text secret resolver cannot preserve this literal exactly".into());
    }
    let sources = host.source_declarations()?;
    let source = sources
        .with_role(busbar_contract::abi::mechanism::door::SUGAR_ROLE_PATH)
        .ok_or("no admitted source declares the path role")?;
    let file = host.externalize_secret(site, path, secret.as_bytes())?;
    for line in report {
        if !secret.is_empty() && line.contains(secret.as_str()) {
            *line = line.replace(secret.as_str(), "[REDACTED]");
        }
    }
    secret.zeroize();
    *slot = serde_json::to_value(
        source
            .reference(file)
            .authoring(&busbar_kernel::seal::acquire()),
    )
    .map_err(|_| "source reference encoding failed")?;
    Ok(())
}

pub use busbar_contract::json::to_yaml as yaml_value;

fn write_back(
    root: &mut Pairs,
    site: &Site,
    handed: &serde_json::Value,
    settings: &serde_json::Value,
) -> Result<(), String> {
    let value = yaml_value;
    if site.kind == busbar_contract::abi::mechanism::kind::PLANE {
        let serde_json::Value::Object(sections) = settings else {
            return Err("a plane answers its sections as one object".into());
        };

        let mut writes = Vec::new();
        for (name, v) in sections {
            let Some(handed) = handed.get(name) else {
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
            root.insert_key(name, v);
        }
        return Ok(());
    }
    let new = value(settings)?;
    let Some((last, parents)) = site.at.split_last() else {
        return Err("no place to write".into());
    };
    let mut at: &mut Pairs = root;
    for seg in parents {
        at = match at.get_key_mut(seg.as_str()) {
            Some(Value::Map(m)) => m,
            _ => return Err(format!("`{seg}` is no longer a mapping")),
        };
    }
    if settings.is_null() {
        super::migrate::swap_remove_key(at, last.as_str());
    } else {
        at.insert_key(last.as_str(), new);
    }
    Ok(())
}

fn allow_destination(root: &mut Pairs, plugin: &str, host: &str, ledger: &mut Ledger<'_>) {
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

pub(super) fn push_allowed(root: &mut Pairs, plugin: &str, host: &str) -> Result<bool, String> {
    let advanced = root.entry_or_insert_with(field::ADVANCED, || Value::Map(Pairs::new()));
    let Value::Map(advanced) = advanced else {
        return Err(format!(
            "advanced: is not a mapping, so '{host}', which the plugin '{plugin}' needs allowed, \
             was not added to advanced.allow_destinations; add it by hand"
        ));
    };
    let list =
        advanced.entry_or_insert_with(field::ALLOW_DESTINATIONS, || Value::Array(Vec::new()));
    let Value::Array(list) = list else {
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

pub(super) fn already_allowed(root: &Pairs, name: &str) -> bool {
    let Some(Value::Map(advanced)) = root.get_key(field::ADVANCED) else {
        return false;
    };
    let Some(Value::Array(list)) = advanced.get_key(field::ALLOW_DESTINATIONS) else {
        return false;
    };
    list.iter().filter_map(Value::as_str).any(|e| {
        let e = e.trim().trim_start_matches('[').trim_end_matches(']');
        e.strip_suffix('.').unwrap_or(e).eq_ignore_ascii_case(name)
    })
}

fn allow_if_private(
    root: &mut Pairs,
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
    let never = "cloud metadata is refused for every outbound connection and no configuration \
                 admits it, so it was not added";

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

fn fetch_list(root: &mut Pairs) -> Option<&mut Vec<Value>> {
    let Some(Value::Map(plugins)) = root.get_key_mut(field::PLUGINS) else {
        return None;
    };
    match plugins.get_key_mut(field::FETCH) {
        Some(Value::Array(list)) => Some(list),
        _ => None,
    }
}

fn repin_fetch(root: &mut Pairs, host: &dyn MigrateHost, ledger: &mut Ledger<'_>) {
    let Some(list) = fetch_list(root) else {
        return;
    };
    for entry in list.iter_mut() {
        let Value::Map(entry) = entry else {
            continue;
        };
        let Some(old) = entry
            .get_key(FETCH_GITHUB_PIN_KEY)
            .and_then(Value::as_str)
            .map(str::to_string)
        else {
            continue;
        };
        match host.repin(&old) {
            Ok(Some(new)) if new != old => {
                entry.insert_key(FETCH_GITHUB_PIN_KEY, Value::from(new.as_str()));
                let pinned = super::migrate::swap_remove_key(entry, field::SHA256).is_some();
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
    root: &mut Pairs,
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
        let plugins = root.entry_or_insert_with(field::PLUGINS, || Value::Map(Pairs::new()));
        let Value::Map(plugins) = plugins else {
            ledger.todos.push("plugins: is not a mapping; required plugin pins could not be added. The original value was preserved; fix plugins and re-run migration".into());
            return;
        };
        let list = plugins.entry_or_insert_with(field::FETCH, || Value::Array(Vec::new()));
        let Value::Array(list) = list else {
            ledger.todos.push("plugins.fetch: is not a list; required plugin pins could not be added. The original value was preserved; fix plugins.fetch and re-run migration".into());
            return;
        };
        let mut entry = Pairs::new();
        entry.insert_key(FETCH_GITHUB_PIN_KEY, Value::from(pin.as_str()));
        list.push(Value::Map(entry));
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
