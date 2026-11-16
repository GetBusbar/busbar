// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::cell::OnceCell;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use busbar_contract::abi::sdk::migrate::MigrationAnswer;
use busbar_kernel::config::PluginsCfg;
use busbar_migrations::config::migrate_plugins::{MigrateHost, Shown, Unobtainable, Unvalidated};

use crate::root::loader::PluginRegistry;

#[path = "migrate_environment.rs"]
mod environment;
#[cfg(test)]
pub(super) use environment::capture as capture_environment;
pub(crate) use environment::ignored_launch_env;

mod index_field {
    pub(crate) const PLUGINS: &str = "plugins";
    pub(crate) const REPO: &str = "repo";
    pub(crate) const FORMER_REPOS: &str = "former_repos";
    pub(crate) const KIND: &str = "kind";
    pub(crate) const ANSWERS_TO: &str = "answers_to";
    pub(crate) const RELEASES: &str = "releases";
    pub(crate) const TAG: &str = "tag";
    pub(crate) const ABI_VERSION_KEY: &str = "abi_version";
}

const RELEASE_DOWNLOAD_ROOT: &str = "https://github.com/GetBusbar/busbar/releases/download";
const RELEASE_INDEX_ASSET: &str = "plugin-index.json";

const HTTPS_SOURCE_PREFIX: &str = "https://";
const HTTP_SOURCE_PREFIX: &str = "http://";
const CONFIG_PLUGINS_KEY: &str = "plugins";
const CONFIG_PROVIDERS_FILE_KEY: &str = "providers_file";
const DEFAULT_PROVIDERS_CATALOG: &str = "providers.yaml";
const UNNAMED_PROVIDERS_CATALOG_STEM: &str = "providers";

fn default_index() -> String {
    format!(
        "{RELEASE_DOWNLOAD_ROOT}/v{}/{RELEASE_INDEX_ASSET}",
        env!("CARGO_PKG_VERSION")
    )
}

pub(crate) const INDEX_ENV: &str = "BUSBAR_PLUGIN_INDEX";

/// The release downloader the migrate host fetches the index and plugin assets with.
fn release_download(url: &str) -> Result<Vec<u8>, String> {
    crate::root::plugin_fetch::downloader(&[])(url)
}

/// THE RELEASE INDEX: every plugin the index knows, each with its repository, the repositories it
/// was published from before, its kind, the words a configuration may name it by, and its
/// releases with the ABI version each was built for.
#[derive(Debug, Clone, Default)]
pub(crate) struct Index {
    /// The plugins.
    pub plugins: Vec<IndexPlugin>,
}

/// One plugin in the [`Index`].
#[derive(Debug, Clone)]
pub(crate) struct IndexPlugin {
    /// `org/repo`, as a `plugins.fetch` GitHub pin names it.
    pub repo: String,
    /// The repositories its earlier releases were published from.
    pub former_repos: Vec<String>,
    /// Its kind (`store`, `auth`, ...).
    pub kind: String,
    /// Every word a configuration's `module:` may name it by: its manifest name, alias and former
    /// names.
    pub answers_to: Vec<String>,
    /// Its releases.
    pub releases: Vec<IndexRelease>,
}

/// One release of an [`IndexPlugin`].
#[derive(Debug, Clone)]
pub(crate) struct IndexRelease {
    /// The release tag (`v1.6.0`).
    pub tag: String,
    /// The kind ABI version its build states.
    pub abi_version: u32,
}

impl Index {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        use serde_json::Value;
        fn object<'a>(
            v: &'a Value,
            at: &str,
            known: &[&str],
        ) -> Result<&'a serde_json::Map<String, Value>, String> {
            let m = v
                .as_object()
                .ok_or_else(|| format!("{at} is not an object"))?;
            match m.keys().find(|k| !known.contains(&k.as_str())) {
                Some(k) => Err(format!("{at} has the unknown key `{k}`")),
                None => Ok(m),
            }
        }
        fn text(m: &serde_json::Map<String, Value>, k: &str, at: &str) -> Result<String, String> {
            m.get(k)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| format!("{at}.{k} is not a string"))
        }
        fn texts(
            m: &serde_json::Map<String, Value>,
            k: &str,
            at: &str,
        ) -> Result<Vec<String>, String> {
            match m.get(k) {
                None => Ok(Vec::new()),
                Some(Value::Array(a)) => a
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .map(str::to_string)
                            .ok_or_else(|| format!("{at}.{k} holds a non-string"))
                    })
                    .collect(),
                Some(_) => Err(format!("{at}.{k} is not a list")),
            }
        }
        let doc: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        let top = object(&doc, "the index", &[index_field::PLUGINS])?;
        let list = top
            .get(index_field::PLUGINS)
            .and_then(Value::as_array)
            .ok_or_else(|| "the index's plugins is not a list".to_string())?;
        let mut plugins = Vec::new();
        for (i, p) in list.iter().enumerate() {
            let at = format!("plugins[{i}]");
            let m = object(
                p,
                &at,
                &[
                    index_field::REPO,
                    index_field::FORMER_REPOS,
                    index_field::KIND,
                    index_field::ANSWERS_TO,
                    index_field::RELEASES,
                ],
            )?;
            let releases = m
                .get(index_field::RELEASES)
                .and_then(Value::as_array)
                .ok_or_else(|| format!("{at}.releases is not a list"))?
                .iter()
                .enumerate()
                .map(|(j, r)| {
                    let rat = format!("{at}.releases[{j}]");
                    let r = object(r, &rat, &[index_field::TAG, index_field::ABI_VERSION_KEY])?;
                    let abi = r
                        .get(index_field::ABI_VERSION_KEY)
                        .and_then(Value::as_u64)
                        .and_then(|n| u32::try_from(n).ok())
                        .ok_or_else(|| format!("{rat}.abi_version is not a version number"))?;
                    Ok(IndexRelease {
                        tag: text(r, index_field::TAG, &rat)?,
                        abi_version: abi,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            plugins.push(IndexPlugin {
                repo: text(m, index_field::REPO, &at)?,
                former_repos: texts(m, index_field::FORMER_REPOS, &at)?,
                kind: text(m, index_field::KIND, &at)?,
                answers_to: texts(m, index_field::ANSWERS_TO, &at)?,
                releases,
            });
        }
        Ok(Self { plugins })
    }

    fn by_repo(&self, repo: &str) -> Option<&IndexPlugin> {
        let same = |r: &String| r.eq_ignore_ascii_case(repo);
        self.plugins
            .iter()
            .find(|p| same(&p.repo) || p.former_repos.iter().any(same))
    }

    fn by_module(&self, kind: &str, module: &str) -> Option<&IndexPlugin> {
        self.plugins
            .iter()
            .find(|p| p.kind == kind && p.answers_to.iter().any(|w| w == module))
    }
}

impl IndexPlugin {
    #[must_use]
    pub(crate) fn pin_for_this_core(&self) -> Option<String> {
        let speaks = crate::root::loader::registry::supported_abi(&self.kind);
        self.releases
            .iter()
            .filter(|r| speaks == Some(r.abi_version))
            .max_by(|a, b| version_order(&a.tag, &b.tag))
            .map(|r| format!("{}@{}", self.repo, r.tag))
    }
}

fn version_order(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    fn parts(tag: &str) -> Option<([u64; 3], Option<&str>)> {
        let tag = tag.strip_prefix('v').unwrap_or(tag);
        let identifiers = |text: &str| {
            text.split('.').all(|id| {
                !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        };
        let version = if let Some((version, build)) = tag.split_once('+') {
            if !identifiers(build) {
                return None;
            }
            version
        } else {
            tag
        };
        let (core, pre) = version
            .split_once('-')
            .map_or((version, None), |(core, pre)| (core, Some(pre)));
        if let Some(pre) = pre {
            if !identifiers(pre)
                || pre.split('.').any(|id| {
                    id.len() > 1 && id.starts_with('0') && id.bytes().all(|b| b.is_ascii_digit())
                })
            {
                return None;
            }
        }
        let mut numbers = core.split('.');
        let mut core = [0; 3];
        for number in &mut core {
            let text = numbers.next()?;
            if text.is_empty()
                || (text.len() > 1 && text.starts_with('0'))
                || !text.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            *number = text.parse().ok()?;
        }
        numbers.next().is_none().then_some((core, pre))
    }
    let (Some((ac, ap)), Some((bc, bp))) = (parts(a), parts(b)) else {
        return parts(a).is_some().cmp(&parts(b).is_some());
    };
    ac.cmp(&bc).then_with(|| match (ap, bp) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(a), Some(b)) => {
            let mut a = a.split('.');
            let mut b = b.split('.');
            loop {
                let order = match (a.next(), b.next()) {
                    (None, None) => return Ordering::Equal,
                    (None, Some(_)) => return Ordering::Less,
                    (Some(_), None) => return Ordering::Greater,
                    (Some(a), Some(b)) => match (
                        a.bytes().all(|v| v.is_ascii_digit()),
                        b.bytes().all(|v| v.is_ascii_digit()),
                    ) {
                        (true, true) => a.len().cmp(&b.len()).then_with(|| a.cmp(b)),
                        (true, false) => Ordering::Less,
                        (false, true) => Ordering::Greater,
                        (false, false) => a.cmp(b),
                    },
                };
                if order != Ordering::Equal {
                    return order;
                }
            }
        }
    })
}

pub struct RootHost {
    plugins: Option<PluginsCfg>,

    config: PathBuf,
    providers_file: Option<String>,

    local: OnceCell<PluginRegistry>,

    index: OnceCell<Result<Index, Unobtainable>>,
    /// Where the release index is read from: `BUSBAR_PLUGIN_INDEX` if set, else the release default.
    pub(in crate::root) index_source: String,
    /// How the index (over https) and plugin assets are downloaded.
    pub(in crate::root) download: fn(&str) -> Result<Vec<u8>, String>,

    fetched: OnceCell<FetchedDir>,
    startup: Option<std::sync::Arc<crate::root::startup_upgrade::documents::Documents>>,
    templates: busbar_migrations::config::templates::ResolvedTemplates,
    runtime_only: std::cell::Cell<bool>,
    /// The migrated document's `plugins:` block after the structural steps, once bound
    /// ([`MigrateHost::bind_grammar`]); unbound, the block this host was built over.
    bound_plugins: std::cell::RefCell<Option<Option<busbar_contract::yaml::Value>>>,
    /// The grammar computed from that block, until the block is bound again.
    grammar: std::cell::RefCell<Option<Result<busbar_contract::secret_ref::Sugars, String>>>,
}

/// Why a migration validation probe stopped: a declared reference this process cannot resolve.
const UNRESOLVABLE_REFERENCE: &str = "migration validation reference could not be resolved";
const STAGING_RANDOM_BYTES: usize = 16;
const STAGING_DIRECTORY_PREFIX: &str = "busbar-migrate-";
#[cfg(unix)]
const STAGING_DIRECTORY_MODE: u32 = 0o700;

struct FetchedDir(PathBuf);

impl FetchedDir {
    fn create_in(parent: &Path) -> std::io::Result<Self> {
        loop {
            let mut random = [0_u8; STAGING_RANDOM_BYTES];
            busbar_contract::crypto::fill(&mut random)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let path = parent.join(format!("{STAGING_DIRECTORY_PREFIX}{}", hex::encode(random)));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(STAGING_DIRECTORY_MODE);
            }
            match builder.create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
    }
}

impl Drop for FetchedDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl RootHost {
    fn validation_probe(
        &self,
        settings: &serde_json::Value,
        statement: &busbar_contract::abi::mechanism::rendering::Read,
    ) -> Result<Option<busbar_contract::abi::sdk::cred::SettingsValue>, String> {
        use busbar_contract::secret_fields;
        let reference = statement.reference_fields()?;
        if secret_fields::contradiction(&statement.secret_refs, &reference).is_some() {
            return Err("migration validation reference declarations contradict".into());
        }
        let allowed = [statement.secret_refs.as_slice(), reference.as_slice()].concat();
        let sources = self.source_declarations()?;
        let mut probe = busbar_contract::abi::sdk::cred::SettingsValue::from(
            busbar_migrations::config::templates::resolved_settings(settings, self)?,
        );
        // The admitted source shorthand (`{env:}`, `{file:}`, …) is a reference here exactly as
        // it is to boot's settings resolution; otherwise a declared reference would reach the
        // plugin's VALIDATE as an object and invent a migration decision.
        busbar_contract::plugin_settings::canonicalize(
            probe.pointer_mut("").expect("the JSON document has a root"),
            &sources,
        )
        .map_err(|_| "migration validation reference shorthand is invalid")?;
        if secret_fields::undeclared_reference(&probe, &allowed).is_some() {
            return Err("migration validation contains an undeclared settings reference".into());
        }
        let mut staged = Vec::new();
        if let Some(documents) = &self.startup {
            for secret in documents.pending_secrets()? {
                // Reuse the artifact owner's normalized source identity. No
                // pending file is read or materialized before native commit.
                let here = crate::root::loader::migration_secrets::externalized_path(
                    &self.config,
                    &secret.site,
                    &secret.settings_path,
                )?;
                let original = crate::root::loader::migration_secrets::externalized_path(
                    &secret.config_path,
                    &secret.site,
                    &secret.settings_path,
                )?;
                if here == original && original == secret.path {
                    staged.push(secret);
                }
            }
        }
        let scope = busbar_contract::config_time::ConfigScope::config_time();
        let mut unresolvable = false;
        // Both declared path classes reach VALIDATE as scalars. Resolution is
        // confined to this wiping probe; authored references and the plugin's
        // actual secret/reference classifications remain unchanged.
        let resolved = secret_fields::resolve_references(
            probe.pointer_mut("").expect("the JSON document has a root"),
            &[],
            &allowed,
            |_, reference| {
                let source =
                    sources.with_role(busbar_contract::abi::mechanism::door::SUGAR_ROLE_PATH);
                if let Some(secret) = staged.iter().find(|secret| {
                    source
                        .zip(secret.path.to_str())
                        .is_some_and(|(source, path)| reference == &source.reference(path))
                }) {
                    let text = std::str::from_utf8(&secret.bytes)
                        .map_err(|_| "staged migration validation reference is not UTF-8")?;
                    if text.is_empty() {
                        return Err("staged migration validation reference is empty".into());
                    }
                    return Ok(text.to_owned());
                }
                match busbar_kernel::config::secret::resolve_linked_string_at_config(
                    reference, &scope,
                ) {
                    Ok(value) => Ok(value.into_exposed(&busbar_kernel::seal::lend())),
                    Err(_) => {
                        unresolvable = true;
                        Err(UNRESOLVABLE_REFERENCE.into())
                    }
                }
            },
        );
        match resolved {
            Ok(()) => Ok(Some(probe)),
            // A declared reference whose source this process cannot read (an unset variable,
            // a file only the serving host has) is not a decision for the operator: the
            // settings cannot be judged here, so judging them is left to the boot reader,
            // which resolves and validates them and refuses an unresolvable reference itself.
            Err(_) if unresolvable => Ok(None),
            Err(error) => Err(error),
        }
    }
    #[must_use]
    pub(crate) fn for_document(raw: &str, config: &std::path::Path) -> Self {
        use busbar_contract::yaml::ValueExt;
        let doc = busbar_contract::yaml::from_str::<busbar_contract::yaml::Value>(raw).ok();
        let plugins = doc
            .as_ref()
            .and_then(|doc| doc.get(CONFIG_PLUGINS_KEY).cloned())
            .and_then(|p| busbar_contract::yaml::from_value::<PluginsCfg>(p).ok());
        let providers_file = doc
            .as_ref()
            .and_then(|doc| doc.get(CONFIG_PROVIDERS_FILE_KEY))
            .and_then(|f| f.as_str())
            .map(str::to_string);
        Self {
            plugins,
            config: config.to_path_buf(),
            providers_file,
            local: OnceCell::new(),
            index: OnceCell::new(),
            index_source: std::env::var(INDEX_ENV).unwrap_or_else(|_| default_index()),
            download: release_download,
            fetched: OnceCell::new(),
            startup: None,
            templates: Default::default(),
            runtime_only: std::cell::Cell::new(false),
            bound_plugins: std::cell::RefCell::new(None),
            grammar: std::cell::RefCell::new(None),
        }
    }

    /// Startup keeps authored-document replacements and protected artifact intents in custody.
    pub(super) fn for_startup_document(
        raw: &str,
        detection: &str,
        config: &Path,
        documents: std::sync::Arc<crate::root::startup_upgrade::documents::Documents>,
    ) -> Result<Self, String> {
        let mut host = Self::for_document(detection, config);
        host.templates =
            busbar_migrations::config::templates::ResolvedTemplates::from_yaml(raw, detection)?;
        host.startup = Some(documents);
        Ok(host)
    }

    /// Frozen Store JSON has already been authored/resolved by its historical
    /// writer. Keep retained config/catalog/plugin custody, without treating any
    /// coincident `${VAR}` data as an authored YAML substitution.
    pub(super) fn for_frozen_overlay(
        raw: &str,
        detection: &str,
        config: &Path,
        documents: std::sync::Arc<crate::root::startup_upgrade::documents::Documents>,
    ) -> Result<Self, String> {
        let mut host = Self::for_startup_document(raw, detection, config, documents)?;
        host.templates = Default::default();
        Ok(host)
    }

    pub(super) fn runtime_only(&self) -> bool {
        self.runtime_only.get()
    }

    /// The migration's grammar: phase 1 over the bound block (interpolated, then read as the
    /// current `plugins:` shape), else over the block this host was built over. A bound block
    /// that still does not read refuses, naming it; no smaller grammar stands in.
    fn migration_grammar(&self) -> Result<busbar_contract::secret_ref::Sugars, String> {
        let plugins = match self.bound_plugins.borrow().as_ref() {
            None => self.plugins.clone().unwrap_or_default(),
            Some(None) => PluginsCfg::default(),
            Some(Some(block)) => {
                let text = busbar_contract::yaml::to_string(block)
                    .map_err(|_| "plugins: the migrated block could not be encoded".to_owned())?;
                let text = busbar_kernel::config::interpolate_env_with(
                    &text,
                    busbar_kernel::config::EnvSubst::Lenient,
                    &mut Vec::new(),
                )
                .map_err(|e| format!("plugins: {e}"))?;
                busbar_contract::yaml::from_str::<PluginsCfg>(&text).map_err(|e| {
                    format!(
                        "plugins: the block does not read as the current shape after the \
                         structural migration, so its modules' secret shorthand cannot be read: {e}"
                    )
                })?
            }
        };
        crate::root::boot::phase_one(&busbar_kernel::config::grammar::PhaseOneIn::of(&plugins))
            .map(|grammar| grammar.sugars)
            .map_err(String::from)
    }

    fn migrate_settings(
        &self,
        kind: &str,
        module: &str,
        settings: &serde_json::Value,
        from: &str,
        references: bool,
    ) -> Result<Option<(String, MigrationAnswer)>, String> {
        use crate::root::loader::dispatch::{
            load::raw,
            migrate::{migrate_door, migrate_references_door},
        };
        let migrate = if references {
            migrate_references_door
        } else {
            migrate_door
        };
        if let Some((name, door)) = Self::linked_door(kind, module) {
            return Ok(migrate(raw(door), settings, from)?.map(|m| (name, m)));
        }

        if kind == busbar_contract::abi::mechanism::kind::PLANE {
            return Ok(None);
        }
        let local = self.local();
        if let Some(row) = local.resolve(module).filter(|r| r.manifest.kind == kind) {
            let answer = if references {
                row.migrate_references(settings, from)
            } else {
                row.migrate(settings, from)
            }?;
            return Ok(answer.map(|m| (row.manifest.name.clone(), m)));
        }

        let Ok(fetched) = self.fetch(kind, module) else {
            return Ok(None);
        };
        let Some(row) = fetched.resolve(module).filter(|r| r.manifest.kind == kind) else {
            return Ok(None);
        };
        let answer = if references {
            row.migrate_references(settings, from)
        } else {
            row.migrate(settings, from)
        }?;
        Ok(answer.map(|m| (row.manifest.name.clone(), m)))
    }

    fn catalog_source(
        &self,
    ) -> Result<Option<(PathBuf, busbar_contract::secure::SecureString)>, String> {
        if let Some(documents) = &self.startup {
            match documents.original_provider()? {
                Some((path, Some(raw))) => return Ok(Some((path, raw))),
                // The retained default catalog is absent, as a NotFound read below reports it.
                Some((_, None)) => return Ok(None),
                None => {}
            }
        }
        let (_, path) = self.catalog_path();
        match std::fs::read_to_string(&path) {
            Ok(raw) => Ok(Some((
                path,
                busbar_contract::secure::SecureString::from(raw),
            ))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) if self.startup.is_some() => {
                Err("original providers source could not be read".into())
            }
            Err(_) => Ok(None),
        }
    }

    fn linked() -> Vec<crate::root::loader::LinkedPlugin> {
        let mut rows: Vec<_> = busbar_kernel::preflight::linked_rows()
            .iter()
            .map(crate::root::boot::linked_row)
            .collect();
        if let Ok(exports) = crate::root::linked::linked_exports(crate::LINKED.export_doors) {
            rows.extend(exports);
        }
        rows
    }

    fn local(&self) -> &PluginRegistry {
        self.local.get_or_init(|| {
            let scanned = self.plugins.as_ref().filter(|p| p.enabled).and_then(|p| {
                crate::root::boot::registry(Self::linked(), Some(p), None, &mut |_| {}).ok()
            });
            scanned.unwrap_or_else(|| {
                crate::root::boot::registry(Self::linked(), None, None, &mut |_| {})
                    .unwrap_or_else(|_| PluginRegistry::empty())
            })
        })
    }

    fn index(&self) -> Result<&Index, Unobtainable> {
        self.index
            .get_or_init(|| {
                let source = &self.index_source;
                // The reader's text echoes the source (credentials, signed queries): drop it and
                // show only what `Shown` keeps.
                let unreachable = |_: String| Unobtainable::IndexUnreachable {
                    source: Shown::of(source),
                };
                let bytes = if source.starts_with(HTTPS_SOURCE_PREFIX)
                    || source.starts_with(HTTP_SOURCE_PREFIX)
                {
                    (self.download)(source).map_err(unreachable)?
                } else {
                    std::fs::read(source).map_err(|_| Unobtainable::IndexUnreachable {
                        source: Shown::of(source),
                    })?
                };
                Index::parse(&bytes).map_err(|_| Unobtainable::NotAnIndex {
                    source: Shown::of(source),
                })
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    fn linked_door(
        kind: &str,
        module: &str,
    ) -> Option<(String, busbar_contract::abi::mechanism::door::DoorFn)> {
        match kind {
            busbar_contract::abi::mechanism::kind::PLANE => {
                let section = busbar_kernel::plane_driver::registry::plane_decls()
                    .iter()
                    .find(|d| d.key == module)
                    .map(|d| d.config_section)?;
                crate::LINKED
                    .plane_doors
                    .iter()
                    .find(|door| {
                        crate::root::loader::boot::Candidate::linked(**door)
                            .is_ok_and(|c| c.verbs.iter().any(|v| v == section))
                    })
                    .map(|door| (module.to_string(), *door))
            }

            busbar_contract::abi::mechanism::kind::HOOK
            | busbar_contract::abi::mechanism::kind::SECRET => {
                let doors = if kind == busbar_contract::abi::mechanism::kind::HOOK {
                    crate::LINKED.hook_doors
                } else {
                    crate::LINKED.secrets
                };
                doors.iter().find_map(|door| {
                    let c = crate::root::loader::boot::Candidate::linked(*door).ok()?;
                    (c.name == module || c.aliases.iter().any(|a| a == module))
                        .then(|| (c.name.clone(), *door))
                })
            }
            _ => None,
        }
    }

    fn served(&self, kind: &str, module: &str) -> bool {
        Self::linked_door(kind, module).is_some() || self.local().answers(module, kind)
    }

    /// Obtain the current plugin for `kind`/`module` from the release index. Each failure is a
    /// closed [`Unobtainable`]; no downloader, reader or registry text is carried.
    fn fetch(&self, kind: &str, module: &str) -> Result<PluginRegistry, Unobtainable> {
        let index = self.index()?;
        let plugin = index
            .by_module(kind, module)
            .ok_or_else(|| Unobtainable::NoSuchPlugin {
                source: Shown::of(&self.index_source),
            })?;
        let pin = plugin
            .pin_for_this_core()
            .ok_or_else(|| Unobtainable::NoReleaseForAbi {
                repo: Shown::of(&plugin.repo),
            })?;
        let target = crate::root::plugin_fetch::release_asset(&pin).ok_or(Unobtainable::BadPin)?;
        if self.fetched.get().is_none() {
            let dir =
                FetchedDir::create_in(&std::env::temp_dir()).map_err(|_| Unobtainable::Staging)?;
            let _ = self.fetched.set(dir);
        }
        let dir = &self
            .fetched
            .get()
            .expect("the staging directory was created")
            .0;
        let bytes = (self.download)(&target.url).map_err(|_| Unobtainable::AssetUnreachable {
            asset: Shown::of(&target.url),
        })?;
        std::fs::write(dir.join(&target.filename), bytes).map_err(|_| Unobtainable::Staging)?;
        let mut cfg = self.plugins.clone().unwrap_or_default();
        cfg.enabled = true;
        cfg.dir = dir.display().to_string();
        crate::root::boot::registry(Vec::new(), Some(&cfg), None, &mut |_| {})
            .map_err(|_| Unobtainable::NotAdmitted)
    }

    /// Check converted settings with the current plugin, keeping apart a plugin the host could
    /// not obtain from one that refused them.
    fn check(&self, kind: &str, module: &str, settings: &serde_json::Value) -> Result<(), Checked> {
        // Planes receive an owned-plus-borrowed migration envelope, not their lifecycle
        // settings blob. Full effective plane validation remains the ordinary boot reader's.
        if kind == busbar_contract::abi::mechanism::kind::PLANE
            || (kind == busbar_contract::abi::mechanism::kind::AUTH
                && busbar_kernel::config::is_builtin_identity_module(module))
        {
            return Ok(());
        }
        let refused = |text: &str| Checked::Refused(text.to_owned());
        if let Some((_, door)) = Self::linked_door(kind, module) {
            let row = crate::root::loader::dispatch::LinkedRow::of(door)
                .map_err(|_| refused("current migration plugin statement is unavailable"))?;
            let statement = busbar_contract::abi::mechanism::rendering::read(&row.statement)
                .map_err(|_| refused("current migration plugin statement is invalid"))?;
            let Some(probe) = self
                .validation_probe(settings, &statement)
                .map_err(Checked::Refused)?
            else {
                return Ok(());
            };
            return crate::root::loader::dispatch::migrate::validate_migrated_door(
                crate::root::loader::dispatch::load::raw(door),
                &*probe,
            )
            .map_err(Checked::Refused);
        }
        let local = self.local();
        if let Some(row) = local
            .resolve(module)
            .filter(|row| row.manifest.kind == kind)
        {
            let statement = row
                .statement()
                .ok_or_else(|| refused("current migration plugin statement is unavailable"))?;
            let statement = busbar_contract::abi::mechanism::rendering::read(&statement)
                .map_err(|_| refused("current migration plugin statement is invalid"))?;
            let Some(probe) = self
                .validation_probe(settings, &statement)
                .map_err(Checked::Refused)?
            else {
                return Ok(());
            };
            return row.validate_migrated(&probe).map_err(Checked::Refused);
        }
        let fetched = self.fetch(kind, module).map_err(Checked::Unavailable)?;
        let row = fetched
            .resolve(module)
            .filter(|row| row.manifest.kind == kind)
            .ok_or(Checked::Unavailable(Unobtainable::NotServed))?;
        let statement = row
            .statement()
            .ok_or_else(|| refused("current migration plugin statement is unavailable"))?;
        let statement = busbar_contract::abi::mechanism::rendering::read(&statement)
            .map_err(|_| refused("current migration plugin statement is invalid"))?;
        let Some(probe) = self
            .validation_probe(settings, &statement)
            .map_err(Checked::Refused)?
        else {
            return Ok(());
        };
        row.validate_migrated(&probe).map_err(Checked::Refused)
    }
}

/// A current-plugin check that did not pass: the plugin could not be obtained, or it (or the
/// host's probe of its statement) refused the settings with this text.
enum Checked {
    Unavailable(Unobtainable),
    Refused(String),
}

impl RootHost {
    fn catalog_path(&self) -> (PathBuf, PathBuf) {
        let dir = self
            .config
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_default();
        let path = dir.join(
            self.providers_file
                .as_deref()
                .unwrap_or(DEFAULT_PROVIDERS_CATALOG),
        );
        (dir, path)
    }
}

impl MigrateHost for RootHost {
    /// Phase 1 over the migrated document's own `plugins:` block (SECRET-SHORTHAND-BOOT §3.13,
    /// F4): a dropped-in module that block admits declares words here exactly as the boot reader
    /// will read them, whatever the live axis holds. Computed once per bound block.
    fn source_declarations(&self) -> Result<busbar_contract::secret_ref::Sugars, String> {
        if let Some(grammar) = self.grammar.borrow().as_ref() {
            return grammar.clone();
        }
        let grammar = self.migration_grammar();
        *self.grammar.borrow_mut() = Some(grammar.clone());
        grammar
    }

    fn bind_grammar(&self, plugins: Option<&busbar_contract::yaml::Value>) {
        *self.bound_plugins.borrow_mut() = Some(plugins.cloned());
        *self.grammar.borrow_mut() = None;
    }

    fn admit_config_profile(
        &self,
        proof: &busbar_migrations::config::HistoricalConfigProof,
    ) -> Result<(), String> {
        if let Some(documents) = &self.startup {
            documents.admit_config_profile(proof)?;
        }
        Ok(())
    }

    fn resolved_authored_scalar(
        &self,
        template: &str,
    ) -> Result<Option<serde_json::Value>, String> {
        self.templates.scalar(template)
    }

    fn plane_selecting_sections(&self, module: &str) -> Vec<String> {
        crate::root::boot::DOOR_CANDIDATES
            .get()
            .into_iter()
            .flatten()
            .find(|candidate| candidate.name == module)
            .map_or_else(Vec::new, |candidate| candidate.selecting.clone())
    }

    fn validate_migrated(
        &self,
        kind: &str,
        module: &str,
        settings: &serde_json::Value,
    ) -> Result<(), String> {
        self.check(kind, module, settings)
            .map_err(|answer| match answer {
                Checked::Unavailable(Unobtainable::NotServed) => {
                    "current migration plugin is unavailable for validation".to_owned()
                }
                Checked::Unavailable(why) => why.to_string(),
                Checked::Refused(text) => text,
            })
    }

    fn validate_current(
        &self,
        kind: &str,
        module: &str,
        settings: &serde_json::Value,
    ) -> Result<(), Unvalidated> {
        // The plugin's own refusal text may echo settings: it is never carried.
        self.check(kind, module, settings)
            .map_err(|answer| match answer {
                Checked::Unavailable(why) => Unvalidated::Unavailable(why),
                Checked::Refused(_) => Unvalidated::Refused,
            })
    }

    fn externalize_secret(
        &self,
        site: &str,
        path: &[String],
        bytes: &[u8],
    ) -> Result<String, String> {
        if let Some(documents) = &self.startup {
            let output = crate::root::loader::migration_secrets::externalized_path(
                &self.config,
                site,
                path,
            )?;
            return documents.stage_secret(
                crate::root::startup_upgrade::documents::SecretPublication {
                    config_path: self.config.clone(),
                    site: site.to_owned(),
                    settings_path: path.to_vec(),
                    bytes: busbar_contract::secure::SecureVec::from(bytes),
                    path: output,
                },
            );
        }
        crate::root::migration_secrets::externalize(&self.config, site, path, bytes)
    }

    fn migrate(
        &self,
        kind: &str,
        module: &str,
        settings: &serde_json::Value,
        from: &str,
    ) -> Result<Option<(String, MigrationAnswer)>, String> {
        match self.migrate_settings(kind, module, settings, from, false) {
            Ok(value) => Ok(value),
            Err(error) => {
                let resolved =
                    busbar_migrations::config::templates::resolved_settings(settings, self)?;
                if &resolved == settings || self.startup.is_none() {
                    return Err(error);
                }
                // One registered converter sees the actual resolved legacy input. Do not
                // infer arithmetic from differential probes or persist a frozen env value.
                let converted = self.migrate_settings(kind, module, &resolved, from, false)?;
                if converted.is_some() {
                    self.runtime_only.set(true);
                }
                Ok(converted)
            }
        }
    }

    fn migrate_references(
        &self,
        kind: &str,
        module: &str,
        settings: &serde_json::Value,
        from: &str,
    ) -> Result<Option<(String, MigrationAnswer)>, String> {
        self.migrate_settings(kind, module, settings, from, true)
    }

    fn repin(&self, github: &str) -> Result<Option<String>, String> {
        let Some((repo, _)) = github.split_once('@') else {
            return Ok(None);
        };

        let Ok(index) = self.index() else {
            return Ok(None);
        };
        Ok(index
            .by_repo(repo)
            .and_then(IndexPlugin::pin_for_this_core)
            .filter(|pin| pin != github))
    }

    fn rewrite_catalog(&self) -> Result<Option<(String, Vec<String>)>, String> {
        let (dir, _) = self.catalog_path();
        let Some((path, raw)) = self.catalog_source()? else {
            return Ok(None);
        };
        let shown = path.display().to_string();
        let Some(mut m) =
            busbar_migrations::config::migrate_catalog::migrate_catalog(&raw, &shown)?
        else {
            return Ok(None);
        };
        if let Some(documents) = &self.startup {
            let staged = documents.stage_catalog(&path, &raw, &m.yaml);
            m.yaml.zeroize();
            m.changes.zeroize();
            staged?;
            // The source path is retained; startup publishes this same document only after validation.
            return Ok(None);
        }
        let stem = path.file_stem().map_or_else(
            || UNNAMED_PROVIDERS_CATALOG_STEM.into(),
            |s| s.to_string_lossy().into_owned(),
        );
        let out = path.with_file_name(format!("{stem}.migrated.yaml"));
        std::fs::write(&out, &m.yaml).map_err(|e| format!("{}: {e}", out.display()))?;

        let file = match out.strip_prefix(&dir) {
            Ok(rel) if !dir.as_os_str().is_empty() => rel.display().to_string(),
            _ => out.display().to_string(),
        };
        Ok(Some((file, m.changes)))
    }

    fn providers_catalog(
        &self,
    ) -> Result<Option<serde_json::Map<String, serde_json::Value>>, String> {
        let Some((path, raw)) = self.catalog_source()? else {
            return Ok(None);
        };
        let shown = path.display();
        match busbar_contract::yaml::from_str::<serde_json::Value>(&raw) {
            Ok(serde_json::Value::Object(entries)) => Ok(Some(entries)),
            Ok(serde_json::Value::Null) => Ok(None),
            Ok(_) => Err(format!("{shown}: not a map of providers")),
            Err(_) if self.startup.is_some() => {
                Err("original providers source is invalid YAML".into())
            }
            Err(e) => Err(format!("{shown}: {e}")),
        }
    }

    fn migrate_credential(
        &self,
        module: &str,
        credential: &busbar_contract::secret_ref::SecretRef,
        from: &str,
    ) -> Result<Option<busbar_contract::secret_ref::SecretRef>, String> {
        let scope = busbar_contract::config_time::ConfigScope::config_time();
        let resolved =
            busbar_kernel::config::secret::resolve_linked_string_at_config(credential, &scope)
                .map_err(|_| "the original credential source could not be resolved".to_string())?;
        let seal = busbar_kernel::seal::lend();
        let local = self.local();
        let answer = if let Some(row) = local
            .resolve(module)
            .filter(|row| row.manifest.kind == busbar_contract::abi::mechanism::kind::AUTH)
        {
            row.migrate_credential(&resolved, from, &seal)?
        } else {
            let fetched = self
                .fetch(busbar_contract::abi::mechanism::kind::AUTH, module)
                .map_err(|_| "credential migration owner is unavailable")?;
            let row = fetched
                .resolve(module)
                .filter(|row| row.manifest.kind == busbar_contract::abi::mechanism::kind::AUTH)
                .ok_or("credential migration owner is unavailable")?;
            row.migrate_credential(&resolved, from, &seal)?
        };
        answer.into_reference(&self.source_declarations()?)
    }

    fn resolve(&self, host: &str) -> Result<Vec<std::net::IpAddr>, String> {
        use std::net::ToSocketAddrs;
        (host, 0)
            .to_socket_addrs()
            .map(|a| a.map(|s| s.ip()).collect())
            .map_err(|e| e.to_string())
    }

    fn release_for(&self, kind: &str, module: &str) -> Result<Option<String>, String> {
        if kind == busbar_contract::abi::mechanism::kind::PLANE || self.served(kind, module) {
            return Ok(None);
        }

        let Ok(index) = self.index() else {
            return Ok(None);
        };
        Ok(index
            .by_module(kind, module)
            .and_then(IndexPlugin::pin_for_this_core))
    }
}

#[cfg(test)]
#[path = "tests/config_migrate.rs"]
mod tests;
