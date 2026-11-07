// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::cell::OnceCell;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use busbar_contract::abi::sdk::migrate::Migrated;
use busbar_kernel::config::PluginsCfg;
use busbar_migrations::config::migrate_plugins::MigrateHost;

use crate::root::loader::PluginRegistry;

#[path = "migrate_environment.rs"]
mod environment;
pub(super) use environment::capture as capture_environment;

mod index_field {
    pub const PLUGINS: &str = "plugins";
    pub const REPO: &str = "repo";
    pub const FORMER_REPOS: &str = "former_repos";
    pub const KIND: &str = "kind";
    pub const ANSWERS_TO: &str = "answers_to";
    pub const RELEASES: &str = "releases";
    pub const TAG: &str = "tag";
    pub const ABI_VERSION: &str = "abi_version";
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

pub const INDEX_ENV: &str = "BUSBAR_PLUGIN_INDEX";

/// THE RELEASE INDEX: every plugin the index knows, each with its repository, the repositories it
/// was published from before, its kind, the words a configuration may name it by, and its
/// releases with the ABI version each was built for.
#[derive(Debug, Clone, Default)]
pub struct Index {
    /// The plugins.
    pub plugins: Vec<IndexPlugin>,
}

/// One plugin in the [`Index`].
#[derive(Debug, Clone)]
pub struct IndexPlugin {
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
pub struct IndexRelease {
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
                    let r = object(r, &rat, &[index_field::TAG, index_field::ABI_VERSION])?;
                    let abi = r
                        .get(index_field::ABI_VERSION)
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
    pub fn pin_for_this_core(&self) -> Option<String> {
        let speaks = crate::root::loader::registry::supported_abi(&self.kind);
        self.releases
            .iter()
            .filter(|r| speaks.contains(&r.abi_version))
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

    index: OnceCell<Result<Index, String>>,

    fetched: OnceCell<FetchedDir>,
    startup: Option<std::sync::Arc<crate::root::startup_upgrade::documents::Documents>>,
    templates: busbar_migrations::config::templates::ResolvedTemplates,
    runtime_only: std::cell::Cell<bool>,
}

const STAGING_RANDOM_BYTES: usize = 16;
const STAGING_DIRECTORY_PREFIX: &str = "busbar-migrate-";
#[cfg(unix)]
const STAGING_DIRECTORY_MODE: u32 = 0o700;

struct FetchedDir(PathBuf);

impl FetchedDir {
    fn create_in(parent: &Path) -> std::io::Result<Self> {
        loop {
            let mut random = [0_u8; STAGING_RANDOM_BYTES];
            getrandom::fill(&mut random)
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
    #[must_use]
    pub fn for_document(raw: &str, config: &std::path::Path) -> Self {
        let doc = serde_yaml::from_str::<serde_yaml::Value>(raw).ok();
        let plugins = doc
            .as_ref()
            .and_then(|doc| doc.get(CONFIG_PLUGINS_KEY).cloned())
            .and_then(|p| serde_yaml::from_value::<PluginsCfg>(p).ok());
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
            fetched: OnceCell::new(),
            startup: None,
            templates: Default::default(),
            runtime_only: std::cell::Cell::new(false),
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

    fn migrate_settings(
        &self,
        kind: &str,
        module: &str,
        settings: &serde_json::Value,
        from: &str,
    ) -> Result<Option<(String, Migrated)>, String> {
        use crate::root::loader::dispatch::{load::raw, migrate::migrate_door};
        if let Some((name, door)) = Self::linked_door(kind, module) {
            return Ok(migrate_door(raw(door), settings, from)?.map(|m| (name, m)));
        }

        if kind == busbar_contract::abi::mechanism::kind::PLANE {
            return Ok(None);
        }
        let local = self.local();
        if let Some(row) = local.resolve(module).filter(|r| r.manifest.kind == kind) {
            return Ok(row
                .migrate(settings, from)?
                .map(|m| (row.manifest.name.clone(), m)));
        }

        let Ok(fetched) = self.fetch(kind, module) else {
            return Ok(None);
        };
        let Some(row) = fetched.resolve(module).filter(|r| r.manifest.kind == kind) else {
            return Ok(None);
        };
        Ok(row
            .migrate(settings, from)?
            .map(|m| (row.manifest.name.clone(), m)))
    }

    fn catalog_source(&self) -> Result<Option<(PathBuf, zeroize::Zeroizing<String>)>, String> {
        if let Some(documents) = &self.startup {
            if let Some(source) = documents.original_provider()? {
                return Ok(Some(source));
            }
        }
        let (_, path) = self.catalog_path();
        match std::fs::read_to_string(&path) {
            Ok(raw) => Ok(Some((path, zeroize::Zeroizing::new(raw)))),
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

    fn index(&self) -> Result<&Index, String> {
        self.index
            .get_or_init(|| {
                let source = std::env::var(INDEX_ENV).unwrap_or_else(|_| default_index());
                let bytes = if source.starts_with(HTTPS_SOURCE_PREFIX)
                    || source.starts_with(HTTP_SOURCE_PREFIX)
                {
                    crate::root::plugin_fetch::downloader(&[])(&source)?
                } else {
                    std::fs::read(&source).map_err(|e| format!("{source}: {e}"))?
                };
                Index::parse(&bytes).map_err(|e| format!("{source}: not a release index: {e}"))
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

    fn fetch(&self, kind: &str, module: &str) -> Result<PluginRegistry, String> {
        let index = self.index()?;
        let plugin = index
            .by_module(kind, module)
            .ok_or_else(|| "the release index names no such plugin".to_string())?;
        let pin = plugin.pin_for_this_core().ok_or_else(|| {
            format!(
                "the release index names no release of {} built for this busbar",
                plugin.repo
            )
        })?;
        let target = crate::root::plugin_fetch::release_asset(&pin)
            .ok_or_else(|| format!("'{pin}' is not an org/repo@tag pin"))?;
        if self.fetched.get().is_none() {
            let dir = FetchedDir::create_in(&std::env::temp_dir())
                .map_err(|e| format!("creating migration staging directory: {e}"))?;
            let _ = self.fetched.set(dir);
        }
        let dir = &self
            .fetched
            .get()
            .expect("the staging directory was created")
            .0;
        let bytes = crate::root::plugin_fetch::downloader(&[])(&target.url)
            .map_err(|e| format!("downloading {}: {e}", target.url))?;
        std::fs::write(dir.join(&target.filename), bytes)
            .map_err(|e| format!("{}: {e}", dir.display()))?;
        let mut cfg = self.plugins.clone().unwrap_or_default();
        cfg.enabled = true;
        cfg.dir = dir.display().to_string();
        crate::root::boot::registry(Vec::new(), Some(&cfg), None, &mut |_| {})
    }
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
        // Planes receive an owned-plus-borrowed migration envelope, not their lifecycle
        // settings blob. Full effective plane validation remains the ordinary boot reader's.
        if kind == busbar_contract::abi::mechanism::kind::PLANE
            || (kind == busbar_contract::abi::mechanism::kind::AUTH
                && busbar_kernel::config::is_builtin_identity_module(module))
        {
            return Ok(());
        }
        let resolved = busbar_migrations::config::templates::resolved_settings(settings, self)?;
        let settings = &resolved;
        if let Some((_, door)) = Self::linked_door(kind, module) {
            return crate::root::loader::dispatch::migrate::validate_migrated_door(
                crate::root::loader::dispatch::load::raw(door),
                settings,
            );
        }
        let local = self.local();
        if let Some(row) = local
            .resolve(module)
            .filter(|row| row.manifest.kind == kind)
        {
            return row.validate_migrated(settings);
        }
        let fetched = self.fetch(kind, module)?;
        let row = fetched
            .resolve(module)
            .filter(|row| row.manifest.kind == kind)
            .ok_or("current migration plugin is unavailable for validation")?;
        row.validate_migrated(settings)
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
                    bytes: zeroize::Zeroizing::new(bytes.to_vec()),
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
    ) -> Result<Option<(String, Migrated)>, String> {
        match self.migrate_settings(kind, module, settings, from) {
            Ok(value) => Ok(value),
            Err(error) => {
                let resolved =
                    busbar_migrations::config::templates::resolved_settings(settings, self)?;
                if &resolved == settings || self.startup.is_none() {
                    return Err(error);
                }
                // One registered converter sees the actual resolved legacy input. Do not
                // infer arithmetic from differential probes or persist a frozen env value.
                let converted = self.migrate_settings(kind, module, &resolved, from)?;
                if converted.is_some() {
                    self.runtime_only.set(true);
                }
                Ok(converted)
            }
        }
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
        match serde_yaml::from_str::<serde_json::Value>(&raw) {
            Ok(serde_json::Value::Object(entries)) => Ok(Some(entries)),
            Ok(serde_json::Value::Null) => Ok(None),
            Ok(_) => Err(format!("{shown}: not a map of providers")),
            Err(_) if self.startup.is_some() => {
                Err("original providers source is invalid YAML".into())
            }
            Err(e) => Err(format!("{shown}: {e}")),
        }
    }

    fn legacy_jwt_credential_file(
        &self,
        credential: &busbar_contract::secret_ref::SecretRef,
    ) -> Result<Option<busbar_contract::secret_ref::SecretRef>, String> {
        let scope = busbar_contract::config_time::ConfigScope::config_time();
        let resolved =
            busbar_kernel::config::secret::resolve_linked_string_at_config(credential, &scope)
                .map_err(|_| "the original credential source could not be resolved".to_string())?;
        let cwd = std::env::current_dir()
            .map_err(|_| "the original process working directory is unavailable".to_string())?;
        legacy_jwt_file_reference(resolved.expose(&busbar_kernel::seal::lend()), &cwd)
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

/// 1.5.5 resolved the outer SecretRef as text (trimming trailing CR/LF), then
/// read a non-JSON credential as an exact path relative to the process cwd, not
/// the config or providers catalog directory. Keep that distinction on output.
fn legacy_jwt_file_reference(
    credential: &str,
    cwd: &Path,
) -> Result<Option<busbar_contract::secret_ref::SecretRef>, String> {
    if credential.trim_start().starts_with('{') {
        return Ok(None);
    }
    if credential.is_empty() {
        return Err("the original credential is empty".into());
    }
    let path = cwd.join(credential);
    let path_text = path
        .to_str()
        .ok_or("the credential filename is not UTF-8")?;
    // Verify the filename before making it public configuration. An arbitrary
    // non-JSON secret must not accidentally become a path in migrated YAML.
    let content = busbar_contract::redacted::Secret::new(
        std::fs::read(&path).map_err(|_| "the original credential file could not be read")?,
    );
    let seal = busbar_kernel::seal::lend();
    let text = std::str::from_utf8(content.expose(&seal))
        .map_err(|_| "the original credential file is not JSON")?;
    if !text.trim_start().starts_with('{')
        || serde_json::from_str::<serde::de::IgnoredAny>(text).is_err()
    {
        return Err("the original credential file is not JSON".into());
    }
    Ok(Some(busbar_contract::secret_ref::SecretRef::file(
        path_text,
    )))
}

#[cfg(test)]
#[path = "tests/config_migrate.rs"]
mod tests;
