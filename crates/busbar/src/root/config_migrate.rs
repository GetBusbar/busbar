// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::cell::OnceCell;
use std::path::{Path, PathBuf};

use busbar_contract::abi::sdk::migrate::Migrated;
use busbar_kernel::config::migrate_plugins::MigrateHost;
use busbar_kernel::config::PluginsCfg;

use crate::root::loader::PluginRegistry;

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
        let path = crate::root::cli::value_flag(
            std::env::args().skip(1),
            crate::root::cli::OPTION_PROVIDERS,
            None,
        )
        .or_else(|| {
            std::env::var(busbar_kernel::ENV_PROVIDERS)
                .ok()
                .filter(|v| !v.is_empty())
        })
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            dir.join(
                self.providers_file
                    .as_deref()
                    .unwrap_or(DEFAULT_PROVIDERS_CATALOG),
            )
        });
        (dir, path)
    }
}

impl MigrateHost for RootHost {
    fn migrate(
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
        let (dir, path) = self.catalog_path();
        let Ok(raw) = std::fs::read_to_string(&path) else {
            return Ok(None);
        };
        let shown = path.display().to_string();
        let Some(m) = busbar_kernel::config::migrate_catalog::migrate_catalog(&raw, &shown)? else {
            return Ok(None);
        };
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
        let (_, path) = self.catalog_path();

        let Ok(raw) = std::fs::read_to_string(&path) else {
            return Ok(None);
        };
        let shown = path.display();
        match serde_yaml::from_str::<serde_json::Value>(&raw) {
            Ok(serde_json::Value::Object(entries)) => Ok(Some(entries)),
            Ok(serde_json::Value::Null) => Ok(None),
            Ok(_) => Err(format!("{shown}: not a map of providers")),
            Err(e) => Err(format!("{shown}: {e}")),
        }
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
