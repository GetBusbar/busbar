// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COMPOSITION ROOT'S HALF OF `busbar --migrate-config` (owner ruling 2026-10-27: each plugin
//! migrates its own settings; core migrates only its own keys). The kernel walks the configuration
//! ([`busbar_kernel::config::migrate_plugins`]); this answers its [`MigrateHost`]:
//!
//! - **a plugin's own migration**: the plugin a section names, found among the doors this build
//!   links, the plugins directory the configuration names, and (when neither has it) the release of
//!   it the release index names for this core, downloaded and verified like any dropped-in plugin;
//!   then its door's optional `migrate` is called (`busbar_plugin_loader::dispatch::migrate`);
//! - **the release index**: which release of a plugin matches this core's ABI for its kind, read
//!   from `plugin-index.json` (this release's own asset, or `BUSBAR_PLUGIN_INDEX`: a path or URL).
//!   The index is data: no plugin name is written here.
//!
//! The index is read only when a lookup needs it (a `plugins.fetch` GitHub pin, or a plugin no
//! build here serves), once per run.

use std::cell::OnceCell;
use std::path::PathBuf;

use busbar_contract::abi::sdk::migrate::Migrated;
use busbar_kernel::config::migrate_plugins::MigrateHost;
use busbar_kernel::config::PluginsCfg;
use serde::Deserialize;

use crate::root::loader::PluginRegistry;

/// Where the release index is read from when `BUSBAR_PLUGIN_INDEX` names none: this release's own
/// `plugin-index.json` asset.
fn default_index() -> String {
    format!(
        "https://github.com/GetBusbar/busbar/releases/download/v{}/plugin-index.json",
        env!("CARGO_PKG_VERSION")
    )
}

/// The environment variable naming the release index to read instead (a path or an `https` URL).
pub const INDEX_ENV: &str = "BUSBAR_PLUGIN_INDEX";

/// THE RELEASE INDEX: every plugin the index knows, each with its repository, the repositories it
/// was published from before, its kind, the words a configuration may name it by, and its
/// releases with the ABI version each was built for.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Index {
    /// The plugins.
    pub plugins: Vec<IndexPlugin>,
}

/// One plugin in the [`Index`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexPlugin {
    /// `org/repo`, as a `plugins.fetch` GitHub pin names it.
    pub repo: String,
    /// The repositories its earlier releases were published from.
    #[serde(default)]
    pub former_repos: Vec<String>,
    /// Its kind (`store`, `auth`, ...).
    pub kind: String,
    /// Every word a configuration's `module:` may name it by: its manifest name, alias and former
    /// names.
    #[serde(default)]
    pub answers_to: Vec<String>,
    /// Its releases.
    pub releases: Vec<IndexRelease>,
}

/// One release of an [`IndexPlugin`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexRelease {
    /// The release tag (`v1.6.0`).
    pub tag: String,
    /// The kind ABI version its build states.
    pub abi_version: u32,
}

impl Index {
    /// The plugin the GitHub repository `repo` (`org/repo`) publishes, under its current or a former
    /// repository name.
    fn by_repo(&self, repo: &str) -> Option<&IndexPlugin> {
        let same = |r: &String| r.eq_ignore_ascii_case(repo);
        self.plugins
            .iter()
            .find(|p| same(&p.repo) || p.former_repos.iter().any(same))
    }

    /// The plugin of `kind` that answers to `module`.
    fn by_module(&self, kind: &str, module: &str) -> Option<&IndexPlugin> {
        self.plugins
            .iter()
            .find(|p| p.kind == kind && p.answers_to.iter().any(|w| w == module))
    }
}

impl IndexPlugin {
    /// The GitHub pin of its newest release built for the ABI version this core speaks for its
    /// kind; `None` when it has none.
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

/// The semver order of two tags (`v1.6.0` < `v1.6.10`); a tag that is not one sorts first.
fn version_order(a: &str, b: &str) -> std::cmp::Ordering {
    let parts = |t: &str| -> Option<(u64, u64, u64)> {
        let mut it = t.trim_start_matches('v').split(['.', '-']);
        Some((
            it.next()?.parse().ok()?,
            it.next()?.parse().ok()?,
            it.next()?.parse().ok()?,
        ))
    };
    parts(a).cmp(&parts(b))
}

/// THE ROOT'S MIGRATION HOST over one configuration: its plugins block, the doors this build links,
/// and the release index, read once when first needed.
pub struct RootHost {
    /// The configuration's `plugins:` block (its directory and trust), when it has one.
    plugins: Option<PluginsCfg>,
    /// The configuration file being migrated, and its `providers_file:` value.
    config: PathBuf,
    providers_file: Option<String>,
    /// The registry of the linked doors and the configured plugins directory.
    local: OnceCell<PluginRegistry>,
    /// The release index, or why it could not be read.
    index: OnceCell<Result<Index, String>>,
    /// Builds downloaded for this run, in a directory of its own.
    fetched: OnceCell<PathBuf>,
}

impl RootHost {
    /// The host over the configuration document `raw`, read from `config` (its `plugins:` block and
    /// `providers_file:`, read as boot reads them).
    #[must_use]
    pub fn for_document(raw: &str, config: &std::path::Path) -> Self {
        let doc = serde_yaml::from_str::<serde_yaml::Value>(raw).ok();
        let plugins = doc
            .as_ref()
            .and_then(|doc| doc.get("plugins").cloned())
            .and_then(|p| serde_yaml::from_value::<PluginsCfg>(p).ok());
        let providers_file = doc
            .as_ref()
            .and_then(|doc| doc.get("providers_file"))
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

    /// The linked rows this build registers, as the boot's registry build takes them.
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

    /// The linked doors and the configured plugins directory. A directory that does not scan (a
    /// build made for an earlier busbar, with no successor beside it) leaves the linked doors alone.
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

    /// The release index, read once.
    fn index(&self) -> Result<&Index, String> {
        self.index
            .get_or_init(|| {
                let source = std::env::var(INDEX_ENV).unwrap_or_else(|_| default_index());
                let bytes = if source.starts_with("https://") || source.starts_with("http://") {
                    crate::root::plugin_fetch::downloader(&[])(&source)?
                } else {
                    std::fs::read(&source).map_err(|e| format!("{source}: {e}"))?
                };
                serde_json::from_slice::<Index>(&bytes)
                    .map_err(|e| format!("{source}: not a release index: {e}"))
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    /// A linked plane or hook door answering `module` on `kind`'s axis, with its printed name.
    fn linked_door(
        kind: &str,
        module: &str,
    ) -> Option<(String, busbar_contract::abi::mechanism::door::DoorFn)> {
        match kind {
            "plane" => crate::LINKED
                .plane_door_declares
                .iter()
                .find(|row| row.0 == module)
                .map(|row| (row.0.to_string(), row.1)),
            "hook" => crate::LINKED_HOOK_NAMES
                .iter()
                .zip(crate::LINKED.hook_doors.iter())
                .find(|pair| *pair.0 == module)
                .map(|(name, door)| ((*name).to_string(), *door)),
            _ => None,
        }
    }

    /// Whether a build here serves `module` on `kind`'s axis.
    fn served(&self, kind: &str, module: &str) -> bool {
        Self::linked_door(kind, module).is_some() || self.local().answers(module, kind)
    }

    /// The release of `module` for this core, downloaded into this run's own directory and scanned
    /// as a dropped-in plugin is (signature, trust, ABI) under the configuration's trust.
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
        let dir = self.fetched.get_or_init(|| {
            std::env::temp_dir().join(format!("busbar-migrate-{}", std::process::id()))
        });
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
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

impl Drop for RootHost {
    fn drop(&mut self) {
        if let Some(dir) = self.fetched.get() {
            let _ = std::fs::remove_dir_all(dir);
        }
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
        let local = self.local();
        if let Some(row) = local.resolve(module).filter(|r| r.manifest.kind == kind) {
            return Ok(row
                .migrate(settings, from)?
                .map(|m| (row.manifest.name.clone(), m)));
        }
        let fetched = self
            .fetch(kind, module)
            .map_err(|e| format!("no build of it is here, and its release for this busbar: {e}"))?;
        let row = fetched
            .resolve(module)
            .filter(|r| r.manifest.kind == kind)
            .ok_or_else(|| {
                "its release for this busbar does not answer to this name".to_string()
            })?;
        Ok(row
            .migrate(settings, from)?
            .map(|m| (row.manifest.name.clone(), m)))
    }

    fn repin(&self, github: &str) -> Result<Option<String>, String> {
        let Some((repo, _)) = github.split_once('@') else {
            return Ok(None);
        };
        let index = self.index()?;
        Ok(index
            .by_repo(repo)
            .and_then(IndexPlugin::pin_for_this_core)
            .filter(|pin| pin != github))
    }

    fn rewrite_catalog(&self) -> Result<Option<(String, Vec<String>)>, String> {
        let dir = self
            .config
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_default();
        // The catalog boot reads: `--providers` > `providers_file:` (beside the config) > the
        // `providers.yaml` beside the config.
        let path = crate::root::cli::providers_override().unwrap_or_else(|| {
            dir.join(self.providers_file.as_deref().unwrap_or("providers.yaml"))
        });
        let Ok(raw) = std::fs::read_to_string(&path) else {
            return Ok(None);
        };
        let shown = path.display().to_string();
        let Some(m) = busbar_kernel::config::migrate_catalog::migrate_catalog(&raw, &shown)? else {
            return Ok(None);
        };
        let stem = path
            .file_stem()
            .map_or_else(|| "providers".into(), |s| s.to_string_lossy().into_owned());
        let out = path.with_file_name(format!("{stem}.migrated.yaml"));
        std::fs::write(&out, &m.yaml).map_err(|e| format!("{}: {e}", out.display()))?;
        // Named beside the configuration when it sits there, as `providers_file:` resolves.
        let file = match out.strip_prefix(&dir) {
            Ok(rel) if !dir.as_os_str().is_empty() => rel.display().to_string(),
            _ => out.display().to_string(),
        };
        Ok(Some((file, m.changes)))
    }

    fn release_for(&self, kind: &str, module: &str) -> Result<Option<String>, String> {
        if self.served(kind, module) {
            return Ok(None);
        }
        let index = self.index()?;
        Ok(index
            .by_module(kind, module)
            .and_then(IndexPlugin::pin_for_this_core))
    }
}

#[cfg(test)]
#[path = "tests/config_migrate.rs"]
mod tests;
