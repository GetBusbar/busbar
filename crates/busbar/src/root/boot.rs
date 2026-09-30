// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BOOT (`BUSBAR-1.6.0.md` THE DESIGN, §3): the composition root's boot stages, reaching the
//! plugin loader through [`super::loader`] (the one module that names it). Stage 0 Plan reads what the configuration USES; stage 1 Discover reads
//! each plugin's facts off its Statement (a signed manifest's rendering; nothing is opened); stage 2
//! Select picks the plugins the configuration uses (BUSBAR-1.6.0.md §2, §4 Law 7). `--validate` runs these three
//! stages and nothing dials, no library is opened and no store is opened.
//!
//! The rest of boot — the one load, register and seal — moves here as BOOT-LOOP 8.

use std::sync::Arc;

use super::loader::{boot::*, dispatch::LoadError, dispatch::ManifestFacts, PluginRegistry};
use busbar_contract::abi::mechanism::KindCode;
use busbar_kernel::config::{FetchTarget, PluginsCfg};
use busbar_kernel::preflight::{Fetched, RegistryIn};

/// THE ONE REGISTRY BUILD (THE DESIGN §3 stage 1 in BUSBAR-1.6.0.md; ARCHITECT ruling Q8): the
/// plugin registry is built here, in the composition root, and nowhere else — the kernel's preflight
/// receives it through the root's rows (the kernel preflight's `RegistryBuild`), and the root's own
/// dropped-plugin scan runs the same build. The linked rows alone, or the `plugins:` block's trust
/// resolved ([`trust_policy`]) and its directory scanned with the first-party floor armed and
/// raised; each step is noted to `note`. Nothing is opened.
///
/// # Errors
///
/// `plugins.trust is invalid: …`, an invalid tarball, manifest or conflict, or a linked row the
/// admission refuses.
pub fn registry(
    i: RegistryIn<'_>,
    note: &mut dyn FnMut(Note<'_>),
) -> Result<PluginRegistry, String> {
    let scan = match i.plugins {
        None => None,
        Some(p) => Some(Scan {
            policy: trust_policy(p, env!("CARGO_PKG_VERSION"))
                .map_err(|e| format!("plugins.trust is invalid: {e}"))?,
            data_dir: i.data_dir,
            dir: p.enabled.then_some(std::path::Path::new(&p.dir)),
        }),
    };
    super::loader::boot::registry(
        Build {
            linked: i.linked,
            scan,
        },
        note,
    )
}

/// THE `plugins:` BLOCK'S TRUST, resolved: the embedded first-party key, the configured
/// publishers and opt-ins and the per-name floors (`min_versions`, the rollback pins), through the
/// loader's `TrustPolicy::from_config`. `binary_version` is carried for diagnostics only. The
/// automatic first-party floor is the registry build's to arm.
///
/// # Errors
///
/// A reserved or malformed publisher.
pub fn trust_policy(
    cfg: &PluginsCfg,
    binary_version: &str,
) -> Result<super::loader::sign::TrustPolicy, String> {
    super::loader::sign::TrustPolicy::from_config(super::loader::sign::TrustInput {
        publishers: &cfg.publisher_keys(),
        allow_unsigned: cfg.trust.allow_unsigned,
        allow_third_party: cfg.trust.allow_third_party,
        min_versions: &cfg.min_versions,
        first_party_floors: &cfg.first_party_floors,
        binary_version,
    })
}

/// THE ROOT'S PLUGINS FETCH (the kernel preflight's `PluginsFetch`): every `plugins.fetch` target
/// through the loader's fetch (cache-by-pin, verify-before-write, atomic write) into `dir`, and only
/// ever through the kernel's SSRF-guarded `download`.
///
/// # Errors
///
/// Every problem, at boot (`fatal_on_miss`).
pub fn plugins_fetch(
    dir: &std::path::Path,
    targets: &[FetchTarget],
    fatal_on_miss: bool,
    download: &dyn Fn(&str) -> Result<Vec<u8>, String>,
) -> Result<Vec<Fetched>, Vec<String>> {
    let specs: Vec<super::loader::FetchSpec> = targets
        .iter()
        .map(|t| super::loader::FetchSpec {
            url: t.url.clone(),
            sha256: t.sha256.clone(),
            filename: t.filename.clone(),
        })
        .collect();
    let outcomes = super::loader::fetch_plugins(dir, &specs, fatal_on_miss, download)?;
    Ok(outcomes
        .into_iter()
        .map(|o| match o {
            super::loader::FetchOutcome::Cached { filename } => Fetched::Cached { filename },
            super::loader::FetchOutcome::Fetched { filename } => Fetched::Fetched { filename },
            super::loader::FetchOutcome::Warned { url, error } => Fetched::Warned { url, error },
        })
        .collect())
}

/// STAGE 0, PLAN: what the configuration file at `path` uses, read off its raw document (secret
/// references stay raw; environment references are interpolated leniently, as the boot's early
/// reads do). An unreadable file uses nothing: the boot's own load reports why.
pub fn plan(path: &std::path::Path) -> Uses {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Uses::default();
    };
    let Ok(text) = busbar_kernel::config::interpolate_env_with(
        &raw,
        busbar_kernel::config::EnvSubst::Lenient,
        &mut Vec::new(),
    ) else {
        return Uses::default();
    };
    serde_yaml::from_str::<serde_json::Value>(&text)
        .map(|doc| Uses::of(&doc))
        .unwrap_or_default()
}

/// STAGE 1, DISCOVER (the dropped-in half): every admitted plugin in `registry` whose signed
/// manifest states a Statement, read off that rendering. A 1.6.0 plugin states one; a manifest that
/// states none keeps today's handling.
///
/// # Errors
///
/// A stated rendering that does not read back, naming the plugin.
pub fn discover(registry: &PluginRegistry) -> Result<Vec<Candidate>, String> {
    let mut out = Vec::new();
    for row in registry.loadable() {
        let Some(stated) = row
            .manifest
            .stated_rendering()
            .map_err(|e| format!("plugin '{}': {e}", row.manifest.name))?
        else {
            continue;
        };
        let origin = Origin::Dropped {
            file: row.file.clone(),
            bytes: Arc::new(row.lib_bytes.clone()),
        };
        out.push(
            Candidate::from_rendering(stated, Some(&row.manifest.alias), origin)
                .map_err(|e| format!("plugin '{}': {e}", row.manifest.name))?,
        );
    }
    Ok(out)
}

/// What stages 0-2 found, for `--validate`'s report.
pub struct Stages {
    /// The discovered plugins.
    pub candidates: Vec<Candidate>,
    /// The instances selected over them.
    pub selected: Vec<Selected>,
}

impl Stages {
    /// One report line per discovered plugin: its stated facts and whether the configuration uses
    /// it.
    pub fn lines(&self) -> Vec<String> {
        self.candidates
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let used: Vec<&str> = self
                    .selected
                    .iter()
                    .filter(|s| s.candidate == i)
                    .map(|s| s.instance.as_str())
                    .collect();
                let abi = ManifestFacts::read(&c.stated).map_or(0, |f| f.kind_abi);
                let status = if used.is_empty() {
                    "not used by this config".to_string()
                } else {
                    format!("selected as {}", used.join(", "))
                };
                format!(
                    "    plugin: {} ({}, ABI {abi}) — {status}",
                    c.name,
                    kind_word(c.kind)
                )
            })
            .collect()
    }
}

fn kind_word(k: KindCode) -> String {
    format!("{k:?}").to_ascii_lowercase()
}

/// `--validate`'s STAGES 0-2 over the configuration at `path` and the dropped-in plugins the
/// preflight admitted: Plan, Discover, Select — and the loader's version refusal for every SELECTED
/// plugin whose Statement states a mechanism or kind ABI version other than this host's, naming
/// the rebuild (BUSBAR-1.6.0.md §11.8). Nothing is opened.
///
/// # Errors
///
/// The first refusal.
pub fn validate(path: &std::path::Path, registry: &PluginRegistry) -> Result<Stages, String> {
    let uses = plan(path);
    let candidates = discover(registry)?;
    let selected = select(&uses, &candidates);
    for s in &selected {
        let c = &candidates[s.candidate];
        let facts =
            ManifestFacts::read(&c.stated).map_err(|e| format!("plugin '{}': {e}", c.name))?;
        let host = facts.kind.abi_version();
        let refusal =
            if facts.mechanism_version != busbar_contract::abi::mechanism::MECHANISM_VERSION {
                Some(LoadError::ManifestMechanism {
                    stated: facts.mechanism_version,
                    host: busbar_contract::abi::mechanism::MECHANISM_VERSION,
                })
            } else if facts.kind_abi != host {
                Some(LoadError::ManifestKindAbi {
                    stated: facts.kind_abi,
                    host,
                })
            } else {
                None
            };
        if let Some(r) = refusal {
            return Err(format!("plugin '{}' ({}): {r}", c.name, s.instance));
        }
    }
    Ok(Stages {
        candidates,
        selected,
    })
}

#[cfg(test)]
#[path = "tests/boot.rs"]
mod tests;
