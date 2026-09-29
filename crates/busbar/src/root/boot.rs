// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BOOT (`BUSBAR-1.6.0.md` THE DESIGN, §3): the one source file of the composition root that
//! names the plugin loader. Stage 0 Plan reads what the configuration USES; stage 1 Discover reads
//! each plugin's facts off its Statement (a signed manifest's rendering; nothing is opened); stage 2
//! Select picks the plugins the configuration uses (§2, §4 Law 7). `--validate` runs these three
//! stages and nothing dials, no library is opened and no store is opened.
//!
//! The rest of boot — the one load, register and seal — moves here as BOOT-LOOP 8 (the loader-naming
//! sites still outside this file are the drain-only ledger in
//! `tests/the_loader_is_named_only_by_boot.rs`).

use std::sync::Arc;

use busbar_contract::abi::mechanism::KindCode;
use busbar_plugin_loader::{boot::*, dispatch::LoadError, dispatch::ManifestFacts, PluginRegistry};

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
            Candidate::from_rendering(stated, Some(&row.manifest.alias), Vec::new(), origin)
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
/// the rebuild (THE DESIGN §11.8). Nothing is opened.
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
