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

/// THE ONE REGISTRY BUILD (BUSBAR-1.6.0.md §3 stage 1; ARCHITECT ruling Q8): the
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
    document(path).map(|doc| Uses::of(&doc)).unwrap_or_default()
}

/// The raw document at `path` (secret references raw, environment interpolated leniently); `None`
/// when it does not read.
fn document(path: &std::path::Path) -> Option<serde_json::Value> {
    let raw = std::fs::read_to_string(path).ok()?;
    let text = busbar_kernel::config::interpolate_env_with(
        &raw,
        busbar_kernel::config::EnvSubst::Lenient,
        &mut Vec::new(),
    )
    .ok()?;
    serde_yaml::from_str::<serde_json::Value>(&text).ok()
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
    /// THE ONE LIST OF LISTENERS (boot stage 3f's input): the root's own, then every selected
    /// instance's inbound listener, each with its bind.
    pub inbound: Vec<InboundBind>,
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
            .chain(
                self.inbound
                    .iter()
                    .filter(|b| b.owner != BindOwner::Root)
                    .map(|b| {
                        let tls = if b.tls.is_some() { "tls" } else { "clear" };
                        format!(
                            "    listens: {} on {} over {} ({tls}, at most {} connections)",
                            b.at, b.listen, b.transport, b.max_conns
                        )
                    }),
            )
            .collect()
    }
}

fn kind_word(k: KindCode) -> String {
    format!("{k:?}").to_ascii_lowercase()
}

/// `--validate`'s STAGES 0-2 over the configuration at `path` and the dropped-in plugins the
/// preflight admitted: Plan, Discover, Select — see [`stages`]. `root` are the host's own listeners
/// ([`root_binds`]). Nothing is opened.
///
/// # Errors
///
/// The first refusal.
pub fn validate(
    path: &std::path::Path,
    registry: &PluginRegistry,
    root: &RootListens<'_>,
) -> Result<Stages, String> {
    let doc = document(path).unwrap_or_default();
    let root = root_binds(&doc, root);
    stages(&doc, discover(registry)?, root)
}

/// The addresses the host's own listeners take, as the resolved configuration states them.
#[derive(Debug, Clone, Copy)]
pub struct RootListens<'a> {
    /// The data door (`listen`).
    pub listen: &'a str,
    /// The admin surface (`admin_listen`).
    pub admin_listen: &'a str,
}

/// THE ROOT'S OWN LISTENERS AS BINDS, the head of the one list: the data door at `listen` with the
/// raw `tls` block, and the admin surface at `admin_listen` with the raw `admin_tls` block. They
/// keep 1.5.5's bound: no connection cap. An address that does not parse as `ip:port` is left to
/// the configuration's own validation and binds nothing here.
#[must_use]
pub fn root_binds(doc: &serde_json::Value, root: &RootListens<'_>) -> Vec<InboundBind> {
    [
        ("listen", root.listen, "tls"),
        ("admin_listen", root.admin_listen, "admin_tls"),
    ]
    .into_iter()
    .filter_map(|(setting, addr, tls)| {
        Some(InboundBind {
            owner: BindOwner::Root,
            transport: String::new(),
            at: setting.to_string(),
            listen: addr.parse().ok()?,
            tls: doc.get(tls).filter(|v| !v.is_null()).cloned(),
            max_conns: u64::MAX,
        })
    })
    .collect()
}

/// STAGES 0 and 2 over `doc` and the discovered `candidates`: Select; the one list of listeners,
/// `root` first, then every selected instance's inbound listener read from its settings — two
/// listeners on one address are refused here, before anything binds; and the loader's version refusal for every
/// SELECTED plugin whose Statement states a mechanism or kind ABI version other than this host's,
/// naming the rebuild (THE DESIGN §11.8).
///
/// # Errors
///
/// The first refusal.
pub fn stages(
    doc: &serde_json::Value,
    candidates: Vec<Candidate>,
    root: Vec<InboundBind>,
) -> Result<Stages, String> {
    let uses = Uses::of(doc);
    let selected = select(&uses, &candidates);
    refuse_inbound(&candidates, &selected)?;
    let inbound = inbound(doc, &candidates, &selected, root)?;
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
        inbound,
    })
}

/// NO ACCEPTED CONNECTION HAS A CONSUMER YET (ARCHITECT ruling 2026-09-30): a selected plugin
/// that declares an inbound need is refused, naming the need, rather than bound and closed. The
/// driver binding that serves an accepted connection removes this refusal.
///
/// # Errors
///
/// The first selected instance with an inbound need.
fn refuse_inbound(candidates: &[Candidate], selected: &[Selected]) -> Result<(), String> {
    use busbar_contract::abi::host::conn::connector::DIRECTION_INBOUND;
    for s in selected {
        let Some(c) = candidates.get(s.candidate) else {
            continue;
        };
        if let Some((i, n)) = c
            .needs
            .iter()
            .enumerate()
            .find(|(_, n)| n.direction == DIRECTION_INBOUND)
        {
            return Err(format!(
                "{} ({}): inbound need {i} over `{}` cannot be served by this build (nothing \
                 serves an accepted connection yet); remove the plugin from the configuration",
                s.instance, c.name, n.transport
            ));
        }
    }
    Ok(())
}

/// BOOT'S HALF OF [`refuse_inbound`]: the configuration at `path` over the dropped-in plugins
/// `registry` admitted, discovered and selected as `--validate` does, refused the same way.
///
/// # Errors
///
/// A Statement that does not read back, or a selected plugin with an inbound need.
pub fn refuse_unserved_inbound(
    path: &std::path::Path,
    registry: &PluginRegistry,
) -> Result<(), String> {
    let doc = document(path).unwrap_or_default();
    let candidates = discover(registry)?;
    refuse_inbound(&candidates, &select(&Uses::of(&doc), &candidates))
}

#[cfg(test)]
#[path = "tests/boot.rs"]
mod tests;
