// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RESOLVING THE `plugins:` BLOCK — the operator's grammar ([`crate::config::PluginsCfg`]) turned
//! into the two things the plugin subsystem actually runs on: a [`FetchSpec`] list and a
//! `busbar_plugin_sign::TrustPolicy`.
//!
//! ## Why both halves live HERE
//!
//! The two halves answer different questions — the GRAMMAR is "what may an operator write, and what
//! is a typo", frozen and snapshot-fingerprinted; the RESOLUTION is "what does that mean to the
//! loader", and it names [`FetchSpec`], `busbar_plugin_sign::TrustPolicy`, the embedded release key,
//! the GitHub release-asset URL convention, and the process ENVIRONMENT. Both questions are about
//! the PLUGIN SUBSYSTEM, and neither is about config: the config layer neither defines nor enforces
//! a word of this policy, and the substrate below it never reads the block at all. So the block's
//! grammar sits in [`crate::config`] and its resolution sits here, one `mod` apart.
//!
//! Keeping them in busbar-core put fourteen sites naming `busbar_plugin_sign::` and
//! `busbar_plugin_loader::` inside the config document root. Moved, the config layer states the
//! grammar by naming this crate — the edge it already has — and this crate reads an operator's block
//! without naming the config layer at all.

use crate::config::{PluginFetch, PluginsCfg};
use busbar_substrate_values::diag_warn;
use busbar_substrate_values::diagnostics::{
    CONFIG_ANTIDOWNGRADE_FLOOR_INVALID, CONFIG_FIRSTPARTY_FLOOR_INVALID,
};

use crate::fetch::FetchSpec;

/// The tarball filename inside `plugins.dir` a fetch URL writes to: the last path segment (before any
/// `?`/`#`), which must be non-empty. Errors if the URL has no usable basename.
fn fetch_filename_from_url(url: &str) -> Result<String, String> {
    let path = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let path = path.split(['?', '#']).next().unwrap_or(path);
    let base = path.rsplit('/').next().unwrap_or("");
    if base.is_empty() {
        return Err(format!(
            "plugins.fetch url '{url}' has no filename (a signed tarball basename is required)"
        ));
    }
    Ok(base.to_string())
}

/// Map one [`PluginFetch`] to a [`FetchSpec`].
fn fetch_spec_from(f: &PluginFetch) -> Result<FetchSpec, String> {
    match f {
        PluginFetch::Github(g) => {
            // "org/repo@tag" → the GitHub release-asset URL. busbar plugins ship one signed
            // `{repo}.tar.gz` per release, so the asset name is derived, not discovered.
            let (repo_path, tag) = g.github.split_once('@').ok_or_else(|| {
                format!(
                    "plugins.fetch github '{}' must be 'org/repo@tag' (missing '@tag')",
                    g.github
                )
            })?;
            let (org, repo) = repo_path.split_once('/').ok_or_else(|| {
                format!(
                    "plugins.fetch github '{}' must be 'org/repo@tag' (missing 'org/repo')",
                    g.github
                )
            })?;
            if org.is_empty() || repo.is_empty() || tag.is_empty() {
                return Err(format!(
                    "plugins.fetch github '{}' must be a non-empty 'org/repo@tag'",
                    g.github
                ));
            }
            let filename = format!("{repo}.tar.gz");
            let url = format!("https://github.com/{org}/{repo}/releases/download/{tag}/{filename}");
            Ok(FetchSpec {
                url,
                sha256: g.sha256.clone(),
                filename,
            })
        }
        PluginFetch::Url(u) => Ok(FetchSpec {
            url: u.url.clone(),
            sha256: u.sha256.clone(),
            filename: fetch_filename_from_url(&u.url)?,
        }),
        PluginFetch::Env(e) => {
            let raw = std::env::var(&e.env).map_err(|_| {
                format!(
                    "plugins.fetch env '{}' is not set (it must hold a url or 'url@sha256')",
                    e.env
                )
            })?;
            // The var value is `url` or `url@sha256`. Split on the LAST '@' so a userinfo '@' in the
            // URL isn't mistaken for the pin separator (pins are hex, no '@').
            let (url, sha256) = match raw.rsplit_once('@') {
                Some((u, s)) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit()) => {
                    (u.to_string(), Some(s.to_string()))
                }
                _ => (raw.clone(), None),
            };
            Ok(FetchSpec {
                filename: fetch_filename_from_url(&url)?,
                url,
                sha256,
            })
        }
    }
}

/// Resolve `plugins.fetch:` into the loader's [`FetchSpec`] list: each entry becomes a
/// `{ url, sha256?, filename }`. `github: "org/repo@tag"` → the release-asset download URL
/// (busbar's one-file-per-plugin `{repo}.tar.gz` convention); `url:` → itself, with the target
/// filename taken from the URL basename; `env:` → the named var's value (a `url` or `url@sha256`),
/// erroring if the var is unset. Called at boot/reload BEFORE the fetch; never in `--validate` (the
/// zero-network contract).
pub fn fetch_specs(cfg: &PluginsCfg) -> Result<Vec<FetchSpec>, String> {
    cfg.fetch.iter().map(fetch_spec_from).collect()
}

/// Resolve into the `busbar-plugin-sign` trust policy: the EMBEDDED first-party release key + the
/// configured third-party publishers/opt-ins/floors. A malformed publisher key is a boot error, not
/// a silent skip (a skipped trust anchor could wrongly reject a good plugin).
///
/// `binary_version` is carried on the policy for error text/telemetry only — it is NOT a floor:
/// `busbar_plugin_sign::evaluate` applies PER-NAME floors alone (`first_party_floors` rollback
/// pins and `min_versions`), because first-party plugins version on independent lines (1.0.x
/// stores / auth / hooks, 2.x headroom, under a 1.5.0 engine) and an automatic
/// "plugin at or above the binary version" floor rejected every correctly-signed current release
/// (removed before 1.5.0 shipped; see plugin-sign's `evaluate()` for the full rationale).
///
/// It is a PARAMETER rather than this crate's own `CARGO_PKG_VERSION` on purpose: the version that
/// belongs on the policy is the ENGINE BINARY's, and this crate versions on its own line. A caller
/// passes its own `env!("CARGO_PKG_VERSION")`.
///
/// Anti-downgrade still holds per name: an explicit operator ROLLBACK (Full-scope, If-Match,
/// audited) persists a per-name pin via the overlay `plugin_versions` mechanism, and
/// `plugins.min_versions` floors first- and third-party alike.
///
/// The AUTOMATIC first-party anti-downgrade floor is NOT resolved here: it is the per-name
/// high-water mark, an observed fact rather than a config value, and it is injected by the engine's
/// preflight from [`crate::HighWaterMarks`]. This resolver leaves `first_party_high_water` empty; a
/// caller that skips the injection gets NO automatic floor.
pub fn trust_policy(
    cfg: &PluginsCfg,
    binary_version: &str,
) -> Result<busbar_plugin_sign::TrustPolicy, String> {
    let mut publishers = std::collections::BTreeMap::new();
    for p in &cfg.trust.publishers {
        if p.name == busbar_plugin_sign::FIRST_PARTY_PUBLISHER {
            return Err(format!(
                "plugins.trust.publishers['{}']: the publisher name '{}' is reserved for \
                 busbar's embedded release key and cannot be configured",
                p.name,
                busbar_plugin_sign::FIRST_PARTY_PUBLISHER
            ));
        }
        let key = busbar_plugin_sign::public_key_from_hex(&p.public_key)
            .map_err(|e| format!("plugins.trust.publishers['{}']: {e}", p.name))?;
        publishers.insert(p.name.clone(), key);
    }
    // A malformed floor is not a config error (it does not stop the boot — `version_at_least`
    // fails closed at the comparator, refusing just the one floored plugin) but
    // it IS worth telling the operator about early, before an artifact is even present: an
    // unparsable floor silently disarms the anti-downgrade control, so an operator who believes
    // it is armed should not have to discover that from a missing `--list-plugins` row.
    for (name, floor) in &cfg.min_versions {
        if !floor.is_empty() && !busbar_plugin_sign::valid_semver(floor) {
            diag_warn!(
                CONFIG_ANTIDOWNGRADE_FLOOR_INVALID,
                key = %format!("plugins.min_versions['{name}']"),
                value = %floor,
                "anti-downgrade floor is not a valid MAJOR.MINOR.PATCH version (no leading \
                 'v'); it cannot be satisfied, so this plugin will be refused. Fix or remove \
                 the entry."
            );
        }
    }
    for (name, floor) in &cfg.first_party_floors {
        if !floor.is_empty() && !busbar_plugin_sign::valid_semver(floor) {
            diag_warn!(
                CONFIG_FIRSTPARTY_FLOOR_INVALID,
                key = %format!("plugins.first_party_floors['{name}']"),
                value = %floor,
                "anti-downgrade floor is not a valid MAJOR.MINOR.PATCH version (no leading \
                 'v'); it cannot be satisfied, so this plugin will be refused — and this pin \
                 REPLACES the binary-version floor, so the plugin is refused unconditionally \
                 until this is fixed. Fix or remove the entry."
            );
        }
    }
    Ok(busbar_plugin_sign::TrustPolicy {
        first_party_key: busbar_plugin_sign::embedded_release_pubkey(),
        binary_version: binary_version.to_string(),
        first_party_floors: cfg.first_party_floors.clone(),
        // The automatic first-party floor is injected by the caller that owns the marks
        // (`plugins_preflight`, from `crate::HighWaterMarks`); config carries no
        // high-water key and never will — the mark is an observed fact, not an operator setting.
        first_party_high_water: Default::default(),
        publishers,
        allow_unsigned: cfg.trust.allow_unsigned,
        allow_third_party: cfg.trust.allow_third_party,
        min_versions: cfg.min_versions.clone(),
    })
}
