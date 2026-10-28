// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE VALIDATOR: everything that makes a resolved configuration valid, in one order, for every
//! caller that asks — boot and every apply/reload ([`crate::build_app_from_config`]), `--validate`,
//! and the admin dry run (`POST /api/v1/admin/config/validate`). Each of those used to assemble the
//! steps by hand, and they drifted: the dry run once answered `ok: true` for a configuration the CLI
//! refused. Now there is one sequence, and a caller chooses only its root rules, whether boot's
//! plugin fetch runs, and whether built-in secrets must resolve.

use std::sync::Arc;

use busbar_contract::plugin_rows::PluginRows;

use super::secret_refs;
use crate::config::{PluginsCfg, RootCfg};

/// Which part of the validator refused. Each caller words its own banner by it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The semantic pass, every error at once.
    Config(Vec<String>),
    /// The composition root's own rules.
    Root(String),
    /// The plugin fetch, the plugin pre-flight, or a secret module the registry cannot back.
    Plugins(String),
    /// `--validate` only: a built-in secret reference that does not resolve.
    Unresolved(String),
}

/// What a caller chooses. Everything else is the same for every caller.
pub struct Check<'a> {
    /// The deployment's `plugins:` block (the admin dry run pins its `dir` first).
    pub plugins: &'a PluginsCfg,
    /// Env-var names left unset by a Lenient load (`--validate`, the dry run); empty at boot.
    pub unset_env_vars: &'a [String],
    /// The composition root's rules, after the semantic pass.
    pub root: &'a dyn Fn(&RootCfg) -> Result<(), String>,
    /// Boot's `plugins.fetch:` download, after the rules and before the plugin scan. Never run by
    /// `--validate` or a dry run (no network, no side effect).
    pub fetch: Option<&'a dyn Fn() -> Result<(), String>>,
    /// Resolve every built-in secret reference (`--validate` only).
    pub resolve_builtins: bool,
}

/// Validate `cfg`: the semantic pass, the root's rules, the plugin pre-flight, the secret modules
/// and references against the registry it builds, and (when asked) the built-in secrets. Returns
/// the validated registry. Manifest-only: nothing is `dlopen`ed and no store is opened.
///
/// # Errors
///
/// The first part to refuse, as a [`Refusal`].
#[cold]
#[inline(never)]
pub fn check(cfg: &RootCfg, c: Check<'_>) -> Result<Arc<dyn PluginRows>, Refusal> {
    super::validate_with_unset(cfg, c.unset_env_vars).map_err(Refusal::Config)?;
    (c.root)(cfg).map_err(Refusal::Root)?;
    if let Some(fetch) = c.fetch {
        fetch().map_err(Refusal::Plugins)?;
    }
    let registry = crate::preflight::plugins_preflight(
        cfg.store.as_ref(),
        cfg.auth.as_ref(),
        &cfg.identity_providers,
        &cfg.hooks,
        c.plugins,
        &cfg.export,
    )
    .map_err(Refusal::Plugins)?;
    secret_refs::registry_refusal(registry.as_ref(), cfg).map_err(Refusal::Plugins)?;
    // A secret reference in a plugin's settings at a field the plugin did not declare secret.
    super::undeclared_secret_refs(registry.as_ref(), cfg).map_err(Refusal::Plugins)?;
    if c.resolve_builtins {
        secret_refs::builtins_resolve(cfg).map_err(Refusal::Unresolved)?;
    }
    Ok(registry)
}

/// Root rules that accept everything (a caller with no composition root's rules to apply).
pub fn no_root_rules(_: &RootCfg) -> Result<(), String> {
    Ok(())
}
