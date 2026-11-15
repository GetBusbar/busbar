// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

pub struct Check<'a> {
    pub plugins: &'a PluginsCfg,

    pub unset_env_vars: &'a [String],

    pub root: &'a dyn Fn(&RootCfg) -> Result<(), String>,

    pub fetch: Option<&'a dyn Fn() -> Result<(), String>>,

    pub resolve_builtins: bool,

    /// The secret axis the references are checked against (each secret module's own check of its
    /// settings): the live axis for a build ([`crate::config::secret::live_axis`]), a read-scoped
    /// view of what start judged for `--validate`. `None`: no module checks its settings.
    pub secret_axis: Option<&'a dyn busbar_contract::secret::SecretAxis>,
}

#[cold]
#[inline(never)]
pub fn check(cfg: &RootCfg, c: Check<'_>) -> Result<Arc<dyn PluginRows>, Refusal> {
    check_with(cfg, None, c)
}

/// `check`, consuming the semantic pass's one result when the caller already judged this exact
/// configuration (`judge_effective`): its advisories are logged here and the pass is not repeated.
/// Inside the boot narration scope (`after_boot_advice`) they stay silent: the narration covered
/// them.
#[cold]
#[inline(never)]
pub fn check_with(
    cfg: &RootCfg,
    judged: Option<super::Judged>,
    c: Check<'_>,
) -> Result<Arc<dyn PluginRows>, Refusal> {
    match judged {
        Some(judged) if super::boot_advised() => drop(judged),
        Some(judged) => judged.log(),
        None => {
            let semantic =
                || super::validate_with_plugins(cfg, c.unset_env_vars, c.plugins.enabled);
            let verdict = if super::boot_advised() {
                tracing::subscriber::with_default(
                    tracing::subscriber::NoSubscriber::default(),
                    semantic,
                )
            } else {
                semantic()
            };
            verdict.map_err(Refusal::Config)?;
        }
    }
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
    super::validate_provider_destinations(cfg, c.unset_env_vars, &|target| {
        crate::preflight::root_rows()
            .endpoint_locate
            .ok_or_else(|| "no transport declaration locator is installed".to_owned())?(
            &registry, target,
        )
    })
    .map_err(Refusal::Config)?;
    crate::preflight::validate_pool_strategies(cfg, &registry).map_err(Refusal::Plugins)?;
    secret_refs::registry_refusal_with(registry.as_ref(), cfg, c.secret_axis)
        .map_err(Refusal::Plugins)?;

    super::undeclared_secret_refs(registry.as_ref(), cfg).map_err(Refusal::Plugins)?;
    if c.resolve_builtins {
        secret_refs::builtins_resolve(cfg).map_err(Refusal::Unresolved)?;
    }
    Ok(registry)
}

pub fn no_root_rules(_: &RootCfg) -> Result<(), String> {
    Ok(())
}
