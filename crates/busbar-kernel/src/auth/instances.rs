// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH INSTANCES OF ONE CONFIG BUILD, keyed by provider name (the `identity-providers` key).
//!
//! A provider is defined once and `resolve_auth` hands every role that names it (`auth.chain`,
//! `auth.admin_auth`, the hosted login methods) the same definition, so one provider is ONE
//! instance per build: one OPEN, one READY (an OIDC discovery and JWKS fetch), one tick schedule
//! and one verdict cache, shared by every role (WASTE-AUTH-SECRETS W1). The first role to name a
//! provider opens it with the provider's whole resolved settings, including the login-only
//! additions (`browser_login.client_id`, the lent `client_secret`) that the same plugin received
//! in its login role before; every later role is handed the same instance. Core owns this
//! decision (decision 185): the loader opens what it is asked to.

use std::sync::Arc;

use busbar_contract::auth_calls::AuthCalls;

/// The instances one build opened, by provider name.
#[derive(Default)]
pub struct AuthInstances {
    by_provider: indexmap::IndexMap<String, Arc<dyn AuthCalls>>,
}

impl std::fmt::Debug for AuthInstances {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthInstances")
            .field("providers", &self.by_provider.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl AuthInstances {
    /// `provider`'s instance: the one this build already opened for another role, else `open()`'s,
    /// kept for the roles after this one. A refusal is not kept.
    pub(crate) fn instance(
        &mut self,
        provider: &str,
        open: impl FnOnce() -> Result<Arc<dyn AuthCalls>, String>,
    ) -> Result<Arc<dyn AuthCalls>, String> {
        if let Some(calls) = self.by_provider.get(provider) {
            return Ok(Arc::clone(calls));
        }
        let calls = open()?;
        self.by_provider
            .insert(provider.to_string(), Arc::clone(&calls));
        Ok(calls)
    }
}

/// The label one provider's shared instance opens under; the role is attributed at the call site.
#[must_use]
pub(crate) fn instance_label(provider: &str) -> String {
    format!("identity-providers.{provider}")
}

/// The settings one provider's instance opens with: its definition's settings resolved, plus the
/// login-only additions when the provider has a `browser_login` block (the same values the plugin
/// received in its login role; a role-local override cannot exist, `resolve_auth`). `settings_err`
/// words a resolution refusal in the calling role's terms.
pub(crate) fn provider_settings(
    cfg: &crate::config::AuthCfg,
    provider: &str,
    module: &str,
    settings: &busbar_contract::plugin_settings::Settings,
    registry: &dyn busbar_contract::plugin_rows::PluginRows,
    secret_resolver: &crate::config::secret::SecretResolver,
    settings_err: impl FnOnce(String) -> String,
) -> Result<busbar_contract::plugin_settings::ResolvedSettings, String> {
    let mut resolved = crate::config::secret::resolve_settings(
        settings,
        &registry.secret_slots(module),
        &registry.reference_slots(module),
        module,
        secret_resolver,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .map_err(|e| settings_err(e.to_string()))?;
    if let Some(cid) = login_block(cfg, provider, module).and_then(|bl| bl.client_id.as_ref()) {
        resolved.default_text("client_id", cid.clone());
    }
    Ok(resolved)
}

/// Lend the provider's `browser_login.client_secret` into `resolved`, when it has one: the login
/// role's secret, lent to the one shared instance.
pub(crate) fn lend_login_secret(
    cfg: &crate::config::AuthCfg,
    provider: &str,
    module: &str,
    registry: &dyn busbar_contract::plugin_rows::PluginRows,
    secret_resolver: &crate::config::secret::SecretResolver,
    resolved: &mut busbar_contract::plugin_settings::ResolvedSettings,
) -> Result<(), String> {
    super::login::lend_browser_login_secret(
        provider,
        module,
        login_block(cfg, provider, module),
        &registry.secret_slots(module),
        secret_resolver,
        resolved,
    )
}

fn login_block<'c>(
    cfg: &'c crate::config::AuthCfg,
    provider: &str,
    module: &str,
) -> Option<&'c crate::config::BrowserLoginCfg> {
    cfg.methods
        .get(provider)
        .filter(|mc| mc.module == module)
        .and_then(|mc| mc.browser_login.as_ref())
}

/// The admin flush: every instance `admin` and `chain` hold for `provider` (all, for `None`) is
/// refreshed ONCE, however many roles hold it, and its flushed count is summed once. The first
/// refusal is answered after every instance was asked.
pub fn flush_distinct(
    admin: &super::AdminAuthChain,
    chain: &super::AuthMiddleware,
    provider: Option<&str>,
) -> Result<u64, String> {
    let mut distinct: Vec<&Arc<dyn AuthCalls>> = Vec::new();
    let admin = admin
        .modules
        .iter()
        .filter(|(name, _)| provider.is_none_or(|p| p == name.as_str()))
        .map(|(_, module)| &module.calls);
    for calls in admin.chain(chain.chain_instances(provider)) {
        if !distinct.iter().any(|seen| Arc::ptr_eq(seen, calls)) {
            distinct.push(calls);
        }
    }
    crate::state::credential_flush_results(distinct.into_iter().map(|calls| calls.refresh()))
}
