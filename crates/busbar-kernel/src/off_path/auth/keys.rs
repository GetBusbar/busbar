// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Off-path code for the auth key and instance slices (`auth::instances`, `auth::effect`,
//! `auth::self_keys`): work a config build, a reload, an admin verb or a key mint runs once, never
//! per request.

pub(crate) mod instances {
    //! THE AUTH PROVIDERS OF ONE CONFIG BUILD, keyed by provider name (the `identity-providers` key):
    //! the settings a role resolves for a provider, and the admin flush over the instances the
    //! admin and data chains hold.

    use std::sync::Arc;

    use busbar_contract::auth_calls::AuthCalls;

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
        .map_err(settings_err)?;
        if let Some(cid) = login_block(cfg, provider, module).and_then(|bl| bl.client_id.as_ref()) {
            resolved.default_text("client_id", cid.clone());
        }
        Ok(resolved)
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
        admin: &crate::auth::AdminAuthChain,
        chain: &crate::auth::AuthMiddleware,
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
}

/// An admin change's effect context (`auth::effect`): built once per admitted admin verb, and
/// rechecked only by that verb's effect admission.
pub(crate) mod effect {
    use crate::auth::effect::Context;
    use crate::auth::AdminDoor;
    use axum::http::HeaderMap;

    /// The roles an admin door was authorized under.
    pub(crate) fn roles(door: &AdminDoor) -> std::collections::BTreeSet<String> {
        match door {
            AdminDoor::Identified(p, _) | AdminDoor::Listed(p, _, _) => {
                p.roles.iter().cloned().collect()
            }
            _ => Default::default(),
        }
    }

    /// The context an admin change's effect keeps: what it was authorized for, and under whom.
    pub(crate) fn context(
        method: &str,
        target: &str,
        headers: HeaderMap,
        admitted: &AdminDoor,
    ) -> Context {
        Context::legacy(method, target, headers, admitted)
    }

    impl crate::inbound::RequestAdmission {
        pub fn effect_context(&self) -> Context {
            let head = &self.inner.original;
            let target = match &head.query {
                Some(query) => format!("{}?{query}", head.target),
                None => head.target.clone(),
            };
            Context::new(
                &head.method,
                &target,
                self.original_headers().clone(),
                &self.admin_verdict().door,
            )
        }
    }
}
