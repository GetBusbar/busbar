// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One semantic admission policy for all config representations and reloads.
use super::transaction::TxnError;
use crate::auth::effect::{Authority, Context};
use crate::state::App;
use serde_json::json;
use sha2::{Digest, Sha256};

pub(super) fn digest(value: &serde_json::Value) -> [u8; 32] {
    let bytes = zeroize::Zeroizing::new(value.to_string().into_bytes());
    Sha256::digest(&*bytes).into()
}

pub(super) fn root_digest(cfg: &super::RootCfg, plugins: &super::PluginsCfg) -> [u8; 32] {
    digest(&json!({
        "auth": cfg.auth,
        "identity-providers": cfg.identity_providers,
        "secrets": cfg.secrets,
        "credentials": cfg.credentials.at_rest.as_ref().map(|keys| json!({"key": keys.key, "previous": keys.previous})),
        "tls": cfg.tls, "admin_tls": cfg.admin_tls, "admin_listen": cfg.admin_listen,
        "blocked_metadata_hosts": cfg.blocked_metadata_hosts,
        "allow_metadata_hosts": cfg.allow_metadata_hosts, "allow_all_metadata": cfg.allow_all_metadata,
        "plugins": {"enabled": plugins.enabled, "dir": plugins.dir,
            "allow_unsigned": plugins.trust.allow_unsigned,
            "allow_third_party": plugins.trust.allow_third_party,
            "publishers": plugins.publisher_keys(), "min_versions": plugins.min_versions,
            "first_party_floors": plugins.first_party_floors},
    }))
}

fn security_changed(current: &App, next: &App) -> bool {
    current.admin_chain != next.admin_chain
        || current.role_bindings != next.role_bindings
        || current.identity_providers != next.identity_providers
        || current.auth_scope_caps != next.auth_scope_caps
        || current
            .configured_view
            .as_ref()
            .map(|v| (v.security_digest, v.deployment_security_digest))
            != next
                .configured_view
                .as_ref()
                .map(|v| (v.security_digest, v.deployment_security_digest))
}

pub(crate) fn admit(
    current: &App,
    next: &App,
    context: Option<&Context>,
    authority: Option<Authority>,
) -> Result<(), TxnError> {
    // Internal boot/kernel maintenance has no HTTP principal. Every admin transport installs the
    // host context; detached effects must explicitly carry it. No privilege is derived from ids.
    let Some(authority) = authority else {
        return Ok(());
    };
    admit_fields(
        current,
        &next.admin_chain,
        &next.identity_providers,
        &next.hook_registry,
    )?;
    if security_changed(current, next) {
        if !authority.full_operator {
            return Err(TxnError::Forbidden);
        }
        // The named auth-chain operation's self-lockout rule applies equally to document/apply/
        // parent replacement/reset/reload. This is a probe, not a second replay-claim spend.
        if current.admin_chain != next.admin_chain
            && context.is_some_and(|context| !context.survives(next))
        {
            return Err(TxnError::Conflict(
                "the proposed admin chain does not preserve this operator's full authority".into(),
            ));
        }
    }
    Ok(())
}

fn admit_fields(
    current: &App,
    chain: &[String],
    providers: &super::IdentityProviders,
    hooks: &std::collections::HashMap<String, super::HookCfg>,
) -> Result<(), TxnError> {
    if !current.admin_chain.is_empty() && chain.is_empty() {
        return Err(TxnError::Conflict("a protected deployment cannot clear admin_auth through the admin API; select open development posture at startup".into()));
    }
    // A provider ceiling is immutable upward through EVERY API representation, including full
    // operators. Removing a definition cannot smuggle a higher ceiling in under the same name.
    use busbar_contract::authz::Scope;
    for (name, provider) in providers {
        let ceiling = |token: Option<&str>| token.and_then(Scope::parse).unwrap_or(Scope::ReadOnly);
        let old = ceiling(
            current
                .identity_providers
                .get(name)
                .and_then(|p| p.max_admin_scope.as_deref()),
        );
        if !old.allows(ceiling(provider.max_admin_scope.as_deref())) {
            return Err(TxnError::Conflict(format!(
                "refusing to raise identity-providers.{name}.max_admin_scope through the admin API"
            )));
        }
    }
    for (name, hook) in hooks {
        if let Some(old) = current.hook_registry.get(name) {
            if (old.kind, old.prompt, old.user) != (hook.kind, hook.prompt, hook.user) {
                return Err(TxnError::Conflict(format!(
                    "hook {name} grants are immutable; delete and re-register to change them"
                )));
            }
        }
    }
    Ok(())
}

#[derive(Default)]
struct BuildAuthority {
    authority: Option<Authority>,
    refusal: Option<TxnError>,
}

thread_local! {
    static BUILD_AUTHORITY: std::cell::RefCell<BuildAuthority> = std::cell::RefCell::default();
}

// The synchronous transaction owns the context on this thread, including while builders open
// plugins. Restore it on unwinding too; a blocking worker must never lend it to its next job.
pub(super) fn scoped<T, E: From<TxnError>>(
    authority: Option<Authority>,
    body: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    struct Reset(Option<BuildAuthority>);
    impl Drop for Reset {
        fn drop(&mut self) {
            if let Some(previous) = self.0.take() {
                BUILD_AUTHORITY.with(|held| {
                    held.replace(previous);
                });
            }
        }
    }
    let previous = BUILD_AUTHORITY.with(|held| {
        held.replace(BuildAuthority {
            authority,
            refusal: None,
        })
    });
    let _reset = Reset(Some(previous));
    let result = body();
    match result {
        Err(error) => match BUILD_AUTHORITY.with(|held| held.borrow_mut().refusal.take()) {
            Some(refusal) => Err(E::from(refusal)),
            None => Err(error),
        },
        ok => ok,
    }
}

/// Same semantic rules, before builder work can open a proposed auth/secret/plugin instance.
/// The transaction transports the typed refusal through the builder's existing String API.
pub(crate) fn check_candidate(
    current: Option<&App>,
    cfg: &super::RootCfg,
    plugins: &super::PluginsCfg,
) -> Result<(), String> {
    let Some(current) = current else {
        return Ok(());
    };
    let Some(authority) = BUILD_AUTHORITY.with(|held| held.borrow().authority) else {
        return Ok(());
    };
    let result = admit_fields(
        current,
        &cfg.admin_auth,
        &cfg.identity_providers,
        &cfg.hooks,
    )
    .and_then(|()| {
        let changed = current
            .configured_view
            .as_ref()
            .is_none_or(|view| view.security_digest != root_digest(cfg, plugins));
        if changed && !authority.full_operator {
            Err(TxnError::Forbidden)
        } else {
            Ok(())
        }
    });
    result.map_err(|refusal| {
        let message = refusal.message();
        BUILD_AUTHORITY.with(|held| held.borrow_mut().refusal = Some(refusal));
        message
    })
}
