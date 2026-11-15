// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The base Store can be opened before overlay-owned definitions are available. This projection
//! contains only bootstrap inputs and is never an application configuration. After recovery the
//! caller must resolve and validate the complete effective deployment before opening listeners.
use super::{DeployCfg, RootCfg};

pub fn resolve_store_bootstrap(deploy: &DeployCfg) -> Result<RootCfg, Vec<String>> {
    resolve_store_bootstrap_with_security(deploy, &deploy.security)
}

/// Non-serving projection with an explicit caller-owned security view. Final
/// deployment resolution must still validate the complete original policy.
pub fn resolve_store_bootstrap_with_security(
    deploy: &DeployCfg,
    security: &Option<super::SecurityCfg>,
) -> Result<RootCfg, Vec<String>> {
    let mut bootstrap: DeployCfg = busbar_contract::yaml::from_str("{}")
        .map_err(|_| vec!["cannot construct the Store bootstrap configuration".into()])?;
    bootstrap.listen.clone_from(&deploy.listen);
    bootstrap.admin_listen.clone_from(&deploy.admin_listen);
    bootstrap.tls.clone_from(&deploy.tls);
    bootstrap.admin_tls.clone_from(&deploy.admin_tls);
    // This projection opens no listener. The complete effective listener policy is checked
    // after the overlay has supplied its TLS/listen overrides.
    bootstrap.admin_require_mtls = false;
    bootstrap.store.clone_from(&deploy.store);
    bootstrap.secrets.clone_from(&deploy.secrets);
    bootstrap.security.clone_from(security);
    bootstrap.limits.clone_from(&deploy.limits);
    bootstrap.advanced.clone_from(&deploy.advanced);
    bootstrap.health.clone_from(&deploy.health);
    bootstrap.routing.clone_from(&deploy.routing);
    bootstrap.credentials.clone_from(&deploy.credentials);
    // The projection is read under the grammar of the document it projects.
    bootstrap.grammar = deploy.grammar.clone();
    bootstrap.auth = deploy.auth.clone().map(|mut auth| {
        // Signed-key/at-rest material remains available to bootstrap, but auth chains, grants,
        // hooks and plane definitions are resolved only after their overlay definitions exist.
        auth.chain.clear();
        auth.admin_auth.clear();
        auth.role_bindings.clear();
        auth
    });
    let cfg = super::resolve(&bootstrap, &Default::default())?;
    crate::config_validate::validate_bootstrap_security(&cfg)?;
    Ok(cfg)
}

#[cfg(test)]
#[path = "tests/bootstrap_tests.rs"]
mod tests;
