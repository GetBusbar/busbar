// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The base Store can be opened before overlay-owned definitions are available. This projection
//! contains only bootstrap inputs and is never an application configuration. After recovery the
//! caller must resolve and validate the complete effective deployment before opening listeners.
use super::{DeployCfg, RootCfg};

pub fn resolve_store_bootstrap(deploy: &DeployCfg) -> Result<RootCfg, Vec<String>> {
    let mut bootstrap: DeployCfg = serde_yaml::from_str("{}")
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
    bootstrap.security.clone_from(&deploy.security);
    bootstrap.limits.clone_from(&deploy.limits);
    bootstrap.advanced.clone_from(&deploy.advanced);
    bootstrap.health.clone_from(&deploy.health);
    bootstrap.routing.clone_from(&deploy.routing);
    bootstrap.credentials.clone_from(&deploy.credentials);
    bootstrap.auth = deploy.auth.clone().map(|mut auth| {
        // Signed-key/at-rest material remains available to bootstrap, but auth chains, grants,
        // hooks and plane definitions are resolved only after their overlay definitions exist.
        auth.chain.clear();
        auth.admin_auth.clear();
        auth.role_bindings.clear();
        auth
    });
    super::resolve(&bootstrap, &Default::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn store_bootstrap_does_not_refuse_overlay_owned_identity_definitions() {
        let deploy: DeployCfg = serde_yaml::from_str("auth: { chain: [overlay-corp], admin_auth: [overlay-admin] }\nstore: { module: memory }\n").unwrap();
        assert!(super::super::resolve(&deploy, &Default::default()).is_err());
        let bootstrap = resolve_store_bootstrap(&deploy).unwrap();
        assert_eq!(bootstrap.store.as_ref().unwrap().module, "memory");
        assert!(bootstrap.auth.unwrap().chain.is_empty());
        // The projection never changes the actual source or its final resolution obligations.
        assert!(super::super::resolve(&deploy, &Default::default()).is_err());
    }
    #[test]
    fn complete_resolution_sees_recovered_named_definitions_and_hook_controls() {
        let mut deploy: DeployCfg = serde_yaml::from_str("auth: { chain: [overlay-corp], admin_auth: [overlay-admin] }\nstore: { module: memory }\n").unwrap();
        let doc: super::super::overlay::OverlayDoc = serde_json::from_value(serde_json::json!({
            "version":2,
            "hooks":{"guard":{"kind":"tap","module":"observer","phase":["response"],"groups":["restricted"]}},
            "groups":{"restricted":{"enabled":false}},
            "named_maps":{"identity-providers":{
                "overlay-corp":{"module":"approved-corp"},
                "overlay-admin":{"module":"approved-admin"}
            }}
        })).unwrap();
        super::super::overlay::apply_root_to_deploy(&mut deploy, &doc);
        let mut cfg = super::super::resolve(&deploy, &Default::default()).unwrap();
        super::super::overlay::merge_into(&mut cfg, doc);
        assert_eq!(cfg.auth.as_ref().unwrap().chain[0].module, "approved-corp");
        assert_eq!(
            cfg.auth.as_ref().unwrap().admin_auth[0].module,
            "approved-admin"
        );
        assert_eq!(cfg.hooks["guard"].groups, ["restricted"]);
        assert_eq!(
            cfg.hooks["guard"].resolved_stages(),
            [super::super::HookStage::Response]
        );
        assert!(!cfg.groups["restricted"].enabled);
    }
}
