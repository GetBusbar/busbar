// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::config::{AuthCfg, AuthChainEntry};

fn chain_with(module: &str, settings: serde_json::Map<String, serde_json::Value>) -> AuthCfg {
    let mut entry = AuthChainEntry::bare(module);
    entry.settings = settings;
    AuthCfg {
        chain: vec![entry],
        ..AuthCfg::default_none()
    }
}

/// Internal policy continuation after identity has been verified. The root's
/// a_verified_oidc_role_is_bound_under_the_provider_name separately checks that the actual
/// OIDC product delivers the provider identity and platform role used here.
#[test]
fn auth_plugin_role_binding_and_scope_cap_apply() {
    use busbar_contract::authz::Scope;
    let mut cfg = chain_with("idp", serde_json::Map::new());
    cfg.chain[0].max_admin_scope = Some("read-only".into());
    let mut roles = std::collections::BTreeMap::new();
    roles.insert(
        "platform".to_string(),
        crate::config::RoleBindingCfg {
            admin_scope: Some("full".into()),
            ..Default::default()
        },
    );
    cfg.role_bindings.insert("idp".into(), roles);
    let operator = crate::auth::Operator::new("operator-provider");
    let mut principal = crate::auth::Principal::from_id("oidc:alice");
    principal.roles = vec!["platform".to_string()];
    let bound = crate::auth::admin_scope_from_bindings(
        &cfg.role_bindings,
        &operator,
        "operator:local",
        Some("idp"),
        Some(&principal),
    );
    assert_eq!(
        bound,
        busbar_contract::authz::Grants::of(Scope::Full),
        "role binds full under the provider name"
    );
    for (configured, expected) in [("read-only", Scope::ReadOnly), ("full", Scope::Full)] {
        cfg.chain[0].max_admin_scope = Some(configured.into());
        let caps = crate::router::project_auth_scope_caps(&cfg);
        assert_eq!(
            crate::auth::cap_admin_scope(
                bound,
                crate::auth::module_scope_cap(&caps, &operator, "idp"),
            ),
            busbar_contract::authz::Grants::of(expected),
            "the configured {configured} ceiling reaches the production authorization policy"
        );
    }
}

#[test]
fn chain_open_wipes_the_resolved_settings() {
    fn wiped_when_dropped<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    let var = format!("BUSBAR_CHAIN_WIPE_{}", std::process::id());
    std::env::set_var(&var, "chain-open-secret\n");
    let settings: serde_json::Map<String, serde_json::Value> = [
        (
            "client_secret".to_string(),
            serde_json::json!({ "env": var }),
        ),
        (
            "issuer".to_string(),
            serde_json::json!("https://idp.example"),
        ),
    ]
    .into_iter()
    .collect();
    let mut resolved = crate::config::secret::resolve_settings(
        &settings,
        &["client_secret".to_string()],
        &[],
        "busbar-auth-oidc",
        &crate::config::secret::SecretResolver::builtins_only(),
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .expect("the declared reference resolves");
    std::env::remove_var(&var);
    assert_eq!(
        resolved.as_value()["client_secret"],
        serde_json::json!("chain-open-secret"),
        "the plugin is handed the resolved value"
    );

    wiped_when_dropped(&resolved);

    zeroize::Zeroize::zeroize(&mut resolved);
    assert!(
        !resolved
            .as_value()
            .to_string()
            .contains("chain-open-secret"),
        "the wipe left the secret: {resolved:?}"
    );
}
