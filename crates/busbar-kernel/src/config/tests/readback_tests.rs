// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::collections::BTreeSet;

#[test]
fn opaque_settings_are_never_copied_and_public_references_stay_hidden() {
    let settings = json!({
        "timeout": 42,
        "opaque": "RAW_SENTINEL",
        "token": "TOKEN_SENTINEL",
        "reference": {"module": "vault", "settings": {"text": "REF_SENTINEL"}},
        // A shorthand its admitted owner declared (db6f4149aa: core declares none itself).
        "nested": [{"lookup": "ENV_SENTINEL"}],
    });
    let public: BTreeSet<_> = ["timeout", "token", "reference", "nested"]
        .into_iter()
        .map(str::to_string)
        .collect();
    let view = plugin_view_with(
        "example",
        &crate::config::secret::test_settings(settings.as_object().unwrap()),
        &public,
        &crate::config::secret::fixture_sources(),
    );
    assert_eq!(view["settings_public"], json!({"timeout": 42}));
    let encoded = serde_json::to_string(&view).unwrap();
    for sentinel in [
        "RAW_SENTINEL",
        "TOKEN_SENTINEL",
        "REF_SENTINEL",
        "ENV_SENTINEL",
    ] {
        assert!(!encoded.contains(sentinel));
    }
    assert_eq!(view["settings_keys"].as_array().unwrap().len(), 5);
}

#[test]
fn absent_public_schema_discloses_only_keys() {
    let settings = json!({"url": "URL_SENTINEL", "enabled": true});
    let view = plugin_view_with(
        "unknown",
        &crate::config::secret::test_settings(settings.as_object().unwrap()),
        &BTreeSet::new(),
        &crate::config::secret::fixture_sources(),
    );
    assert_eq!(view["settings_public"], json!({}));
    assert!(!format!("{view:?}").contains("URL_SENTINEL"));
}

#[test]
fn tls_is_presence_only_including_secret_reference_settings() {
    let tls = super::super::TlsCfg {
        cert: super::super::SecretRef::template(
            "CERT_SENTINEL",
            &crate::config::secret::fixture_sources(),
        )
        .unwrap(),
        key: super::super::SecretRef::template(
            "KEY_SENTINEL",
            &crate::config::secret::fixture_sources(),
        )
        .unwrap(),
        client_ca: None,
    };
    let view = tls_view(Some(&tls));
    assert_eq!(view["present"], true);
    assert_eq!(view["client_ca"]["present"], false);
    let encoded = serde_json::to_string(&view).unwrap();
    assert!(!encoded.contains("SENTINEL"));
}
#[test]
fn public_role_readback_preserves_grant_tristate_without_raw_json() {
    let mut bindings: super::super::RoleBindings = serde_json::from_value(json!({
        "identity": {
            "unbounded": {"admin_scope":"read-only", "verbs":["get_info"]},
            "denied": {"allowed_pools":[], "group":"team"},
            "specific": {"allowed_pools":["primary"], "verbs":"*", "allowed_tools":["search"]}
        }
    }))
    .unwrap();
    let view = role_bindings_view(&bindings);
    assert_eq!(view["identity"]["unbounded"]["allowed_pools"], Value::Null);
    assert_eq!(view["identity"]["denied"]["allowed_pools"], json!([]));
    assert_eq!(
        view["identity"]["specific"]["allowed_pools"],
        json!(["primary"])
    );
    assert_eq!(
        view["identity"]["specific"]["allowed_tools"],
        json!(["search"])
    );
    assert_eq!(view["identity"]["specific"]["verbs"], "*");
    bindings
        .get_mut("identity")
        .unwrap()
        .get_mut("specific")
        .unwrap()
        .verbs = Some(busbar_contract::json::json!({"opaque":"VERB_SECRET_CANARY"}));
    assert!(!role_bindings_view(&bindings)
        .to_string()
        .contains("VERB_SECRET_CANARY"));
}

#[test]
fn public_pool_readback_exposes_typed_routing_without_opaque_tags() {
    let pool: super::super::PoolCfg = serde_json::from_value(json!({
        "members":[{"model":"m", "weight":3,"context_max":4096,"attempt_timeout_ms":50,"reasoning":true,"tags":["TAG_SECRET_CANARY"]}],
        "weights":{"m":7}, "tier":"small", "attempt_timeout_ms":100,
        "hooks":[{"strategy":"fastest"},"guard"],
        "repeatable":["search"],"upstream_credentials":"own",
        "breaker":{"base_cooldown_secs":4,"max_cooldown_secs":8,"trip":{"mode":"consecutive","consecutive_n":2}},
        "failover":{"timeout_secs":2,"max_hops":1,"exclusions":["spare"]},
        "on_exhausted":{"queue":{"max_ms":100}},
        "affinity":{"mode":"session","header_name":"x-session-id"}
    })).unwrap();
    let view = pool_view(&pool);
    assert_eq!(view["members"][0]["weight"], 3);
    assert_eq!(
        view["members"][0]["tags"],
        json!({"count":1,"values":"hidden"})
    );
    assert_eq!(view["weights"]["m"], 7);
    assert_eq!(view["ordering_strategy"], "fastest");
    assert_eq!(view["ordering_explicit"], true);
    assert_eq!(view["gates"], json!(["guard"]));
    assert_eq!(view["breaker"]["trip"]["consecutive_n"], 2);
    assert_eq!(view["on_exhausted"]["queue"]["max_ms"], 100);
    assert!(!view.to_string().contains("TAG_SECRET_CANARY"));
}

#[test]
fn public_catalog_readback_keeps_urls_references_and_options_hidden() {
    let def = super::super::ProviderDef {
        authored: Default::default(),
        protocol: "dialect".into(),
        base_url: "https://BASE_SECRET_CANARY".into(),
        error_map: std::collections::HashMap::from([("429".into(), "ERROR_SECRET_CANARY".into())]),
        health: Some(super::super::HealthCfg {
            mode: super::super::HealthMode::Dead,
            interval_secs: Some(10),
            timeout_secs: Some(3),
        }),
        path: Some("PATH_SECRET_CANARY".into()),
        path_base: None,
        token_url: Some("https://TOKEN_SECRET_CANARY".into()),
        scope: Some("SCOPE_SECRET_CANARY".into()),
        subject: Some("SUBJECT_SECRET_CANARY".into()),
        auth: Some(super::super::ProviderAuth::named("credential-style")),
        allow_metadata_hosts: vec!["169.254.169.254".into()],
        options: serde_json::Map::from_iter([(
            "opaque".into(),
            json!({"literal":"OPTION_SECRET_CANARY"}),
        )]),
    };
    let view = catalog_provider_view(&def);
    assert_eq!(view["protocol"], "dialect");
    assert_eq!(view["auth_style"], "credential-style");
    assert_eq!(view["health_config"]["mode"], "dead");
    assert_eq!(view["health_config"]["interval_secs"], 10);
    assert_eq!(view["base_url"]["present"], true);
    assert_eq!(view["path_base"]["present"], false);
    assert_eq!(view["opaque_keys"], json!(["opaque"]));
    assert!(!view.to_string().contains("SECRET_CANARY"));
}
