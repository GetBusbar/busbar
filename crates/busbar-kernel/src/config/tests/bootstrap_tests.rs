// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
#[test]
fn captured_interpolation_reuses_the_current_injection_checks() {
    let mut unset = Vec::new();
    let text = super::super::interpolate_env_lookup(
        "port: ${PORT}",
        super::super::EnvSubst::Strict,
        &mut unset,
        |key| (key == "PORT").then(|| "42".into()),
    )
    .unwrap();
    assert_eq!(text, "port: 42");
    assert!(super::super::interpolate_env_lookup(
        "port: ${PORT}",
        super::super::EnvSubst::Strict,
        &mut unset,
        |_| Some("1\nother: injected".into())
    )
    .is_err());
}
#[test]
fn store_bootstrap_does_not_refuse_overlay_owned_identity_definitions() {
    let deploy: DeployCfg = busbar_contract::yaml::from_str(
        "auth: { chain: [overlay-corp], admin_auth: [overlay-admin] }\nstore: { module: memory }\n",
    )
    .unwrap();
    assert!(super::super::resolve(&deploy, &Default::default()).is_err());
    let bootstrap = resolve_store_bootstrap(&deploy).unwrap();
    assert_eq!(bootstrap.store.as_ref().unwrap().module, "memory");
    assert!(bootstrap.auth.unwrap().chain.is_empty());
    // The projection never changes the actual source or its final resolution obligations.
    assert!(super::super::resolve(&deploy, &Default::default()).is_err());
}
#[test]
fn complete_resolution_sees_recovered_named_definitions_and_hook_controls() {
    // The overlay's named definitions are read under the deployment read's grammar, so the
    // document is read through the grammar-carrying reader (an ambient decode is Unbound).
    let mut deploy = crate::config::deploy_from_yaml_str(
        "auth: { chain: [overlay-corp], admin_auth: [overlay-admin] }\nstore: { module: memory }\n",
        &crate::config::Grammar::empty(),
    )
    .unwrap();
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
#[test]
fn store_bootstrap_checks_security_before_opening_without_requiring_overlay_tls() {
    let deploy: DeployCfg =
        busbar_contract::yaml::from_str("store: { module: memory }\nadmin_require_mtls: true\n")
            .unwrap();
    let cfg = resolve_store_bootstrap(&deploy).unwrap();
    assert!(crate::config_validate::validate_bootstrap_security(&cfg).is_ok());
    for field in ["blocked_metadata_hosts", "allow_metadata_hosts"] {
        for invalid in ["169.254.0.0/16", "not-an-ip.123"] {
            let raw =
                format!("store: {{ module: memory }}\nsecurity: {{ {field}: ['{invalid}'] }}\n");
            let deploy: DeployCfg = busbar_contract::yaml::from_str(&raw).unwrap();
            let errors = resolve_store_bootstrap(&deploy).unwrap_err();
            assert!(
                errors.iter().any(|error| error.contains(field)),
                "{errors:?}"
            );
        }
    }
}
