// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::config::providers::CORE_PROVIDER_KEYS;
use busbar_kernel::config::ModelCfg;

#[test]
fn configured_model_accepts_its_adopted_dialect_override() {
    for key in ["protocol", "dialect"] {
        let source =
            format!("provider: deployment\nupstream_model: wire-model\n{key}: second-dialect\n");
        let model: ModelCfg = busbar_contract::yaml::from_str(&source)
            .expect("IF 8.6: model dialect overrides the provider dialect");
        assert_eq!(model.provider, "deployment");
        assert_eq!(model.upstream_model.as_deref(), Some("wire-model"));
    }
}

#[test]
fn both_model_dialect_spellings_are_not_two_independent_overrides() {
    let source = "provider: deployment\nprotocol: first\ndialect: second\n";
    assert!(busbar_contract::yaml::from_str::<ModelCfg>(source).is_err());
}

#[test]
fn provider_protocol_is_core_owned_and_cannot_enter_a_plane_projection() {
    assert!(CORE_PROVIDER_KEYS.contains(&"protocol"));
}
