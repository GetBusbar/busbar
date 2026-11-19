// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OPERATOR-FROM-ADMITTED-AUTH R21 (kernel half): the 1.5.5 configuration as normalization leaves
//! it (its `token:` definition passed through untouched, `fixtures/operator_token_after_normalize
//! .yaml`) is refused with the one named remedy, `operator_token("admin-tokens")` plus the install
//! remedy (no operator row is admitted in this binary), and never with the generic no-mint-path
//! refusal. No words are installed: this test owns its binary.

use busbar_kernel::plane_driver::registry::{publish_planes, PlaneDecl, PlaneDeclaration};

const FIXTURE: &str = include_str!("fixtures/operator_token_after_normalize.yaml");

/// The read's grammar. The 1.5.5 configuration spells its secrets `{ env: … }` and `{ file: … }`.
/// Core declares no source shorthand itself: an admitted secret module does. This read admits one
/// that declares both words.
fn fixture_grammar() -> busbar_kernel::config::Grammar {
    use busbar_contract::plugin_settings::sugar_words::REWRITE_SUGAR;
    let mut sugars = busbar_contract::secret_ref::Sugars::default();
    sugars
        .declare(
            "fixture-source",
            &[
                (REWRITE_SUGAR, "env".into(), "slot".into()),
                (REWRITE_SUGAR, "file".into(), "path".into()),
            ],
        )
        .expect("the fixture source declares its shorthand");
    busbar_kernel::config::Grammar::new(sugars, std::collections::BTreeMap::new(), Vec::new())
}

/// A test-only fallback plane declaration (no plane plugin, no hooks): the 1.5.5 `pools:` and
/// `models:` sections are owned by the fallback plane, and this kernel-only binary links none.
static FALLBACK_PLANE: PlaneDecl = PlaneDecl {
    declaration: PlaneDeclaration {
        key: "r21-fallback",
        fallback: true,
        config_section: "models",
        scope_kinds: &[],
        subject_noun: "model",
        admin_noun: "model",
        audit_kind: "model",
        card_signing_domain: None,
        card_kid_prefix: None,
        owned_config_sections: &[],
        billable_classes: &[],
        class_parents: &[],
        fee_units: &[],
        metric_families: &[],
        record_kinds: &[],
        required_config_sections: &[],
        trust_keys: &[],
        served_op_classes: &[],
        caller_credential_refusal: None,
    },
    wire_format_names: |_| &[],
    provider_dialects: |_| &[],
    claims: |_| Vec::new(),
    admission: |_| None,
    build: |_, _| None,
    routes: None,
    admin_routes: None,
    openapi: None,
    hydrate: None,
    start: None,
    config_validate: None,
    named_def_list: None,
    named_def_get: None,
    registry_contains: None,
    openapi_schemas: None,
    on_swap: None,
    parse_section: None,
    parse_endpoint: None,
    lower_endpoint: None,
    build_runtime: None,
    viewer: None,
    retain_verify_gates: None,
    default_section: None,
    resolve_provider: None,
    door: None,
};

/// One provider definition per configured provider, as a providers.yaml would give.
fn defs_for(
    deploy: &busbar_kernel::config::DeployCfg,
) -> std::collections::HashMap<String, busbar_kernel::config::ProviderDef> {
    deploy
        .providers
        .keys()
        .map(|name| {
            let def: busbar_kernel::config::ProviderDef = busbar_contract::yaml::from_str(
                "{ protocol: proto-a, base_url: \"https://provider.invalid\" }",
            )
            .expect("the fixed ProviderDef literal parses");
            (name.clone(), def)
        })
        .collect()
}

/// The admitted provider plane serving `proto-a`: every configured model and pool must be served
/// by a configured provider plane (native provider catalog), so the read reaches the operator check.
fn provider_plane() -> busbar_kernel::plane_driver::provider_catalog::ProviderPlane {
    busbar_kernel::plane_driver::provider_catalog::ProviderPlane {
        instance: "chat".into(),
        image: "admitted-plane".into(),
        dialects: ["proto-a".into()].into(),
        schema: r#"{"type":"object","properties":{},"additionalProperties":false}"#.into(),
    }
}

#[test]
fn a_normalized_1_5_5_token_config_is_refused_with_its_named_remedy() {
    publish_planes(&[&FALLBACK_PLANE]);
    let deploy = busbar_kernel::config::deploy_from_yaml_str(FIXTURE, &fixture_grammar())
        .expect("the fixture parses");
    let errors = match busbar_kernel::config::resolve_with_provider_planes(
        &deploy,
        &defs_for(&deploy),
        &[provider_plane()],
    ) {
        Err(errors) => errors,
        Ok(resolved) => busbar_kernel::config_validate::validate(&resolved.config)
            .err()
            .unwrap_or_default(),
    };
    let remedy = busbar_kernel_identity::operator::operator_token("admin-tokens");
    let install = busbar_kernel_identity::operator::operator_install_remedy();
    assert!(
        errors
            .iter()
            .any(|e| e.contains(&remedy) && e.contains(&install)),
        "refused with operator_token(\"admin-tokens\") and the install remedy: {errors:?}"
    );
    assert!(
        errors
            .iter()
            .all(|e| !e.contains("no admin credential can mint") && !e.contains("``")),
        "never the generic no-mint-path refusal, never an empty word: {errors:?}"
    );
}
