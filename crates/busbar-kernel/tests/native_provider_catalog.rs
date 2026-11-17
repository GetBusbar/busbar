// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::json::JsonValueTrait as _;
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
fn selected_resource_is_shared_by_actual_direct_and_pool_targets() {
    let deployment = DEPLOY.replace(
        "upstream_model: wire-model-a",
        "upstream_model: wire-model-a\n    resource: shared",
    );
    let result = resolved(
        CATALOG,
        &deployment,
        &[plane("chat", &["wire-a", "wire-b"], SCHEMA)],
    );
    let plan = &result.catalogs["chat"];
    for selector in ["fast", "slow", "m0"] {
        assert_eq!(
            plan.target(plan.select(selector).unwrap(), "chat\u{1f}m0")
                .unwrap()
                .resource
                .as_deref(),
            Some("shared")
        );
    }
    assert!(plan
        .target(plan.select("fast").unwrap(), "chat\u{1f}m1")
        .unwrap()
        .resource
        .is_none());
    for value in [
        "''".to_owned(),
        "x".repeat(129),
        "é".repeat(65),
        "\"bad\\nlabel\"".to_owned(),
    ] {
        let invalid = DEPLOY.replace(
            "upstream_model: wire-model-a",
            &format!("upstream_model: wire-model-a\n    resource: {value}"),
        );
        assert!(refused(
            CATALOG,
            &invalid,
            &[plane("chat", &["wire-a", "wire-b"], SCHEMA)]
        )
        .contains("resource"));
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

use busbar_kernel::config::{self, providers, Grammar, ResolvedConfig};
use busbar_kernel::plane_driver::provider_catalog::{ProviderPlane, RouteKind};

const CATALOG: &str = "p:\n  protocol: wire-a\n  base_url: https://upstream.example/api\n  path: /chat?fixed=one\n  path_base: /models\n  required_option: catalog\n  capabilities: [{models: ['wire-*'], enabled: true}]\nunused:\n  protocol: unsupported\n  base_url: https://unused.example\n  arbitrary_menu_property: [false, 5]\n";
const DEPLOY: &str = "providers:\n  p:\n    api_key: {module: fixture-secret, settings: {slot: lane-key}}\nmodels:\n  m0:\n    provider: p\n    upstream_model: wire-model-a\n    max_concurrent: 2\n    max_requests: 19\n    default_max_tokens: 23\n    reasoning: true\n    prompt_caching: false\n  m1:\n    provider: p\n    dialect: wire-b\n    upstream_model: wire-model-b\npools:\n  fast:\n    members: [{model: m0, reasoning: false, context_max: 1000}, m1]\n    weights: {m0: 7}\n    tier: standard\n    attempt_timeout_ms: 41\n  slow:\n    members: [m0]\n    upstream_credentials: passthrough\n    attempt_timeout_ms: 99\n";
const SCHEMA: &str = r#"{"type":"object","properties":{"required_option":{"type":"string"},"capabilities":{"type":"array","items":{"type":"object","properties":{"models":{"type":"array","items":{"type":"string"}},"enabled":{"type":"boolean"}},"required":["models"],"additionalProperties":false}}},"required":["required_option"],"additionalProperties":false}"#;

fn plane(instance: &str, dialects: &[&str], schema: &str) -> ProviderPlane {
    ProviderPlane {
        instance: instance.into(),
        image: format!("image-{instance}"),
        dialects: dialects.iter().map(|d| (*d).to_owned()).collect(),
        schema: schema.into(),
    }
}

fn resolve(
    catalog: &str,
    deployment: &str,
    planes: &[ProviderPlane],
) -> Result<ResolvedConfig, Vec<String>> {
    let grammar = Grammar::empty();
    let definitions = providers::catalog_from_str(catalog, &grammar).expect("catalog core grammar");
    let deploy =
        config::deploy_from_yaml_str(deployment, &grammar).expect("deployment core grammar");
    config::resolve_with_provider_planes(&deploy, &definitions, planes)
}

fn resolved(catalog: &str, deployment: &str, planes: &[ProviderPlane]) -> ResolvedConfig {
    resolve(catalog, deployment, planes).unwrap_or_else(|errors| panic!("{errors:?}"))
}

fn refused(catalog: &str, deployment: &str, planes: &[ProviderPlane]) -> String {
    match resolve(catalog, deployment, planes) {
        Ok(_) => panic!("invalid native catalog was accepted"),
        Err(errors) => errors.join("\n"),
    }
}

#[test]
fn native_catalog_resolves_real_pool_members_and_direct_models_without_a_legacy_door() {
    let result = resolved(
        CATALOG,
        DEPLOY,
        &[plane("chat", &["wire-a", "wire-b"], SCHEMA)],
    );
    let plan = &result.catalogs["chat"];
    let fast = plan.select("fast").unwrap();
    let slow = plan.select("slow").unwrap();
    let direct = plan.select("m0").unwrap();
    assert_ne!(fast, slow);
    assert_ne!(fast, direct);
    assert!(plan.select("").is_none());
    assert!(plan.select("unknown").is_none());
    assert!(plan.select("wire-model-a").is_none());
    assert!(matches!(&plan.pools()[fast].kind, RouteKind::NamedPool(name) if name == "fast"));
    assert!(matches!(&plan.pools()[direct].kind, RouteKind::DirectModel(name) if name == "m0"));
    let a = plan.target(fast, "chat\u{1f}m0").unwrap();
    let b = plan.target(fast, "chat\u{1f}m1").unwrap();
    assert_eq!(
        (&*a.model, &*a.wire_model, &*a.dialect),
        ("m0", "wire-model-a", "wire-a")
    );
    assert_eq!(
        (&*b.model, &*b.wire_model, &*b.dialect),
        ("m1", "wire-model-b", "wire-b")
    );
    assert!(plan.target(fast, "m0").is_none());
    assert!(plan.target(fast, "other\u{1f}m0").is_none());
    assert!(plan.target("unknown", "chat\u{1f}m0").is_none());
    assert_eq!(a.max_concurrent, Some(2));
    assert_eq!(a.max_requests, 19);
    assert_eq!(a.context_max, Some(1000));
    assert_eq!(a.attempt_timeout_ms, Some(41));
    assert_eq!(
        plan.target(slow, "chat\u{1f}m0")
            .unwrap()
            .attempt_timeout_ms,
        Some(99)
    );
    assert_eq!(
        plan.target(slow, "chat\u{1f}m0").unwrap().credential_mode,
        busbar_contract::config::UpstreamCreds::Passthrough
    );
    assert_eq!(plan.pools()[fast].config.members[0].weight, 7);
    assert_eq!(
        plan.pools()[fast].config.members[0].tier.as_deref(),
        Some("standard")
    );
    assert_eq!(a.base_path, "/models");
    let param = |key: &str| {
        a.params
            .iter()
            .find(|(k, _)| k.as_ref() == key)
            .map(|(_, v)| v.as_ref())
    };
    assert_eq!(param("path"), Some("/chat?fixed=one"));
    assert_eq!(param("reasoning"), Some("false"));
    assert_eq!(param("default_max_tokens"), Some("23"));
    assert_eq!(param("prompt_caching"), Some("false"));
    let projection: busbar_contract::json::Value =
        busbar_contract::json::parse_value(a.projection.as_bytes()).unwrap();
    assert_eq!(projection["capabilities"][0]["models"][0], "wire-*");
    for key in CORE_PROVIDER_KEYS {
        assert!(projection.get(*key).is_none(), "{key}");
    }
    assert!(!a.projection.contains("lane-key"));
    assert!(!a.projection.contains("upstream.example"));
}

#[test]
fn merged_required_options_can_come_from_deployment_and_unused_catalog_data_is_ignored() {
    let catalog = CATALOG.replace("  required_option: catalog\n", "");
    let deploy = DEPLOY.replace(
        "    api_key:",
        "    required_option: deployment\n    api_key:",
    );
    let result = resolved(
        &catalog,
        &deploy,
        &[plane("chat", &["wire-a", "wire-b"], SCHEMA)],
    );
    assert!(result.catalogs["chat"]
        .targets()
        .values()
        .all(|target| target.projection.contains("deployment")));
}

#[test]
fn same_provider_gets_each_reached_images_projection_and_unrelated_images_cannot_forgive_keys() {
    let deployment = "providers:\n  p:\n    api_key: {module: fixture-secret, settings: {slot: key}}\nmodels:\n  m0: {provider: p}\n";
    let catalog =
        "p:\n  protocol: wire-a\n  base_url: https://upstream.example\n  alpha: a\n  beta: b\n";
    let a = plane(
        "a",
        &["wire-a"],
        r#"{"type":"object","properties":{"alpha":{"type":"string"}},"additionalProperties":false}"#,
    );
    let b = plane(
        "b",
        &["wire-a"],
        r#"{"type":"object","properties":{"beta":{"type":"string"}},"additionalProperties":false}"#,
    );
    let result = resolved(catalog, deployment, &[a.clone(), b.clone()]);
    assert_eq!(
        result.catalogs["a"]
            .targets()
            .values()
            .next()
            .unwrap()
            .projection
            .as_ref(),
        r#"{"alpha":"a"}"#
    );
    assert_eq!(
        result.catalogs["b"]
            .targets()
            .values()
            .next()
            .unwrap()
            .projection
            .as_ref(),
        r#"{"beta":"b"}"#
    );
    let unrelated = ProviderPlane {
        dialects: ["other".to_owned()].into(),
        ..b
    };
    assert!(
        refused(catalog, deployment, &[a, unrelated]).contains("providers.yaml providers.p.beta")
    );
}

#[test]
fn deployment_plane_property_without_reach_refuses_even_when_an_image_admits_it() {
    let deployment = "providers:\n  p:\n    api_key: {module: fixture-secret, settings: {slot: key}}\n    required_option: authored\n";
    let error = refused(
        CATALOG,
        deployment,
        &[plane("chat", &["wire-a", "wire-b"], SCHEMA)],
    );
    assert!(
        error.contains("config.yaml providers.p.required_option: provider is not reached"),
        "{error}"
    );
}

#[test]
fn no_descriptor_authority_or_incompatible_pool_is_a_configuration_refusal() {
    assert!(refused(CATALOG, DEPLOY, &[]).contains("no configured provider plane"));
    let separate = [
        plane("a", &["wire-a"], SCHEMA),
        plane("b", &["wire-b"], SCHEMA),
    ];
    assert!(refused(CATALOG, DEPLOY, &separate)
        .contains("pools.fast: no configured provider plane serves every member"));
}

#[test]
fn optional_core_null_really_unsets_catalog_path_and_required_null_is_not_defaulted() {
    let deployment = DEPLOY.replace(
        "    api_key:",
        "    path: null\n    path_base: null\n    capabilities: null\n    api_key:",
    );
    let result = resolved(
        CATALOG,
        &deployment,
        &[plane("chat", &["wire-a", "wire-b"], SCHEMA)],
    );
    assert!(result.config.providers["p"].path.is_none());
    for target in result.catalogs["chat"].targets().values() {
        assert!(target.base_path.is_empty());
        assert!(!target.params.iter().any(|(k, _)| k.as_ref() == "path"));
        assert!(!target.projection.contains("capabilities"));
    }
    let invalid = DEPLOY.replace("    api_key:", "    required_option: null\n    api_key:");
    let error = refused(
        CATALOG,
        &invalid,
        &[plane("chat", &["wire-a", "wire-b"], SCHEMA)],
    );
    assert!(
        error.contains("config.yaml providers.p/required_option: schema"),
        "{error}"
    );
    let invalid = DEPLOY.replace("    api_key:", "    protocol: null\n    api_key:");
    assert!(refused(
        CATALOG,
        &invalid,
        &[plane("chat", &["wire-a", "wire-b"], SCHEMA)]
    )
    .contains("providers.p.protocol: required"));
}

#[test]
fn nested_schema_refusals_preserve_pointer_without_echoing_values() {
    let invalid = DEPLOY.replace(
        "    api_key:",
        "    capabilities: [{models: ['wire-*'], enabled: DO_NOT_ECHO_THIS}]\n    api_key:",
    );
    let error = refused(
        CATALOG,
        &invalid,
        &[plane("chat", &["wire-a", "wire-b"], SCHEMA)],
    );
    assert!(
        error.contains("config.yaml providers.p/capabilities/0/enabled: schema"),
        "{error}"
    );
    assert!(!error.contains("DO_NOT_ECHO_THIS"));
}

#[test]
fn provider_projection_uses_the_existing_stray_secret_scanner() {
    let invalid = DEPLOY.replace("    api_key:", "    capabilities: [{module: fixture-secret, settings: {slot: DO_NOT_ECHO_THIS}}]\n    api_key:");
    let error = refused(
        CATALOG,
        &invalid,
        &[plane("chat", &["wire-a", "wire-b"], SCHEMA)],
    );
    assert!(error.contains("StraySecret"), "{error}");
    assert!(!error.contains("DO_NOT_ECHO_THIS"));
}

#[test]
fn request_alias_cannot_ambiguously_name_both_model_and_pool() {
    let invalid = DEPLOY.replace("  fast:\n", "  m0:\n");
    assert!(refused(
        CATALOG,
        &invalid,
        &[plane("chat", &["wire-a", "wire-b"], SCHEMA)]
    )
    .contains("invalid or ambiguous"));
}

#[test]
fn merged_string_map_preserves_each_members_document_origin() {
    let catalog = "p:\n  protocol: wire-a\n  base_url: https://upstream.example\n  options: {catalog: DO_NOT_ECHO, replaced: old}\n";
    let deploy = "providers:\n  p:\n    api_key: {module: fixture-secret, settings: {slot: key}}\n    options: {replaced: good}\nmodels:\n  m: {provider: p}\n";
    let schema = r#"{"type":"object","properties":{"options":{"type":"object","additionalProperties":{"enum":["good"]}}}}"#;
    let error = refused(catalog, deploy, &[plane("chat", &["wire-a"], schema)]);
    assert!(
        error.contains("providers.yaml providers.p/options/catalog: schema"),
        "{error}"
    );
    assert!(!error.contains("DO_NOT_ECHO"));
}

#[test]
fn validation_paths_does_not_change_ordinary_schema_validation() {
    let check = busbar_contract::json::SchemaCheck::new(
        br#"{"type":"object","properties":{"flag":{"type":"boolean"}}}"#,
    )
    .unwrap();
    let invalid = br#"{"flag":"SENSITIVE_VALUE"}"#;
    let paths = check.validation_paths(invalid).unwrap_err();
    assert_eq!(paths.0, "/flag");
    assert_eq!(paths.1, "/properties/flag/type");
    assert!(!format!("{paths:?}").contains("SENSITIVE_VALUE"));
    assert!(check.validate(invalid).is_err());
    assert!(check.validate(br#"{"flag":true}"#).is_ok());
    assert!(check.validation_paths(br#"{"flag":true}"#).is_ok());
}

#[test]
fn declared_pattern_properties_own_header_options_without_core_header_knowledge() {
    let catalog =
        "p:\n  protocol: wire-a\n  base_url: https://upstream.example\n  X-Option: catalog\n";
    let deploy = "providers:\n  p:\n    api_key: {module: fixture-secret, settings: {slot: key}}\nmodels:\n  m: {provider: p}\n";
    let schema = r#"{"type":"object","properties":{},"patternProperties":{"^[Xx]-[Oo]ption$":{"type":"string"}},"additionalProperties":false}"#;
    let result = resolved(catalog, deploy, &[plane("chat", &["wire-a"], schema)]);
    assert_eq!(
        result.catalogs["chat"]
            .targets()
            .values()
            .next()
            .unwrap()
            .projection
            .as_ref(),
        r#"{"X-Option":"catalog"}"#
    );
    let wrong = catalog.replace("X-Option", "X-Unknown");
    assert!(
        refused(&wrong, deploy, &[plane("chat", &["wire-a"], schema)])
            .contains("no reached image owns")
    );
}

#[test]
fn declared_nested_optional_nulls_unset_without_dropping_required_nulls() {
    let planes = [plane("chat", &["wire-a", "wire-b"], SCHEMA)];
    let optional = DEPLOY.replace(
        "    api_key:",
        "    capabilities: [{models: ['wire-*'], enabled: null}]\n    api_key:",
    );
    let result = resolved(CATALOG, &optional, &planes);
    assert!(!result.catalogs["chat"]
        .targets()
        .values()
        .next()
        .unwrap()
        .projection
        .contains("enabled"));
    let required = DEPLOY.replace(
        "    api_key:",
        "    capabilities: [{models: null}]\n    api_key:",
    );
    assert!(refused(CATALOG, &required, &planes).contains("/capabilities/0/models"));
}

#[test]
fn auth_binding_form_retains_catalog_style_deployment_instance_and_explicit_unset() {
    use busbar_kernel::plane_driver::provider_catalog::ProviderAuthSelection;
    let planes = [plane("chat", &["wire-a", "wire-b"], SCHEMA)];
    let catalog = CATALOG.replace(
        "  protocol: wire-a",
        "  auth: catalogue-style\n  protocol: wire-a",
    );
    let inherited = resolved(&catalog, DEPLOY, &planes);
    assert!(inherited.catalogs["chat"].targets().values().all(|target| matches!(&target.auth_selection, ProviderAuthSelection::Style(name) if name == "catalogue-style")));
    let explicit = DEPLOY.replace(
        "    api_key:",
        "    auth: actual-auth-instance\n    api_key:",
    );
    let explicit = resolved(&catalog, &explicit, &planes);
    assert!(explicit.catalogs["chat"].targets().values().all(|target| matches!(&target.auth_selection, ProviderAuthSelection::Instance(name) if name == "actual-auth-instance")));
    let unset = DEPLOY.replace("    api_key:", "    auth: null\n    api_key:");
    let unset = resolved(&catalog, &unset, &planes);
    assert!(unset.catalogs["chat"]
        .targets()
        .values()
        .all(|target| matches!(&target.auth_selection, ProviderAuthSelection::Implicit)));
}
