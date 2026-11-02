// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn duplicate_lifted_sections_and_policies_are_refused_by_the_live_reader() {
    for yaml in [
        "credentials: {}\ncredentials: {}\n",
        "oauth_as: null\noauth_as: null\n",
        "auth: {policy: {self_mint: false}, policy: {self_mint: true}}\n",
    ] {
        let error = deploy_from_yaml_str(yaml)
            .expect_err("duplicates must not replace policy")
            .to_string();
        assert!(error.contains("duplicate field"), "{error}");
    }

    let mut json = serde_json::Deserializer::from_str(r#"{"auth":{"policy":{},"policy":{}}}"#);
    let error = deploy_from_deserializer(&mut json)
        .expect_err("duplicate JSON policy")
        .to_string();
    assert!(
        error.contains("duplicate field") && error.contains("policy"),
        "{error}"
    );
}

#[test]
fn duplicate_provider_names_are_refused_in_deployment_and_catalog_readers() {
    let error = deploy_from_yaml_str("providers: {p: {api_key: none}, p: {api_key: none}}")
        .expect_err("a duplicate deployment must not silently replace its destination")
        .to_string();
    assert!(
        error.contains("duplicate entry") && error.contains("p"),
        "{error}"
    );
    let error = providers::catalog_from_str("p: {protocol: x, base_url: https://one.example}\np: {protocol: x, base_url: https://two.example}\n")
        .expect_err("a duplicate catalog name must not replace its destination").to_string();
    assert!(
        error.contains("duplicate entry") && error.contains("p"),
        "{error}"
    );
}

const POLICY_VAR: &str = "BUSBAR_TEST_KC_DUPLICATE_POLICY_TTL";
const POLICY_TEMPLATE: &str = r#"{providers: {}, models: {}, store: {module: memory}, auth: {policy: {self_mint: false, max_ttl: 7d, default_ttl: "${BUSBAR_TEST_KC_DUPLICATE_POLICY_TTL}"}}}"#;

#[test]
fn interpolation_cannot_replace_a_lifted_auth_policy() {
    let _guard = crate::test_support::EnvVarGuard::capture(POLICY_VAR);
    std::env::set_var(
        POLICY_VAR,
        r#"90d"}, policy: {self_mint: true, default_ttl: "90d"#,
    );
    let error =
        interpolate_env(POLICY_TEMPLATE).expect_err("duplicate-map expansion must fail closed");
    assert!(
        error.contains(POLICY_VAR) && error.contains("refusing to proceed"),
        "{error}"
    );
    assert!(
        !error.contains("self_mint: true"),
        "expanded values must not enter diagnostics"
    );
    std::env::set_var(POLICY_VAR, "3d");
    let expanded = interpolate_env(POLICY_TEMPLATE).expect("ordinary scalar interpolation");
    deploy_from_yaml_str(&expanded).expect("the valid interpolated config still parses");
}

#[test]
fn an_unparseable_interpolation_does_not_echo_a_secret_map_key() {
    const VAR: &str = "BUSBAR_TEST_KC_SECRET_MAP_KEY";
    let _guard = crate::test_support::EnvVarGuard::capture(VAR);
    std::env::set_var(VAR, "secret-value-that-must-not-be-logged");
    let error = interpolate_env(
        r#"{x: {"${BUSBAR_TEST_KC_SECRET_MAP_KEY}": 1, "${BUSBAR_TEST_KC_SECRET_MAP_KEY}": 2}}"#,
    )
    .expect_err("the generic YAML parse refuses duplicate keys");
    assert!(error.contains(VAR), "{error}");
    assert!(
        !error.contains("secret-value-that-must-not-be-logged"),
        "{error}"
    );
}

#[test]
fn disk_loader_refuses_interpolation_before_policy_can_be_overwritten() {
    let _guard = crate::test_support::EnvVarGuard::capture("BUSBAR_TEST_KC_BOOT_POLICY_TTL");
    std::env::set_var(
        "BUSBAR_TEST_KC_BOOT_POLICY_TTL",
        r#"90d"}, policy: {self_mint: true, default_ttl: "90d"#,
    );
    let dir = std::env::temp_dir().join(format!(
        "busbar-kc-env-{}-{}",
        std::process::id(),
        hex::encode(crate::door::op_id().0)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.yaml");
    std::fs::write(
        &path,
        POLICY_TEMPLATE.replace(POLICY_VAR, "BUSBAR_TEST_KC_BOOT_POLICY_TTL"),
    )
    .unwrap();
    std::fs::write(dir.join("providers.yaml"), "{}").unwrap();
    let result = crate::load_config_from_disk(&path, None, false, EnvSubst::Strict);
    let _ = std::fs::remove_dir_all(dir);
    let error = result.err().expect("boot refuses injected policy");
    assert!(
        error.contains("config.yaml:") && error.contains("BUSBAR_TEST_KC_BOOT_POLICY_TTL"),
        "{error}"
    );
}

#[test]
fn hook_timeout_validation_covers_zero_boundary_and_overflow_in_resolved_config() {
    const MAX_MS: u64 = 30 * 365 * 86_400 * 1_000;
    for timeout in [0, 1, MAX_MS] {
        crate::config_validate::validate_hook_timeout("gate", timeout).unwrap();
    }
    let mut deploy = super::tests::base_deploy();
    deploy.hooks.insert(
        "too-slow".into(),
        serde_yaml::from_str(&format!(
            "module: test-hook\nkind: gate\ntimeout_ms: {}",
            u64::MAX
        ))
        .unwrap(),
    );
    let cfg =
        resolve(&deploy, &std::collections::HashMap::new()).expect("no providers need resolving");
    let errors = crate::config_validate::validate(&cfg)
        .expect_err("boot semantic validation refuses the hook timeout");
    assert!(
        errors
            .iter()
            .any(|e| e.contains("too-slow") && e.contains("timeout_ms") && e.contains("30 years")),
        "{errors:?}"
    );
    assert!(crate::config_validate::validate_hook_timeout("gate", MAX_MS + 1).is_err());
}

#[test]
fn noninterpolated_malformed_yaml_keeps_the_typed_readers_diagnostic() {
    let raw = "auth: [";
    assert_eq!(interpolate_env(raw).unwrap(), raw);
    assert!(deploy_from_yaml_str(raw).is_err());
}
