// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::{checked_reference_result, reference_module_row, secret_module_row};

// Inert admitted-row metadata for the actual host classifier: no door or registry.
fn secret_metadata() -> busbar_contract::plugin_rows::Row {
    use busbar_contract::plugin_rows::{NeedLevel, Row, Trust};
    Row {
        file: "metadata-only.tar.gz".into(),
        key: "acme-secret-vault".into(),
        name: "acme-secret-vault".into(),
        alias: "vault".into(),
        kind: "secret".into(),
        version: "1.0.0".into(),
        abi_version: 1,
        trust: Trust::Trusted {
            publisher: "metadata-only".into(),
            first_party: false,
        },
        ephemeral: false,
        in_process: false,
        linked: false,
        needs_prompt: NeedLevel::No,
        needs_user: NeedLevel::No,
        settings_schema: None,
    }
}
#[test]
fn secrets_block_rejects_unknown_module() {
    let err = secret_module_row("typo-vault", None).unwrap_err();
    assert!(
        err.contains("no loadable") && err.contains("typo-vault"),
        "unknown module named in the error: {err}"
    );
}
#[test]
fn secrets_block_canonicalizes_alias_and_name_to_the_same_key() {
    assert_eq!(
        secret_module_row("vault", Some(secret_metadata())).unwrap(),
        "acme-secret-vault"
    );
    assert_eq!(
        secret_module_row("acme-secret-vault", Some(secret_metadata())).unwrap(),
        "acme-secret-vault"
    );
}
#[test]
fn secrets_block_rejects_non_secret_kind() {
    let mut row = secret_metadata();
    row.kind = "store".into();
    row.key = "acme-store-x".into();
    let err = secret_module_row("x", Some(row)).unwrap_err();
    assert!(
        err.contains("not 'secret'"),
        "wrong-kind rejection names the mismatch: {err}"
    );
}

// Only typed host-policy inputs; no App, plane declaration, registry, or secret axis.
fn host_reference_input(reference: crate::config::SecretRef) -> crate::config::RootCfg {
    let deploy: crate::config::DeployCfg = serde_json::from_value(serde_json::json!({
        "providers": {}, "models": {}, "auth": {"chain": [], "admin_auth": []},
        "store": {"module": "inert-store-metadata"},
    }))
    .expect("host policy input parses");
    let mut cfg =
        crate::config::resolve(&deploy, &Default::default()).expect("host policy input resolves");
    let provider = crate::config::ProviderCfg {
        protocol: "inert-host-metadata".into(),
        base_url: "https://api.example.com".into(),
        api_key: reference,
        health: None,
        error_map: Default::default(),
        path: None,
        path_base: None,
        token_url: None,
        scope: None,
        subject: None,
        auth: None,
        allow_metadata_hosts: Vec::new(),
        options: Default::default(),
    };
    cfg.providers.insert("acme".into(), provider.into());
    cfg
}
fn semantic_reference_errors(cfg: &crate::config::RootCfg) -> Vec<String> {
    let mut errors = Vec::new();
    super::super::validate_cost_model(cfg, &mut errors);
    errors
}

#[test]
fn secret_ref_plugin_backed_module_passes_when_plugin_present() {
    for module in ["vault", "acme-secret-vault"] {
        let cfg = host_reference_input(crate::config::SecretRef {
            module: module.to_string(),
            settings: serde_json::Map::new(),
        });

        assert!(
            semantic_reference_errors(&cfg).is_empty(),
            "pre-registry validate must not reject plugin-backed module '{module}'"
        );

        assert!(
            reference_module_row(
                "providers.acme.api_key",
                module,
                false,
                Some(secret_metadata())
            )
            .is_ok(),
            "a loaded kind:secret plugin '{module}' must pass the secret-ref pre-flight"
        );
    }
}
#[test]
fn secret_ref_typo_module_still_fails_at_preflight() {
    let cfg = host_reference_input(crate::config::SecretRef {
        module: "vaultt".to_string(),
        settings: serde_json::Map::new(),
    });

    assert!(
        semantic_reference_errors(&cfg).is_empty(),
        "pre-registry validate cannot (and must not) reject the unknown module by itself"
    );
    let err = reference_module_row("providers.acme.api_key", "vaultt", false, None)
        .expect_err("a typo'd secret module with no plugin must fail the pre-flight");
    assert!(
        err.contains("providers.acme.api_key")
            && err.contains("vaultt")
            && err.contains("no loadable"),
        "the error must name the ref and the unknown module: {err}"
    );
}
#[test]
fn secret_ref_builtin_modules_pass_with_empty_registry() {
    assert!(
        reference_module_row("providers.acme.api_key", "env", true, None).is_ok(),
        "a built-in env ref must pass the pre-flight with no plugins loaded"
    );
}
#[test]
fn a_reference_its_plugins_check_refuses_fails_the_preflight() {
    assert_eq!(
        checked_reference_result(
            "providers.acme.api_key",
            Err(vec![
                "settings.path: missing".to_string(),
                "settings: names no secret".to_string()
            ])
        ),
        Err("providers.acme.api_key: settings.path: missing\n\
             providers.acme.api_key: settings: names no secret"
            .to_string())
    );
    assert_eq!(
        checked_reference_result("providers.acme.api_key", Ok(())),
        Ok(())
    );
}
#[test]
fn secret_ref_wrong_kind_plugin_fails_at_preflight() {
    let mut row = secret_metadata();
    row.kind = "store".into();
    row.key = "acme-store-x".into();
    let err = reference_module_row("providers.acme.api_key", "x", false, Some(row))
        .expect_err("a store-kind plugin cannot back a secret reference");
    assert!(
        err.contains("not 'secret'") && err.contains("providers.acme.api_key"),
        "wrong-kind rejection names the ref and mismatch: {err}"
    );
}
