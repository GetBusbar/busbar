// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{early_cli_flags_of, render_help, Argv};

#[test]
fn the_list_plugins_header_heads_the_row_formats_columns() {
    let names: Vec<&str> = super::LIST_PLUGINS_HEADER.split_whitespace().collect();
    assert_eq!(names.len(), 7, "six columns and STATUS");
    assert_eq!(
        super::LIST_PLUGINS_HEADER,
        format!(
            "{:<34} {:<24} {:<12} {:<6} {:<9} {:<24} {}",
            names[0], names[1], names[2], names[3], names[4], names[5], names[6]
        )
    );
}

#[test]
fn the_default_distributions_help_is_byte_identical() {
    assert_eq!(
        render_help("<VERSION>"),
        include_str!(
            "../../../../../testing/shadow-oracle/fixtures/law0/help-default-build-1.6.0.txt"
        )
    );
}

#[test]
fn list_plugins_refuses_a_config_that_exists_but_cannot_be_parsed() {
    let dir = std::env::temp_dir().join(format!("busbar-listplugins-3016-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let broken = dir.join("config.yaml");
    std::fs::write(&broken, "plugins: [this is: not: valid\n  - {\n").unwrap();
    let refused = super::list_plugins_config(&broken, None);
    let absent = super::list_plugins_config(&dir.join("absent.yaml"), None);
    std::fs::remove_dir_all(&dir).ok();
    let message = refused.expect_err("a broken config must refuse, not inventory the default dir");
    assert!(message.contains("BUSBAR-3016"), "{message}");
    assert!(absent.is_ok(), "no config file is a bare inventory");
}

fn parsed(words: &[&str]) -> Argv {
    Argv::parse(words.iter().copied())
}

/// WP1-GAP r3 §1.3, B-N9 and B2: `--stdio` with a value, twice, beside an exiting command or beside
/// a principal transition is a usage refusal (exit 2), decided by the early arms.
#[test]
fn stdio_argument_rules_refuse_with_usage() {
    for words in [
        &["--stdio=mcp"][..],
        &["--stdio", "--stdio"],
        &["--stdio", "--help"],
        &["--help", "--stdio"],
        &["--stdio", "-h"],
        &["--stdio", "--version"],
        &["--stdio", "--validate"],
        &["--stdio", "--list-plugins"],
        &["--stdio", "--generate-signing-key"],
        &[
            "--stdio",
            "--principal-transition",
            "-",
            "--transition-action",
            "inspect",
        ],
    ] {
        assert_eq!(early_cli_flags_of(&parsed(words)), Some(2), "{words:?}");
    }
    for words in [
        &["--stdio"][..],
        &["--stdio", "-c", "config.yaml"],
        &["--stdio", "--providers", "providers.yaml"],
    ] {
        let argv = parsed(words);
        assert!(argv.stdio, "{words:?}");
        assert_eq!(early_cli_flags_of(&argv), None, "{words:?} serves");
        assert_eq!(
            super::ordinary_cli_flags_of(&argv),
            None,
            "{words:?} serves"
        );
    }
    assert!(!parsed(&[]).stdio);
}

/// B-N1 and B2: the informational arms answer from the early group, before anything is scanned or
/// read, so a configuration path that does not exist cannot change their answer.
#[test]
fn help_version_and_signing_key_touch_no_file() {
    let absent = std::env::temp_dir().join(format!(
        "busbar-early-arms-{}/no/such/config.yaml",
        std::process::id()
    ));
    let absent = absent.to_str().expect("a UTF-8 temp path");
    for arm in [
        "--help",
        "-h",
        "--version",
        "-V",
        "--build-info",
        "--generate-signing-key",
    ] {
        assert_eq!(
            early_cli_flags_of(&parsed(&["-c", absent, arm])),
            Some(0),
            "{arm}"
        );
    }
    assert!(!std::path::Path::new(absent).exists());
    for late in ["--validate", "--list-plugins", "--print-metadata-blocklist"] {
        assert_eq!(
            early_cli_flags_of(&parsed(&[late])),
            None,
            "{late} reads the start grammar"
        );
    }
}

/// B-N10: the retired `--mcp-stdio` spelling is an unknown argument like any other; core holds no
/// plugin flag, and the unknown-argument refusal stays in the late group (B2).
#[test]
fn an_unknown_flag_gets_the_generic_refusal() {
    let argv = parsed(&["--mcp-stdio"]);
    assert!(!argv.stdio);
    assert_eq!(early_cli_flags_of(&argv), None);
    assert_eq!(super::ordinary_cli_flags_of(&argv), Some(2));
    assert!(!render_help("<VERSION>").contains("mcp-stdio"));
}

/// SECREF-BOOT: `--validate` resolves the documented `{ file: .. }` and `{ env: .. }` secret
/// references (docs/operations.md) through the linked secret images, as boot does: a config that
/// boots validates. A reference that does not resolve, and one naming a secret module no image
/// admits, are still refused.
#[cfg(distribution_root)]
#[test]
fn secret_ref_validate_resolves_documented_env_and_file_references_as_boot_does() {
    use crate::root::test_plugins as plugins;
    crate::dist_root_install::install();
    busbar_kernel::preflight::install_operator(crate::root::auth_bindings::operator_binding());
    // The start stage's publish (`register_root`): the linked secret images' grammar.
    crate::root::native_secrets::linked_for_tests();
    let library_path = plugins::application_store_library();
    let module = plugins::native_image(&library_path).name;
    let manifest = plugins::native_manifest("store", &library_path, plugins::FIXTURE_PUBLISHER);
    let library = std::fs::read(&library_path).expect("the application Store image reads");
    let directory = plugins::scratch("validate-secret-ref");
    std::fs::write(
        directory.join("store.tar.gz"),
        plugins::signed(&crate::dist_root_install::release_key(), manifest, &library),
    )
    .expect("stage the signed application Store");
    let key = directory.join("signing.key");
    std::fs::write(&key, "5a".repeat(32)).expect("write the signing key file");
    let variable = "BUSBAR_SECREF_BOOT_VALIDATE_SIGNING_KEY";
    std::env::set_var(variable, "5a".repeat(32));
    let providers = directory.join("providers.yaml");
    std::fs::write(&providers, "{}\n").expect("write providers.yaml");
    let plain = serde_json::json!({ "accept": ["plaintext"], "reason": "validate fixture" });
    let validate = |signing_key: serde_json::Value| -> Result<(), String> {
        let config = directory.join("config.yaml");
        let document = serde_json::json!({
            "providers": {},
            "models": {},
            "listen_insecure_transport": plain,
            "admin_listen_insecure_transport": plain,
            "auth": { "chain": [], "signing_key": signing_key },
            "store": { "module": module, "settings": plugins::application_store_settings(&directory) },
            "plugins": plugins::trusted_config_document(&directory),
        });
        std::fs::write(
            &config,
            serde_json::to_string(&document).expect("the document encodes"),
        )
        .expect("write config.yaml");
        super::validate_judged(&config, Some(&providers), false)
            .map(drop)
            .map_err(|refused| refused.render())
    };

    let file = validate(serde_json::json!({ "file": key }));
    assert!(
        file.is_ok(),
        "a documented `{{file: ..}}` signing key that resolves validates: {file:?}"
    );
    let env = validate(serde_json::json!({ "env": variable }));
    assert!(
        env.is_ok(),
        "a documented `{{env: ..}}` signing key that resolves validates: {env:?}"
    );
    let absent = validate(serde_json::json!({ "file": directory.join("absent.key") }));
    assert!(
        absent
            .as_ref()
            .is_err_and(|refused| refused.contains("auth.signing_key")),
        "a `{{file: ..}}` that does not resolve is refused by its position: {absent:?}"
    );
    let unset = validate(serde_json::json!({ "env": "BUSBAR_SECREF_BOOT_NEVER_SET" }));
    assert!(
        unset
            .as_ref()
            .is_err_and(|refused| refused.contains("auth.signing_key")),
        "an `{{env: ..}}` naming an unset variable is refused by its position: {unset:?}"
    );
    let unadmitted = validate(serde_json::json!({
        "module": "secret-not-admitted", "settings": { "path": key },
    }));
    assert!(
        unadmitted.is_err(),
        "a reference to a secret module no image admits is refused"
    );
    std::env::remove_var(variable);
    std::fs::remove_dir_all(&directory).expect("remove the validate fixture");
}
