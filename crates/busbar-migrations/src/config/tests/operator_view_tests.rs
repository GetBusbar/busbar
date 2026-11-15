// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OP-3B: pass 1 (`normalize_plugins_view`), the `ViewOnly` host, the 1.5 `token:` definition
//! passing through the plugin-settings walker (R20, R21's normalize half), and the 1.4
//! `governance.admin_token` step with no operator words (R15).

use busbar_contract::abi::sdk::migrate::MigrationAnswer;
use busbar_contract::persistence::lifecycle::DocumentSemantics;
use busbar_contract::yaml::{self, prelude::*};

use super::{normalize_plugins_view, normalize_supported_source};
use crate::config::migrate::migrate_config;
use crate::config::migrate_plugins::{MigrateHost, NoPlugins, ViewOnly};

const V155: &str =
    include_str!("../../../../../tests/migration-corpus/from-tags/v1.5.5_config.yaml");
const AFTER_NORMALIZE: &str =
    include_str!("../../../tests/fixtures/operator_token_after_normalize.yaml");

/// A host whose `validate_*` refuses `kind: auth` settings without `sha256`, as admin-tokens
/// does, and a `store` module named `refused` outright.
struct ShaHost;

impl MigrateHost for ShaHost {
    fn validate_migrated(
        &self,
        kind: &str,
        module: &str,
        settings: &serde_json::Value,
    ) -> Result<(), String> {
        match kind {
            "auth" if settings.get("sha256").is_none() => Err("settings need a sha256".into()),
            "store" if module == "refused" => Err("refused".into()),
            _ => Ok(()),
        }
    }

    fn migrate(
        &self,
        _: &str,
        _: &str,
        _: &serde_json::Value,
        _: &str,
    ) -> Result<Option<(String, MigrationAnswer)>, String> {
        Ok(None)
    }

    fn repin(&self, _: &str) -> Result<Option<String>, String> {
        Ok(None)
    }

    fn release_for(&self, _: &str, _: &str) -> Result<Option<String>, String> {
        Ok(None)
    }
}

fn plugins_of(text: &str) -> Option<Value> {
    let doc: Value = yaml::from_str(text).expect("YAML");
    doc.get("plugins").cloned()
}

fn body(text: &str) -> Value {
    let kept: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();
    yaml::from_str(&kept.join("\n")).expect("the migrated document parses")
}

#[test]
fn view_only_answers_auth_ok_and_delegates_every_other_kind() {
    let settings = serde_json::json!({});
    ShaHost
        .validate_migrated("auth", "admin-tokens", &settings)
        .expect_err("the host itself refuses auth settings without sha256");
    let view = ViewOnly(&ShaHost);
    assert!(view
        .validate_migrated("auth", "admin-tokens", &settings)
        .is_ok());
    assert!(view
        .validate_current("auth", "admin-tokens", &settings)
        .is_ok());
    view.validate_migrated("store", "refused", &settings)
        .expect_err("a non-auth kind is delegated");
    view.validate_current("store", "refused", &settings)
        .expect_err("a non-auth kind is delegated");
    assert!(view.validate_migrated("store", "fine", &settings).is_ok());
}

#[test]
fn normalize_plugins_view_over_the_1_5_5_config_returns_the_golden_plugins() {
    let view = normalize_plugins_view(V155, &ShaHost);
    assert!(view.is_ok(), "pass 1 refused: {view:?}");
    let golden = normalize_supported_source(DocumentSemantics::Historical, V155, &NoPlugins)
        .expect("normalizes under a host that checks nothing");
    assert_eq!(view.ok().flatten(), plugins_of(&golden.yaml));
}

#[test]
fn full_normalization_of_the_1_5_5_config_keeps_the_token_definition() {
    let out = normalize_supported_source(DocumentSemantics::Historical, V155, &ShaHost)
        .unwrap_or_else(|e| panic!("normalization refused: {e}"));
    let after = body(&out.yaml);
    let definition = after.at("identity-providers").at("admin-tokens");
    assert_eq!(
        *definition,
        *body(V155).at("identity-providers").at("admin-tokens"),
        "the token: definition passes through untouched:\n{}",
        out.yaml
    );
    assert!(definition.at("settings").is_null());
    // The checked-in output the kernel half reads keeps the same definition.
    assert_eq!(
        *definition,
        *body(AFTER_NORMALIZE)
            .at("identity-providers")
            .at("admin-tokens")
    );
}

#[test]
fn a_1_4_admin_token_with_no_operator_row_writes_no_empty_key() {
    assert_eq!(busbar_kernel_identity::operator::provider(), "");
    for (token, secret) in [
        ("\"${LEGACY_ADMIN_TOKEN_VAR}\"", "LEGACY_ADMIN_TOKEN_VAR"),
        ("literal-secret-value", "BUSBAR_ADMIN_TOKEN"),
    ] {
        let raw = format!("governance:\n  admin_token: {token}\n");
        let out = migrate_config(&raw).expect("migrates");
        let after = body(&out.yaml);
        assert!(
            after.at("auth").at("admin_auth").is_null(),
            "nothing is written under an empty key:\n{}",
            out.yaml
        );
        let written: String = out
            .yaml
            .lines()
            .filter(|l| !l.starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!written.contains(secret), "{written}");
        assert!(
            !out.changes
                .iter()
                .any(|c| c.starts_with("governance.admin_token ->")),
            "{:?}",
            out.changes
        );
        assert!(
            out.todos.iter().any(|t| t.contains("Install")
                && t.contains("identity-providers")
                && t.contains("sha256")),
            "the TODO carries the install remedy: {:?}",
            out.todos
        );
    }
}
