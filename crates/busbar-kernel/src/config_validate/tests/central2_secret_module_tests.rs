// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::secret_module_row;

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
