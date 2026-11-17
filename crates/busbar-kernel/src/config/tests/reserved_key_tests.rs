// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DES-359 r3 L10: a reserved or retired key is refused by name, with a coded error, before the
//! typed read, for config.yaml and for admin document publication.

use super::*;
use crate::config::document_patch::DocumentPatch;

const BASE: &str = "providers: {}\nmodels: {}\n";

#[test]
fn plugins_trust_operator_in_config_yaml_is_refused_by_code() {
    let error = deploy_from_yaml_str(
        &format!("plugins:\n  trust:\n    operator: anything\n{BASE}"),
        &Grammar::empty(),
    )
    .expect_err("a reserved key is refused")
    .to_string();
    assert!(error.contains("BUSBAR-3171"), "{error}");
    assert!(error.contains("plugins.trust.operator"), "{error}");
    assert!(
        error.contains("1.6.0 operator plugins must be first-party signed (Q13)"),
        "{error}"
    );
}

#[test]
fn plugins_trust_operator_in_a_document_patch_is_refused_by_code() {
    let patch = DocumentPatch::from_value(
        serde_json::json!({"set": {"/plugins/trust/operator": "anything"}}),
    )
    .unwrap();
    let error = patch
        .patched_text(BASE, |_| Ok(()))
        .expect_err("admin publication refuses the reserved key");
    assert!(error.contains("BUSBAR-3171"), "{error}");
    assert!(error.contains("plugins.trust.operator"), "{error}");
}

#[test]
fn another_unknown_trust_key_keeps_the_generic_error() {
    let error = deploy_from_yaml_str(
        &format!("plugins:\n  trust:\n    bogus: 1\n{BASE}"),
        &Grammar::empty(),
    )
    .expect_err("an unknown key is refused")
    .to_string();
    assert!(error.contains("unknown field `bogus`"), "{error}");
    assert!(!error.contains("BUSBAR-3171"), "{error}");
}
