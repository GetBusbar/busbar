// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The legacy Statement `public_settings` expectations (tests/public_settings_tests.rs), held by
//! the native reader over the same schema shapes.

use super::*;

use busbar_plugin_abi::types::KindCode;

const SCHEMA: &str = r#"{"type":"object","properties":{
    "url":{"type":"string","x-busbar-public":true},
    "timeout_ms":{"type":"integer","x-busbar-public":true},
    "client_secret":{"type":"string","x-busbar-secret":true},
    "retries":{"type":"integer"}
}}"#;

fn described(schema: Option<&str>, secret_paths: &[&str]) -> Described {
    Described {
        kind: KindCode::Auth,
        methods: 0,
        facts: 0,
        items: secret_paths
            .iter()
            .map(|p| (tag::D_SECRET_PATH, p.as_bytes().to_vec()))
            .collect(),
        schema: schema.map(Into::into),
        metrics: Vec::new(),
        error_codes_refused: None,
    }
}

#[test]
fn a_plugin_with_no_schema_has_no_row() {
    assert_eq!(
        public_settings_of_described("stub-plain", &["stub-plain"], &described(None, &[]), &[]),
        Ok(None)
    );
}

#[test]
fn a_schema_declares_its_public_settings_under_every_name() {
    let facts = public_settings_of_described(
        "stub-public",
        &["stub-public", "stub-former"],
        &described(Some(SCHEMA), &["/client_secret"]),
        &["stub-alias"],
    )
    .expect("the schema reads")
    .expect("the stub declares public settings");
    assert_eq!(facts.name, "stub-public");
    assert_eq!(
        facts.public.iter().map(String::as_str).collect::<Vec<_>>(),
        ["timeout_ms", "url"]
    );
    assert_eq!(facts.words, ["stub-alias", "stub-former", "stub-public"]);
}

#[test]
fn a_public_field_holding_a_declared_secret_position_is_refused() {
    for pointer in ["/url", "/url/token", "/*", ""] {
        let refused = public_settings_of_described(
            "stub-leaky",
            &["stub-leaky"],
            &described(Some(SCHEMA), &[pointer]),
            &[],
        )
        .expect_err("refused");
        assert!(
            refused.starts_with("plugin 'stub-leaky': its settings schema: field '"),
            "{pointer}: {refused}"
        );
        assert!(refused.ends_with("cannot be public"), "{refused}");
    }
}

#[test]
fn a_credential_looking_public_field_keeps_the_schema_refusal() {
    let leaky = r#"{"type":"object","properties":{
        "api_token":{"type":"string","x-busbar-public":true}
    }}"#;
    let refused = public_settings_of_described(
        "stub-leaky",
        &["stub-leaky"],
        &described(Some(leaky), &[]),
        &[],
    )
    .expect_err("refused");
    assert!(
        refused.starts_with(
            "plugin 'stub-leaky': its settings schema: field 'api_token' looks like a credential"
        ),
        "{refused}"
    );
}

#[test]
fn pointer_roots_unescape_and_cover_the_whole_document() {
    assert_eq!(pointer_root("/a~1b/c"), "a/b");
    assert_eq!(pointer_root("/m~0n"), "m~n");
    assert_eq!(pointer_root("/*/x"), "*");
    assert_eq!(pointer_root(""), "*");
}
