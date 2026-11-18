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

#[test]
fn outbound_styles_keep_describe_order_and_their_declared_flags() {
    let mut d = described(None, &[]);
    d.items = vec![
        (
            busbar_plugin_abi::auth::tag::D_OUTBOUND_STYLE,
            b"jwt-bearer".to_vec(),
        ),
        (tag::D_SECRET_PATH, b"/key".to_vec()),
        (
            busbar_plugin_abi::auth::tag::D_OUTBOUND_STYLE,
            b"client-credentials".to_vec(),
        ),
    ];
    let styles = auth_styles_of_described(&d, |name| u64::from(name == "jwt-bearer") * 4);
    assert_eq!(
        styles,
        [
            AuthStyle {
                name: "jwt-bearer".into(),
                flags: 4,
            },
            AuthStyle {
                name: "client-credentials".into(),
                flags: 0,
            },
        ]
    );
    assert!(auth_styles_of_described(&described(None, &[]), |_| 1).is_empty());
}

/// A chain module is an auth image that declares inbound verify. The legacy "reads no host-held
/// credentials" half needs no native fact: in MIN-3 core alone reads host-held credentials
/// (KEY_CARRIERS, `Keys::build`; ABI-MIN3 r34 l.12131, §12.8, §16.119).
#[test]
fn an_auth_image_declaring_inbound_verify_is_a_chain_module() {
    use busbar_plugin_abi::auth::{M_OUTBOUND, M_VERIFY, M_VERIFY_IO};
    let mut verify = described(None, &[]);
    verify.methods = M_VERIFY;
    assert!(declares_chain_module(&verify));
    let mut verify_io = described(None, &[]);
    verify_io.methods = M_VERIFY_IO | M_OUTBOUND;
    assert!(declares_chain_module(&verify_io));

    let mut outbound_only = described(None, &[]);
    outbound_only.methods = M_OUTBOUND;
    assert!(!declares_chain_module(&outbound_only));
    let mut other_kind = described(None, &[]);
    other_kind.kind = KindCode::Store;
    other_kind.methods = M_VERIFY;
    assert!(!declares_chain_module(&other_kind));
}
