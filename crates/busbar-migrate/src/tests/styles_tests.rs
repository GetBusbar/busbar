// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-OUTBOUND-STYLE (IF §14, §12.10 item 3, §12.18): every deferred `{"$style": w}` binding becomes
//! the identity of the unique admitted auth plugin declaring that style, in one process, between
//! `Registry::add` and `boot_plan`. The fixtures name styles and identities, never a plugin.

use busbar_contract::yaml::{self, Value, ValueExt};

use crate::styles::resolve;

const DEFERRED: &str = "config_version: 1\nauth:\n  anthropic-outbound:\n    module: {\"$style\": jwt-bearer}\n    config: {style: jwt-bearer, credential: {env: KEY}}\n  mine:\n    module: written-by-hand\n    config: {style: other}\n";

fn tree(text: &str) -> Value {
    yaml::from_str(text).expect("parses")
}

#[test]
fn a_style_becomes_the_unique_declaring_identity_and_only_that_binding_changes() {
    let styles: [(&str, &[&str]); 2] = [("auth-jwt", &["jwt-bearer", "x"]), ("auth-other", &["other"])];
    let (written, lines) = resolve(DEFERRED, &styles).expect("resolves");
    let tree = tree(&written);
    assert_eq!(tree.at("auth").at("anthropic-outbound").at("module").as_str(), Some("auth-jwt"));
    assert_eq!(tree.at("auth").at("mine").at("module").as_str(), Some("written-by-hand"));
    assert_eq!(tree.at("auth").at("anthropic-outbound").at("config").at("style").as_str(), Some("jwt-bearer"));
    assert!(!written.contains("$style"));
    assert_eq!(lines.len(), 1, "{lines:?}");
}

#[test]
fn a_document_with_no_deferred_binding_is_returned_as_written() {
    let text = "config_version: 1\nauth: {a: {module: m}}\n";
    let (written, lines) = resolve(text, &[]).expect("nothing to resolve");
    assert_eq!(written, text);
    assert!(lines.is_empty());
}

#[test]
fn no_declaring_plugin_refuses_config_naming_the_binding_and_the_style() {
    let refused = resolve(DEFERRED, &[("auth-other", &["other"][..])]).unwrap_err();
    assert_eq!(refused.word(), "CONFIG");
    let text = refused.to_string();
    assert!(
        text.contains("`auth.anthropic-outbound`: no admitted auth plugin implements the outbound style `jwt-bearer`; write `module:`"),
        "{text}"
    );
}

#[test]
fn several_declaring_plugins_refuse_config_naming_them() {
    let styles: [(&str, &[&str]); 2] = [("auth-a", &["jwt-bearer"]), ("auth-b", &["jwt-bearer"])];
    let refused = resolve(DEFERRED, &styles).unwrap_err();
    let text = refused.to_string();
    assert!(text.contains("`auth.anthropic-outbound`") && text.contains("several do") && text.contains("auth-a") && text.contains("auth-b"), "{text}");
    assert!(text.contains("write `module:`"), "{text}");
}
