// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::hook_schema_selection;

#[test]
fn test_admin_v1_plugin_schema_falls_back_to_manifest_when_describe_answers_null() {
    let manifest_schema = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {"order": {"type": "array"}},
    });
    let signed_schema = manifest_schema.to_string();
    let got = hook_schema_selection(
        "fallback-hook",
        None,
        Some(&signed_schema),
        "trusted",
        Some("hook"),
        Some(false),
    );
    assert_eq!(
        got["source"], "manifest",
        "describe answered null -> falls back to the manifest baseline: {got}"
    );
    assert_eq!(
        got["schema"], manifest_schema,
        "the ACTUAL manifest schema comes back, not just a source label: {got}"
    );
    assert_eq!(got["schema_error"], serde_json::Value::Null);
}

#[test]
fn a_live_description_takes_precedence_without_parsing_the_unused_manifest() {
    let schema = serde_json::json!({"type":"object","properties":{"url":{"type":"string"}}});
    let got = hook_schema_selection(
        "live-hook",
        Some(schema.clone()),
        Some("{ invalid unused schema"),
        "trusted",
        Some("hook"),
        Some(false),
    );
    assert_eq!(got["schema"], schema);
    assert_eq!(got["source"], "describe");
    assert_eq!(got["schema_error"], serde_json::Value::Null);
}
