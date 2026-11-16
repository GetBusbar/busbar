// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADMIN-API-1.6 §5: the kind-generic discovery surface's pure parts.

use super::*;
use busbar_contract::json::json;

#[test]
fn discovery_categories_preserve_names_and_order() {
    assert_eq!(
        CATEGORIES,
        [
            "plane",
            "auth",
            "store",
            "secret",
            "export",
            "hook",
            "transport",
            "core"
        ]
    );
    for (kind, expected) in [
        (Kind::Plane, "plane"),
        (Kind::Transport, "transport"),
        (Kind::Auth, "auth"),
        (Kind::Store, "store"),
        (Kind::Secret, "secret"),
        (Kind::Hook, "hook"),
        (Kind::Export, "export"),
    ] {
        assert_eq!(category_of(kind), expected);
        assert!(CATEGORIES.contains(&expected));
    }
    assert!(!CATEGORIES.contains(&"unknown"));
    assert!(KindCode::ALL.iter().all(|kind| kind.word() != "core"));
}

#[cfg(feature = "openapi-schema")]
#[test]
fn discovery_category_schemas_match_runtime_categories() {
    let expected = json!([
        "plane",
        "auth",
        "store",
        "secret",
        "export",
        "hook",
        "transport",
        "core"
    ]);
    let parameters: Vec<Value> = doc::query(&["category"]);
    assert_eq!(parameters.len(), 1);
    assert_eq!(parameters[0]["schema"]["enum"], expected);
    assert_eq!(parameters[0]["schema"]["type"], "string");

    let schema = <doc::KindsPage as schemars::JsonSchema>::json_schema(
        &mut schemars::SchemaGenerator::default(),
    );
    let bytes = busbar_contract::json::to_vec(&schema).expect("encode discovery schema");
    let schema: Value = busbar_contract::json::parse(&bytes).expect("parse discovery schema");
    assert_eq!(
        schema["properties"]["items"]["items"]["properties"]["category"]["enum"],
        expected
    );
    assert_eq!(json!(CATEGORIES), expected);
}

#[test]
fn links_from_schema_refs() {
    let schema = json!({
        "type": "object",
        "properties": {
            "upstream_auth": {"type": "string", "x-busbar-ref": "auth"},
            "sinks": {"type": "array", "items": {"type": "string"}, "x-busbar-ref": "export"},
            "nested": {"type": "object", "properties": {
                "store": {"type": "string", "x-busbar-ref": "store"},
                "label": {"type": "string"}
            }},
            "routes": {"type": "array", "items": {"type": "object", "properties": {
                "via": {"type": "string", "x-busbar-ref": "transport"}
            }}},
            "odd": {"type": "string", "x-busbar-ref": "not-a-category"}
        }
    });
    let config = json!({
        "upstream_auth": "corp",
        "sinks": ["metrics", "audit-log"],
        "nested": {"store": "store", "label": "corp"},
        "routes": [{"via": "edge"}, {"via": "edge-2"}],
        "odd": "ignored"
    });
    let found = links(&schema, &config);
    let pairs: Vec<(String, String)> = found
        .iter()
        .map(|link| {
            (
                link["kind"].as_str().unwrap().to_owned(),
                link["id"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let want: Vec<(String, String)> = [
        ("auth", "corp"),
        ("export", "metrics"),
        ("export", "audit-log"),
        ("store", "store"),
        ("transport", "edge"),
        ("transport", "edge-2"),
    ]
    .iter()
    .map(|(k, i)| ((*k).to_owned(), (*i).to_owned()))
    .collect();
    let mut sorted_found = pairs.clone();
    sorted_found.sort();
    let mut sorted_want = want.clone();
    sorted_want.sort();
    assert_eq!(
        sorted_found, sorted_want,
        "every annotated position, and only those, is a link"
    );
    assert!(
        links(&json!({"type": "object"}), &config).is_empty(),
        "no annotation, no link: core never guesses one from a value"
    );
}

#[test]
fn core_instances_are_the_reserved_ids() {
    let served: Vec<&str> = CORE_SECTIONS.iter().map(|(id, _)| *id).collect();
    assert_eq!(
        served,
        busbar_kernel::config_validate::CORE_INSTANCES.to_vec(),
        "the core instances served are exactly the ids validate reserves"
    );
}

#[test]
fn plane_kind_ids_match_the_kind_grammar() {
    for key in ["llm", "class-parent-plane", "MCP", "9lives", "a2a"] {
        let kind = plane_kind(key);
        assert!(
            super::super::views::is_id(&kind),
            "{key} folds to {kind}, a kind id"
        );
    }
    assert_eq!(plane_kind("llm"), "llm");
    assert_eq!(plane_kind("class-parent-plane"), "class_parent_plane");
}

static FACTS_PLANE: busbar_kernel::plane_driver::registry::PlaneDeclaration =
    busbar_kernel::plane_driver::registry::PlaneDeclaration {
        key: "facts-plane",
        fallback: false,
        config_section: "examples",
        scope_kinds: &["example"],
        subject_noun: "example",
        admin_noun: "example",
        audit_kind: "example",
        card_signing_domain: None,
        card_kid_prefix: None,
        owned_config_sections: &["example_extras"],
        billable_classes: &[busbar_kernel::plane_driver::registry::BillableClass {
            class: "calls",
            family: "count",
        }],
        class_parents: &[],
        fee_units: &["per_request"],
        metric_families: &[],
        served_op_classes: &[],
        record_kinds: &["note"],
        required_config_sections: &[],
        trust_keys: &[],
        caller_credential_refusal: None,
    };

#[test]
fn runtime_plane_facts_match_the_declaration() {
    let facts = plane_facts(&FACTS_PLANE);
    assert_eq!(facts["plane"], "facts-plane");
    assert_eq!(facts["config_section"], "examples");
    assert_eq!(facts["owned_config_sections"], json!(["example_extras"]));
    assert_eq!(facts["scope_kinds"], json!(["example"]));
    assert_eq!(
        facts["billable_classes"],
        json!([{"class": "calls", "family": "count"}])
    );
    assert_eq!(facts["fee_units"], json!(["per_request"]));
    assert_eq!(facts["record_kinds"], json!(["note"]));
    assert_eq!(facts["card_signing"], json!(false));
    assert_eq!(facts["fallback"], json!(false));
}
