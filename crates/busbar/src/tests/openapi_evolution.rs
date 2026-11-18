// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The evolution rules over the committed admin document (ADMIN-API-1.6-ONE-MODEL r3.1 §5.1, §5.2
//! and the static rules of §5.4; #308). The response side is every component a response reaches,
//! every schema written inline under a response, and every reason's `details` schema. On that side
//! no object is closed (`additionalProperties: false`), and every enum either carries
//! `x-busbar-extensible-enum: true` or is closed with `x-busbar-closed-enum: "<reason>"`, never
//! both. The request side is not checked here: request objects and request enums stay closed.

use busbar_contract::json::JsonContainerTrait as _;
use busbar_contract::json::{self, JsonValueTrait as _};
use std::collections::BTreeSet;

const DOCUMENT: &str = include_str!("../../../busbar-core-admin/src/v1/json/openapi.json");
const SCHEMA_REF: &str = "#/components/schemas/";
const OPERATIONS: [&str; 5] = ["get", "put", "post", "delete", "patch"];
/// Members whose value is a map of name to schema.
const SCHEMA_MAPS: [&str; 4] = ["properties", "patternProperties", "$defs", "definitions"];
/// Members whose value is a schema or an array of schemas.
const SCHEMA_CHILDREN: [&str; 11] = [
    "items",
    "prefixItems",
    "additionalProperties",
    "not",
    "if",
    "then",
    "else",
    "contains",
    "oneOf",
    "anyOf",
    "allOf",
];

fn refs(value: &json::Value, out: &mut Vec<String>) {
    if let Some(object) = value.as_object() {
        for (key, member) in object.iter() {
            if key == "$ref" {
                if let Some(name) = member.as_str().and_then(|r| r.strip_prefix(SCHEMA_REF)) {
                    out.push(name.to_owned());
                }
            } else {
                refs(member, out);
            }
        }
    } else if let Some(items) = value.as_array() {
        for item in items.iter() {
            refs(item, out);
        }
    }
}

/// An enum site: `enum`, or a `oneOf`/`anyOf` whose every branch is one value (`const` or `enum`).
fn is_enum(schema: &json::Value) -> bool {
    if schema.get("enum").is_some() {
        return true;
    }
    ["oneOf", "anyOf"].iter().any(|key| {
        schema
            .get(*key)
            .and_then(|branches| branches.as_array())
            .is_some_and(|branches| {
                !branches.is_empty()
                    && branches.iter().all(|branch| {
                        branch.is_object()
                            && (branch.get("const").is_some() || branch.get("enum").is_some())
                            && branch.get("properties").is_none()
                    })
            })
    })
}

fn visit(at: &str, schema: &json::Value, offenders: &mut Vec<String>) {
    if let Some(items) = schema.as_array() {
        for (index, item) in items.iter().enumerate() {
            visit(&format!("{at}/{index}"), item, offenders);
        }
        return;
    }
    if !schema.is_object() {
        return;
    }
    if schema
        .get("additionalProperties")
        .and_then(|closed| closed.as_bool())
        == Some(false)
    {
        offenders.push(format!(
            "{at}: a response object is closed (additionalProperties: false)"
        ));
    }
    if is_enum(schema) {
        let extensible = schema
            .get("x-busbar-extensible-enum")
            .and_then(|mark| mark.as_bool())
            == Some(true);
        let closed = schema
            .get("x-busbar-closed-enum")
            .and_then(|reason| reason.as_str())
            .is_some_and(|reason| !reason.trim().is_empty());
        if extensible == closed {
            offenders.push(format!(
                "{at}: a response enum is neither x-busbar-extensible-enum: true nor \
                 x-busbar-closed-enum with a reason (or is both)"
            ));
        }
        return;
    }
    for key in SCHEMA_MAPS {
        if let Some(members) = schema.get(key).and_then(|m| m.as_object()) {
            for (name, member) in members.iter() {
                visit(&format!("{at}/{key}/{name}"), member, offenders);
            }
        }
    }
    for key in SCHEMA_CHILDREN {
        if let Some(child) = schema.get(key) {
            visit(&format!("{at}/{key}"), child, offenders);
        }
    }
}

#[test]
fn response_objects_are_open_and_response_enums_are_marked() {
    let doc = json::parse_value(DOCUMENT.as_bytes()).expect("the committed admin document parses");
    let schemas = doc["components"]["schemas"]
        .as_object()
        .expect("the document has component schemas");
    let paths = doc["paths"].as_object().expect("the document has paths");

    let mut offenders = Vec::new();
    let mut todo = Vec::new();
    for (path, item) in paths.iter() {
        for method in OPERATIONS {
            let Some(responses) = item.get(method).and_then(|op| op.get("responses")) else {
                continue;
            };
            refs(responses, &mut todo);
            let Some(responses) = responses.as_object() else {
                continue;
            };
            for (status, response) in responses.iter() {
                for carrier in ["content", "headers"] {
                    let Some(entries) = response.get(carrier).and_then(|e| e.as_object()) else {
                        continue;
                    };
                    for (name, entry) in entries.iter() {
                        if let Some(schema) = entry.get("schema") {
                            visit(
                                &format!(
                                    "paths/{path}/{method}/responses/{status}/{carrier}/{name}"
                                ),
                                schema,
                                &mut offenders,
                            );
                        }
                    }
                }
            }
        }
    }
    assert!(
        !todo.is_empty(),
        "the document's responses reference component schemas"
    );

    let mut reached = BTreeSet::new();
    while let Some(name) = todo.pop() {
        if !reached.insert(name.clone()) {
            continue;
        }
        let schema = schemas
            .get(&name.as_str())
            .unwrap_or_else(|| panic!("a response references the missing component {name}"));
        refs(schema, &mut todo);
        visit(
            &format!("components/schemas/{name}"),
            schema,
            &mut offenders,
        );
    }

    let reasons = doc["components"]["x-busbar-reasons"]
        .as_object()
        .expect("the document carries the reason table");
    assert!(!reasons.is_empty(), "the reason table is not empty");
    for (reason, row) in reasons.iter() {
        let schema = row
            .get("details_schema")
            .unwrap_or_else(|| panic!("reason {reason} declares its details schema"));
        visit(
            &format!("components/x-busbar-reasons/{reason}/details_schema"),
            schema,
            &mut offenders,
        );
    }

    assert!(
        offenders.is_empty(),
        "{} response-side schema(s) break the evolution rules (ADMIN-API-1.6-ONE-MODEL §5.1, \
         §5.2):\n  {}",
        offenders.len(),
        offenders.join("\n  ")
    );
}

/// DES-I-3-376: 1.6.0 has no deployment keyset rotation (no transaction, route or writer; a replaced
/// keyset is a new deployment, refused as `StoreMissing`), so `keyset.rotated` can never fire and is
/// not published. Neither the engine's closed action catalogue nor the committed document's
/// `components.x-busbar-audit-actions` lists it.
#[test]
fn the_published_audit_actions_omit_keyset_rotated() {
    let doc = json::parse_value(DOCUMENT.as_bytes()).expect("the committed admin document parses");
    let published = doc["components"]["x-busbar-audit-actions"]
        .as_object()
        .expect("the document publishes the audit action catalogue");
    assert!(
        published.get(&"keyset.rotated").is_none(),
        "the document publishes keyset.rotated, which nothing writes"
    );
    assert!(
        !busbar_kernel::audit::auditlog::AUDIT_ACTIONS.contains(&"keyset.rotated"),
        "the engine catalogue lists keyset.rotated, which nothing writes"
    );
}
