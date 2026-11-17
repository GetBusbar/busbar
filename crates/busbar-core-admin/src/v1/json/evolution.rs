// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The enum rule of ADMIN-API-1.6-ONE-MODEL r3.1 §5.2, applied to the generated document (#308).
//! A response enum is extensible by default: every enum on the response side that does not already
//! say what it is gets `x-busbar-extensible-enum: true`. An enum that must stay closed says so at
//! its source with `x-busbar-closed-enum: "<reason>"`, and this pass leaves it alone. The response
//! side is every component a response reaches, every schema inline under a response, and every
//! reason's `details` schema. Request enums are closed and are never marked.

use serde_json::{Map, Value};
use std::collections::BTreeSet;

const SCHEMA_REF: &str = "#/components/schemas/";
const OPERATIONS: [&str; 5] = ["get", "put", "post", "delete", "patch"];
const EXTENSIBLE: &str = "x-busbar-extensible-enum";
const CLOSED: &str = "x-busbar-closed-enum";
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

/// Marks every unmarked response enum of `doc` extensible.
pub(super) fn mark_response_enums(doc: &mut Value) {
    let reached = response_components(doc);
    if let Some(schemas) = doc
        .pointer_mut("/components/schemas")
        .and_then(Value::as_object_mut)
    {
        for (name, schema) in schemas.iter_mut() {
            if reached.contains(name) {
                mark(schema);
            }
        }
    }
    if let Some(paths) = doc.get_mut("paths").and_then(Value::as_object_mut) {
        for item in paths.values_mut() {
            for method in OPERATIONS {
                let Some(responses) = item
                    .get_mut(method)
                    .and_then(|op| op.get_mut(super::RESPONSES_KEY))
                    .and_then(Value::as_object_mut)
                else {
                    continue;
                };
                for response in responses.values_mut() {
                    for carrier in ["content", "headers"] {
                        let Some(entries) =
                            response.get_mut(carrier).and_then(Value::as_object_mut)
                        else {
                            continue;
                        };
                        for entry in entries.values_mut() {
                            if let Some(schema) = entry.get_mut("schema") {
                                mark(schema);
                            }
                        }
                    }
                }
            }
        }
    }
    if let Some(reasons) = doc
        .pointer_mut("/components/x-busbar-reasons")
        .and_then(Value::as_object_mut)
    {
        for row in reasons.values_mut() {
            if let Some(schema) = row.get_mut("details_schema") {
                mark(schema);
            }
        }
    }
}

/// The names of every component schema a response reaches, directly or through other components.
fn response_components(doc: &Value) -> BTreeSet<String> {
    let mut todo = Vec::new();
    if let Some(paths) = doc.get("paths").and_then(Value::as_object) {
        for item in paths.values() {
            for method in OPERATIONS {
                if let Some(responses) =
                    item.get(method).and_then(|op| op.get(super::RESPONSES_KEY))
                {
                    refs(responses, &mut todo);
                }
            }
        }
    }
    let schemas = doc
        .pointer("/components/schemas")
        .and_then(Value::as_object);
    let mut reached = BTreeSet::new();
    while let Some(name) = todo.pop() {
        if reached.contains(&name) {
            continue;
        }
        if let Some(schema) = schemas.and_then(|schemas| schemas.get(&name)) {
            refs(schema, &mut todo);
        }
        reached.insert(name);
    }
    reached
}

fn refs(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(members) => {
            for (key, member) in members {
                if key == "$ref" {
                    if let Some(name) = member.as_str().and_then(|r| r.strip_prefix(SCHEMA_REF)) {
                        out.push(name.to_owned());
                    }
                } else {
                    refs(member, out);
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| refs(item, out)),
        _ => {}
    }
}

/// An enum site: `enum`, or a `oneOf`/`anyOf` whose every branch is one value (`const` or `enum`).
fn is_enum(schema: &Map<String, Value>) -> bool {
    if schema.contains_key("enum") {
        return true;
    }
    ["oneOf", "anyOf"].iter().any(|key| {
        schema
            .get(*key)
            .and_then(Value::as_array)
            .is_some_and(|branches| {
                !branches.is_empty()
                    && branches.iter().all(|branch| {
                        branch.as_object().is_some_and(|branch| {
                            (branch.contains_key("const") || branch.contains_key("enum"))
                                && !branch.contains_key("properties")
                        })
                    })
            })
    })
}

fn mark(schema: &mut Value) {
    if let Some(items) = schema.as_array_mut() {
        items.iter_mut().for_each(mark);
        return;
    }
    let Some(schema) = schema.as_object_mut() else {
        return;
    };
    if is_enum(schema) {
        if !schema.contains_key(EXTENSIBLE) && !schema.contains_key(CLOSED) {
            schema.insert(EXTENSIBLE.to_owned(), Value::Bool(true));
        }
        return;
    }
    for key in SCHEMA_MAPS {
        if let Some(members) = schema.get_mut(key).and_then(Value::as_object_mut) {
            members.values_mut().for_each(mark);
        }
    }
    for key in SCHEMA_CHILDREN {
        if let Some(child) = schema.get_mut(key) {
            mark(child);
        }
    }
}
