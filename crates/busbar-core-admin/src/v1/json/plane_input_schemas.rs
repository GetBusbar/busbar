// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Raw user-input grammar explicitly declared inside a plane's lifecycle schema document.
//! Installation consumes cached Statements at startup; schema reads never call a plugin.

use busbar_kernel::admission::Stated;
use serde_json::{Map, Value};
use std::sync::OnceLock;

#[derive(Default)]
struct InputSchemas {
    definitions: Map<String, Value>,
    properties: Map<String, Value>,
}

static INPUT_SCHEMAS: OnceLock<InputSchemas> = OnceLock::new();

/// Install schemas from already-discovered plane Statements. A lifecycle schema alone does not
/// describe raw configuration: the owner must explicitly declare its user-configuration entry point.
pub fn install_plane_input_schemas(statements: &[Stated]) {
    let _ = INPUT_SCHEMAS.set(collect(statements));
}

#[cfg(feature = "openapi-schema")]
pub(super) fn extend(document: &mut Value) {
    let Some(inputs) = INPUT_SCHEMAS.get() else {
        return;
    };
    let definitions = document["$defs"].as_object_mut().expect("host definitions");
    definitions.extend(inputs.definitions.clone());
    let properties = document["properties"]
        .as_object_mut()
        .expect("host properties");
    for (name, schema) in &inputs.properties {
        // Host-owned blocks cannot be replaced by a plane's additional declaration.
        properties
            .entry(name.clone())
            .or_insert_with(|| schema.clone());
    }
}

fn collect(statements: &[Stated]) -> InputSchemas {
    use busbar_contract::abi::mechanism::door::{SECTION_CONSUMED, SECTION_DECLARING};
    let mut inputs = InputSchemas::default();
    for stated in statements.iter().filter(|stated| stated.kind == "plane") {
        let Some(declaration) = stated.configuration.as_ref().filter(|d| d.valid) else {
            continue;
        };
        let Some(mut schema) = stated
            .settings_schema
            .as_deref()
            .and_then(|text| serde_json::from_str::<Value>(text).ok())
        else {
            continue;
        };
        let Some(extension) = schema.get("x-busbar-user-configuration") else {
            continue;
        };
        if extension["version"] != 1
            || extension["context"] != "raw_user_configuration"
            || extension["reference_base"] != "returned_schema_document"
        {
            continue;
        }
        let Some(pointer) = extension["schema_ref"]
            .as_str()
            .and_then(|reference| reference.strip_prefix('#'))
        else {
            continue;
        };
        let Some(properties) = schema
            .pointer(pointer)
            .and_then(|root| root.get("properties"))
            .and_then(Value::as_object)
        else {
            continue;
        };
        let roots: std::collections::BTreeSet<_> = extension["roots"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|root| {
                declaration.sections.iter().any(|(section, flags)| {
                    section.as_str() == *root
                        && (flags & SECTION_DECLARING != 0 || flags & SECTION_CONSUMED == 0)
                }) && properties.contains_key(*root)
            })
            .map(str::to_owned)
            .collect();
        if roots.is_empty() {
            continue;
        }
        let namespace = format!("PlaneInput:{}", stated.name);
        let mut properties = properties.clone();
        // The entry-point metadata refers to the original returned document. Its schemas are
        // embedded below, but retaining that metadata would advertise stale unrelocated links.
        schema
            .as_object_mut()
            .expect("schema document")
            .remove("x-busbar-user-configuration");
        relocate(&mut schema, &namespace);
        for root in roots {
            let mut property = properties.remove(&root).expect("declared property");
            relocate(&mut property, &namespace);
            inputs.properties.entry(root).or_insert(property);
        }
        inputs.definitions.entry(namespace).or_insert(schema);
    }
    inputs
}

fn relocate(value: &mut Value, namespace: &str) {
    match value {
        Value::Object(fields) => {
            if let Some(Value::String(reference)) = fields.get_mut("$ref") {
                if let Some(pointer) = reference.strip_prefix('#') {
                    if pointer.is_empty() || pointer.starts_with('/') {
                        let escaped = namespace.replace('~', "~0").replace('/', "~1");
                        *reference = format!("#/$defs/{escaped}{pointer}");
                    }
                }
            }
            for child in fields.values_mut() {
                relocate(child, namespace);
            }
        }
        Value::Array(values) => {
            for child in values {
                relocate(child, namespace);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
#[path = "tests/plane_input_schemas.rs"]
mod tests;
