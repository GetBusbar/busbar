// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-owned loader input and the installed OAuth owner's separately declared grammar.
use serde_json::{json, Map, Value};

pub(super) fn definitions(defs: &mut Map<String, Value>) {
    let mut loader = serde_json::to_value(schemars::schema_for!(busbar_kernel::config::PluginsCfg))
        .expect("the loader's derived input schema serializes");
    if let Some(nested) = loader.get_mut("$defs").and_then(Value::as_object_mut) {
        defs.extend(std::mem::take(nested));
    }
    loader.as_object_mut().unwrap().remove("$defs");
    loader.as_object_mut().unwrap().remove("$schema");
    loader["x-busbar-runtime-validation"] = json!([
        "signature/publisher key and anti-downgrade version admission",
        "fetch URL/env resolution, integrity and bounded archive verification; validate performs no network fetch",
        "log level/directory/rotation validation and live plugin-log reconfiguration",
        "canonical semantic-diff security policy and source/revision fences"
    ]);
    loader["x-busbar-edit"] = json!({
        "operation":"PUT /api/v1/admin/config/settings document_patch",
        "source_fence":"configuration.source_revision and config ETag",
        "activation":"new plugin policy is used by normal rebuild/preflight; fetch is performed at boot/plugin reload; response restart metadata remains authoritative",
        "runtime_only":{"first_party_floors":"not authored input; managed by explicit digest-fenced plugin rollback and persisted version pins"}
    });
    annotate_integer_tokens(&mut loader);
    for schema in defs.values_mut() {
        annotate_integer_tokens(schema);
    }
    defs.insert("Plugins".into(), loader);
    let oauth = match busbar_kernel::oauth_as::seam::input_schema() {
        Some(schema) => schema,
        None => {
            json!({"not":{},"x-busbar-supported":false,"description":"This build has no installed OAuth authorization-server input owner. Do not invent OAuth fields or send a configured block."})
        }
    };
    defs.insert("OAuthAS".into(), oauth);
}

fn annotate_integer_tokens(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if let Some(format) = map.get("format").and_then(Value::as_str) {
                let maximum = match format {
                    "uint64" => Some(u64::MAX),
                    "uint32" => Some(u64::from(u32::MAX)),
                    _ => None,
                };
                if let Some(maximum) = maximum {
                    map.insert("x-busbar-integer-token".into(), json!("unsigned"));
                    map.insert("maximum".into(), json!(maximum));
                }
            }
            for child in map.values_mut() {
                annotate_integer_tokens(child);
            }
        }
        Value::Array(values) => {
            for child in values {
                annotate_integer_tokens(child);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn loader_schema_is_derived_from_actual_parser_and_excludes_runtime_floor() {
        let mut defs = Map::new();
        definitions(&mut defs);
        assert!(defs["Plugins"]["properties"]
            .get("first_party_floors")
            .is_none());
        assert!(defs["Plugins"]["properties"].get("logs").is_some());
        let schema = json!({"$schema":"https://json-schema.org/draft/2020-12/schema","$defs":defs,"$ref":"#/$defs/Plugins"});
        let validator = jsonschema::validator_for(&schema).unwrap();
        for value in [
            json!({}),
            json!({"enabled":true,"trust":{"publishers":[{"name":"third","public_key":"hex"}]}}),
            json!({"fetch":[{"github":"org/repo@tag","sha256":null},{"url":"https://example/a.tar.gz"},{"env":"URL"}]}),
            json!({"logs":{"level":null,"rotate_mb":null}}),
            json!({"logs":{"levels":{"instance":"debug"},"keep":5}}),
            json!({"first_party_floors":{}}),
            json!({"fetch":[{"url":"https://example/a.tar.gz","env":"URL"}]}),
            json!({"trust":null}),
            json!({"logs":{"unknown":true}}),
        ] {
            assert_eq!(
                validator.is_valid(&value),
                serde_json::from_value::<busbar_kernel::config::PluginsCfg>(value.clone()).is_ok(),
                "{value}"
            );
        }
    }
}
