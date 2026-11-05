// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Additive contract metadata for implemented admin semantics; no runtime parsing policy here.
use super::RESPONSES_KEY;
use serde_json::{json, Map, Value};

pub(super) fn number_profile() -> Value {
    json!({
        "profile":"lossless-number-token-v1",
        "client_requirement":"Parse raw JSON numeric tokens as exact integers or decimals before any binary64 conversion. A browser-facing adapter carries exact quantities as decimal strings. Never recover precision from an already rounded number.",
        "legacy_wire":"Existing Count, u64 and signed integer fields remain JSON numbers. Metadata does not negotiate or change their wire types.",
        "count":{"representation":"json-number-token","mantissa_bits":128,"signed":true,"scale":6,
            "minimum":"-170141183460469231731687303715884.105728","maximum":"170141183460469231731687303715884.105727",
            "unit":"field-defined usage units","quantum":"0.000001"},
        "u64":{"representation":"json-integer-token","minimum":"0","maximum":"18446744073709551615"},
        "units":{"spend_cents":"cents","spend_micros":"millionths of the rate-card cost unit; use response denomination when present","ledger_amount":"ledger nano-units; decimal integer string","duration":"the seconds/milliseconds/nanoseconds suffix on the field"},
        "new_exact_fields":"New exact quantities use decimal strings with explicit unit, range, sign and scale; legacy fields retain their existing representation.",
        "examples":["9007199254740993","9007199254.740993","-0.000001"]
    })
}

pub(super) fn group_patch_schema() -> Value {
    json!({"type":"object","additionalProperties":false,
        "description":"Omitted and null legacy fields preserve their current value. Non-null limits and child_default replace the entire value. clear explicitly removes parent or child_default; do not also set that field. An empty child_default is a present empty template, not removal.",
        "properties":{
            "parent":{"type":["string","null"]},"enabled":{"type":["boolean","null"]},
            "limits":{"anyOf":[{"type":"array","items":super::config_forms::core_reference("Limit")},{"type":"null"}]},
            "child_default":{"anyOf":[super::config_forms::core_reference("ChildDefault"),{"type":"null"}]},
            "clear":{"type":"array","items":{"enum":["parent","child_default"]},"default":[]}
        },
        "x-busbar-runtime-validation":["a field cannot be both set to a non-null value and named in clear","tree and pool references; canonical current-policy checks; If-Match"]
    })
}

pub(super) fn hook_settings_schema() -> Value {
    let mut schema = super::named_map::settings_request_schema();
    schema["additionalProperties"] = json!(true);
    schema["description"] = json!(
        "Select exactly one mode. settings replaces the entire bag, dropping omitted keys. edit applies explicit top-level set/remove and preserves every unmentioned key, including hidden secrets. Null setting values are values; remove is explicit. Both modes use the existing runtime configure acknowledgement before config commit and the same conflict/outcome semantics. Never submit redacted readback as replacement settings."
    );
    schema["x-busbar-runtime-validation"] = json!([
        "set/remove key overlap is invalid",
        "module schema and SecretRef resolution",
        "runtime acknowledgement; config generation must remain unchanged during the push"
    ]);
    schema
}

pub(super) fn complete(paths: &mut Map<String, Value>, schemas: &mut Map<String, Value>) {
    let prefix = crate::v1::contract::ADMIN_PREFIX;
    let error = json!({"application/json":{"schema":{"$ref":"#/components/schemas/Error"}}});
    for (path, methods) in paths.iter_mut() {
        let Some(methods) = methods.as_object_mut() else {
            continue;
        };
        for method in ["get", "post", "put", "patch", "delete", "head"] {
            let Some(op) = methods.get_mut(method) else {
                continue;
            };
            let responses = op[RESPONSES_KEY]
                .as_object_mut()
                .expect("operation responses");
            responses.entry("413").or_insert_with(||json!({"description":"Admin request exceeds the listener body limit (request_too_large)","content":error}));
            // Ordinary admin write admission is shared by core and kernel verbs.
            if !matches!(method, "get" | "head") || path.ends_with("/ledger/recovery") {
                responses.entry("429").or_insert_with(||json!({"description":"Per-principal administrative budget exhausted (rate_limited)","content":error}));
            }
            responses.entry("default").or_insert_with(||json!({"description":"Other typed administrative refusal. Branch on known codes while preserving unknown strings; retry depends on operation semantics.","content":error}));
            for status in ["429", "503"] {
                if let Some(response) = responses.get_mut(status) {
                    response["headers"]["Retry-After"] = json!({"description":"Delay in seconds when supplied by the listener's rate/backpressure refusal; absence makes no retry promise.","schema":{"type":"integer","minimum":0}});
                }
            }
            if path == &format!("{prefix}/groups") && method == "get" {
                responses.entry("400").or_insert_with(|| json!({"description":"Malformed continuation cursor (invalid_request)","content":error}));
                op["parameters"] = json!([
                    {"name":"limit","in":"query","required":false,"schema":{"type":"integer","default":200,"minimum":1,"maximum":1000},"description":"Effective page size clamps numeric values to 1..1000; omitted or malformed legacy values use 200."},
                    {"name":"cursor","in":"query","required":false,"schema":{"type":"string"},"description":"Opaque live-list offset continuation, ordered by group name. Collections may change between pages; this is not a snapshot or operation-bound token."}
                ]);
            }
            if method == "post"
                && [
                    "/keys",
                    "/keys/{id}/rotate",
                    "/plane-record-write",
                    "/commit-upgrade",
                ]
                .iter()
                .any(|suffix| path == &format!("{prefix}{suffix}"))
            {
                let parameter = json!({"name":"Idempotency-Key","in":"header","required":false,"schema":{"type":"string"},"description":"Optional replay action identity scoped to authenticated actor, operation and target. Retained about 10 minutes. Exact request bytes must match. Credential secret replay is process-local; a durable applied receipt survives restart without retaining the secret. See operation recovery semantics before retrying."});
                if let Some(parameters) = op.get_mut("parameters").and_then(Value::as_array_mut) {
                    parameters.push(parameter)
                } else {
                    op["parameters"] = json!([parameter])
                }
            }
        }
    }
    if let Some(code) = schemas
        .get_mut("Error")
        .and_then(|error| error.pointer_mut("/properties/error/properties/code"))
    {
        // Preserve the legacy enum shape and publish the reader compatibility requirement.
        let mut known = code.get("enum").cloned().unwrap_or_else(|| json!([]));
        for value in ["request_too_large"] {
            if !known.as_array().unwrap().contains(&json!(value)) {
                known.as_array_mut().unwrap().push(json!(value));
            }
        }
        *code = json!({"type":"string","enum":known,"x-busbar-extensible-enum":true,"description":"Known server codes; forward-compatible readers preserve unknown code strings instead of failing the whole response."});
    }
    if let Some(schema) = schemas.get_mut("UpdateKeyReq") {
        schema["properties"]["enabled"]["description"] =
            json!("Omitted or null preserves enabled; a boolean sets it.");
        schema["properties"]["group"]["description"] = json!("Omitted preserves binding; null explicitly unbinds; a string rebinds to an existing group.");
    }
    if let Some(schema) = schemas.get_mut("LimitView") {
        schema["properties"]["admission"]["enum"] = json!(["exact", "estimate"]);
        schema["properties"]["on_exhaustion"]["enum"] = json!(["finish-unit", "cut-stream"]);
    }
    for methods in paths.values_mut() {
        if let Some(operation) = methods.get_mut("patch") {
            if let Some(schema) =
                operation.pointer_mut("/requestBody/content/application~1json/schema")
            {
                if schema.get("oneOf").is_some() && schema.pointer("/properties/edit").is_some() {
                    schema["description"] = json!("settings replaces the entire bag, dropping omitted keys; edit explicitly sets/removes top-level keys and preserves all others. Null setting values are values. A setting cannot appear in both set and remove. Never reconstruct a replacement from redacted readback.");
                }
            }
        }
    }
    schemas.insert("PatchSettingsReq".into(), hook_settings_schema());
    super::replay_metadata::complete(paths, schemas);
    for schema in schemas.values_mut() {
        exact_metadata(schema);
    }
}

fn exact_metadata(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if map.get("x-busbar-count-scale").is_some() {
                map.remove("format");
                map.insert(
                    "x-busbar-exact-number".into(),
                    number_profile()["count"].clone(),
                );
            } else if map
                .get("format")
                .and_then(Value::as_str)
                .is_some_and(|format| {
                    matches!(format, "uint64" | "int64" | "uint" | "int128" | "uint128")
                })
            {
                let format = map["format"].as_str().unwrap().to_string();
                map.insert("x-busbar-exact-number".into(), json!({"representation":"json-integer-token","integer_format":format,"client":"lossless-number-token-v1; preserve raw token before binary64 conversion"}));
            }
            for child in map.values_mut() {
                exact_metadata(child);
            }
        }
        Value::Array(array) => {
            for child in array {
                exact_metadata(child);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn published_contract_declares_group_pages_refusals_and_replay_headers() {
        let doc = super::super::handlers::openapi_doc();
        let paths = doc["paths"].as_object().unwrap();
        let groups = &paths["/api/v1/admin/groups"]["get"];
        let params = groups["parameters"].as_array().unwrap();
        let limit = params.iter().find(|p| p["name"] == "limit").unwrap();
        assert_eq!(
            limit["schema"],
            json!({"type":"integer","default":200,"minimum":1,"maximum":1000})
        );
        assert!(params.iter().any(|p| p["name"] == "cursor"));
        assert!(groups[RESPONSES_KEY].get("400").is_some());
        for methods in paths.values() {
            for method in ["get", "post", "put", "patch", "delete"] {
                let Some(op) = methods.get(method) else {
                    continue;
                };
                assert!(op[RESPONSES_KEY].get("413").is_some());
                assert!(op[RESPONSES_KEY].get("default").is_some());
                if !matches!(method, "get") {
                    assert!(op[RESPONSES_KEY]["429"]["headers"]
                        .get("Retry-After")
                        .is_some());
                }
            }
        }
        for path in [
            "/keys",
            "/keys/{id}/rotate",
            "/plane-record-write",
            "/commit-upgrade",
        ] {
            assert!(paths[&format!("/api/v1/admin{path}")]["post"]["parameters"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["name"] == "Idempotency-Key" && p["in"] == "header"));
        }
        let codes = &doc["components"]["schemas"]["Error"]["properties"]["error"]["properties"]
            ["code"]["enum"];
        assert!(codes.as_array().unwrap().contains(&json!(
            busbar_contract::protocol::ERR_TYPE_REQUEST_TOO_LARGE
        )));
    }

    #[test]
    fn authoring_refs_resolve_and_count_schemas_preserve_numeric_wire_without_double() {
        let doc = super::super::handlers::openapi_doc();
        let schemas = &doc["components"]["schemas"];
        for name in ["Group", "Limit", "ChildDefault", "Hook", "HookDefinition"] {
            assert!(schemas.get(format!("ConfigInput{name}")).is_some());
        }
        fn check(value: &Value, doc: &Value, count: &mut usize) {
            if let Some(reference) = value.get("$ref").and_then(Value::as_str) {
                if reference.starts_with("#/components/") {
                    assert!(doc.pointer(&reference[1..]).is_some(), "{reference}");
                }
            }
            if value.get("x-busbar-count-scale").is_some() {
                *count += 1;
                assert_eq!(value["type"], "number");
                assert!(value.get("format").is_none());
                assert_eq!(value["x-busbar-exact-number"]["mantissa_bits"], 128);
            }
            match value {
                Value::Object(map) => {
                    for child in map.values() {
                        check(child, doc, count)
                    }
                }
                Value::Array(values) => {
                    for child in values {
                        check(child, doc, count)
                    }
                }
                _ => {}
            }
        }
        let mut count = 0;
        check(&doc["components"], &doc, &mut count);
        assert!(count > 0);
        let count: busbar_contract::count::Count =
            serde_json::from_str("9007199254.740993").unwrap();
        assert_eq!(serde_json::to_string(&count).unwrap(), "9007199254.740993");
        let integer: u64 = serde_json::from_str("9007199254740993").unwrap();
        assert_eq!(serde_json::to_string(&integer).unwrap(), "9007199254740993");
    }
}
