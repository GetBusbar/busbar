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

/// The closed top-level grammar of RootSettings. Nested section grammars stay with
/// their parsers; unlike the old free-form branch, unknown mode keys cannot match.
pub(super) fn root_settings_schema() -> Value {
    let section = |description: &str| {
        json!({
            "anyOf": [{"type":"object","additionalProperties":true}, {"type":"array","items":{}}, {"type":"null"}],
            "description": description,
            "x-busbar-runtime-validation": "The owning section parser validates field names, types and positional forms."
        })
    };
    json!({
        "title": "ConfigSettingsReplacement",
        "type": "object",
        "additionalProperties": false,
        "description": "Replace named root settings sections, merging omitted sections with the existing overlay. Null preserves a section. A mutable configuration stores changes through its configured Store; a locked configuration refuses changes. Listen, TLS and Store changes require restart. Unknown or retired fields, including persist, are refused. Nested section parsers and normal configuration validation remain authoritative.",
        "properties": {
            "listen": {"type":["string","null"]},
            "tls": section("Inbound TLS: cert and key SecretRefs, plus optional client_ca."),
            "admin_listen": {"type":["string","null"]},
            "admin_tls": section("Admin listener TLS: cert and key SecretRefs, plus optional client_ca."),
            "admin_require_mtls": {"type":["boolean","null"]},
            "rate_card": {"type":["object","null"],"additionalProperties":{
                "anyOf":[{"type":"object","additionalProperties":true},{"type":"array","items":{}}],
                "description":"RateEntryCfg: input_utok, output_utok, cache_read_utok, cache_write_utok and units. Normal rate validation applies."
            }},
            "per_request_fee": {"type":["integer","null"],"format":"int64","minimum":i64::MIN,"maximum":i64::MAX},
            "store": section("Store selection: module and module-owned settings; requires restart."),
            "security": section("Per-field SecurityPatch; omitted or null members preserve their value."),
            "limits": section("Per-field LimitsPatch; omitted members preserve their value. Null datagram_line_memory_bytes explicitly disables that limit."),
            "advanced": section("Per-field AdvancedPatch; omitted or null members preserve their value."),
            "health": section("Per-field HealthPatch; omitted or null members preserve their value."),
            "routing": section("Per-field RoutingPatch; omitted or null members preserve their value.")
        }
    })
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
            let extracts_request = op.get("requestBody").is_some()
                || op["parameters"].as_array().is_some_and(|parameters| {
                    parameters
                        .iter()
                        .any(|parameter| matches!(parameter["in"].as_str(), Some("path" | "query")))
                });
            let plane_operation = op.get("x-busbar-plane").is_some();
            let responses = op[RESPONSES_KEY]
                .as_object_mut()
                .expect("operation responses");
            if extracts_request {
                responses.entry("400").or_insert_with(|| json!({"description":"Malformed admin request path, query or body (invalid_request). Request values and parser diagnostics are not echoed.","content":error}));
            }
            if plane_operation {
                responses.entry("503").or_insert_with(|| json!({"description":"A plane dependency is temporarily unavailable (unavailable); no backend diagnostic detail is returned.","content":error}));
            }
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
        schema["properties"]["group"]["description"] = json!(
            "Omitted preserves binding; null explicitly unbinds; a string rebinds to an existing group."
        );
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
                if schema.pointer("/oneOf/0/properties/edit").is_some() {
                    schema["description"] = json!(
                        "settings replaces the entire bag, dropping omitted keys; edit explicitly sets/removes top-level keys and preserves all others. Null setting values are values. A setting cannot appear in both set and remove. Never reconstruct a replacement from redacted readback."
                    );
                }
            }
        }
    }
    schemas.insert("PatchSettingsReq".into(), hook_settings_schema());
    // Omission is allowed, but the custom runtime deserializer rejects JSON null.
    // Schemars derives the Option default independently of the String wire override.
    if let Some(field) = schemas
        .get_mut("PluginRollbackReq")
        .and_then(|schema| schema.pointer_mut("/properties/expected_archive_sha256"))
        .and_then(Value::as_object_mut)
    {
        field.remove("default");
    }
    super::replay_metadata::complete(paths, schemas);
    etag_responses(paths);
    for methods in paths.values_mut().filter_map(Value::as_object_mut) {
        for operation in methods.values_mut() {
            if let Some(responses) = operation
                .get_mut(RESPONSES_KEY)
                .and_then(Value::as_object_mut)
            {
                for response in responses.values_mut() {
                    response["headers"]["Cache-Control"] = json!({"description":"Administrative responses, including credential issuance and replay, must not be stored.","schema":{"type":"string","const":"no-store"}});
                }
            }
        }
    }
    for schema in schemas.values_mut() {
        exact_metadata(schema);
    }
}

/// The actual successful handlers which return the configuration generation.
/// Key ETags use a separate resource version and must never be interchanged with it.
fn etag_responses(paths: &mut Map<String, Value>) {
    let prefix = crate::v1::contract::ADMIN_PREFIX;
    let config = json!({
        "description": "Quoted configuration generation for If-Match on configuration mutations. Preserve the header verbatim; re-read after a version conflict.",
        "schema": {"type": "string", "pattern": "^\"[0-9]+\"$"}
    });
    fn add(paths: &mut Map<String, Value>, path: &str, methods: &[&str], header: &Value) {
        for method in methods {
            let Some(responses) = paths
                .get_mut(path)
                .and_then(|item| item.get_mut(*method))
                .and_then(|operation| operation.get_mut(RESPONSES_KEY))
                .and_then(Value::as_object_mut)
            else {
                continue;
            };
            for (status, response) in responses {
                if status.starts_with('2') {
                    response["headers"]["ETag"] = header.clone();
                }
            }
        }
    }
    for (path, methods) in [
        ("/hooks", &["get", "post"][..]),
        ("/hooks/{name}", &["get", "put", "delete"][..]),
        ("/hooks/{name}/settings", &["patch"][..]),
        ("/groups", &["get", "post"][..]),
        ("/groups/{name}", &["get", "put", "patch", "delete"][..]),
        ("/admin-auth", &["get", "put"][..]),
        ("/config", &["get"][..]),
        ("/config/settings", &["get", "put"][..]),
        ("/config/apply", &["post"][..]),
        ("/config/reload", &["post"][..]),
        ("/config/rollback", &["post"][..]),
        ("/plugins/rollback", &["post"][..]),
        ("/overlay/{section}", &["delete"][..]),
    ] {
        add(paths, &format!("{prefix}{path}"), methods, &config);
    }
    for section in busbar_kernel::config::named_map::NamedMapSection::sections() {
        let root = format!("{prefix}{}", section.path_root());
        add(paths, &root, &["get"], &config);
        add(
            paths,
            &format!("{root}/{{name}}"),
            &["get", "put", "delete"],
            &config,
        );
        add(
            paths,
            &format!("{root}/{{name}}/settings"),
            &["patch"],
            &config,
        );
    }
    add(
        paths,
        &format!("{prefix}/keys/{{id}}"),
        &["get"],
        &json!({
            "description": "Quoted key version for If-Match on this key's patch or delete operation. Re-read this key after mutation; this is not a configuration-generation ETag.",
            "schema": {"type": "string", "pattern": "^\"[0-9a-f]{16}\"$"}
        }),
    );
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
                // Input forms already declare their exact sign and width. A conventional
                // generator format supplements that contract; it must not replace it.
                map.entry("x-busbar-exact-number")
                    .or_insert_with(|| json!({"representation":"json-integer-token","integer_format":format,"client":"lossless-number-token-v1; preserve raw token before binary64 conversion"}));
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
    fn settings_request_alternatives_keep_exclusivity_and_null_refusals() {
        let schema = super::super::named_map::settings_request_schema();
        let validator = jsonschema::validator_for(&schema).unwrap();
        for good in [
            json!({"settings": {}}),
            json!({"settings": {"nullable": null}}),
            json!({"edit": {}}),
            json!({"edit": {"set": {"nullable": null}, "remove": ["retired"]}}),
        ] {
            assert!(validator.is_valid(&good), "{good}");
        }
        for bad in [
            json!({}),
            json!({"settings": {}, "edit": {}}),
            json!({"settings": null}),
            json!({"edit": null}),
            json!({"settings": {}, "edit": null}),
            json!({"settings": null, "edit": {}}),
            json!({"edit": {"sets": {"typo": true}}}),
        ] {
            assert!(!validator.is_valid(&bad), "{bad}");
        }
        for alternative in schema["oneOf"].as_array().unwrap() {
            assert_eq!(alternative["type"], "object");
            assert!(alternative["properties"].is_object());
            assert!(alternative.get("not").is_none());
        }
    }

    #[test]
    fn concurrency_headers_describe_real_versions_and_do_not_promise_mutation_key_etags() {
        let doc = super::super::handlers::openapi_doc();
        let response = super::super::with_config_etag(
            axum::response::Response::new(axum::body::Body::empty()),
            u64::MAX,
        );
        assert_eq!(response.headers()["etag"], "\"18446744073709551615\"");
        for (path, method, status) in [
            ("/config", "get", "200"),
            ("/config/settings", "get", "200"),
            ("/config/settings", "put", "200"),
            ("/groups/{name}", "get", "200"),
            ("/groups/{name}", "delete", "204"),
            ("/hooks", "post", "201"),
        ] {
            let header = &doc["paths"][format!("/api/v1/admin{path}")][method][RESPONSES_KEY]
                [status]["headers"]["ETag"];
            assert_eq!(header["schema"]["type"], "string", "{method} {path}");
            assert_eq!(header["schema"]["pattern"], "^\"[0-9]+\"$");
        }
        let key = &doc["paths"]["/api/v1/admin/keys/{id}"];
        assert_eq!(
            key["get"][RESPONSES_KEY]["200"]["headers"]["ETag"]["schema"]["pattern"],
            "^\"[0-9a-f]{16}\"$"
        );
        assert!(key["patch"][RESPONSES_KEY]["200"]["headers"]
            .get("ETag")
            .is_none());
        assert!(
            doc["paths"]["/api/v1/admin/restart"]["post"][RESPONSES_KEY]["202"]["headers"]
                .get("ETag")
                .is_none()
        );
    }

    #[test]
    fn rollback_digest_schema_matches_omission_but_rejects_null() {
        use super::super::handlers::PluginRollbackReq;
        let doc = super::super::handlers::openapi_doc();
        let schema = &doc["components"]["schemas"]["PluginRollbackReq"];
        let digest = &schema["properties"]["expected_archive_sha256"];
        assert_eq!(digest["type"], "string");
        assert!(digest.get("default").is_none());
        assert!(!schema["required"]
            .as_array()
            .unwrap()
            .contains(&json!("expected_archive_sha256")));
        assert!(
            serde_json::from_value::<PluginRollbackReq>(json!({"file":"plugin.tar.gz"})).is_ok()
        );
        assert!(serde_json::from_value::<PluginRollbackReq>(
            json!({"file":"plugin.tar.gz", "expected_archive_sha256":null})
        )
        .is_err());
        assert!(serde_json::from_value::<PluginRollbackReq>(
            json!({"file":"plugin.tar.gz", "expected_archive_sha256":"a".repeat(64)})
        )
        .is_ok());
    }

    #[test]
    fn telemetry_phase_is_a_string_enum_matching_the_wire() {
        use super::super::telemetry::Phase;
        let doc = super::super::handlers::openapi_doc();
        let phase = &doc["components"]["schemas"]["Phase"];
        assert_eq!(phase["type"], "string");
        assert_eq!(
            phase["enum"],
            json!([
                serde_json::to_value(Phase::LlmProducerDrive).unwrap(),
                serde_json::to_value(Phase::MountedResponseReady).unwrap(),
            ])
        );
        assert!(phase.get("oneOf").is_none());
    }

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
        for name in ["ConfigSettingsView", "ConfigDocumentMutationView"] {
            let version = &schemas[name]["properties"]["config_version"];
            assert_eq!(version["type"], "integer", "{name}");
            assert_eq!(version["format"], "uint64", "{name}");
            assert_eq!(
                version["x-busbar-exact-number"]["integer_format"], "uint64",
                "{name} must preserve the same exact config generation in both mutation arms"
            );
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
