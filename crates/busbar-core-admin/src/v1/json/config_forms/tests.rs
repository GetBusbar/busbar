// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde_json::json;

fn compiled(name: &str) -> jsonschema::Validator {
    let mut schema = super::schema_document();
    let definitions = schema["$defs"].take();
    super::validator(
        &json!({"$schema":"https://json-schema.org/draft/2020-12/schema",
        "x-busbar-settings-profile":"integer-token-v1","$defs":definitions,
        "$ref":format!("#/$defs/{name}")}),
    )
}

#[test]
fn secret_and_identity_forms_match_owning_parsers_and_scope_ceiling() {
    use busbar_kernel::config::IdentityProviderCfg;
    let secret = compiled("SecretRef");
    for case in [
        json!("none"),
        json!({"env":"TOKEN"}),
        json!({"file":"key"}),
        json!({"module":"vault","settings":{"path":"x"}}),
        json!("inline-secret"),
        json!({"env":" "}),
        json!({"env":"TOKEN","unknown":true}),
        json!(null),
    ] {
        assert_eq!(
            secret.is_valid(&case),
            serde_json::from_value::<busbar_contract::secret_ref::SecretRef>(case.clone()).is_ok(),
            "{case}"
        );
    }
    let identity = compiled("IdentityProvider");
    for case in [
        json!({"module":"example"}),
        json!({}),
        json!({"module":"example","max_admin_scope":"none"}),
        json!({"module":"example","max_admin_scope":"read-only"}),
        json!({"module":"example","max_admin_scope":"full","token":{"env":"ADMIN"}}),
        json!({"module":"example","settings":null}),
        json!({"module":"example","settings":{"opaque":1}}),
        json!({"module":"example","browser_login":{"client_secret":"inline"}}),
        json!({"module":"example","browser_login":{"client_secret":{"env":"CLIENT"},"client_id":null}}),
        json!({"module":"example","unexpected":true}),
    ] {
        let actual = serde_json::from_value::<IdentityProviderCfg>(case.clone()).is_ok_and(|cfg| {
            cfg.max_admin_scope.as_deref().is_none_or(|scope| {
                busbar_kernel::config::parse::parse_ceiling("test", scope).is_ok()
            })
        });
        assert_eq!(identity.is_valid(&case), actual, "{case}");
    }
}

#[test]
fn auth_role_forms_match_owned_grammar_and_policy_prepass() {
    use busbar_kernel::config::RoleBindingCfg;
    let roles = compiled("RoleBinding");
    for case in [
        json!({}),
        json!({"allowed_pools":[]}),
        json!({"allowed_pools":null}),
        json!({"allowed_tools":["t"]}),
        json!({"allowed_tools":null}),
        json!({"allowed_s":[]}),
        json!({"allowed_\nfoos":[]}),
        json!({"verbs":"*"}),
        json!({"verbs":["get_keys"]}),
        json!({"verbs":[4]}),
        json!({"verbs":["not_a_declared_verb"]}),
        json!({"verbs":"get_keys"}),
        json!({"verbs":null}),
        json!({"admin_scope":"none"}),
        json!({"admin_scope":"full"}),
        json!({"unknown":[]}),
    ] {
        let actual = serde_json::from_value::<RoleBindingCfg>(case.clone()).is_ok_and(|cfg| {
            cfg.verb_grant().is_none_or(|grant| match grant {
                Ok(busbar_kernel::config::VerbGrant::All) => true,
                Ok(busbar_kernel::config::VerbGrant::Named(names)) => names
                    .iter()
                    .all(|name| crate::admin_codec::verbs::named_rung(name).is_some()),
                Err(_) => false,
            }) && cfg.admin_scope.as_deref().is_none_or(|scope| {
                busbar_kernel::config::parse::parse_ceiling("test", scope).is_ok()
            })
        });
        assert_eq!(roles.is_valid(&case), actual, "{case}");
    }
    let auth = compiled("Auth");
    for case in [
        json!({}),
        json!({"chain":["keys"],"admin_auth":[]}),
        json!({"chain":null}),
        json!({"chain":[{"module":"keys"}]}),
        json!({"policy":{"self_mint":false,"binding_modes":["both"]}}),
        json!({"policy":null}),
        json!({"policy":{"binding_modes":["other"]}}),
        json!({"policy":{"mint_ceilings":{"role":{"allowed_pools":[],"max_ttl":"1h"}}}}),
        json!({"policy":{"unknown":true}}),
        json!({"signing_key":{"env":"SIGNER"}}),
        json!({"unknown":true}),
    ] {
        let actual = busbar_kernel::config::deploy_from_deserializer(
            json!({"providers":{},"models":{},"auth":case.clone()}),
        )
        .is_ok();
        assert_eq!(auth.is_valid(&case), actual, "{case}");
    }
}

#[test]
fn export_forms_match_actual_projection_resolver_and_producer_capabilities() {
    use busbar_kernel::config::ExportDefCfg;
    let validator = compiled("Export");
    for case in [
        json!({"module":"fixture"}),
        json!({"module":"fixture","durable":true}),
        json!({"module":"fixture","durable":null}),
        json!({"module":"fixture","streams":[]}),
        json!({"module":"fixture","streams":["metrics"]}),
        json!({"module":"fixture","streams":["audit"]}),
        json!({"module":"fixture","streams":["costs"]}),
        json!({"module":"fixture","streams":["logs","logs"]}),
        json!({"module":"fixture","streams":["metrics"],"fields":["ts"]}),
        json!({"module":"fixture","streams":["logs"],"fields":["ts","outcome"]}),
        json!({"module":"fixture","streams":["traces"],"fields":["trace_id","span_id"]}),
        json!({"module":"fixture","streams":["events"],"fields":["seq","ts","prev_hash"]}),
        json!({"module":"fixture","streams":["events"],"fields":["seq","ts"]}),
        json!({"module":"fixture","streams":["events"],"fields":["seq","ts","prev_hash","latency_ms"]}),
        json!({"module":"fixture","streams":["events"],"fields":[]}),
        json!({"module":"fixture","streams":["events"],"fields":["seq","ts","prev_hash","seq"]}),
        json!({"module":"fixture","streams":["metrics","events"],"fields":["seq","ts","prev_hash"]}),
        json!({"module":"fixture","streams":null,"fields":null}),
        json!({"module":"fixture","settings":null}),
        json!({"module":"fixture","unknown":true}),
    ] {
        let actual = serde_json::from_value::<ExportDefCfg>(case.clone()).is_ok_and(|cfg| {
            busbar_kernel::export::validate_configuration_projection(&cfg).is_ok()
        });
        assert_eq!(validator.is_valid(&case), actual, "{case}");
    }
    let caps = busbar_kernel::export::configuration_capabilities();
    assert_eq!(caps["durable"], false);
    for stream in caps["streams"].as_array().unwrap() {
        assert_eq!(
            stream["fields_override"],
            stream["name"] == "events",
            "actual current producer restrictions"
        );
    }
}

#[test]
fn openapi_publishes_separate_user_input_forms_with_local_references() {
    let document = super::super::handlers::openapi_doc();
    let extension = &document["x-busbar-config-schemas"];
    assert_eq!(extension["context"], "user_configuration");
    assert_eq!(extension["version"], 1);
    assert_eq!(extension["reference_base"], "schema");
    fn check_references(root: &serde_json::Value, value: &serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                if let Some(reference) = map.get("$ref").and_then(serde_json::Value::as_str) {
                    let pointer = reference.strip_prefix('#').expect("local reference");
                    assert!(root.pointer(pointer).is_some(), "unresolved {reference}");
                }
                for child in map.values() {
                    check_references(root, child);
                }
            }
            serde_json::Value::Array(values) => {
                for child in values {
                    check_references(root, child);
                }
            }
            _ => {}
        }
    }
    check_references(&extension["schema"], &extension["schema"]);
    // Conventional generators need the numeric format as well as the lossless-token metadata.
    for schema in [
        &extension["schema"]["$defs"]["Limit"]["oneOf"][0]["properties"]["requests"],
        &document["components"]["schemas"]["ConfigInputHook"]["properties"]["timeout_ms"],
    ] {
        assert_eq!(schema["format"], "uint64");
        assert_eq!(schema["maximum"], u64::MAX);
        assert_eq!(schema["x-busbar-exact-number"]["signed"], false);
    }
    let validator = super::validator(&extension["schema"]);
    assert!(validator.is_valid(&json!({"auth":{"admin_auth":[],"role_bindings":{"idp":{"reader":{"admin_scope":"read-only"}}}}})));
    assert!(extension["schema"]["$defs"]["SecretRef"]["writeOnly"]
        .as_bool()
        .unwrap());
    assert!(extension["schema"]["x-busbar-partial"].as_bool().unwrap());
    assert!(document["paths"]["/api/v1/admin/telemetry"]["get"].is_object());
    assert!(extension["ownership"]["other_plane_sections"]
        .as_str()
        .unwrap()
        .contains("declaring plane"));
}
