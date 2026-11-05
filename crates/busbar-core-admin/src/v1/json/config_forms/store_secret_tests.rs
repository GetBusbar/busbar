// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde_json::{json, Value};

fn compiled(name: &str) -> jsonschema::Validator {
    let mut schema = super::schema_document();
    let definitions = schema["$defs"].take();
    super::validator(&json!({
        "$schema":"https://json-schema.org/draft/2020-12/schema",
        "$defs":definitions,"$ref":format!("#/$defs/{name}")
    }))
}

fn deployment(section: &str, value: Value) -> Value {
    let mut document = json!({"providers":{},"models":{}});
    document[section] = value;
    document
}

#[test]
fn store_forms_match_actual_wrapper_and_deployment_parsers() {
    use busbar_kernel::config::StoreCfg;
    let schema = super::schema_document();
    let store = compiled("Store");
    let document = super::validator(&schema);
    for (index, case) in [
        json!({}),
        json!({"module":""}),
        json!({"module":"fixture"}),
        json!({"settings":{}}),
        json!({"module":"fixture","settings":{"opaque":null,"number":0.125}}),
        json!({"module":null}),
        json!({"module":42}),
        json!({"settings":null}),
        json!({"settings":[]}),
        json!({"module":"fixture","unknown":true}),
        json!({"named-store":{"module":"fixture"}}),
        json!(null),
        json!([]),
        json!(["fixture"]),
        json!(["fixture", {}]),
        json!(["fixture", {"opaque":null,"number":0.125}]),
        json!([null]),
        json!([{}]),
        json!([42]),
        json!(["fixture", null]),
        json!(["fixture", []]),
        json!(["fixture", {}, "extra"]),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            store.is_valid(&case),
            serde_json::from_value::<StoreCfg>(case.clone()).is_ok(),
            "store wrapper case {index}"
        );
        let raw = deployment("store", case);
        assert_eq!(
            document.is_valid(&raw),
            busbar_kernel::config::deploy_from_deserializer(raw).is_ok(),
            "store deployment case {index}"
        );
    }
    let defaults: StoreCfg = serde_json::from_value(json!({})).unwrap();
    assert_eq!(
        schema["$defs"]["Store"]["oneOf"][0]["properties"]["module"]["default"],
        json!(defaults.module)
    );
    assert_eq!(
        schema["$defs"]["Store"]["oneOf"][0]["properties"]["settings"]["default"],
        json!(defaults.settings)
    );
    assert!(schema["$defs"]["Store"]["oneOf"][0]
        .get("required")
        .is_none());
    assert_eq!(
        schema["$defs"]["Store"]["oneOf"][0]["additionalProperties"],
        false
    );
    for raw in [json!([]), json!(["fixture"])] {
        let parsed: StoreCfg = serde_json::from_value(raw.clone()).unwrap();
        assert!(parsed.settings.is_empty());
        assert_eq!(
            parsed.module,
            if raw.as_array().unwrap().is_empty() {
                ""
            } else {
                "fixture"
            }
        );
        assert!(
            serde_json::to_value(parsed).unwrap().is_object(),
            "serialization keeps the canonical object form"
        );
    }
    // Absence/null parse as None; the actual resolver still requires a usable store selection.
    assert!(document.is_valid(&json!({"providers":{},"models":{}})));
    assert!(schema["$defs"]["Store"]["x-busbar-runtime-validation"]
        .as_array()
        .unwrap()
        .iter()
        .any(|rule| rule.as_str().unwrap().contains("selection is required")));
}

#[test]
fn secret_module_forms_match_actual_module_keyed_parser() {
    use busbar_kernel::config::SecretModuleCfg;
    let schema = super::schema_document();
    let module = compiled("SecretModule");
    for (index, case) in [
        json!({}),
        json!({"settings":{}}),
        json!({"settings":{"token":{"env":"FIXTURE_TOKEN"}}}),
        json!({"settings":{"token":{"file":"/fixture/token"},"opaque":[1,null]}}),
        json!({"settings":null}),
        json!({"settings":[]}),
        json!({"module":"fixture","settings":{}}),
        json!({"unknown":true}),
        json!(null),
        json!([]),
        json!([{}]),
        json!([{"token":{"env":"FIXTURE_TOKEN"}}]),
        json!([null]),
        json!([[]]),
        json!(["fixture"]),
        json!([{}, {}]),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            module.is_valid(&case),
            serde_json::from_value::<SecretModuleCfg>(case).is_ok(),
            "secret module wrapper case {index}"
        );
    }
    let document = super::validator(&schema);
    for (index, case) in [
        json!({}),
        json!({"fixture":{}}),
        json!({"fixture":{"settings":{"token":{"env":"FIXTURE_TOKEN"}}}}),
        // These names are accepted structurally; runtime validation rejects their initialization.
        json!({"env":{"settings":{}}}),
        json!({"file":{"settings":{}}}),
        json!({"fixture":[]}),
        json!({"fixture":[{}]}),
        json!({"fixture":[{"token":{"file":"/fixture/token"}}]}),
        json!({"fixture":[{},{}]}),
        json!({"fixture":[null]}),
        json!({"instance":{"module":"fixture","settings":{}}}),
        json!({"fixture":null}),
        json!(null),
        json!([]),
    ]
    .into_iter()
    .enumerate()
    {
        let raw = deployment("secrets", case);
        assert_eq!(
            document.is_valid(&raw),
            busbar_kernel::config::deploy_from_deserializer(raw).is_ok(),
            "secret module map case {index}"
        );
    }
    let defaults: SecretModuleCfg = serde_json::from_value(json!({})).unwrap();
    assert_eq!(
        schema["$defs"]["SecretModule"]["oneOf"][0]["properties"]["settings"]["default"],
        json!(defaults.settings)
    );
    assert_eq!(schema["properties"]["secrets"]["default"], json!({}));
    assert_eq!(
        schema["$defs"]["SecretModule"]["oneOf"][0]["additionalProperties"],
        false
    );
    assert!(schema["$defs"]["SecretModule"]["oneOf"][0]
        .get("required")
        .is_none());
    assert!(schema["$defs"]["SecretModule"]["oneOf"][0]["properties"]
        .get("module")
        .is_none());
    let positional: SecretModuleCfg = serde_json::from_value(json!([])).unwrap();
    assert!(positional.settings.is_empty());
    assert!(
        serde_json::to_value(positional).unwrap().is_object(),
        "serialization keeps the canonical object form"
    );
}

#[test]
fn store_secret_forms_keep_runtime_rules_and_never_publish_input_values() {
    let before = super::extension();
    let raw = json!({
        "providers":{},"models":{},
        "store":{"module":"fixture","settings":{"password":{"file":"/private/STORE_FORM_CANARY"}}},
        "secrets":{"fixture":{"settings":{"token":{"env":"SECRET_FORM_CANARY"},"opaque":"PRIVATE_FORM_CANARY"}}}
    });
    let parsed = busbar_kernel::config::deploy_from_deserializer(raw.clone()).unwrap();
    assert!(super::validator(&before["schema"]).is_valid(&raw));
    assert_eq!(
        parsed.secrets["fixture"].settings["token"],
        json!({"env":"SECRET_FORM_CANARY"})
    );
    assert_eq!(
        parsed.store.unwrap().settings["password"],
        json!({"file":"/private/STORE_FORM_CANARY"})
    );
    let after = super::extension();
    assert_eq!(
        before, after,
        "form export is independent of configuration inputs"
    );
    let serialized = serde_json::to_string(&after).unwrap();
    for marker in [
        "STORE_FORM_CANARY",
        "SECRET_FORM_CANARY",
        "PRIVATE_FORM_CANARY",
    ] {
        assert!(
            !serialized.contains(marker),
            "form export must not contain input values"
        );
    }
    for name in ["Store", "SecretModule"] {
        assert_eq!(
            after["schema"]["$defs"][name]["oneOf"][0]["properties"]["settings"]
                ["x-busbar-module-settings"],
            true
        );
        assert_eq!(
            after["schema"]["$defs"][name]["oneOf"][0]["properties"]["settings"]["default"],
            json!({})
        );
    }
    let rules = after["schema"]["$defs"]["SecretModule"]["x-busbar-runtime-validation"]
        .as_array()
        .unwrap();
    assert!(rules
        .iter()
        .any(|rule| rule.as_str().unwrap().contains("bootstrap env/file")));
    assert!(rules
        .iter()
        .any(|rule| rule.as_str().unwrap().contains("built-in env/file")));
    assert!(after["ownership"]["store"]
        .as_str()
        .unwrap()
        .contains("singular"));
    assert!(after["ownership"]["secrets"]
        .as_str()
        .unwrap()
        .contains("keyed by module"));
}
