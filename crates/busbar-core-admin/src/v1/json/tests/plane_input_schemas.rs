// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::mechanism::door::{SECTION_CONSUMED, SECTION_DECLARING};
use busbar_kernel::admission::ConfigurationDeclaration;
use serde_json::json;

fn stated(name: &str, root: &str) -> Stated {
    Stated {
        name: name.into(),
        alias: name.into(),
        kind: "plane".into(),
        version: "1.0.0".into(),
        publisher: "test".into(),
        abi_version: 1,
        configuration: Some(ConfigurationDeclaration {
            valid: true,
            sections: vec![
                (root.into(), SECTION_DECLARING),
                (format!("{root}_endpoint"), 0),
                ("borrowed".into(), SECTION_CONSUMED),
            ],
            claims: vec![],
        }),
        settings_schema: Some(json!({
            "$schema":"https://json-schema.org/draft/2020-12/schema",
            "$defs":{
                "member":{"type":"object","properties":{"url":{"type":"string"}},"required":["url"],"additionalProperties":false},
                "authored_section":{"type":"object","properties":{
                    "hooks":{"type":"array","items":{"type":"string"}},
                    "upstream_credentials":{"const":"own"},"pools":false
                },"additionalProperties":{"$ref":"#/$defs/member"}},
                "user_configuration":{"type":"object","properties":{
                    root:{"anyOf":[{"$ref":"#/$defs/authored_section"},{"type":"null"}]},
                    format!("{root}_endpoint"): {"type":"object"},
                    "borrowed":true,"invented":true
                }}
            },
            "x-busbar-user-configuration":{
                "version":1,"context":"raw_user_configuration",
                "schema_ref":"#/$defs/user_configuration",
                "reference_base":"returned_schema_document",
                "roots":[root,format!("{root}_endpoint"),"borrowed","invented"]
            }
        }).to_string()),
    }
}

#[test]
fn only_valid_planes_explicitly_owning_raw_configuration_contribute() {
    let valid = stated("test-plane", "widgets");
    let inputs = collect(std::slice::from_ref(&valid));
    assert_eq!(inputs.properties.len(), 2);
    assert!(inputs.properties.contains_key("widgets"));
    assert!(inputs.properties.contains_key("widgets_endpoint"));
    assert!(!inputs.properties.contains_key("borrowed"));
    assert!(!inputs.properties.contains_key("invented"));

    let mut cases = vec![];
    let mut no_extension = valid.clone();
    no_extension.settings_schema = Some(json!({"type":"object"}).to_string());
    cases.push(no_extension);
    let mut wrong_kind = valid.clone();
    wrong_kind.kind = "hook".into();
    cases.push(wrong_kind);
    let mut invalid = valid.clone();
    invalid.configuration.as_mut().unwrap().valid = false;
    cases.push(invalid);
    let mut absent = valid;
    absent.configuration = None;
    cases.push(absent);
    for case in cases {
        assert!(collect(&[case]).properties.is_empty());
    }
}

#[test]
fn owner_local_refs_keep_closed_members_and_reserved_controls_after_embedding() {
    let mut first = stated("first/plane", "widgets");
    let second = stated("second~plane", "gadgets");
    let mut schema: Value = serde_json::from_str(first.settings_schema.as_ref().unwrap()).unwrap();
    schema["$defs"]["member"]["properties"]["url"] = json!({"const":"first"});
    first.settings_schema = Some(schema.to_string());
    let inputs = collect(&[first, second]);
    assert_eq!(
        inputs.definitions.len(),
        2,
        "same local names stay owner-scoped"
    );
    let document = json!({"$schema":"https://json-schema.org/draft/2020-12/schema",
        "$defs":inputs.definitions,"type":"object","properties":inputs.properties});
    let validator = jsonschema::validator_for(&document).unwrap();
    for case in [
        json!({"widgets":null}),
        json!({"widgets":{"one":{"url":"first"}},"gadgets":{"two":{"url":"other"}}}),
        json!({"widgets":{"hooks":["audit"],"upstream_credentials":"own"}}),
    ] {
        assert!(validator.is_valid(&case), "{case}");
    }
    for case in [
        json!({"widgets":{"one":{"url":"other"}}}),
        json!({"widgets":{"one":{"url":"first","unknown":true}}}),
        json!({"widgets":{"hooks":{"url":"first"}}}),
        json!({"widgets":{"pools":{}}}),
        json!({"widgets":{"upstream_credentials":"passthrough"}}),
    ] {
        assert!(!validator.is_valid(&case), "{case}");
    }
}
