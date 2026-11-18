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
        signature_present: false,
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

#[cfg(feature = "openapi-schema")]
#[test]
fn published_registration_resource_reaches_core_ownership_without_plane_authority() {
    use busbar_contract::json::JsonValueTrait as _;
    use busbar_kernel::upstreams::{core_field_paths, core_secret_paths, declared, Upstreams as _};

    let mut plane = stated("resource/fixture", "widgets");
    let mut schema: Value = serde_json::from_str(plane.settings_schema.as_ref().unwrap()).unwrap();
    schema["$defs"]["member"]["properties"]["resource"] = json!({
        "type":["string","null"],"minLength":1,"maxLength":128,
        "pattern":"^[^\\u0000-\\u001f\\u007f-\\u009f]+$",
        "description":"Core resource label; canonical admission additionally enforces at most 128 UTF-8 bytes."
    });
    plane.settings_schema = Some(schema.to_string());
    let inputs = collect(&[plane]);
    let mut document = super::super::config_forms::schema_document();
    inputs.extend_document(&mut document);
    assert!(document["properties"].get("upstreams").is_none());
    let validator = jsonschema::validator_for(&document).unwrap();
    for resource in [
        None,
        Some(Value::Null),
        Some(json!("shared/a")),
        Some(json!("é".repeat(64))),
    ] {
        let mut authored = json!({"widgets":{"member":{"url":"https://example.test"}}});
        if let Some(resource) = &resource {
            authored["widgets"]["member"]["resource"] = resource.clone();
        }
        assert!(validator.is_valid(&authored), "{authored}");
        let bag = busbar_contract::json::parse_value(authored.to_string().as_bytes()).unwrap();
        let split = declared("resource/fixture", &bag, &["/widgets/*"], &|_| {
            Err("no trust anchor".into())
        })
        .unwrap();
        let expected = resource.as_ref().and_then(Value::as_str);
        assert_eq!(split.parsed["member"].resource.as_deref(), expected);
        assert_eq!(
            split.definitions.get("member").unwrap().resource.as_deref(),
            expected
        );
        assert!(split.visible_bag["widgets"]["member"]
            .get("resource")
            .is_none());
        assert_eq!(split.reattach(&split.visible_bag).unwrap(), bag);
        assert!(core_field_paths(&bag, &["/widgets/*"])
            .unwrap()
            .contains("/widgets/member/resource"));
        assert!(!core_secret_paths(&bag, &["/widgets/*"])
            .unwrap()
            .contains("/widgets/member/resource"));
        let injected =
            busbar_contract::json::parse_value(br#"{"widgets":{"member":{"resource":null}}}"#)
                .unwrap();
        assert!(split.reattach(&injected).is_err());
    }
    for resource in [
        json!(1),
        json!(""),
        json!("bad\nlabel"),
        json!("x".repeat(129)),
    ] {
        let authored =
            json!({"widgets":{"member":{"url":"https://example.test","resource":resource}}});
        assert!(!validator.is_valid(&authored), "{authored}");
    }
    let multibyte =
        json!({"widgets":{"member":{"url":"https://example.test","resource":"é".repeat(65)}}});
    assert!(
        validator.is_valid(&multibyte),
        "standard maxLength measures characters"
    );
    let bag = busbar_contract::json::parse_value(multibyte.to_string().as_bytes()).unwrap();
    assert!(
        declared("resource/fixture", &bag, &["/widgets/*"], &|_| Err(
            "no trust anchor".into()
        ))
        .is_err()
    );
}

// Producer: busbar-plane-a2a 788c2ba8b07369bad53bf29c0aa0d4dbad7b2349.
// Exact schema SHA256: 077316d34a01fe9eda0d3732eb46e0ff66983f3731ba9aa3f0d3be72731031e1.
// This admitted-Statements fixture proves collector composition. Root must separately prove
// native descriptor admission supplies that section ownership in production.
#[cfg(feature = "openapi-schema")]
#[test]
fn native_authored_registration_resource_uses_the_actual_bag_relative_pointer() {
    use busbar_kernel::upstreams::{core_field_paths, core_secret_paths, declared, Upstreams as _};

    let mut plane = stated("native-registration-fixture", "a2a");
    plane.settings_schema =
        Some(include_str!("fixtures/a2a-native-registration.schema.json").to_owned());
    let inputs = collect(&[plane]);
    let mut document = super::super::config_forms::schema_document();
    inputs.extend_document(&mut document);
    assert_eq!(
        document["properties"]["a2a"]["$ref"],
        "#/$defs/PlaneInput:native-registration-fixture/$defs/authored_settings"
    );
    assert!(document["properties"].get("upstreams").is_none());
    let validator = jsonschema::validator_for(&document).unwrap();
    let lifecycle: Value =
        serde_json::from_str(include_str!("fixtures/a2a-native-registration.schema.json")).unwrap();
    let lifecycle_validator = jsonschema::validator_for(&lifecycle).unwrap();
    for resource in [
        None,
        Some(Value::Null),
        Some(json!("shared/a")),
        Some(json!("é".repeat(64))),
    ] {
        let mut authored = json!({"a2a":{"format":2,"agents":{"vendor":{
            "url":"https://example.test/a2a", "pin":"unpinned", "hooks":["audit"]
        }}}});
        if let Some(resource) = &resource {
            authored["a2a"]["agents"]["vendor"]["resource"] = resource.clone();
        }
        assert!(validator.is_valid(&authored), "{authored}");
        // Native root::min3_boot::plane_instances selects the a2a section first.
        let bag =
            busbar_contract::json::parse_value(authored["a2a"].to_string().as_bytes()).unwrap();
        let split = declared("a2a", &bag, &["/agents/*"], &|_| {
            Err("no trust anchor".into())
        })
        .unwrap();
        let expected = resource.as_ref().and_then(Value::as_str);
        assert_eq!(split.parsed["vendor"].resource.as_deref(), expected);
        assert_eq!(
            split.definitions.get("vendor").unwrap().resource.as_deref(),
            expected
        );
        assert_eq!(
            split.visible_bag,
            busbar_contract::json::parse_value(
                br#"{"format":2,"agents":{"vendor":{"pin":"unpinned","hooks":["audit"]}}}"#
            )
            .unwrap()
        );
        assert_eq!(split.reattach(&split.visible_bag).unwrap(), bag);
        let visible: Value =
            serde_json::from_str(&busbar_contract::json::to_string(&split.visible_bag).unwrap())
                .unwrap();
        assert!(lifecycle_validator.is_valid(&visible));
        assert!(!lifecycle_validator.is_valid(&authored["a2a"]));
        let mut resource_in_lifecycle = visible;
        resource_in_lifecycle["agents"]["vendor"]["resource"] =
            resource.clone().unwrap_or(Value::Null);
        assert!(!lifecycle_validator.is_valid(&resource_in_lifecycle));
        assert!(core_field_paths(&bag, &["/agents/*"])
            .unwrap()
            .contains("/agents/vendor/resource"));
        assert!(!core_secret_paths(&bag, &["/agents/*"])
            .unwrap()
            .contains("/agents/vendor/resource"));
        for injected in [
            br#"{"format":2,"agents":{"vendor":{"pin":"unpinned","resource":null}}}"#.as_slice(),
            br#"{"format":2,"agents":{"vendor":{"pin":"unpinned","resource":"invented"}}}"#
                .as_slice(),
        ] {
            assert!(split
                .reattach(&busbar_contract::json::parse_value(injected).unwrap())
                .is_err());
        }
    }
    for resource in [
        json!(1),
        json!(true),
        json!({}),
        json!([]),
        json!(""),
        json!("bad\nlabel"),
        json!("bad\u{85}label"),
        json!("x".repeat(129)),
    ] {
        let authored = json!({"a2a":{"format":2,"agents":{"vendor":{
            "url":"https://example.test/a2a", "pin":"unpinned", "resource":resource
        }}}});
        assert!(!validator.is_valid(&authored), "{authored}");
        let bag =
            busbar_contract::json::parse_value(authored["a2a"].to_string().as_bytes()).unwrap();
        assert!(declared("a2a", &bag, &["/agents/*"], &|_| Err(
            "no trust anchor".into()
        ))
        .is_err());
    }
    let multibyte = json!({"a2a":{"format":2,"agents":{"vendor":{
        "url":"https://example.test/a2a", "pin":"unpinned", "resource":"é".repeat(65)
    }}}});
    assert!(validator.is_valid(&multibyte), "schema counts characters");
    let bag = busbar_contract::json::parse_value(multibyte["a2a"].to_string().as_bytes()).unwrap();
    assert!(
        declared("a2a", &bag, &["/agents/*"], &|_| Err(
            "no trust anchor".into()
        ))
        .is_err(),
        "host counts UTF-8 bytes"
    );
}
