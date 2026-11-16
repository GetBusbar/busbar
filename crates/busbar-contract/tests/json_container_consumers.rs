// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::{hook_wire, json, jsonrpc, provider_keys};

#[test]
fn parsed_object_and_array_values_reach_contract_readers() {
    let request = json::parse_value(
        br#"{"jsonrpc":"2.0","id":"container-reader","method":"probe","params":[]}"#,
    )
    .unwrap();
    assert_eq!(
        jsonrpc::read(&request).unwrap(),
        jsonrpc::Envelope::Request {
            id: json::json!("container-reader"),
            method: "probe".to_string(),
        }
    );

    let restrict = json::parse_value(br#"{"tags_any":[" first ","second"]}"#).unwrap();
    assert_eq!(
        hook_wire::parse_restrict(&restrict).unwrap().tags_any,
        ["first", "second"]
    );
    for malformed in [br#"{"tags_any":{}}"#.as_slice(), br#"{"tags_any":[1]}"#] {
        assert!(hook_wire::parse_restrict(&json::parse_value(malformed).unwrap()).is_none());
    }

    let descriptor = br#"{
        "catalog":{"deny_unknown":true,"keys":[
            {"name":"modes","shape":{"list":{"one-of":["a","b"]}},"required":true}
        ]},
        "deployment":{"deny_unknown":true,"keys":[]},
        "entry":{"deny_unknown":true,"keys":[]}
    }"#;
    let keys = provider_keys::decode(descriptor).unwrap();
    assert_eq!(
        keys.catalog.keys[0].shape,
        provider_keys::Shape::List(Box::new(provider_keys::Shape::OneOf(vec![
            "a".to_string(),
            "b".to_string(),
        ])))
    );
    assert_eq!(
        provider_keys::decode(&provider_keys::encode(&keys)),
        Ok(keys)
    );
}
