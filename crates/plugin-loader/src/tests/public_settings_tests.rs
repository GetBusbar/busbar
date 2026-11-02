// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};

pub struct Stub;

impl Life for Stub {
    const CANCEL: u32 = 0;
    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Stub)
    }
    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

pub struct Resolve;

impl SafeSlot for Resolve {
    type In = busbar_contract::abi::secret::ResolveIn;
    type Out = busbar_contract::abi::secret::ResolveOut;
    type State = Held<Stub>;
    fn call(_: Instance<'_, Held<Stub>>, _: Lent<'_, Self::In>, _: Out<'_, Self::Out>) -> Outcome {
        Outcome::Refused
    }
}

mod plain {
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::sdk::door::statement("stub-plain", "1.6.0", 1),
        lifecycle: life(super::Stub),
        kind_ops: { resolve: busbar_contract::abi::sdk::Safe<super::Resolve> },
    }
}

fn stated(door: DoorFn) -> Vec<u8> {
    crate::dispatch::rendering_of(door).expect("the stub states itself")
}

#[test]
fn a_plugin_with_no_schema_has_no_row() {
    assert_eq!(public_settings(&stated(plain::door), &[]), Ok(None));
}

const SCHEMA: &[u8] = br#"{"type":"object","properties":{
    "url":{"type":"string","x-busbar-public":true},
    "timeout_ms":{"type":"integer","x-busbar-public":true},
    "client_secret":{"type":"string","x-busbar-secret":true},
    "audience":{"type":"string"}}}"#;

const LEAKY: &[u8] =
    br#"{"type":"object","properties":{"api_token":{"type":"string","x-busbar-public":true}}}"#;

const fn schema(bytes: &'static [u8]) -> busbar_contract::abi::mechanism::call::Blob {
    busbar_contract::abi::mechanism::call::Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: busbar_contract::abi::mechanism::call::BLOB_JSON,
        flags: 0,
    }
}

mod schematized {
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::mechanism::door::Statement {
            settings_schema: super::schema(super::SCHEMA),
            ..busbar_contract::abi::sdk::door::statement("stub-public", "1.6.0", 1)
        },
        lifecycle: life(super::Stub),
        kind_ops: { resolve: busbar_contract::abi::sdk::Safe<super::Resolve> },
    }
}

mod leaky {
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::mechanism::door::Statement {
            settings_schema: super::schema(super::LEAKY),
            ..busbar_contract::abi::sdk::door::statement("stub-leaky", "1.6.0", 1)
        },
        lifecycle: life(super::Stub),
        kind_ops: { resolve: busbar_contract::abi::sdk::Safe<super::Resolve> },
    }
}

#[test]
fn a_stub_plugins_schema_declares_its_public_settings() {
    let facts = public_settings(&stated(schematized::door), &["stub-alias"])
        .expect("the schema reads")
        .expect("the stub declares public settings");
    assert_eq!(
        facts.public.iter().map(String::as_str).collect::<Vec<_>>(),
        ["timeout_ms", "url"]
    );
    assert_eq!(facts.words, ["stub-alias", "stub-public"]);
}

#[test]
fn a_stub_plugin_declaring_a_credential_public_is_refused() {
    let refused = public_settings(&stated(leaky::door), &[]).expect_err("refused");
    assert!(
        refused.starts_with(
            "plugin 'stub-leaky': its settings schema: field 'api_token' looks \
         like a credential"
        ),
        "{refused}"
    );
}

#[test]
fn indirect_public_marks_are_refused_instead_of_silently_hidden() {
    use crate::settings_schema::public_settings_of_schema;
    let property = serde_json::json!({"region": {"type": "string", "x-busbar-public": true}});
    for keyword in ["oneOf", "anyOf", "allOf"] {
        let schema = serde_json::json!({keyword: [{"properties": property.clone()}]});
        assert!(
            public_settings_of_schema(&serde_json::to_vec(&schema).unwrap()).is_err(),
            "{keyword}"
        );
    }
    for keyword in ["if", "then", "else"] {
        let schema = serde_json::json!({keyword: {"properties": property.clone()}});
        assert!(
            public_settings_of_schema(&serde_json::to_vec(&schema).unwrap()).is_err(),
            "{keyword}"
        );
    }
    for schema in [
        serde_json::json!({"$defs": {"Region": {"properties": property.clone()}}, "$ref": "#/$defs/Region"}),
        serde_json::json!({"$defs": {"Region": {"type": "string", "x-busbar-public": true}}, "properties": {"region": {"$ref": "#/$defs/Region"}}}),
    ] {
        assert!(public_settings_of_schema(&serde_json::to_vec(&schema).unwrap()).is_err());
    }
    let schema = serde_json::json!({
        "$defs": {"Region": {"type": "string"}},
        "properties": {"region": {"$ref": "#/$defs/Region", "x-busbar-public": true}}
    });
    assert_eq!(
        public_settings_of_schema(&serde_json::to_vec(&schema).unwrap()).unwrap(),
        ["region".to_owned()].into_iter().collect()
    );
}

#[test]
fn repeated_reference_dag_keeps_its_small_effective_schema() {
    for branch in ["allOf", "oneOf", "anyOf", "properties"] {
        let mut defs = serde_json::Map::new();
        defs.insert("Leaf".into(), serde_json::json!({"type": "string"}));
        let mut previous = "Leaf".to_owned();
        for depth in 0..30 {
            let name = format!("Layer{depth}");
            let reference = format!("#/$defs/{previous}");
            let node = if branch == "properties" {
                serde_json::json!({"properties": {"left": {"$ref": reference}, "right": {"$ref": reference}}})
            } else {
                serde_json::json!({branch: [{"$ref": reference}, {"$ref": reference}]})
            };
            defs.insert(name.clone(), node);
            previous = name;
        }
        let schema = serde_json::json!({
            "$defs": defs,
            "properties": {"region": {"$ref": format!("#/$defs/{previous}"), "x-busbar-public": true}}
        });
        assert_eq!(
            crate::settings_schema::public_settings_of_schema(
                &serde_json::to_vec(&schema).unwrap()
            )
            .unwrap(),
            ["region".to_owned()].into_iter().collect()
        );
        let mut invalid = schema;
        invalid["$defs"]["Leaf"] =
            serde_json::json!({"properties": {"api_token": {"type": "string"}}});
        assert!(
            crate::settings_schema::validate_secret_fields(&invalid)
                .unwrap_err()
                .contains("api_token"),
            "{branch} must still inspect the leaf"
        );
    }
}

#[test]
fn reused_definitions_keep_depth_and_cycle_refusals() {
    use crate::settings_schema::validate_secret_fields;
    let mut defs = serde_json::Map::new();
    defs.insert("Leaf".into(), serde_json::json!({"type": "string"}));
    let mut previous = "Leaf".to_owned();
    for depth in 0..40 {
        let name = format!("Layer{depth}");
        defs.insert(
            name.clone(),
            serde_json::json!({"$ref": format!("#/$defs/{previous}")}),
        );
        previous = name;
    }
    let long = previous.clone();
    for depth in 0..30 {
        let name = format!("Wrapper{depth}");
        defs.insert(
            name.clone(),
            serde_json::json!({"$ref": format!("#/$defs/{previous}")}),
        );
        previous = name;
    }
    let schema = serde_json::json!({
        "$defs": defs,
        "allOf": [{"$ref": format!("#/$defs/{long}")}, {"$ref": format!("#/$defs/{previous}")}]
    });
    assert!(validate_secret_fields(&schema)
        .unwrap_err()
        .contains("deeper"));
    let cycle = serde_json::json!({
        "$defs": {"Loop": {"allOf": [{"$ref": "#/$defs/Loop"}]}},
        "$ref": "#/$defs/Loop"
    });
    assert!(validate_secret_fields(&cycle)
        .unwrap_err()
        .contains("cyclic"));
}

#[test]
fn a_scanned_definition_keeps_the_position_of_each_reference() {
    let schema = serde_json::json!({
        "$defs": {"Fields": {"properties": {"api_token": {"type": "string", "x-busbar-secret": true}}}},
        "oneOf": [
            {"oneOf": [{"$ref": "#/$defs/Fields"}]},
            {"properties": {"boxed": {"$ref": "#/$defs/Fields"}}}
        ]
    });
    assert!(crate::settings_schema::validate_secret_fields(&schema)
        .unwrap_err()
        .contains("direct root-level"));
}

#[test]
fn allof_properties_merging_refuses_a_nonobject_without_panicking() {
    let mut schema = serde_json::json!({
        "properties": false,
        "allOf": [{"properties": {"region": {"type": "string"}}}]
    });
    let bytes = serde_json::to_vec(&schema).unwrap();
    assert!(crate::settings_schema::public_settings_of_schema(&bytes).is_err());
    schema["properties"] = serde_json::json!({});
    assert!(crate::settings_schema::public_settings_of_schema(
        &serde_json::to_vec(&schema).unwrap()
    )
    .unwrap()
    .is_empty());
}

#[test]
fn reference_property_override_keeps_inherited_allof_validation() {
    let mut schema = serde_json::json!({
        "$ref": "#/$defs/Base",
        "properties": {"region": {"type": "string"}},
        "$defs": {"Base": {"allOf": [{"properties": {"password": {"type": "string"}}}]}}
    });
    assert!(crate::settings_schema::validate_secret_fields(&schema)
        .unwrap_err()
        .contains("password"));
    schema["$defs"]["Base"]["allOf"][0]["properties"]["password"]["x-busbar-secret"] = true.into();
    assert!(crate::settings_schema::validate_secret_fields(&schema).is_ok());
}

#[test]
fn reference_allof_and_local_siblings_keep_their_precedence() {
    let schema = serde_json::json!({
        "$defs": {
            "Plain": {"allOf": [{"type": "integer"}]},
            "Text": {"allOf": [{"type": "string"}]}
        },
        "properties": {
            "client_secret": {
                "$ref": "#/$defs/Plain",
                "type": "string",
                "x-busbar-secret": true,
                "allOf": [{"contentEncoding": "base64"}]
            },
            "region": {"$ref": "#/$defs/Text", "x-busbar-public": true}
        }
    });
    assert_eq!(
        crate::settings_schema::public_settings_of_schema(&serde_json::to_vec(&schema).unwrap())
            .unwrap(),
        ["region".to_owned()].into_iter().collect()
    );
    let mut invalid = schema;
    invalid["properties"]["client_secret"]["allOf"] =
        serde_json::json!([{"contentEncoding": "hex"}]);
    assert!(
        crate::settings_schema::validate_secret_fields(&invalid).is_err(),
        "local allOf still participates after a resolved reference"
    );
}
