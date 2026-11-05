// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use serde_json::json;

#[test]
fn settings_schema_profile_distinguishes_mathematical_integers_from_tokens() {
    for (kind, minimum, maximum) in [
        ("unsigned", json!(0), json!(u64::MAX)),
        ("signed", json!(i64::MIN), json!(i64::MAX)),
    ] {
        let schema = json!({
            "x-busbar-settings-profile": "integer-token-v1",
            "type": "integer", "minimum": minimum, "maximum": maximum,
            "x-busbar-integer-token": kind
        });
        let standard = jsonschema::validator_for(&schema).unwrap();
        let profile = validator(&schema).unwrap();
        for token in ["1.0", "1e0", "1E+0", "0.0", "0e0", "-0.0", "-0e0"] {
            let value: Value = serde_json::from_str(token).unwrap();
            assert!(standard.is_valid(&value), "standard: {token}");
            assert!(!profile.is_valid(&value), "profile: {token}");
            assert!(profile.validate(&value).is_err(), "validate: {token}");
        }
        for token in ["0", "1", "4294967295"] {
            assert!(profile.is_valid(&serde_json::from_str(token).unwrap()));
        }
        for token in [
            "true",
            "null",
            "\"1\"",
            "1.5",
            "18446744073709551616",
            "-9223372036854775809",
        ] {
            assert!(!profile.is_valid(&serde_json::from_str(token).unwrap()));
        }
        let negative_zero: Value = serde_json::from_str("-0").unwrap();
        let native_zero = if kind == "signed" {
            negative_zero.as_i64().is_some()
        } else {
            negative_zero.as_u64().is_some()
        };
        assert_eq!(profile.is_valid(&negative_zero), native_zero);
        assert!(profile.is_valid(&json!(i64::MAX)));
        assert_eq!(profile.is_valid(&json!(-1)), kind == "signed");
        assert_eq!(profile.is_valid(&json!(u64::MAX)), kind == "unsigned");
        assert_eq!(profile.is_valid(&json!(i64::MIN)), kind == "signed");
    }
}

#[test]
fn settings_schema_profile_keeps_applicator_branches_and_noninteger_values() {
    let schema = json!({
        "x-busbar-settings-profile": "integer-token-v1",
        "$defs": {"count": {"type": "integer", "minimum": 0,
            "maximum": u32::MAX, "x-busbar-integer-token": "unsigned"}},
        "type": "object", "properties": {
            "count": {"anyOf": [{"$ref": "#/$defs/count"}, {"type": "null"}]},
            "ratio": {"type": "number"},
            "opaque": {}
        }
    });
    let profile = validator(&schema).unwrap();
    for text in [
        r#"{"count":0,"ratio":1.0,"opaque":{"n":1e0}}"#,
        r#"{"count":null}"#,
        r#"{"count":4294967295}"#,
    ] {
        assert!(
            profile.is_valid(&serde_json::from_str(text).unwrap()),
            "{text}"
        );
    }
    for text in [
        r#"{"count":1.0}"#,
        r#"{"count":1e0}"#,
        r#"{"count":4294967296}"#,
    ] {
        assert!(
            !profile.is_valid(&serde_json::from_str(text).unwrap()),
            "{text}"
        );
    }
    // Negative zero is governed by the native Number representation, including
    // through $ref/anyOf. Preserve the case without inventing a lexical refusal.
    let value: Value = serde_json::from_str(r#"{"count":-0}"#).unwrap();
    let native = value["count"]
        .as_u64()
        .and_then(|count| u32::try_from(count).ok())
        .is_some();
    assert_eq!(profile.is_valid(&value), native, "native negative zero");
    assert_eq!(
        profile.validate(&value).is_ok(),
        native,
        "native negative zero"
    );
}

#[test]
fn settings_schema_profile_refuses_undeclared_or_unknown_keywords() {
    for schema in [
        json!({"type": "integer", "x-busbar-integer-token": "unsigned"}),
        json!({"x-busbar-settings-profile": "future"}),
        json!({"x-busbar-settings-profile": "integer-token-v1", "type": "integer",
            "x-busbar-integer-token": true}),
        json!({"x-busbar-settings-profile": "integer-token-v1", "type": "number",
            "x-busbar-integer-token": "unsigned"}),
    ] {
        assert!(validator(&schema).is_err(), "{schema}");
    }
    let standard = validator(&json!({"type": "integer"})).unwrap();
    assert!(standard.is_valid(&json!(1.0)));
}

#[test]
fn settings_schema_profile_preserves_nullable_integer_type_unions() {
    let schema = json!({
        "x-busbar-settings-profile": "integer-token-v1",
        "$defs": {"count": {"type": ["integer", "null"], "minimum": 0,
            "maximum": u64::MAX, "x-busbar-integer-token": "unsigned"}},
        "type": "object", "properties": {"count": {"$ref": "#/$defs/count"}},
        "allOf": [{"if": {"required": ["null_only"]},
            "then": {"properties": {"count": {"type": "null"}}}}]
    });
    let profile = validator(&schema).unwrap();
    for text in [
        r#"{}"#,
        r#"{"count":null}"#,
        r#"{"count":0}"#,
        r#"{"count":18446744073709551615}"#,
        r#"{"count":null,"null_only":true}"#,
    ] {
        assert!(
            profile.is_valid(&serde_json::from_str(text).unwrap()),
            "{text}"
        );
    }
    for text in [
        r#"{"count":1.0}"#,
        r#"{"count":1e0}"#,
        r#"{"count":-1}"#,
        r#"{"count":18446744073709551616}"#,
        r#"{"count":1,"null_only":true}"#,
    ] {
        assert!(
            !profile.is_valid(&serde_json::from_str(text).unwrap()),
            "{text}"
        );
    }
    let nonnullable = json!({"x-busbar-settings-profile":"integer-token-v1",
        "type":"integer", "x-busbar-integer-token":"unsigned"});
    assert!(!validator(&nonnullable).unwrap().is_valid(&Value::Null));
}
