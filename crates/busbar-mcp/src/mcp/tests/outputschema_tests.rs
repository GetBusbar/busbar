// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for [`crate::mcp::outputschema`] — the check that keeps the promise `outputSchema` makes.
//!
//! The suite is arranged around this module's ONE-SIDED rule, because that rule is the whole of its
//! safety argument: a missed violation lets a lie through, but a FALSE violation turns a working
//! tool call into a failure for a caller who did nothing wrong. So for every keyword the validator
//! DOES model there is a test that it catches a violation, and for the keywords it does NOT model
//! there is a test that it stays silent rather than guessing.

use crate::mcp::outputschema::check;
use serde_json::json;

#[test]
fn a_conforming_object_passes() {
    let schema = json!({
        "type": "object",
        "properties": { "count": { "type": "integer" }, "label": { "type": "string" } },
        "required": ["count"],
    });
    assert!(check(&json!({ "count": 3, "label": "x" }), &schema).is_ok());
}

#[test]
fn a_wrong_type_is_a_violation() {
    let schema = json!({ "type": "object", "properties": { "count": { "type": "integer" } } });
    let e = check(&json!({ "count": "not-an-integer" }), &schema).unwrap_err();
    assert!(e.contains("$.count"), "{e}");
    assert!(e.contains("expected type"), "{e}");
}

#[test]
fn a_missing_required_property_is_a_violation() {
    let schema = json!({ "type": "object", "required": ["count"] });
    let e = check(&json!({}), &schema).unwrap_err();
    assert!(e.contains("missing required property `count`"), "{e}");
}

#[test]
fn the_hostile_peers_lie_is_caught() {
    // Byte-for-byte the battery's `outputschema-lie` mode: it declares `{count: integer}` with
    // `count` required, and returns `{count: "not-an-integer", extra: true}`.
    let schema = json!({
        "type": "object",
        "properties": { "count": { "type": "integer" } },
        "required": ["count"],
    });
    assert!(check(
        &json!({ "count": "not-an-integer", "extra": true }),
        &schema
    )
    .is_err());
}

#[test]
fn an_integral_float_satisfies_integer() {
    // JSON has one numeric type: `1.0` and `1` are the same value, and refusing the former
    // would fail a conforming upstream over its serialiser's formatting.
    let schema = json!({ "type": "object", "properties": { "n": { "type": "integer" } } });
    assert!(check(&json!({ "n": 1.0 }), &schema).is_ok());
}

#[test]
fn a_ref_is_never_dereferenced_and_never_fails() {
    // THE ONE-SIDED RULE. A subschema behind a `$ref` is UNCHECKED, not violated — dereferencing
    // it is a MUST NOT for the network case and a guess for the local one.
    let schema = json!({
        "type": "object",
        "properties": { "a": { "$ref": "https://example.invalid/s.json" } },
        "$defs": { "x": { "type": "integer" } },
    });
    assert!(check(&json!({ "a": "anything at all" }), &schema).is_ok());
}

#[test]
fn unmodelled_keywords_never_manufacture_a_violation() {
    // A document that ONLY `allOf`/`if`/`pattern` would reject must pass, because this module
    // does not evaluate them and a false violation is a self-inflicted outage.
    let schema = json!({
        "type": "object",
        "properties": { "s": { "type": "string", "pattern": "^\\d+$", "minLength": 40 } },
        "allOf": [{ "required": ["nope"] }],
        "if": { "required": ["s"] },
        "then": { "required": ["also-nope"] },
    });
    assert!(check(&json!({ "s": "abc" }), &schema).is_ok());
}

#[test]
fn additional_properties_false_is_enforced_and_the_schema_form_is_not() {
    let closed = json!({
        "type": "object",
        "properties": { "a": { "type": "string" } },
        "additionalProperties": false,
    });
    assert!(check(&json!({ "a": "x", "b": 1 }), &closed).is_err());
    // The SCHEMA form of the same keyword is an evaluation this module does not model, so it
    // must not be read as `false`.
    let schema_form = json!({
        "type": "object",
        "properties": { "a": { "type": "string" } },
        "additionalProperties": { "type": "integer" },
    });
    assert!(check(&json!({ "a": "x", "b": "also a string" }), &schema_form).is_ok());
}

#[test]
fn arrays_are_walked_and_the_tuple_form_is_not() {
    let schema = json!({ "type": "array", "items": { "type": "integer" } });
    assert!(check(&json!([1, 2, 3]), &schema).is_ok());
    assert!(check(&json!([1, "two"]), &schema).is_err());
    // The tuple form is a different evaluation: unchecked, never misapplied.
    let tuple = json!({ "type": "array", "items": [{ "type": "integer" }] });
    assert!(check(&json!(["not an integer"]), &tuple).is_ok());
}

#[test]
fn enum_and_const_are_exact() {
    let e = json!({ "type": "object", "properties": { "k": { "enum": ["a", "b"] } } });
    assert!(check(&json!({ "k": "a" }), &e).is_ok());
    assert!(check(&json!({ "k": "c" }), &e).is_err());
    let c = json!({ "type": "object", "properties": { "k": { "const": 7 } } });
    assert!(check(&json!({ "k": 7 }), &c).is_ok());
    assert!(check(&json!({ "k": 8 }), &c).is_err());
}

#[test]
fn a_self_referential_value_cannot_exhaust_the_stack() {
    // The depth bound STOPS CHECKING; it never manufactures a violation.
    let mut v = json!(1);
    let mut s = json!({ "type": "integer" });
    for _ in 0..200 {
        v = json!([v]);
        s = json!({ "type": "array", "items": s });
    }
    assert!(check(&v, &s).is_ok());
}

#[test]
fn a_non_object_schema_constrains_nothing() {
    assert!(check(&json!({ "anything": true }), &json!(true)).is_ok());
    assert!(check(&json!(1), &json!("not a schema")).is_ok());
}
