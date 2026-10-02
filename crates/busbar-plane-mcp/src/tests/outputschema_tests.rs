// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for [`crate::outputschema`] — the check that keeps the promise `outputSchema` makes.
//!
//! The suite is arranged around this module's ONE-SIDED rule, because that rule is the whole of its
//! safety argument: a missed violation lets a lie through, but a FALSE violation turns a working
//! tool call into a failure for a caller who did nothing wrong. So for every keyword the validator
//! DOES model there is a test that it catches a violation, and for the keywords it does NOT model
//! there is a test that it stays silent rather than guessing.

use crate::outputschema::{check, MAX_ERRORS};
use serde_json::{json, Value};

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

/// JSON HAS ONE NUMERIC TYPE, and `const`/`enum` must read it the way `type` already does. `1` and
/// `1.0` are the same number, so a schema that pins one and an upstream that serialised the other
/// agree — and reporting that as a violation would fail a conforming tool over its serialiser's
/// formatting, which is exactly the false violation this module promises never to produce.
#[test]
fn an_integral_float_and_an_integer_are_the_same_constant() {
    let c = json!({ "type": "object", "properties": { "k": { "const": 1.0 } } });
    assert!(check(&json!({ "k": 1 }), &c).is_ok());
    let c = json!({ "type": "object", "properties": { "k": { "const": 1 } } });
    assert!(check(&json!({ "k": 1.0 }), &c).is_ok());
    let e = json!({ "type": "object", "properties": { "k": { "enum": [1.0, 2.0] } } });
    assert!(check(&json!({ "k": 1 }), &e).is_ok());
    assert!(check(&json!({ "k": 2 }), &e).is_ok());
    // And a number that is genuinely a different number is still a violation.
    assert!(check(&json!({ "k": 3 }), &e).is_err());
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

/// THE VIOLATION LIST IS BOUNDED, and the bound is a defence rather than a tidiness rule: without
/// it an upstream returning a thousand unexpected properties makes busbar build a thousand-clause
/// string on the request path and hand it to an operator who reads the first few.
#[test]
fn the_violation_list_stops_at_the_cap() {
    let closed = json!({
        "type": "object",
        "properties": { "a": { "type": "string" } },
        "additionalProperties": false,
    });
    let mut value = serde_json::Map::new();
    value.insert("a".to_string(), json!("x"));
    for i in 0..100 {
        value.insert(format!("extra{i}"), json!(i));
    }
    let e = check(&Value::Object(value), &closed).unwrap_err();
    assert_eq!(
        e.split("; ").count(),
        MAX_ERRORS,
        "a hundred unexpected properties must report the cap's worth and stop: {e}"
    );
}

/// THE TYPE UNION IS A DISJUNCTION. `["string", "null"]` is how a schema says "a string, or nothing"
/// — the commonest optional-field shape there is — and reading it as a conjunction would reject
/// every value, which is the false violation this module must never produce.
#[test]
fn a_type_union_accepts_any_of_its_members() {
    let schema = json!({
        "type": "object",
        "properties": { "note": { "type": ["string", "null"] } },
    });
    assert!(check(&json!({ "note": "x" }), &schema).is_ok());
    assert!(check(&json!({ "note": null }), &schema).is_ok());
    let e = check(&json!({ "note": 1 }), &schema).unwrap_err();
    assert!(e.contains("$.note"), "{e}");
    assert!(e.contains("expected type"), "{e}");
}

/// THE DEPTH BOUND IS A STATEMENT ABOUT THIS WALKER, NEVER ABOUT THE DOCUMENT — so it must fire
/// nowhere near ordinary nesting, and where it does fire it must go SILENT rather than report.
/// A schema and a value nested ten deep are entirely ordinary and are still checked; the same pair
/// nested a hundred deep is past what this walker will follow, and it says nothing at all.
#[test]
fn a_violation_inside_the_depth_bound_is_reported_and_one_beyond_it_is_silent() {
    /// A value that is `"not an integer"` under `n` nested arrays, and the matching `n`-deep schema
    /// that declares the innermost item an integer. The pair violates at exactly depth `n`.
    fn nested(n: usize) -> (Value, Value) {
        let mut v = json!("not an integer");
        let mut s = json!({ "type": "integer" });
        for _ in 0..n {
            v = json!([v]);
            s = json!({ "type": "array", "items": s });
        }
        (v, s)
    }
    let (v, s) = nested(10);
    let e = check(&v, &s).unwrap_err();
    assert!(e.contains("expected type"), "{e}");
    let (v, s) = nested(100);
    assert!(
        check(&v, &s).is_ok(),
        "past the bound the walk STOPS; it never manufactures a violation"
    );
}

#[test]
fn a_non_object_schema_constrains_nothing() {
    assert!(check(&json!({ "anything": true }), &json!(true)).is_ok());
    assert!(check(&json!(1), &json!("not a schema")).is_ok());
}
