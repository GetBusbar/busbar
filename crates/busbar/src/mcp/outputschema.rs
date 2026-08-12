// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! KEEPING THE PROMISE `outputSchema` MAKES.
//!
//! ## The obligation, and why it is busbar's rather than the upstream's
//!
//! `tools/list` may publish an `outputSchema` for a tool, and the specification turns the mere
//! PRESENCE of that key into a MUST: *"If an output schema is provided: Servers MUST provide
//! structured results that conform to this schema."* The server that published the schema is the
//! server that is held to it, and on this plane that server is busbar — a caller never speaks to the
//! upstream and has no way to attribute a violation to it.
//!
//! busbar publishes the OPERATOR's schema (`tools.<server>.tools_allow.<tool>.output_schema`), for
//! the same reason it publishes the operator's description and the operator's input schema: an
//! upstream that could write the schema could rewrite the promise busbar is held to, narrowing it
//! after a client cached it or widening it to legalise whatever it returned today.
//!
//! But busbar does not COMPUTE the structured result; the upstream does. So publishing without
//! checking would put busbar in violation of that MUST every time the upstream lied, with busbar's
//! name on the answer — which is exactly the shape the battery's own `outputschema-lie` hostile peer
//! exists to plant. This module is the check.
//!
//! ## DELIBERATELY A SUBSET, AND DELIBERATELY ONE-SIDED
//!
//! A wrong answer here has two very different costs. A missed violation lets a lie through, which is
//! the status quo this module improves on. A FALSE violation turns a working tool call into a
//! failure for a caller who did nothing wrong — a self-inflicted outage on the request path. The two
//! are not symmetric, so this validator is arranged to be silent whenever it is not certain:
//!
//! - **Every keyword it does not model is IGNORED**, never treated as unsatisfied. `allOf`,
//!   `anyOf`, `oneOf`, `not`, `if`/`then`/`else`, `patternProperties`, `format`, `pattern`,
//!   `dependentRequired` and the rest are not evaluated, so a document that only those keywords
//!   would reject is passed. The honest consequence is stated rather than softened: this catches the
//!   violations a plain type/required/enum schema describes, which is what real MCP output schemas
//!   overwhelmingly are, and it does not claim to be a complete JSON Schema implementation.
//! - **`$ref` IS NEVER DEREFERENCED**, local or remote. The remote case is forbidden outright
//!   (`Implementations MUST NOT automatically dereference $ref values that resolve to a network
//!   URI`), and resolving only the local case would make the behaviour depend on where an author
//!   happened to put a definition. A subschema behind a `$ref` is therefore UNCHECKED, not failed.
//! - **A schema that is not an object is not a schema busbar can read**, and is ignored rather than
//!   treated as rejecting everything.
//!
//! What it DOES model is type (including the `integer`/`number` relationship and type unions),
//! `required`, `properties`, `additionalProperties: false`, `items`, `enum` and `const` — walked
//! recursively under a depth bound, because a schema and a value that recurse into each other must
//! not be able to exhaust the stack on the request path.

use serde_json::Value;

/// How deep the paired schema/value walk goes before it stops. Exceeding it STOPS CHECKING rather
/// than reporting a violation, for this module's one-sided rule: a bound that fires is a statement
/// about this walker, never about the document.
const MAX_DEPTH: usize = 32;

/// How many violations are collected before the walk stops. The first few are what an operator
/// reads; an unbounded list is a way for an upstream to make busbar build a large string.
const MAX_ERRORS: usize = 8;

/// CHECK a structured result against a published output schema.
///
/// `Ok(())` means "no violation this validator can see" — which, given the one-sided rule above, is
/// weaker than "conforms" and is documented as such at the call site. `Err` carries a short,
/// operator-readable list of the violations found.
pub(crate) fn check(value: &Value, schema: &Value) -> Result<(), String> {
    let mut errors = Vec::new();
    walk(value, schema, "$", 0, &mut errors);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn walk(v: &Value, s: &Value, path: &str, depth: usize, errors: &mut Vec<String>) {
    if depth > MAX_DEPTH || errors.len() >= MAX_ERRORS {
        return;
    }
    let Some(obj) = s.as_object() else { return }; // not a schema busbar can read: unchecked
    if obj.contains_key("$ref") {
        return; // never dereferenced — see the module header
    }

    // `const` and `enum` are exact-value constraints, and a mismatch is unambiguous.
    if let Some(c) = obj.get("const") {
        if c != v {
            errors.push(format!("{path}: expected the constant {c}, got {v}"));
            return;
        }
    }
    if let Some(Value::Array(allowed)) = obj.get("enum") {
        if !allowed.iter().any(|a| a == v) {
            errors.push(format!(
                "{path}: {v} is not one of the declared enum values"
            ));
            return;
        }
    }

    if let Some(declared) = obj.get("type") {
        if !type_matches(v, declared) {
            errors.push(format!(
                "{path}: expected type {declared}, got {}",
                actual_type(v)
            ));
            return; // a value of the wrong type cannot usefully be walked against this schema
        }
    }

    match v {
        Value::Object(map) => {
            for name in obj
                .get("required")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                if !map.contains_key(name) {
                    errors.push(format!("{path}: missing required property `{name}`"));
                    if errors.len() >= MAX_ERRORS {
                        return;
                    }
                }
            }
            let props = obj.get("properties").and_then(Value::as_object);
            // `additionalProperties: false` and NOTHING ELSE from that keyword: the schema form is
            // also legal, and a schema there would be an evaluation this module does not model, so
            // it is ignored rather than guessed at.
            if obj.get("additionalProperties") == Some(&Value::Bool(false)) {
                for key in map.keys() {
                    if !props.is_some_and(|p| p.contains_key(key)) {
                        errors.push(format!("{path}: property `{key}` is not permitted"));
                        if errors.len() >= MAX_ERRORS {
                            return;
                        }
                    }
                }
            }
            if let Some(props) = props {
                for (key, sub) in props {
                    if let Some(child) = map.get(key) {
                        walk(child, sub, &format!("{path}.{key}"), depth + 1, errors);
                    }
                }
            }
        }
        Value::Array(items) => {
            // The single-schema form only. The tuple form (`items` as an array) is a different
            // evaluation and is not modelled, so it is left unchecked rather than misapplied.
            if let Some(item_schema) = obj.get("items").filter(|i| i.is_object()) {
                for (i, item) in items.iter().enumerate() {
                    walk(
                        item,
                        item_schema,
                        &format!("{path}[{i}]"),
                        depth + 1,
                        errors,
                    );
                    if errors.len() >= MAX_ERRORS {
                        return;
                    }
                }
            }
        }
        _ => {}
    }
}

/// Does `v` satisfy a `type` keyword? Handles the union form, and the one relationship JSON Schema
/// defines between two of its type names: every `integer` is a `number`, and a `number` with no
/// fractional part IS an `integer` (JSON has one numeric type, so `1.0` and `1` are the same value).
fn type_matches(v: &Value, declared: &Value) -> bool {
    match declared {
        Value::String(name) => one_type_matches(v, name),
        Value::Array(names) => names
            .iter()
            .filter_map(Value::as_str)
            .any(|n| one_type_matches(v, n)),
        // A `type` that is neither a string nor an array of strings is not something this validator
        // reads, so it constrains nothing here.
        _ => true,
    }
}

fn one_type_matches(v: &Value, name: &str) -> bool {
    match name {
        "object" => v.is_object(),
        "array" => v.is_array(),
        "string" => v.is_string(),
        "boolean" => v.is_boolean(),
        "null" => v.is_null(),
        "number" => v.is_number(),
        "integer" => v.as_f64().is_some_and(|f| f.fract() == 0.0),
        // An unknown type name is not a constraint this validator can apply.
        _ => true,
    }
}

fn actual_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) => {
            if n.as_f64().is_some_and(|f| f.fract() == 0.0) {
                "integer"
            } else {
                "number"
            }
        }
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
