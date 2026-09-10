// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/secret-grammar/src/lib.rs`.

use super::*;

/// Deserialize: the `{env}` / `{file}` sugar desugars to the canonical module + settings; the
/// canonical form parses; mixed / unknown / empty forms are rejected.
#[test]
fn deserialize_accepts_canonical_and_sugar_rejects_malformed() {
    let r: SecretRef = serde_yaml::from_str("{ env: MY_VAR }").unwrap();
    assert_eq!(r, SecretRef::env("MY_VAR"));
    assert_eq!(r.env_var(), Some("MY_VAR"));
    let r: SecretRef = serde_yaml::from_str("{ file: /run/secrets/x }").unwrap();
    assert_eq!(r, SecretRef::file("/run/secrets/x"));
    assert_eq!(r.file_path(), Some("/run/secrets/x"));
    let r: SecretRef =
        serde_yaml::from_str("{ module: vault, settings: { path: kv/data/x } }").unwrap();
    assert_eq!(r.module, "vault");
    assert_eq!(
        r.settings.get("path").and_then(|v| v.as_str()),
        Some("kv/data/x")
    );

    for bad in [
        "{ env: A, file: B }",
        "{ module: vault, env: A }",
        "{ env: A, settings: {} }",
        "{ unknown_key: A }",
        "{}",
        "{ env: \"\" }",
        "{ module: \"\" }",
        "plain-string",
    ] {
        assert!(
            serde_yaml::from_str::<SecretRef>(bad).is_err(),
            "must reject: {bad}"
        );
    }
}

/// `describe()`'s three real forms — the env/file sugar takes priority over the canonical
/// module+settings form, and the module fallback quotes the module name.
#[test]
fn describe_renders_env_file_and_module_forms() {
    assert_eq!(SecretRef::env("MY_VAR").describe(), "env:MY_VAR");
    assert_eq!(
        SecretRef::file("/run/secrets/x").describe(),
        "file:/run/secrets/x"
    );
    let r: SecretRef =
        serde_yaml::from_str("{ module: vault, settings: { path: kv/data/x } }").unwrap();
    assert_eq!(r.describe(), "secret module 'vault'");
}

/// `none` — the EXPLICIT keyless declaration — parses from the bare scalar and from the canonical
/// `{ module: none }`, and `describe()` renders it as the word itself, so a diagnostic about a
/// keyless provider reads naturally while still naming no source.
///
/// The near-misses matter as much as the hit: `none` is a reserved WORD, so anything that is not
/// exactly it must still take the non-echoing inline-literal refusal, and the `{ none: … }` map
/// form must not exist at all (it would invite settings on a reference that names no source).
#[test]
fn none_is_the_one_scalar_a_secret_field_accepts() {
    let r: SecretRef = serde_yaml::from_str("none").unwrap();
    assert_eq!(r, SecretRef::none());
    assert!(r.is_none());
    assert!(
        r.settings.is_empty(),
        "`none` names no source and carries no settings"
    );
    assert_eq!(r.describe(), "none");
    // The canonical spelling, and the JSON (config-overlay) wire form.
    assert!(serde_yaml::from_str::<SecretRef>("{ module: none }")
        .unwrap()
        .is_none());
    assert!(serde_json::from_str::<SecretRef>("\"none\"")
        .unwrap()
        .is_none());

    for bad in ["None", "NONE", "no", "nones", "{ none: true }"] {
        assert!(
            serde_yaml::from_str::<SecretRef>(bad).is_err(),
            "only the exact scalar `none` declares keyless: {bad}"
        );
    }

    // A pasted literal is still refused, and still not echoed.
    let err = serde_yaml::from_str::<SecretRef>("sk-live-abc123")
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("never an inline literal") && !err.contains("sk-live-abc123"),
        "a non-`none` scalar keeps the non-echoing refusal: {err}"
    );
}

/// The `Visitor::expecting` error message actually names the accepted shapes — asserted via a
/// real deserialize failure on a shape with NO `visit_*` override, so serde falls back to its
/// default invalid-type error, which is built from `expecting()`. This proves serde actually wires
/// it into the real error path, not just that the method compiles.
#[test]
fn deserialize_error_message_names_the_accepted_shapes() {
    // A SEQUENCE, not a scalar: every scalar spelling now takes the explicit non-echoing refusal
    // (a bare number is a pasted secret far more often than it is a typo'd shape), so the input
    // that still exercises serde's own `expecting()`-built message is one this visitor does not
    // handle at all.
    let err = serde_yaml::from_str::<SecretRef>("[1, 2]").unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("a secret reference map"),
        "error must name the accepted shapes: {msg}"
    );
}

/// The derived `oneOf` is itself a valid JSON Schema 2020-12 fragment, and it accepts EXACTLY
/// the shapes `SecretRef::deserialize` accepts (round-trip fidelity — this is the whole point of
/// deriving instead of hand-writing).
#[test]
fn oneof_schema_accepts_exactly_what_secretref_accepts() {
    // NO `"type": "object"` of our own: a secret reference is one of three object shapes OR the
    // bare scalar `none`, so the derived `oneOf` is the whole constraint.
    let full = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
    });
    let mut full = full.as_object().unwrap().clone();
    for (k, v) in oneof_schema().as_object().unwrap() {
        full.insert(k.clone(), v.clone());
    }
    let full = serde_json::Value::Object(full);
    let validator = jsonschema::validator_for(&full).expect("valid 2020-12 schema");

    let accept = [
        serde_json::json!({"module": "vault", "settings": {"key": "x"}}),
        serde_json::json!({"module": "env"}),
        serde_json::json!({"env": "MY_VAR"}),
        serde_json::json!({"file": "/run/secrets/x"}),
        // The keyless declaration — the one scalar this type accepts.
        serde_json::json!("none"),
    ];
    for v in &accept {
        assert!(validator.is_valid(v), "should accept {v}");
        // Every accepted shape also round-trips through SecretRef's real Deserialize impl —
        // the derived schema is not merely permissive, it agrees with the actual type.
        assert!(
            serde_json::from_value::<SecretRef>(v.clone()).is_ok(),
            "derived oneOf accepted {v} but SecretRef::deserialize rejects it — drift"
        );
    }

    let reject = [
        // A bare string secret value — never valid (the whole point of this type).
        serde_json::json!("s3cret"),
        // `{ literal: ... }` is NOT a SecretRef shape (handled one layer above, in
        // resolve_settings()) — the derived oneOf must not accept it either.
        serde_json::json!({"literal": "s3cret"}),
        serde_json::json!({"env": "A", "file": "B"}),
        serde_json::json!({}),
    ];
    for v in &reject {
        assert!(!validator.is_valid(v), "should reject {v}");
    }
}

/// The derived fragment is written out by hand next to the deserializer, not generated from it, so
/// what actually keeps the two in step is this: ONE table of shapes, each put to BOTH the schema and
/// `SecretRef::deserialize`, with the two verdicts asserted EQUAL. Either side changing alone shows
/// up here.
///
/// The whitespace-only rows are the drift this found: the schema said `minLength: 1`, the visitor
/// says `trim().is_empty()`, and a three-space value satisfies the first while failing the second —
/// a reference busbar-ui would have rendered as valid and the engine would have refused at boot.
#[test]
fn the_schema_and_the_deserializer_agree_shape_for_shape() {
    let mut full = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
    })
    .as_object()
    .unwrap()
    .clone();
    for (k, v) in oneof_schema().as_object().unwrap() {
        full.insert(k.clone(), v.clone());
    }
    let validator = jsonschema::validator_for(&serde_json::Value::Object(full))
        .expect("the derived fragment is a valid 2020-12 schema");

    let cases = [
        // (shape, is it a legal secret reference)
        (serde_json::json!({"module": "vault"}), true),
        (
            serde_json::json!({"module": "vault", "settings": {"key": "x"}}),
            true,
        ),
        (serde_json::json!({"env": "MY_VAR"}), true),
        (serde_json::json!({"file": "/run/secrets/x"}), true),
        // The keyless declaration, scalar and canonical. `none` is a reserved WORD, so the
        // near-misses below must land on the same refusal every other bare scalar gets.
        (serde_json::json!("none"), true),
        (serde_json::json!({"module": "none"}), true),
        (serde_json::json!("None"), false),
        (serde_json::json!("NONE"), false),
        (serde_json::json!({"none": true}), false),
        // Blank-but-present values: the reason this test exists.
        (serde_json::json!({"env": "   "}), false),
        (serde_json::json!({"file": "\t"}), false),
        (serde_json::json!({"module": " "}), false),
        (serde_json::json!({"env": ""}), false),
        (serde_json::json!({"module": ""}), false),
        // Structural refusals.
        (serde_json::json!({}), false),
        (serde_json::json!({"env": "A", "file": "B"}), false),
        (serde_json::json!({"module": "vault", "env": "A"}), false),
        (serde_json::json!({"env": "A", "settings": {}}), false),
        (serde_json::json!({"literal": "s3cret"}), false),
        (serde_json::json!({"unknown": "x"}), false),
        (serde_json::json!("s3cret"), false),
        (serde_json::json!(483_920_175_534u64), false),
        (serde_json::json!(true), false),
    ];

    for (shape, expected) in &cases {
        let by_schema = validator.is_valid(shape);
        let by_serde = serde_json::from_value::<SecretRef>(shape.clone()).is_ok();
        assert_eq!(
            by_schema, by_serde,
            "the schema and the deserializer disagree about {shape}: schema says {by_schema}, \
             serde says {by_serde}"
        );
        assert_eq!(
            by_serde, *expected,
            "and the agreed verdict for {shape} must be {expected}"
        );
    }
}

/// A secret is not always quoted. `api_key: 483920175534` and `api_key: true` are ordinary YAML, and
/// each one used to miss the non-echoing refusal entirely and land on serde's default `invalid type`
/// error — which prints the value it was handed. The value it was handed is the secret, and the boot
/// log is exactly the place this type exists to keep it out of.
#[test]
fn an_unquoted_inline_secret_is_refused_without_echoing_it() {
    for (yaml, value) in [
        // THE QUOTED STRING FIRST, and it was the one form this table was missing. `visit_str` is
        // the overwhelmingly common spelling of an inline secret, and it had no absence assertion
        // anywhere: the two places that fed it (`"plain-string"` and `json!("s3cret"))` asserted
        // only `is_err()`. Dropping the `visit_str` override -- or spelling `{_v}` into its message
        // -- put the secret verbatim into the boot log, which is the single thing this type exists
        // to prevent, and every test in the file stayed green.
        ("\"hunter2secret\"", "hunter2secret"),
        ("483920175534", "483920175534"),
        ("-42", "42"),
        ("true", "true"),
        ("1.5", "1.5"),
    ] {
        let err = serde_yaml::from_str::<SecretRef>(yaml)
            .expect_err("an inline literal is never a secret reference")
            .to_string();
        assert!(
            !err.contains(value),
            "the refusal echoed the value into the error text: {err}"
        );
        assert!(
            err.contains("never an inline literal"),
            "and it must be the same non-echoing refusal a quoted literal gets: {err}"
        );
    }
}
