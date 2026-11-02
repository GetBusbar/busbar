// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-contract/src/secret_ref.rs`.

use super::*;

/// Deserialize: the `{env}` / `{file}` sugar desugars to the canonical module + settings; the
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

    let err = serde_yaml::from_str::<SecretRef>("sk-live-abc123")
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("never an inline literal") && !err.contains("sk-live-abc123"),
        "a non-`none` scalar keeps the non-echoing refusal: {err}"
    );
}

/// The `Visitor::expecting` error message actually names the accepted shapes — asserted via a
#[test]
fn deserialize_error_message_names_the_accepted_shapes() {
    let err = serde_yaml::from_str::<SecretRef>("[1, 2]").unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("a secret reference map"),
        "error must name the accepted shapes: {msg}"
    );
}

/// The derived `oneOf` is itself a valid JSON Schema 2020-12 fragment, and it accepts EXACTLY
#[test]
fn oneof_schema_accepts_exactly_what_secretref_accepts() {
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
        serde_json::json!("none"),
    ];
    for v in &accept {
        assert!(validator.is_valid(v), "should accept {v}");

        assert!(
            serde_json::from_value::<SecretRef>(v.clone()).is_ok(),
            "derived oneOf accepted {v} but SecretRef::deserialize rejects it — drift"
        );
    }

    let reject = [
        serde_json::json!("s3cret"),
        serde_json::json!({"literal": "s3cret"}),
        serde_json::json!({"env": "A", "file": "B"}),
        serde_json::json!({}),
    ];
    for v in &reject {
        assert!(!validator.is_valid(v), "should reject {v}");
    }
}

/// The derived fragment is written out by hand next to the deserializer, not generated from it, so
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
        (serde_json::json!({"module": "vault"}), true),
        (
            serde_json::json!({"module": "vault", "settings": {"key": "x"}}),
            true,
        ),
        (serde_json::json!({"env": "MY_VAR"}), true),
        (serde_json::json!({"file": "/run/secrets/x"}), true),
        (serde_json::json!("none"), true),
        (serde_json::json!({"module": "none"}), true),
        (serde_json::json!("None"), false),
        (serde_json::json!("NONE"), false),
        (serde_json::json!({"none": true}), false),
        (serde_json::json!({"env": "   "}), false),
        (serde_json::json!({"file": "\t"}), false),
        (serde_json::json!({"module": " "}), false),
        (serde_json::json!({"env": ""}), false),
        (serde_json::json!({"module": ""}), false),
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
#[test]
fn an_unquoted_inline_secret_is_refused_without_echoing_it() {
    for (yaml, value) in [
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

/// A pasted credential dropped into the WRONG SLOT — `settings:` given as a scalar rather than the
#[test]
fn a_scalar_in_the_settings_slot_is_refused_without_echoing_it() {
    let err = serde_yaml::from_str::<SecretRef>("{ module: vault, settings: \"sk-live-abc123\" }")
        .expect_err("settings must be a map, never a pasted scalar credential")
        .to_string();
    assert!(
        !err.contains("sk-live-abc123"),
        "the refusal echoed the mis-slotted credential into the error text: {err}"
    );
    assert!(
        err.contains("never an inline literal"),
        "a scalar in the settings slot takes the same non-echoing refusal: {err}"
    );
}

/// The sugar keys carry secrets too, and an unquoted YAML number/bool in an `{ env: … }` /
#[test]
fn a_non_string_sugar_value_is_refused_without_echoing_it() {
    for (yaml, value) in [("{ env: 12345 }", "12345"), ("{ file: true }", "true")] {
        let err = serde_yaml::from_str::<SecretRef>(yaml)
            .expect_err("the sugar value must be a string")
            .to_string();
        assert!(
            !err.contains(value),
            "the refusal echoed the sugar value into the error text: {err}"
        );
        assert!(
            err.contains("never an inline literal"),
            "a non-string sugar value takes the same non-echoing refusal: {err}"
        );
    }
}

/// A non-string `module:` names no module — and a typed `next_value::<String>()` would echo whatever
#[test]
fn a_non_string_module_is_refused_without_echoing_it() {
    let err = serde_yaml::from_str::<SecretRef>("{ module: 12345 }")
        .expect_err("module must be a string naming a secret module")
        .to_string();
    assert!(
        !err.contains("12345"),
        "the refusal echoed the module value into the error text: {err}"
    );
    assert!(
        err.contains("must be a string"),
        "a non-string module names no module: {err}"
    );
}

/// Duplicate `module:` / `settings:` keys are a malformed reference, and the visitor catches each
#[test]
fn duplicate_keys_are_refused() {
    let err = serde_json::from_str::<SecretRef>(r#"{"module":"vault","module":"env"}"#)
        .expect_err("a duplicate module: is malformed")
        .to_string();
    assert!(
        err.contains("duplicate field") && err.contains("module"),
        "duplicate module: must be a duplicate_field error: {err}"
    );

    let err = serde_json::from_str::<SecretRef>(
        r#"{"module":"vault","settings":{"key":"x"},"settings":{"key":"y"}}"#,
    )
    .expect_err("a duplicate settings: is malformed")
    .to_string();
    assert!(
        err.contains("duplicate field") && err.contains("settings"),
        "duplicate settings: must be a duplicate_field error: {err}"
    );
}

/// Serialize round-trip: every one of the four accepted input spellings lands on the SAME canonical
#[test]
fn serialize_yields_the_canonical_module_settings_wire_shape() {
    let env: SecretRef = serde_yaml::from_str("{ env: MY_VAR }").unwrap();
    let file: SecretRef = serde_yaml::from_str("{ file: /run/secrets/x }").unwrap();
    let canonical: SecretRef =
        serde_yaml::from_str("{ module: vault, settings: { key: kv/data/x } }").unwrap();
    let none: SecretRef = serde_yaml::from_str("none").unwrap();

    for r in [&env, &file, &canonical, &none] {
        let wire = serde_json::to_value(r).expect("SecretRef serializes");
        let obj = wire.as_object().expect("the wire shape is a map");
        assert!(
            obj.contains_key("module"),
            "the canonical wire shape names `module`: {wire}"
        );
        assert!(
            obj.contains_key("settings"),
            "the canonical wire shape names `settings` (admin redaction keys off it): {wire}"
        );
        assert_eq!(
            obj.len(),
            2,
            "the wire shape is EXACTLY {{ module, settings }}, nothing else: {wire}"
        );
    }

    assert_eq!(
        serde_json::to_value(&env).unwrap(),
        serde_json::json!({"module": "env", "settings": {"key": "MY_VAR"}})
    );
    assert_eq!(
        serde_json::to_value(&file).unwrap(),
        serde_json::json!({"module": "file", "settings": {"path": "/run/secrets/x"}})
    );
    assert_eq!(
        serde_json::to_value(&canonical).unwrap(),
        serde_json::json!({"module": "vault", "settings": {"key": "kv/data/x"}})
    );
    assert_eq!(
        serde_json::to_value(&none).unwrap(),
        serde_json::json!({"module": "none", "settings": {}})
    );
}

/// A TEMPLATE reference (a credential `${VAR}` filled in part) resolves by filling each `${VAR}`
#[test]
fn a_template_reference_resolves_each_variable_in_place() {
    let resolve = |r: &SecretRef| match r.env_var() {
        Some("A") => Ok("alpha".to_string()),
        Some("B") => Ok("beta".to_string()),
        _ => Err(format!("{} does not resolve", r.describe())),
    };
    let t = SecretRef::template("Bearer ${A}:${B} $5 ${ and ${");
    assert_eq!(t.module, SECRET_MODULE_TEMPLATE);
    assert_eq!(t.template_text(), Some("Bearer ${A}:${B} $5 ${ and ${"));
    assert_eq!(
        t.resolve_template(&resolve).as_deref(),
        Ok("Bearer alpha:beta $5 ${ and ${")
    );
    assert_eq!(
        SecretRef::env("B").resolve_template(&resolve).as_deref(),
        Ok("beta")
    );
    let unresolved = SecretRef::template("x ${C}").resolve_template(&resolve);
    assert_eq!(unresolved, Err("env:C does not resolve".to_string()));

    let back: SecretRef = serde_json::from_value(serde_json::to_value(&t).unwrap()).unwrap();
    assert_eq!(back, t);
}
