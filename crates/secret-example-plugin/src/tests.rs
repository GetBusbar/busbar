// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Coverage for the trivial `kind: secret` reference plugin: `open`'s config parsing (empty /
//! present / malformed) and `ExampleSecret::resolve`'s fail-closed lookup (missing `key`,
//! non-string `key`, unknown key, a reference that is not an object at all, and the successful
//! round-trip).
//!
//! Every failure assertion names the EXACT face variant rather than "is an error", because the
//! variant is the whole of what the face tells an operator: `Unknown` sends them to the key,
//! `Malformed` sends them to the reference's shape, and a plugin that swapped the two would send
//! them to the wrong place while staying green under an `is_err()`.

use super::*;

/// One reference in the cold lane's grammar, from a settings object.
fn reference(pairs: &[(&str, serde_json::Value)]) -> SecretRef {
    let map: serde_json::Map<String, serde_json::Value> = pairs
        .iter()
        .cloned()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    SecretRef(serde_json::Value::Object(map).to_string())
}

#[test]
fn open_with_empty_config_yields_a_module_that_resolves_nothing() {
    let module = open("").expect("empty config must open cleanly");
    assert_eq!(
        module.resolve(&reference(&[("key", serde_json::json!("anything"))])),
        Err(SecretError::Unknown)
    );
}

#[test]
fn open_with_blank_whitespace_config_is_also_treated_as_empty() {
    // `cfg.trim().is_empty()` — pure whitespace must take the same "no config" path as "".
    assert!(open("   \n\t  ").is_ok());
}

#[test]
fn open_with_malformed_json_is_a_load_error() {
    match open("{ not json") {
        Err(e) => assert!(
            e.contains("invalid secret-example-plugin config"),
            "error message must name the failure: {e}"
        ),
        Ok(_) => panic!("malformed config must not open"),
    }
}

#[test]
fn open_with_a_map_resolves_a_known_key() {
    let module = open(r#"{"map": {"db-password": "hunter2"}}"#).expect("valid config");
    let value = module
        .resolve(&reference(&[("key", serde_json::json!("db-password"))]))
        .expect("known key must resolve");
    assert_eq!(value.expose(), b"hunter2");
}

#[test]
fn resolve_missing_key_field_is_outside_the_grammar() {
    let module = open(r#"{"map": {"a": "b"}}"#).unwrap();
    assert_eq!(module.resolve(&reference(&[])), Err(SecretError::Malformed));
}

#[test]
fn resolve_non_string_key_field_is_outside_the_grammar() {
    let module = open(r#"{"map": {"a": "b"}}"#).unwrap();
    assert_eq!(
        module.resolve(&reference(&[("key", serde_json::json!(42))])),
        Err(SecretError::Malformed)
    );
}

#[test]
fn a_reference_that_is_not_a_json_object_is_outside_the_grammar() {
    let module = open(r#"{"map": {"a": "b"}}"#).unwrap();
    assert_eq!(
        module.resolve(&SecretRef("db-password".to_string())),
        Err(SecretError::Malformed),
        "the grammar this module declares is an OBJECT; a bare string is not one, and saying so is \
         what `ref_grammar` is for"
    );
    assert!(module.ref_grammar().contains("JSON object"));
}

#[test]
fn resolve_unknown_key_is_a_miss_and_not_a_malformed_reference() {
    let module = open(r#"{"map": {"a": "b"}}"#).unwrap();
    assert_eq!(
        module.resolve(&reference(&[("key", serde_json::json!("nonexistent"))])),
        Err(SecretError::Unknown),
        "a well-formed reference to a key that is not there is a MISS: the operator should check \
         the key, not the reference's shape"
    );
}

#[test]
fn resolve_never_leaks_the_secret_value_in_its_failure() {
    // A negative-space assertion, and under the face it is stronger than it was: the failure is a
    // taxonomy with NO message field at all, so there is nowhere for a value to appear even by
    // accident. This states it by construction rather than by grepping a string.
    let module = open(r#"{"map": {"a": "top-secret-value"}}"#).unwrap();
    let err = module
        .resolve(&reference(&[("key", serde_json::json!("missing-key"))]))
        .unwrap_err();
    assert_eq!(err, SecretError::Unknown);
    assert!(!format!("{err:?}").contains("top-secret-value"));
    assert!(!err.to_string().contains("top-secret-value"));
}

/// The module answers the three identity questions the base face asks, and answers them with the
/// SDK's own constant rather than a literal — a plugin whose declared generation drifts from the
/// SDK it was built with is refused at the handshake, which is not a thing to discover in the field.
#[test]
fn the_module_declares_the_kind_and_the_generation_it_was_built_against() {
    let module = open("").unwrap();
    assert_eq!(module.kind(), Kind::Secret);
    assert_eq!(
        module.abi(),
        AbiVersion(busbar_plugin_sdk::secret_abi_version() as u16)
    );
    assert_eq!(module.key(), "secret-example");
}
