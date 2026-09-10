// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Coverage for the trivial `kind: secret` reference plugin: `open`'s config parsing (empty /
//! present / malformed) and `ExampleSecret::resolve`'s fail-closed lookup (missing `key`,
//! non-string `key`, unknown key, and the successful round-trip).

use super::*;

fn settings(pairs: &[(&str, serde_json::Value)]) -> serde_json::Map<String, serde_json::Value> {
    pairs
        .iter()
        .cloned()
        .map(|(k, v)| (k.to_string(), v))
        .collect()
}

#[test]
fn open_with_empty_config_yields_a_module_that_resolves_nothing() {
    let module = open("").expect("empty config must open cleanly");
    let err = module
        .resolve(&settings(&[("key", serde_json::json!("anything"))]))
        .unwrap_err();
    assert_eq!(err.class, ErrorClass::NotFound);
    assert_eq!(err.code, CODE_NO_ENTRY);
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
    let bytes = module
        .resolve(&settings(&[("key", serde_json::json!("db-password"))]))
        .expect("known key must resolve");
    assert_eq!(bytes, b"hunter2".to_vec());
}

#[test]
fn resolve_missing_key_field_is_invalid() {
    let module = open(r#"{"map": {"a": "b"}}"#).unwrap();
    let err = module.resolve(&settings(&[])).unwrap_err();
    assert_eq!(err.class, ErrorClass::Malformed);
    assert_eq!(err.code, CODE_KEY_MISSING);
}

#[test]
fn resolve_non_string_key_field_is_invalid() {
    let module = open(r#"{"map": {"a": "b"}}"#).unwrap();
    let err = module
        .resolve(&settings(&[("key", serde_json::json!(42))]))
        .unwrap_err();
    assert_eq!(err.class, ErrorClass::Malformed);
    assert_eq!(err.code, CODE_KEY_MISSING);
}

#[test]
fn resolve_unknown_key_is_not_found() {
    let module = open(r#"{"map": {"a": "b"}}"#).unwrap();
    let err = module
        .resolve(&settings(&[("key", serde_json::json!("nonexistent"))]))
        .unwrap_err();
    assert_eq!(err.class, ErrorClass::NotFound);
    assert_eq!(err.code, CODE_NO_ENTRY);
    assert!(err.developer_message.contains("nonexistent"));
}

#[test]
fn resolve_never_leaks_the_secret_value_in_its_error_message() {
    // A negative-space assertion: the not-found message names the KEY, never a value from the map.
    let module = open(r#"{"map": {"a": "top-secret-value"}}"#).unwrap();
    let err = module
        .resolve(&settings(&[("key", serde_json::json!("missing-key"))]))
        .unwrap_err();
    assert!(!err.developer_message.contains("top-secret-value"));
}

/// THE CATALOG IS WELL-FORMED AND DECLARES EVERY CODE THIS PLUGIN EMITS, in the default locale
/// and one more; a locale it lacks falls back to the default, never to nothing.
#[test]
fn the_catalog_checks_and_declares_every_emitted_code_with_locale_fallback() {
    let catalog: Catalog =
        serde_json::from_str(CATALOG).expect("the catalog is a catalog document");
    catalog.check().expect("the catalog checks");
    for code in [CODE_KEY_MISSING, CODE_NO_ENTRY] {
        assert!(catalog.entry(code).is_some(), "{code} is declared");
        assert!(catalog.template(code, "de").expect("de").contains(' '));
        assert_eq!(
            catalog.template(code, "fr-CA"),
            catalog.template(code, "en"),
            "a locale the catalog lacks falls back to the default locale"
        );
    }
    assert!(catalog
        .template(CODE_NO_ENTRY, "en")
        .unwrap()
        .contains("{key}"));
}
