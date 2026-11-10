// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Canonical reference grammar and explicit owner-declared shorthand.

use super::*;
use crate::abi::mechanism::door::{
    REWRITE_SUGAR, REWRITE_SUGAR_ROLE, SUGAR_ROLE_FILL, SUGAR_ROLE_PATH,
};

fn sources() -> Sugars {
    let mut sources = Sugars::default();
    for (word, owner, setting, role) in [
        ("cabinet", "first-source", "entry", SUGAR_ROLE_FILL),
        ("drawer", "second-source", "location", SUGAR_ROLE_PATH),
    ] {
        sources
            .declare(
                owner,
                &[
                    (REWRITE_SUGAR, word.into(), setting.into()),
                    (REWRITE_SUGAR_ROLE, word.into(), role.into()),
                ],
            )
            .unwrap();
    }
    sources
}
fn authored(yaml: &str) -> Result<SecretRef, serde_yaml::Error> {
    context::deserialize(serde_yaml::Deserializer::from_str(yaml), &sources())
}
fn named(word: &str, value: &str) -> SecretRef {
    sources().get(word).unwrap().reference(value)
}

#[test]
fn deserialize_accepts_canonical_and_declared_shorthand_rejects_malformed() {
    assert_eq!(
        authored("{ cabinet: item }").unwrap(),
        named("cabinet", "item")
    );
    assert_eq!(
        authored("{ drawer: other }").unwrap(),
        named("drawer", "other")
    );
    let canonical: SecretRef =
        serde_yaml::from_str("{module: independent-source, settings: {slot: opaque}}").unwrap();
    assert_eq!(canonical.source_module(), Some("independent-source"));
    assert_eq!(
        serde_json::to_value(canonical.source().unwrap().settings.writing()).unwrap(),
        serde_json::json!({"slot":"opaque"})
    );
    for bad in [
        "{cabinet: A, drawer: B}",
        "{module: independent-source, cabinet: A}",
        "{cabinet: A, settings: {}}",
        "{unknown_key: A}",
        "{}",
        "{cabinet: ''}",
        "{module: ''}",
        "plain-string",
    ] {
        assert!(authored(bad).is_err(), "must reject: {bad}");
    }
    for word in ["cabinet", "drawer", "unadmitted"] {
        let text = format!("{{{word}: credential-canary}}");
        let error = serde_yaml::from_str::<SecretRef>(&text)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("credential-canary"));
        assert!(error.contains("admitted source declaration"));
    }
}

#[test]
fn describe_names_only_source_identity_without_settings() {
    for (word, owner) in [("cabinet", "first-source"), ("drawer", "second-source")] {
        let reference = named(word, "private-descriptor-canary");
        assert_eq!(reference.describe(), format!("secret module '{owner}'"));
        assert!(!format!("{reference:?}").contains("private-descriptor-canary"));
    }
}

#[test]
fn none_is_the_one_scalar_a_secret_field_accepts() {
    let r: SecretRef = serde_yaml::from_str("none").unwrap();
    assert_eq!(r, SecretRef::none());
    assert!(r.is_none());
    assert!(
        r.source().is_none(),
        "keyless declares no source or settings"
    );
    assert_eq!(r.describe(), "none");
    assert!(serde_yaml::from_str::<SecretRef>("{module: none}")
        .unwrap()
        .is_none());
    assert!(serde_json::from_str::<SecretRef>("\"none\"")
        .unwrap()
        .is_none());
    for bad in ["None", "NONE", "no", "nones", "{none: true}"] {
        assert!(serde_yaml::from_str::<SecretRef>(bad).is_err(), "{bad}");
    }
    let error = serde_yaml::from_str::<SecretRef>("sk-live-abc123")
        .unwrap_err()
        .to_string();
    assert!(error.contains("never an inline literal") && !error.contains("sk-live-abc123"));
}

#[test]
fn deserialize_error_message_names_the_accepted_shapes() {
    assert!(serde_yaml::from_str::<SecretRef>("[1,2]")
        .unwrap_err()
        .to_string()
        .contains("a secret reference map"));
}

#[test]
fn oneof_schema_accepts_exactly_what_secretref_accepts() {
    let validator = jsonschema::validator_for(&oneof_schema()).unwrap();
    for value in [
        serde_json::json!({"module":"independent-source","settings":{"slot":"x"}}),
        serde_json::json!({"module":"independent-source"}),
        serde_json::json!("none"),
        serde_json::to_value(
            SecretRef::template("literal ${A}", &sources())
                .unwrap()
                .writing(),
        )
        .unwrap(),
    ] {
        assert!(validator.is_valid(&value), "{value}");
        assert!(
            serde_json::from_value::<SecretRef>(value.clone()).is_ok(),
            "schema/decoder drift: {value}"
        );
    }
    for value in [
        serde_json::json!("s3cret"),
        serde_json::json!({"literal":"s3cret"}),
        serde_json::json!({"cabinet":"A","drawer":"B"}),
        serde_json::json!({}),
    ] {
        assert!(!validator.is_valid(&value), "{value}");
    }
}

#[test]
fn the_schema_and_the_deserializer_agree_shape_for_shape() {
    let validator = jsonschema::validator_for(&oneof_schema()).unwrap();
    let cases = [
        (serde_json::json!({"module":"independent-source"}), true),
        (
            serde_json::json!({"module":"independent-source","settings":{"slot":"x"}}),
            true,
        ),
        (serde_json::json!("none"), true),
        (serde_json::json!({"module":"none"}), true),
        (serde_json::json!("None"), false),
        (serde_json::json!("NONE"), false),
        (serde_json::json!({"none":true}), false),
        (serde_json::json!({"cabinet":"item"}), false),
        (serde_json::json!({"drawer":"item"}), false),
        (serde_json::json!({"cabinet":"   "}), false),
        (serde_json::json!({"drawer":"\t"}), false),
        (serde_json::json!({"module":" "}), false),
        (serde_json::json!({"module":""}), false),
        (serde_json::json!({}), false),
        (serde_json::json!({"cabinet":"A","drawer":"B"}), false),
        (
            serde_json::json!({"module":"independent-source","cabinet":"A"}),
            false,
        ),
        (serde_json::json!({"cabinet":"A","settings":{}}), false),
        (serde_json::json!({"literal":"s3cret"}), false),
        (serde_json::json!({"unknown":"x"}), false),
        (serde_json::json!("s3cret"), false),
        (serde_json::json!(483_920_175_534u64), false),
        (serde_json::json!(true), false),
        (
            serde_json::json!({"template":{"text":"${A}","source":{"module":"first-source","setting":"entry"}}}),
            true,
        ),
        (
            serde_json::json!({"template":{"text":"${A}","source":{"module":"","setting":"entry"}}}),
            false,
        ),
        (serde_json::json!({"template":{"text":"${A}"}}), false),
    ];
    for (shape, expected) in cases {
        let by_schema = validator.is_valid(&shape);
        let by_serde = serde_json::from_value::<SecretRef>(shape.clone()).is_ok();
        assert_eq!(by_schema, by_serde, "schema/decoder drift: {shape}");
        assert_eq!(by_serde, expected, "wrong verdict: {shape}");
    }
}

#[test]
fn an_unquoted_inline_secret_is_refused_without_echoing_it() {
    for (yaml, value) in [
        ("\"hunter2secret\"", "hunter2secret"),
        ("483920175534", "483920175534"),
        ("-42", "42"),
        ("true", "true"),
        ("1.5", "1.5"),
    ] {
        let error = serde_yaml::from_str::<SecretRef>(yaml)
            .unwrap_err()
            .to_string();
        assert!(!error.contains(value), "{error}");
        assert!(error.contains("never an inline literal"), "{error}");
    }
}
#[test]
fn a_scalar_in_the_settings_slot_is_refused_without_echoing_it() {
    let error = serde_yaml::from_str::<SecretRef>("{module: source, settings: sk-live-abc123}")
        .unwrap_err()
        .to_string();
    assert!(!error.contains("sk-live-abc123"), "{error}");
    assert!(error.contains("never an inline literal"), "{error}");
}
#[test]
fn a_non_string_declared_shorthand_value_is_refused_without_echoing_it() {
    for (yaml, value) in [("{cabinet: 12345}", "12345"), ("{drawer: true}", "true")] {
        let error = authored(yaml).unwrap_err().to_string();
        assert!(!error.contains(value), "{error}");
        assert!(error.contains("non-empty text value"), "{error}");
    }
}
#[test]
fn a_non_string_module_is_refused_without_echoing_it() {
    let error = serde_yaml::from_str::<SecretRef>("{module: 12345}")
        .unwrap_err()
        .to_string();
    assert!(!error.contains("12345"), "{error}");
    assert!(error.contains("must be a string"), "{error}");
}
#[test]
fn duplicate_keys_are_refused() {
    for (text, field) in [
        (r#"{"module":"source","module":"other"}"#, "module"),
        (
            r#"{"module":"source","settings":{"slot":"x"},"settings":{"slot":"y"}}"#,
            "settings",
        ),
    ] {
        let error = serde_json::from_str::<SecretRef>(text)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("duplicate field") && error.contains(field),
            "{error}"
        );
    }
}
#[test]
fn serialize_yields_the_canonical_module_settings_wire_shape() {
    let refs = [
        named("cabinet", "item"),
        named("drawer", "other"),
        serde_json::from_value(
            serde_json::json!({"module":"independent-source","settings":{"slot":"opaque"}}),
        )
        .unwrap(),
        SecretRef::none(),
    ];
    let expected = [
        serde_json::json!({"module":"first-source","settings":{"entry":"item"}}),
        serde_json::json!({"module":"second-source","settings":{"location":"other"}}),
        serde_json::json!({"module":"independent-source","settings":{"slot":"opaque"}}),
        serde_json::json!({"module":"none","settings":{}}),
    ];
    for (reference, expected) in refs.iter().zip(expected) {
        let wire = serde_json::to_value(reference.writing()).unwrap();
        let object = wire.as_object().unwrap();
        assert!(object.contains_key("module"));
        assert!(object.contains_key("settings"));
        assert_eq!(object.len(), 2);
        assert_eq!(
            wire, expected,
            "including legacy canonical keyless encoding"
        );
        assert_eq!(
            serde_json::from_value::<SecretRef>(wire).unwrap(),
            *reference
        );
    }
}
#[test]
fn a_template_reference_resolves_each_variable_in_place() {
    let resolve = |r: &SecretRef| {
        if r == &named("cabinet", "A") {
            Ok(crate::Secret::new("alpha".to_owned()))
        } else if r == &named("cabinet", "B") {
            Ok(crate::Secret::new("beta".to_owned()))
        } else {
            Err("source refused the requested descriptor".to_owned())
        }
    };
    let t = SecretRef::template("Bearer ${A}:${B} $5 ${ and ${", &sources()).unwrap();
    assert!(matches!(t, SecretRef::Template(_)));
    assert_eq!(
        serde_json::to_value(t.writing()).unwrap()["template"]["text"],
        "Bearer ${A}:${B} $5 ${ and ${"
    );
    assert_eq!(
        t.resolve_template(&resolve).map(|s| s.0.clone()).as_deref(),
        Ok("Bearer alpha:beta $5 ${ and ${")
    );
    assert_eq!(
        named("cabinet", "B")
            .resolve_template(&resolve)
            .map(|s| s.0.clone())
            .as_deref(),
        Ok("beta")
    );
    let unresolved = SecretRef::template("x ${C}", &sources())
        .unwrap()
        .resolve_template(&resolve);
    assert_eq!(
        unresolved,
        Err("source refused the requested descriptor".to_owned())
    );
    assert_eq!(
        serde_json::from_value::<SecretRef>(serde_json::to_value(t.writing()).unwrap()).unwrap(),
        t
    );
}
#[test]
fn templates_capture_one_admitted_owner_and_preserve_typed_refusals() {
    assert!(SecretRef::template("${A}", &Sugars::default()).is_err());
    let reference = SecretRef::template("private-template ${A}", &sources()).unwrap();
    assert_eq!(reference.source_module(), Some("first-source"));
    assert!(!format!("{reference:?}").contains("private-template"));
    assert!(matches!(
        reference.resolve_template_typed(&|_| Err::<crate::Secret<String>, _>(17u32)),
        Err(TemplateRefused::Source(17))
    ));
    let wire = serde_json::to_value(reference.writing()).unwrap();
    assert!(context::deserialize::<SecretRef, _>(wire.clone(), &Sugars::default()).is_err());
    let mut other = Sugars::default();
    other
        .declare(
            "unrelated-owner",
            &[
                (REWRITE_SUGAR, "elsewhere".into(), "entry".into()),
                (
                    REWRITE_SUGAR_ROLE,
                    "elsewhere".into(),
                    SUGAR_ROLE_FILL.into(),
                ),
            ],
        )
        .unwrap();
    assert!(context::deserialize::<SecretRef, _>(wire.clone(), &other).is_err());
    assert!(context::deserialize::<SecretRef, _>(wire, &sources()).is_ok());
}

#[test]
fn template_text_rejects_nontext_without_scalar_coercion_or_echo() {
    for text in [
        "483920175534",
        "true",
        "null",
        "[private-marker]",
        "{private-marker: private-value}",
    ] {
        let yaml = format!(
            "template:\n  text: {text}\n  source: {{module: first-source, setting: entry}}\n"
        );
        let error = authored(&yaml).unwrap_err().to_string();
        assert!(!error.contains("483920175534"));
        assert!(!error.contains("private-marker"));
        assert!(!error.contains("private-value"));
        assert!(serde_yaml::from_str::<SecretRef>(&yaml).is_err());
    }
}
