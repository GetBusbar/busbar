// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use serde_json::json;

fn field(name: &str, shape: Shape, required: bool) -> Key {
    Key {
        name: name.into(),
        shape,
        required,
        nullable: None,
    }
}
fn rule() -> Shape {
    Shape::List(Box::new(Shape::Table(Table {
        name: None,
        deny_unknown: true,
        keys: vec![
            field("globs", Shape::List(Box::new(Shape::Str)), true),
            field("enabled", Shape::Bool, false),
            field(
                "spelling",
                Shape::OneOf(vec!["first".into(), "second".into()]),
                false,
            ),
        ],
    })))
}
fn read(key: &Key, text: &str) -> Result<Value, busbar_contract::yaml::Error> {
    busbar_contract::yaml::with_deserializer(text, |d| ValueSeed::field(key).deserialize(d))
}

#[test]
fn a_new_descriptor_key_needs_no_kernel_grammar_change() {
    let key = field("a-new-plane-setting", rule(), false);
    assert_eq!(
        read(
            &key,
            "[{globs: ['wire-*'], enabled: false, spelling: second}]"
        )
        .unwrap(),
        json!([{"globs":["wire-*"],"enabled":false,"spelling":"second"}])
    );
    let error = read(&key, "[{globs: [], unexpected: true}]")
        .unwrap_err()
        .to_string();
    assert!(
        error
            .contains("unknown field `unexpected`, expected one of `globs`, `enabled`, `spelling`"),
        "{error}"
    );
    let error = read(&key, "[{enabled: true}]").unwrap_err().to_string();
    assert!(error.contains("missing field `globs`"), "{error}");
    let error = read(&key, "[{globs: [], enabled: perhaps}]")
        .unwrap_err()
        .to_string();
    assert!(error.contains("invalid boolean"), "{error}");
    let error = read(&key, "[{globs: [], spelling: typo}]")
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("unknown variant `typo`, expected `first` or `second`"),
        "{error}"
    );
}

#[test]
fn explicit_null_distinguishes_optional_values_from_defaulted_collections() {
    let mut key = field("rules", rule(), false);
    assert_eq!(read(&key, "null").unwrap(), Value::Null);
    key.nullable = Some(false);
    let error = read(&key, "null").unwrap_err().to_string();
    assert!(error.contains("expected sequence start"), "{error}");
    assert_eq!(read(&key, "[]").unwrap(), json!([]));
}

#[test]
fn required_nested_list_and_optional_scalar_keep_distinct_null_semantics() {
    let key = field("rules", rule(), false);
    assert_eq!(
        read(&key, "[{globs: [], enabled: null}]").unwrap(),
        json!([{"globs":[]}])
    );
    let error = read(&key, "[{globs: null}]").unwrap_err().to_string();
    assert!(error.contains("expected sequence start"), "{error}");
    let error = read(&key, "[{globs: [], enabled: true, enabled: false}]")
        .unwrap_err()
        .to_string();
    assert!(error.contains("duplicate field `enabled`"), "{error}");
}
#[test]
fn open_tables_preserve_unknown_and_required_nullable_values() {
    let mut required = field("required", Shape::Bool, true);
    required.nullable = Some(true);
    let key = field(
        "settings",
        Shape::Table(Table {
            name: None,
            deny_unknown: false,
            keys: vec![required, field("optional", Shape::Bool, false)],
        }),
        true,
    );
    assert_eq!(
        read(&key, "{required: null, optional: null, extension: null}").unwrap(),
        json!({"required":null,"extension":null})
    );
}
#[test]
fn top_level_null_omission_uses_only_the_entrys_own_form() {
    let mut key = field("setting", Shape::Bool, true);
    key.nullable = Some(true);
    let mut optional = key.clone();
    optional.required = false;
    let descriptor = ProviderKeys {
        catalog: Table {
            name: None,
            deny_unknown: false,
            keys: vec![key.clone()],
        },
        deployment: Table {
            name: None,
            deny_unknown: false,
            keys: vec![optional],
        },
        entry: Table {
            name: None,
            deny_unknown: false,
            keys: vec![key],
        },
    };
    for form in [Form::Catalog, Form::Entry, Form::Deployment] {
        let mut values = Map::from_iter([
            ("setting".into(), Value::Null),
            ("extension".into(), Value::Null),
        ]);
        form.omit_unset(&mut values, &descriptor);
        assert_eq!(
            values.contains_key("setting"),
            !matches!(form, Form::Deployment)
        );
        assert_eq!(values.get("extension"), Some(&Value::Null));
    }
}
