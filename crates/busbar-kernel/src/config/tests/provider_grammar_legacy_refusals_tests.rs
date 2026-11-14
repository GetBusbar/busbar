// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Spelling {
    First,
    Second,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct Rule {
    globs: Vec<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    spelling: Option<Spelling>,
}
fn field(name: &str, shape: Shape, required: bool) -> Key {
    Key {
        name: name.into(),
        shape,
        required,
        nullable: None,
    }
}

#[test]
fn descriptor_validation_preserves_derived_serde_refusals_byte_for_byte() {
    let key = Key {
        name: "rules".into(),
        required: false,
        nullable: Some(false),
        shape: Shape::List(Box::new(Shape::Table(Table {
            name: Some("Rule".into()),
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
        }))),
    };
    for text in [
        "null",
        "true",
        "[true]",
        "[null]",
        "[{}]",
        "[{globs: null}]",
        "[{globs: [{}]}]",
        "[{globs: [], enabled: wrong}]",
        "[{globs: [], spelling: wrong}]",
        "[{globs: [], spelling: 1}]",
        "[{globs: [], unknown: true}]",
        "[{globs: [], enabled: true, enabled: false}]",
    ] {
        let legacy = serde_yaml::from_str::<Vec<Rule>>(text)
            .unwrap_err()
            .to_string();
        let descriptor = ValueSeed::field(&key)
            .deserialize(serde_yaml::Deserializer::from_str(text))
            .unwrap_err()
            .to_string();
        assert_eq!(descriptor, legacy, "{text}");
    }
}
