// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Read plane-owned provider values from a plane's neutral descriptor. No request-shape
//! key, model capability, or wire spelling is part of this parser.

use busbar_contract::provider_keys::{Key, ProviderKeys, Shape, Table};
use serde::de::{DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::fmt;

#[derive(Clone, Copy)]
pub(super) enum Form {
    Catalog,
    Deployment,
    Entry,
}
impl Form {
    pub(super) fn table(self, keys: &ProviderKeys) -> &Table {
        match self {
            Self::Catalog => &keys.catalog,
            Self::Deployment => &keys.deployment,
            Self::Entry => &keys.entry,
        }
    }
    pub(super) fn omit_unset(self, values: &mut Map<String, Value>, keys: &ProviderKeys) {
        let table = self.table(keys);
        values.retain(|name, value| {
            !value.is_null()
                || !table
                    .keys
                    .iter()
                    .any(|key| key.name == *name && !key.required)
        });
    }
}

pub(super) struct ValueSeed<'a> {
    shape: &'a Shape,
    nullable: bool,
}
impl<'a> ValueSeed<'a> {
    pub(super) fn field(key: &'a Key) -> Self {
        Self {
            shape: &key.shape,
            nullable: key.nullable.unwrap_or(!key.required),
        }
    }
    fn value(shape: &'a Shape) -> Self {
        Self {
            shape,
            nullable: false,
        }
    }
}
impl<'de> DeserializeSeed<'de> for ValueSeed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Value, D::Error> {
        if self.nullable {
            return de.deserialize_option(OptionalValue(self.shape));
        }
        match self.shape {
            Shape::Str => String::deserialize(de).map(Value::String),
            Shape::Bool => bool::deserialize(de).map(Value::Bool),
            Shape::Int => i64::deserialize(de).map(Value::from),
            Shape::StrMap => {
                std::collections::BTreeMap::<String, String>::deserialize(de).map(|m| {
                    Value::Object(m.into_iter().map(|(k, v)| (k, Value::String(v))).collect())
                })
            }
            Shape::OneOf(words) => de.deserialize_enum("", &[], Word(words)),
            Shape::List(shape) => de.deserialize_seq(List(shape)),
            Shape::Table(table) => de.deserialize_map(Fields(table)),
        }
    }
}
struct OptionalValue<'a>(&'a Shape);
impl<'de> Visitor<'de> for OptionalValue<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an optional value")
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_some<D: serde::Deserializer<'de>>(self, de: D) -> Result<Value, D::Error> {
        ValueSeed::value(self.0).deserialize(de)
    }
}
struct Word<'a>(&'a [String]);
impl<'de> Visitor<'de> for Word<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("string or map")
    }
    fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<Value, A::Error> {
        let (word, variant) = data.variant::<String>()?;
        if !self.0.contains(&word) {
            let expected = match self.0 {
                [only] => format!("expected `{only}`"),
                [first, second] => format!("expected `{first}` or `{second}`"),
                words => format!(
                    "expected one of {}",
                    words
                        .iter()
                        .map(|s| format!("`{s}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            };
            return Err(serde::de::Error::custom(format!(
                "unknown variant `{word}`, {expected}"
            )));
        }
        variant.unit_variant()?;
        Ok(Value::String(word))
    }
}
struct List<'a>(&'a Shape);
impl<'de> Visitor<'de> for List<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a sequence")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(ValueSeed::value(self.0))? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
}
// Unknown names must fail in the key deserializer itself. Returning the same
// error later from visit_map loses the key's YAML source column.
struct FieldName<'a>(&'a Table);
impl<'de> DeserializeSeed<'de> for FieldName<'_> {
    type Value = String;
    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<String, D::Error> {
        struct NameVisitor<'a>(&'a Table);
        impl<'de> Visitor<'de> for NameVisitor<'_> {
            type Value = String;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("field identifier")
            }
            fn visit_str<E: serde::de::Error>(self, name: &str) -> Result<String, E> {
                if self.0.deny_unknown && !self.0.keys.iter().any(|key| key.name == name) {
                    return Err(E::custom(format!(
                        "unknown field `{name}`, expected one of {}",
                        self.0
                            .keys
                            .iter()
                            .map(|key| format!("`{}`", key.name))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )));
                }
                Ok(name.to_string())
            }
            fn visit_string<E: serde::de::Error>(self, name: String) -> Result<String, E> {
                self.visit_str(&name)
            }
        }
        de.deserialize_identifier(NameVisitor(self.0))
    }
}

struct Fields<'a>(&'a Table);
impl<'de> Visitor<'de> for Fields<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0.name {
            Some(name) => write!(f, "struct {name}"),
            None => f.write_str("a map"),
        }
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(name) = map.next_key_seed(FieldName(self.0))? {
            let key = self.0.keys.iter().find(|k| k.name == name);
            let value = if let Some(key) = key {
                if values.contains_key(&name) {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate field `{name}`"
                    )));
                }
                map.next_value_seed(ValueSeed::field(key))?
            } else {
                map.next_value::<Value>()?
            };
            values.insert(name, value);
        }
        for key in &self.0.keys {
            if key.required && !values.contains_key(&key.name) {
                return Err(serde::de::Error::custom(format!(
                    "missing field `{}`",
                    key.name
                )));
            }
        }
        // Optional declared nulls serialize like an unset Option. Required nullable
        // fields and unknown open-table extensions remain explicit values.
        values.retain(|name, value| {
            !value.is_null()
                || !self
                    .0
                    .keys
                    .iter()
                    .any(|key| key.name == *name && !key.required)
        });
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
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
    fn read(key: &Key, text: &str) -> Result<Value, serde_yaml::Error> {
        ValueSeed::field(key).deserialize(serde_yaml::Deserializer::from_str(text))
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
            error.contains(
                "unknown field `unexpected`, expected one of `globs`, `enabled`, `spelling`"
            ),
            "{error}"
        );
        let error = read(&key, "[{enabled: true}]").unwrap_err().to_string();
        assert!(error.contains("missing field `globs`"), "{error}");
        let error = read(&key, "[{globs: [], enabled: perhaps}]")
            .unwrap_err()
            .to_string();
        assert!(error.contains("expected a boolean"), "{error}");
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
        assert!(error.contains("expected a sequence"), "{error}");
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
        assert!(error.contains("expected a sequence"), "{error}");
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
}

#[cfg(test)]
mod legacy_refusals {
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
}

#[cfg(test)]
mod actual_plane_legacy_grammar {
    use super::*;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum MaxOutputKeyCfg {
        MaxTokens,
        MaxCompletionTokens,
    }
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct ModelCapabilities {
        models: Vec<String>,
        #[serde(default)]
        max_output_key: Option<MaxOutputKeyCfg>,
        #[serde(default)]
        anthropic_adaptive_thinking: Option<bool>,
        #[serde(default)]
        native_structured_output: Option<bool>,
        #[serde(default)]
        reasoning_none: Option<bool>,
        #[serde(default)]
        thinking_always_on: Option<bool>,
    }

    #[test]
    fn the_actual_exported_plane_descriptor_keeps_legacy_capability_refusals() {
        let fixture: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testing/config/provider-keys-llm.json"
        )))
        .unwrap();
        let descriptor = busbar_contract::provider_keys::decode(
            fixture["descriptor_text"].as_str().unwrap().as_bytes(),
        )
        .unwrap();
        for table in [&descriptor.catalog, &descriptor.entry] {
            let key = table
                .keys
                .iter()
                .find(|k| k.name == "model_capabilities")
                .unwrap();
            for text in [
                "null",
                "true",
                "[true]",
                "[null]",
                "[{}]",
                "[{models: null}]",
                "[{models: [{}]}]",
                "[{models: [], anthropic_adaptive_thinking: wrong}]",
                "[{models: [], max_output_key: wrong}]",
                "[{models: [], max_output_key: 1}]",
                "[{models: [], unknown: true}]",
                "[{models: [], reasoning_none: true, reasoning_none: false}]",
            ] {
                let legacy = serde_yaml::from_str::<Vec<ModelCapabilities>>(text)
                    .unwrap_err()
                    .to_string();
                let actual = ValueSeed::field(key)
                    .deserialize(serde_yaml::Deserializer::from_str(text))
                    .unwrap_err()
                    .to_string();
                assert_eq!(actual, legacy, "{text}");
            }
        }
        let key = descriptor
            .deployment
            .keys
            .iter()
            .find(|k| k.name == "model_capabilities")
            .unwrap();
        assert!(
            serde_yaml::from_str::<Option<Vec<ModelCapabilities>>>("null")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            ValueSeed::field(key)
                .deserialize(serde_yaml::Deserializer::from_str("null"))
                .unwrap(),
            Value::Null
        );
    }
}
