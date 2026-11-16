// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
            // The YAML reader's own refusal of a derived enum's unknown variant, word for word,
            // so a descriptor-driven key refuses as the derived grammar it replaced did.
            return Err(serde::de::Error::custom(format!(
                "unknown variant `{word}`, expected {}",
                one_of(self.0.iter().map(String::as_str))
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
                    // The YAML reader's own refusal of a derived struct's unknown field.
                    return Err(E::custom(format!(
                        "unknown field `{name}`, expected {}",
                        one_of(self.0.keys.iter().map(|key| key.name.as_str()))
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

/// The expected names as serde's derived refusals word them (1.5.5's spelling): "`a`",
/// "`a` or `b`", or "one of `a`, `b`, `c`".
fn one_of<'a>(names: impl Iterator<Item = &'a str>) -> String {
    let quoted: Vec<String> = names.map(|name| format!("`{name}`")).collect();
    match quoted.as_slice() {
        [] => "nothing".to_string(),
        [one] => one.clone(),
        [a, b] => format!("{a} or {b}"),
        all => format!("one of {}", all.join(", ")),
    }
}

#[cfg(test)]
#[path = "tests/provider_grammar_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/provider_grammar_legacy_refusals_tests.rs"]
mod legacy_refusals;

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
    struct ModelCapabilities {
        #[serde(rename = "models")]
        _models: Vec<String>,
        #[serde(default, rename = "max_output_key")]
        _max_output_key: Option<MaxOutputKeyCfg>,
        #[serde(default, rename = "anthropic_adaptive_thinking")]
        _anthropic_adaptive_thinking: Option<bool>,
        #[serde(default, rename = "native_structured_output")]
        _native_structured_output: Option<bool>,
        #[serde(default, rename = "reasoning_none")]
        _reasoning_none: Option<bool>,
        #[serde(default, rename = "thinking_always_on")]
        _thinking_always_on: Option<bool>,
    }

    #[test]
    fn the_actual_exported_plane_descriptor_keeps_legacy_capability_refusals() {
        let fixture: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/config/tests/fixtures/provider-keys-llm.json"
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
                let legacy = busbar_contract::yaml::from_str::<Vec<ModelCapabilities>>(text)
                    .unwrap_err()
                    .to_string();
                let actual = busbar_contract::yaml::with_deserializer(text, |d| {
                    ValueSeed::field(key).deserialize(d)
                })
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
            busbar_contract::yaml::from_str::<Option<Vec<ModelCapabilities>>>("null")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            busbar_contract::yaml::with_deserializer("null", |d| ValueSeed::field(key)
                .deserialize(d))
            .unwrap(),
            Value::Null
        );
    }
}
