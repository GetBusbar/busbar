// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Internal normalization keeps every unconsumed key and value guarded even when a
//! reference visitor refuses early. No owner settings decoder is exposed to callers.
use super::Tree;
use serde::de::{self, DeserializeSeed, IntoDeserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserializer;
use serde_json::Value;
use zeroize::Zeroizing;

type Error = de::value::Error;

impl<'de> IntoDeserializer<'de, Error> for Tree {
    type Deserializer = Self;
    fn into_deserializer(self) -> Self {
        self
    }
}

impl<'de> Deserializer<'de> for Tree {
    type Error = Error;
    fn deserialize_any<V: Visitor<'de>>(mut self, visitor: V) -> Result<V::Value, Error> {
        match &mut self.0 {
            Value::Null => visitor.visit_unit(),
            Value::Bool(value) => visitor.visit_bool(*value),
            Value::Number(value) => {
                if let Some(value) = value.as_u64() {
                    visitor.visit_u64(value)
                } else if let Some(value) = value.as_i64() {
                    visitor.visit_i64(value)
                } else {
                    visitor.visit_f64(value.as_f64().expect("JSON number"))
                }
            }
            Value::String(value) => visitor.visit_str(value),
            Value::Array(values) => {
                let held: Vec<Tree> = std::mem::take(values).into_iter().map(Tree).collect();
                visitor.visit_seq(Sequence(held.into_iter()))
            }
            Value::Object(values) => {
                let held: Vec<_> = std::mem::take(values)
                    .into_iter()
                    .map(|(key, value)| (Zeroizing::new(key), Tree(value)))
                    .collect();
                visitor.visit_map(Object {
                    entries: held.into_iter(),
                    pending: None,
                })
            }
        }
    }
    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        if self.0.is_null() {
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_newtype_struct(self)
    }
    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string bytes byte_buf
        unit unit_struct seq tuple tuple_struct map struct enum identifier ignored_any
    }
}

struct Sequence(std::vec::IntoIter<Tree>);
impl<'de> SeqAccess<'de> for Sequence {
    type Error = Error;
    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        self.0
            .next()
            .map(|value| seed.deserialize(value))
            .transpose()
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.0.len())
    }
}

struct Object {
    entries: std::vec::IntoIter<(Zeroizing<String>, Tree)>,
    pending: Option<Tree>,
}
impl<'de> MapAccess<'de> for Object {
    type Error = Error;
    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        let Some((mut key, value)) = self.entries.next() else {
            return Ok(None);
        };
        self.pending = Some(value);
        seed.deserialize(Tree(Value::String(std::mem::take(&mut *key))))
            .map(Some)
    }
    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
        let value = self
            .pending
            .take()
            .ok_or_else(|| de::Error::custom("missing reference value"))?;
        seed.deserialize(value)
    }
    fn size_hint(&self) -> Option<usize> {
        Some(self.entries.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[test]
    fn normalization_retains_nested_settings_without_reinterpreting_owner_schema() {
        let written = serde_json::json!({"module":"source", "settings":{
            "values":[null,true,3,-4,1.5,"private"], "nested":{"key":"value"}
        }});
        let reference = crate::secret_ref::SecretRef::deserialize(Tree(written.clone())).unwrap();
        assert_eq!(serde_json::to_value(reference).unwrap(), written);
    }

    #[test]
    #[allow(unsafe_code)]
    fn an_early_reference_refusal_retires_all_unconsumed_guarded_payloads() {
        use crate::alloc_counter::{watch_initialized_payload, InitializedPayloadProbe};
        // SAFETY: all registered strings remain exclusively owned on this thread until freed.
        let probe = unsafe { InitializedPayloadProbe::start().unwrap() };
        let key = "a-unknown-reference-member".to_owned();
        let value = "private-descriptor-value".to_owned();
        let nested = "unconsumed-nested-material".to_owned();
        // SAFETY: each slice is the initialized prefix at the base of its owned string allocation.
        unsafe {
            watch_initialized_payload(key.as_bytes());
            watch_initialized_payload(value.as_bytes());
            watch_initialized_payload(nested.as_bytes());
        }
        let tree = Tree(Value::Object(
            [
                (key, Value::String(value)),
                (
                    "settings".into(),
                    Value::Object(
                        [("nested".into(), Value::String(nested))]
                            .into_iter()
                            .collect(),
                    ),
                ),
            ]
            .into_iter()
            .collect(),
        ));
        let error = crate::secret_ref::SecretRef::deserialize(tree)
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown reference member"));
        assert!(!error.contains("private-descriptor-value"));
        let observed = probe.finish();
        assert!(!observed.reentered);
        assert_eq!(observed.payloads.len(), 3);
        for payload in observed.payloads {
            assert!(payload.freed);
            assert!(!payload.reallocated);
            #[cfg(target_os = "linux")]
            {
                assert_eq!(payload.read_error, None);
                assert!(payload.complete_read);
                assert!(payload.wiped);
            }
            #[cfg(not(target_os = "linux"))]
            assert_eq!(payload.read_error, Some(std::io::ErrorKind::Unsupported));
        }
    }
}
