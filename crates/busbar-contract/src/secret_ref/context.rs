// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Explicit owner metadata carried through serde's existing field boundaries.

use serde::de::{
    self, DeserializeSeed, EnumAccess, IntoDeserializer, MapAccess, SeqAccess, VariantAccess,
    Visitor,
};
use serde::{Deserialize, Deserializer};
use std::fmt;

use super::Sugars;

pub(super) const REFERENCE: &str = "busbar.secret-reference";

/// Deserialize a document using only the source shorthand its admitted owners declared.
/// Ordinary maps are untouched: shorthand expansion happens only at a `SecretRef` field.
pub fn deserialize<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
    deserializer: D,
    sugars: &Sugars,
) -> Result<T, D::Error> {
    T::deserialize(Context {
        inner: deserializer,
        sugars,
    })
}

struct Context<'a, D> {
    inner: D,
    sugars: &'a Sugars,
}
struct Wrapped<'a, V> {
    inner: V,
    sugars: &'a Sugars,
}

macro_rules! delegate {
    ($($method:ident),* $(,)?) => {$(
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
            self.inner.$method(Wrapped { inner: visitor, sugars: self.sugars })
        }
    )*};
}
impl<'de, D: Deserializer<'de>> Deserializer<'de> for Context<'_, D> {
    type Error = D::Error;
    delegate!(
        deserialize_any,
        deserialize_bool,
        deserialize_i8,
        deserialize_i16,
        deserialize_i32,
        deserialize_i64,
        deserialize_i128,
        deserialize_u8,
        deserialize_u16,
        deserialize_u32,
        deserialize_u64,
        deserialize_u128,
        deserialize_f32,
        deserialize_f64,
        deserialize_char,
        deserialize_str,
        deserialize_string,
        deserialize_bytes,
        deserialize_byte_buf,
        deserialize_option,
        deserialize_unit,
        deserialize_seq,
        deserialize_map,
        deserialize_identifier,
        deserialize_ignored_any
    );
    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_unit_struct(
            name,
            Wrapped {
                inner: visitor,
                sugars: self.sugars,
            },
        )
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        if name == REFERENCE {
            self.inner.deserialize_any(Reference {
                inner: visitor,
                sugars: self.sugars,
            })
        } else {
            self.inner.deserialize_newtype_struct(
                name,
                Wrapped {
                    inner: visitor,
                    sugars: self.sugars,
                },
            )
        }
    }
    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_tuple(
            len,
            Wrapped {
                inner: visitor,
                sugars: self.sugars,
            },
        )
    }
    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_tuple_struct(
            name,
            len,
            Wrapped {
                inner: visitor,
                sugars: self.sugars,
            },
        )
    }
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_struct(
            name,
            fields,
            Wrapped {
                inner: visitor,
                sugars: self.sugars,
            },
        )
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_enum(
            name,
            variants,
            Wrapped {
                inner: visitor,
                sugars: self.sugars,
            },
        )
    }
    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }
}

macro_rules! visit_scalar {
    ($($method:ident($ty:ty)),* $(,)?) => {$(
        fn $method<E: de::Error>(self, value: $ty) -> Result<Self::Value, E> { self.inner.$method(value) }
    )*};
}
impl<'de, V: Visitor<'de>> Visitor<'de> for Wrapped<'_, V> {
    type Value = V::Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.expecting(f)
    }
    visit_scalar!(
        visit_bool(bool),
        visit_i8(i8),
        visit_i16(i16),
        visit_i32(i32),
        visit_i64(i64),
        visit_i128(i128),
        visit_u8(u8),
        visit_u16(u16),
        visit_u32(u32),
        visit_u64(u64),
        visit_u128(u128),
        visit_f32(f32),
        visit_f64(f64),
        visit_char(char),
        visit_str(&str),
        visit_borrowed_str(&'de str),
        visit_string(String),
        visit_bytes(&[u8]),
        visit_borrowed_bytes(&'de [u8]),
        visit_byte_buf(Vec<u8>)
    );
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_unit()
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_none()
    }
    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        self.inner.visit_some(Context {
            inner: deserializer,
            sugars: self.sugars,
        })
    }
    fn visit_newtype_struct<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        self.inner.visit_newtype_struct(Context {
            inner: deserializer,
            sugars: self.sugars,
        })
    }
    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_seq(Wrapped {
            inner: seq,
            sugars: self.sugars,
        })
    }
    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_map(Wrapped {
            inner: map,
            sugars: self.sugars,
        })
    }
    fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_enum(Wrapped {
            inner: data,
            sugars: self.sugars,
        })
    }
}
impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for Wrapped<'_, S> {
    type Value = S::Value;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        self.inner.deserialize(Context {
            inner: deserializer,
            sugars: self.sugars,
        })
    }
}
impl<'de, A: SeqAccess<'de>> SeqAccess<'de> for Wrapped<'_, A> {
    type Error = A::Error;
    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, A::Error> {
        self.inner.next_element_seed(Wrapped {
            inner: seed,
            sugars: self.sugars,
        })
    }
    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}
impl<'de, A: MapAccess<'de>> MapAccess<'de> for Wrapped<'_, A> {
    type Error = A::Error;
    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, A::Error> {
        self.inner.next_key_seed(Wrapped {
            inner: seed,
            sugars: self.sugars,
        })
    }
    fn next_value_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<T::Value, A::Error> {
        self.inner.next_value_seed(Wrapped {
            inner: seed,
            sugars: self.sugars,
        })
    }
    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}
impl<'de, 'a, A: EnumAccess<'de>> EnumAccess<'de> for Wrapped<'a, A> {
    type Error = A::Error;
    type Variant = Wrapped<'a, A::Variant>;
    fn variant_seed<V: DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant), A::Error> {
        let (value, variant) = self.inner.variant_seed(Wrapped {
            inner: seed,
            sugars: self.sugars,
        })?;
        Ok((
            value,
            Wrapped {
                inner: variant,
                sugars: self.sugars,
            },
        ))
    }
}
impl<'de, A: VariantAccess<'de>> VariantAccess<'de> for Wrapped<'_, A> {
    type Error = A::Error;
    fn unit_variant(self) -> Result<(), A::Error> {
        self.inner.unit_variant()
    }
    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, A::Error> {
        self.inner.newtype_variant_seed(Wrapped {
            inner: seed,
            sugars: self.sugars,
        })
    }
    fn tuple_variant<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value, A::Error> {
        self.inner.tuple_variant(
            len,
            Wrapped {
                inner: visitor,
                sugars: self.sugars,
            },
        )
    }
    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, A::Error> {
        self.inner.struct_variant(
            fields,
            Wrapped {
                inner: visitor,
                sugars: self.sugars,
            },
        )
    }
}

struct Reference<'a, V> {
    inner: V,
    sugars: &'a Sugars,
}
impl<'de, V: Visitor<'de>> Visitor<'de> for Reference<'_, V> {
    type Value = V::Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "a canonical secret reference or a shorthand declared by an admitted source owner",
        )
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        self.inner.visit_newtype_struct(value.into_deserializer())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        use crate::plugin_settings::Tree;
        use zeroize::Zeroizing;
        let mut held = Tree::default();
        while let Some((mut key, mut value)) = map.next_entry::<Zeroizing<String>, Tree>()? {
            let object = held.0.as_object_mut().expect("reference map");
            if object.contains_key(key.as_str()) {
                return Err(de::Error::custom(
                    "duplicate secret-reference member (value not echoed)",
                ));
            }
            object.insert(std::mem::take(&mut *key), std::mem::take(&mut value.0));
        }
        let object = held.0.as_object().expect("reference map");
        if !object.contains_key("module") && !object.contains_key("template") && object.len() == 1 {
            let (word, value) = object.iter().next().expect("one entry");
            let sugar = self.sugars.get(word).ok_or_else(|| de::Error::custom(format!(
                "secret source shorthand `{word}` is not declared by an admitted owner; use its canonical module/settings reference"
            )))?;
            let value = value.as_str().filter(|s| !s.trim().is_empty()).ok_or_else(||
                de::Error::custom("a declared secret shorthand requires a non-empty text value (value not echoed)"))?;
            let reference = sugar.reference(value);
            held = Tree(serde_json::to_value(reference).map_err(de::Error::custom)?);
        }
        if held
            .0
            .as_object()
            .expect("reference map")
            .contains_key("template")
        {
            let reference: super::SecretRef = serde::Deserialize::deserialize(held.clone())
                .map_err(|_| de::Error::custom("malformed core template (value not echoed)"))?;
            reference
                .admitted_template(self.sugars)
                .map_err(de::Error::custom)?;
        }
        self.inner
            .visit_newtype_struct(held.into_deserializer())
            .map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::mechanism::door::REWRITE_SUGAR;
    use crate::secret_ref::SecretRef;

    #[derive(Deserialize)]
    struct Document {
        credential: SecretRef,
        ordinary: serde_json::Value,
        nested: Vec<Option<SecretRef>>,
    }
    fn declared(word: &str, owner: &str, setting: &str) -> Sugars {
        let mut sugars = Sugars::default();
        sugars
            .declare(owner, &[(REWRITE_SUGAR, word.into(), setting.into())])
            .unwrap();
        sugars
    }
    #[test]
    fn declared_owners_work_at_typed_fields_without_rewriting_ordinary_maps() {
        for (word, owner, setting) in [
            ("cabinet", "owner-one", "entry"),
            ("drawer", "owner-two", "location"),
        ] {
            let sugars = declared(word, owner, setting);
            let raw = format!(
                r#"{{"credential":{{"{word}":"item"}},"ordinary":{{"{word}":"untouched"}},"nested":[null,{{"{word}":"other"}}]}}"#
            );
            let mut decoder = serde_json::Deserializer::from_str(&raw);
            let result: Document = deserialize(&mut decoder, &sugars).unwrap();
            assert_eq!(result.credential.source_module(), Some(owner));
            assert_eq!(
                result.credential,
                sugars.get(word).unwrap().reference("item")
            );
            assert_eq!(result.ordinary[word], "untouched");
            assert!(result.nested[0].is_none());
            assert_eq!(
                result.nested[1].as_ref().unwrap(),
                &sugars.get(word).unwrap().reference("other")
            );
        }
    }
    #[test]
    fn missing_and_conflicting_source_declarations_are_refused() {
        let mut raw = serde_json::Deserializer::from_str(r#"{"cabinet":"not-echoed"}"#);
        let error = deserialize::<SecretRef, _>(&mut raw, &Sugars::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("not declared"));
        assert!(!error.contains("not-echoed"));
        let mut sugars = declared("cabinet", "first", "entry");
        assert!(sugars
            .declare(
                "second",
                &[(REWRITE_SUGAR, "cabinet".into(), "other".into())]
            )
            .is_err());
    }
}
