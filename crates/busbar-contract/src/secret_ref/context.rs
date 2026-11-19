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
        ctx: Ctx { sugars, used: None },
    })
}

/// [`deserialize`], recording into `used` every word the document uses (SECRET-SHORTHAND-BOOT
/// §3.8): the one-entry key of each reference position, declared or not, the fill role of each
/// template, and every one-entry key of a plugin settings bag outside `{literal: …}` and canonical
/// `{module, settings}` subtrees (the positions settings resolution reads shorthand at).
pub fn deserialize_recording<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
    deserializer: D,
    sugars: &Sugars,
    used: &UsedWords,
) -> Result<T, D::Error> {
    T::deserialize(Context {
        inner: deserializer,
        ctx: Ctx {
            sugars,
            used: Some(used),
        },
    })
}

/// What one read's parse used of the secret grammar: the shorthand words and the core grammar
/// roles. Filled by [`deserialize_recording`]; positions the parse does not read as a reference or
/// a settings bag (core's own TLS source grammar, `plugins.fetch`) record nothing.
#[derive(Debug, Default)]
pub struct UsedWords {
    words: std::cell::RefCell<std::collections::BTreeSet<String>>,
    roles: std::cell::RefCell<std::collections::BTreeSet<String>>,
}

impl UsedWords {
    fn word(&self, word: &str) {
        self.words.borrow_mut().insert(word.to_owned());
    }

    fn role(&self, role: &str) {
        self.roles.borrow_mut().insert(role.to_owned());
    }

    /// The words and roles recorded, in order.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        std::collections::BTreeSet<String>,
        std::collections::BTreeSet<String>,
    ) {
        (self.words.into_inner(), self.roles.into_inner())
    }

    /// Record the words of a settings bag read outside a recording parse (a stored definition
    /// typed later): the same positions [`deserialize_recording`] records.
    pub fn bag(&self, tree: &serde_json::Value) {
        record_bag(tree, self);
    }
}

/// Every one-entry key of a settings tree outside `{literal: …}` and canonical `{module,
/// settings}` subtrees: the positions `plugin_settings::canonicalize` reads shorthand at.
fn record_bag(tree: &serde_json::Value, used: &UsedWords) {
    match tree {
        serde_json::Value::Object(object) => {
            if object.len() == 1 && object.contains_key(crate::secret_fields::LITERAL_KEY) {
                return;
            }
            if object.contains_key("module")
                && object
                    .keys()
                    .all(|key| key == "module" || key == "settings")
            {
                return;
            }
            if object.len() == 1 {
                if let Some(word) = object.keys().next() {
                    used.word(word);
                }
            }
            for child in object.values() {
                record_bag(child, used);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                record_bag(child, used);
            }
        }
        _ => {}
    }
}

#[derive(Clone, Copy)]
struct Ctx<'a> {
    sugars: &'a Sugars,
    used: Option<&'a UsedWords>,
}

struct Context<'a, D> {
    inner: D,
    ctx: Ctx<'a>,
}
struct Wrapped<'a, V> {
    inner: V,
    ctx: Ctx<'a>,
}

macro_rules! delegate {
    ($($method:ident),* $(,)?) => {$(
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
            self.inner.$method(Wrapped { inner: visitor, ctx: self.ctx })
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
                ctx: self.ctx,
            },
        )
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        if name == REFERENCE {
            // Asked through the inner reader's own reference position, so a context nested inside
            // another (a type that reads itself under the installed owners, read by a caller that
            // named its owners) defers to the enclosing one: the context nearest the input governs.
            self.inner.deserialize_newtype_struct(
                REFERENCE,
                Reference {
                    inner: visitor,
                    ctx: self.ctx,
                },
            )
        } else if name == crate::plugin_settings::BAG {
            // A plugin settings bag: its shorthand is read at resolution, so the read records the
            // words it may hold here, where the bag is parsed.
            self.inner.deserialize_newtype_struct(
                crate::plugin_settings::BAG,
                Bag {
                    inner: visitor,
                    ctx: self.ctx,
                },
            )
        } else {
            self.inner.deserialize_newtype_struct(
                name,
                Wrapped {
                    inner: visitor,
                    ctx: self.ctx,
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
                ctx: self.ctx,
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
                ctx: self.ctx,
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
                ctx: self.ctx,
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
                ctx: self.ctx,
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
            ctx: self.ctx,
        })
    }
    fn visit_newtype_struct<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        self.inner.visit_newtype_struct(Context {
            inner: deserializer,
            ctx: self.ctx,
        })
    }
    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_seq(Wrapped {
            inner: seq,
            ctx: self.ctx,
        })
    }
    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_map(Wrapped {
            inner: map,
            ctx: self.ctx,
        })
    }
    fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_enum(Wrapped {
            inner: data,
            ctx: self.ctx,
        })
    }
}
impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for Wrapped<'_, S> {
    type Value = S::Value;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        self.inner.deserialize(Context {
            inner: deserializer,
            ctx: self.ctx,
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
            ctx: self.ctx,
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
            ctx: self.ctx,
        })
    }
    fn next_value_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<T::Value, A::Error> {
        self.inner.next_value_seed(Wrapped {
            inner: seed,
            ctx: self.ctx,
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
            ctx: self.ctx,
        })?;
        Ok((
            value,
            Wrapped {
                inner: variant,
                ctx: self.ctx,
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
            ctx: self.ctx,
        })
    }
    fn tuple_variant<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value, A::Error> {
        self.inner.tuple_variant(
            len,
            Wrapped {
                inner: visitor,
                ctx: self.ctx,
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
                ctx: self.ctx,
            },
        )
    }
}

/// serde_json's exact-number transport key (`arbitrary_precision`).
pub(super) const JSON_NUMBER_TOKEN: &str = "$serde_json::private::Number";

/// The fixed class marker an undeclared-shorthand refusal starts with (BUSBAR-3121). The operator's
/// word is echoed escaped and with this marker removed, so no key in a document can forge the class.
pub const UNDECLARED_MARKER: &str = "BUSBAR-3121\u{b7}undeclared:";

/// The longest echo of an undeclared word, in characters, after escaping.
const ECHOED_WORD_CHARS: usize = 64;

/// The refusal for a one-entry reference map whose key no admitted secret module declares. A
/// shorthand is a secret module's word, never core's: the text names the word, says it is a secret
/// shorthand and what must be installed and admitted for it, and names no plugin.
fn undeclared(word: &str) -> String {
    let mut shown = word.escape_debug().to_string();
    while shown.contains(UNDECLARED_MARKER) {
        shown = shown.replace(UNDECLARED_MARKER, "");
    }
    let shown: String = shown.chars().take(ECHOED_WORD_CHARS).collect();
    format!(
        "{UNDECLARED_MARKER} `{{{shown}: \u{2026}}}` is a secret shorthand, and no admitted secret \
         module declares `{shown}`. Install a signed `kind: secret` module that declares `{shown}` \
         into plugins.dir and admit it (plugins.enabled, plugins.trust), or write the canonical \
         `{{ module: <secret module>, settings: {{ \u{2026} }} }}` reference. `busbar \
         --list-plugins` shows what was admitted."
    )
}

struct Reference<'a, V> {
    inner: V,
    ctx: Ctx<'a>,
}
impl<'de, V: Visitor<'de>> Visitor<'de> for Reference<'_, V> {
    type Value = V::Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "a canonical secret reference or a shorthand declared by an admitted source owner",
        )
    }
    fn visit_newtype_struct<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        self.inner.visit_newtype_struct(value.into_deserializer())
    }
    // Every other scalar is an inline literal. serde's default refusal quotes the value
    // (`invalid type: integer `483920175534``), so each is refused here without echoing it.
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Err(E::custom(super::INLINE_LITERAL_REFUSAL))
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Err(E::custom(super::INLINE_LITERAL_REFUSAL))
    }
    fn visit_i128<E: de::Error>(self, _: i128) -> Result<Self::Value, E> {
        Err(E::custom(super::INLINE_LITERAL_REFUSAL))
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
        Err(E::custom(super::INLINE_LITERAL_REFUSAL))
    }
    fn visit_u128<E: de::Error>(self, _: u128) -> Result<Self::Value, E> {
        Err(E::custom(super::INLINE_LITERAL_REFUSAL))
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Err(E::custom(super::INLINE_LITERAL_REFUSAL))
    }
    fn visit_char<E: de::Error>(self, _: char) -> Result<Self::Value, E> {
        Err(E::custom(super::INLINE_LITERAL_REFUSAL))
    }
    fn visit_bytes<E: de::Error>(self, _: &[u8]) -> Result<Self::Value, E> {
        Err(E::custom(super::INLINE_LITERAL_REFUSAL))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Err(E::custom(super::INLINE_LITERAL_REFUSAL))
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Err(E::custom(super::INLINE_LITERAL_REFUSAL))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        use crate::plugin_settings::Tree;
        use crate::secure::SecureString;
        let mut held = Tree::default();
        while let Some(key) = map.next_key::<SecureString>()? {
            // serde_json (arbitrary_precision) carries a number as this synthetic one-entry map;
            // its value is the literal's text, so it is refused before that value is read.
            if key.as_str() == JSON_NUMBER_TOKEN {
                return Err(de::Error::custom(super::INLINE_LITERAL_REFUSAL));
            }
            let mut value: Tree = map.next_value()?;
            let object = held.0.as_object_mut().expect("reference map");
            if object.contains_key(key.as_str()) {
                return Err(de::Error::custom(
                    "duplicate secret-reference member (value not echoed)",
                ));
            }
            object.insert(key.into_string(), std::mem::take(&mut value.0));
        }
        let object = held.0.as_object().expect("reference map");
        if !object.contains_key("module") && !object.contains_key("template") && object.len() == 1 {
            let (word, value) = object.iter().next().expect("one entry");
            if let Some(used) = self.ctx.used {
                used.word(word);
            }
            let sugar = self
                .ctx
                .sugars
                .get(word)
                .ok_or_else(|| de::Error::custom(undeclared(word)))?;
            let value = value.as_str().filter(|s| !s.trim().is_empty()).ok_or_else(||
                de::Error::custom("a declared secret shorthand requires a non-empty text value (value not echoed)"))?;
            let reference = sugar.checked_reference(value).map_err(de::Error::custom)?;
            held = Tree(serde_json::to_value(reference.writing()).map_err(de::Error::custom)?);
        }
        if held
            .0
            .as_object()
            .expect("reference map")
            .contains_key("template")
        {
            if let Some(used) = self.ctx.used {
                used.role(crate::plugin_settings::sugar_words::SUGAR_ROLE_FILL);
            }
            let reference: super::SecretRef = serde::Deserialize::deserialize(held.clone())
                .map_err(|_| de::Error::custom("malformed core template (value not echoed)"))?;
            reference
                .admitted_template(self.ctx.sugars)
                .map_err(de::Error::custom)?;
        }
        self.inner
            .visit_newtype_struct(held.into_deserializer())
            .map_err(de::Error::custom)
    }
}

/// A plugin settings bag read inside a context: read whole, its shorthand positions recorded, then
/// handed on as read. Any other shape reaches the settings reader unchanged, which refuses it
/// without echoing it.
struct Bag<'a, V> {
    inner: V,
    ctx: Ctx<'a>,
}
impl<'de, V: Visitor<'de>> Visitor<'de> for Bag<'_, V> {
    type Value = V::Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.expecting(f)
    }
    fn visit_newtype_struct<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        let tree = crate::plugin_settings::Tree::deserialize(deserializer)?;
        if let Some(used) = self.ctx.used {
            record_bag(&tree.0, used);
        }
        self.inner
            .visit_newtype_struct(tree.into_deserializer())
            .map_err(de::Error::custom)
    }
    visit_scalar!(
        visit_bool(bool),
        visit_i64(i64),
        visit_i128(i128),
        visit_u64(u64),
        visit_u128(u128),
        visit_f64(f64),
        visit_char(char),
        visit_str(&str),
        visit_string(String),
        visit_bytes(&[u8])
    );
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_unit()
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_none()
    }
    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_seq(seq)
    }
    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_map(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin_settings::sugar_words::REWRITE_SUGAR;
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
        assert!(error.contains("no admitted secret module declares `cabinet`"));
        assert!(!error.contains("not-echoed"));
        let mut sugars = declared("cabinet", "first", "entry");
        assert!(sugars
            .declare(
                "second",
                &[(REWRITE_SUGAR, "cabinet".into(), "other".into())]
            )
            .is_err());
    }

    /// A context nested inside another defers to the enclosing one: the declarations the outer
    /// reader was given govern its reference positions, whatever an inner type would install.
    #[test]
    fn the_context_nearest_the_input_governs_a_nested_one() {
        struct Inner(SecretRef);
        impl<'de> Deserialize<'de> for Inner {
            fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
                deserialize(de, &Sugars::default()).map(Inner)
            }
        }
        let outer = declared("cabinet", "owner-one", "entry");
        let mut raw = serde_json::Deserializer::from_str(r#"{"cabinet":"item"}"#);
        let read: Inner = deserialize(&mut raw, &outer).unwrap();
        assert_eq!(read.0, outer.get("cabinet").unwrap().reference("item"));
        let Err(alone) = serde_json::from_str::<Inner>(r#"{"cabinet":"item"}"#) else {
            panic!("an inner context with no owners refuses on its own");
        };
        assert!(
            alone.to_string().contains("is a secret shorthand"),
            "{alone}"
        );
    }

    /// SECRET-SHORTHAND-BOOT §3.8 (G7, G22): a recording read records the word of each reference
    /// position, declared or not, and every one-entry key of a settings bag outside `{literal: …}`
    /// and canonical `{module, settings}` subtrees. An ordinary map records nothing, and the
    /// settings still read as written.
    #[test]
    fn a_recording_read_records_reference_and_bag_words() {
        #[derive(Deserialize)]
        struct Doc {
            credential: SecretRef,
            bag: crate::plugin_settings::Settings,
            ordinary: serde_json::Value,
        }
        let sugars = declared("cabinet", "owner-one", "entry");
        let used = UsedWords::default();
        let raw = r#"{"credential":{"cabinet":"item"},"bag":{"nested":{"drawer":"x"},"kept":{"literal":{"shelf":"y"}},"canon":{"module":"m","settings":{"box":"z"}}},"ordinary":{"crate":"w"}}"#;
        let mut decoder = serde_json::Deserializer::from_str(raw);
        let read: Doc = deserialize_recording(&mut decoder, &sugars, &used).unwrap();
        assert_eq!(
            read.credential,
            sugars.get("cabinet").unwrap().reference("item")
        );
        assert_eq!(read.ordinary["crate"], "w");
        let mut keys = read.bag.key_names();
        keys.sort();
        assert_eq!(keys, ["canon", "kept", "nested"]);
        let (words, roles) = used.into_parts();
        assert_eq!(
            words.into_iter().collect::<Vec<_>>(),
            vec!["cabinet".to_owned(), "drawer".to_owned()]
        );
        assert!(roles.is_empty());
        let mut undeclared = serde_json::Deserializer::from_str(r#"{"vault":"item"}"#);
        let used = UsedWords::default();
        assert!(deserialize_recording::<SecretRef, _>(&mut undeclared, &sugars, &used).is_err());
        assert!(
            used.into_parts().0.contains("vault"),
            "an undeclared word is recorded too"
        );
    }

    /// No scalar literal at a secret-reference position is ever echoed: every one is refused with
    /// the one inline-literal sentence, through JSON, YAML and every serde scalar visitor.
    #[test]
    fn no_inline_scalar_literal_is_ever_echoed() {
        use crate::secret_ref::INLINE_LITERAL_REFUSAL;
        use serde::de::value::{BytesDeserializer, Error as ValueError};
        let refused = |error: String, literal: &str| {
            assert!(
                error.contains(INLINE_LITERAL_REFUSAL),
                "{literal}: refused with the inline-literal sentence, got {error}"
            );
            assert!(!error.contains(literal), "{literal} echoed: {error}");
        };
        let sugars = declared("cabinet", "owner-one", "entry");
        for literal in [
            "483920175534",
            "-483920175534",
            "18446744073709551615",
            "4839.20175534",
            "true",
            "false",
            "\"483920175534-secret\"",
        ] {
            let mut json = serde_json::Deserializer::from_str(literal);
            let error = deserialize::<SecretRef, _>(&mut json, &sugars)
                .err()
                .unwrap_or_else(|| panic!("{literal} admitted"));
            refused(error.to_string(), literal.trim_matches('"'));
            let error = serde_json::from_str::<SecretRef>(literal)
                .err()
                .unwrap_or_else(|| panic!("{literal} admitted without owner context"));
            refused(error.to_string(), literal.trim_matches('"'));
            let error = crate::yaml::from_str::<SecretRef>(literal)
                .err()
                .unwrap_or_else(|| panic!("{literal} admitted from YAML without owner context"));
            refused(error.to_string(), literal.trim_matches('"'));
            let yaml = format!("api_key: {literal}\n");
            #[derive(Debug, Deserialize)]
            struct Keyed {
                #[serde(rename = "api_key")]
                _api_key: SecretRef,
            }
            let error =
                crate::yaml::with_deserializer(&yaml, |d| deserialize::<Keyed, _>(d, &sugars))
                    .unwrap_err();
            refused(error.to_string(), literal.trim_matches('"'));
        }
        let scalar = |d: Result<SecretRef, ValueError>, literal: &str| {
            refused(
                d.err()
                    .unwrap_or_else(|| panic!("{literal} admitted"))
                    .to_string(),
                literal,
            );
        };
        scalar(
            deserialize(483_920_175_534_i64.into_deserializer(), &sugars),
            "483920175534",
        );
        scalar(
            deserialize(483_920_175_534_u64.into_deserializer(), &sugars),
            "483920175534",
        );
        scalar(
            deserialize(483_920_175_534_999_i128.into_deserializer(), &sugars),
            "483920175534999",
        );
        scalar(
            deserialize(483_920_175_534_999_u128.into_deserializer(), &sugars),
            "483920175534999",
        );
        scalar(
            deserialize(4839.25_f64.into_deserializer(), &sugars),
            "4839.25",
        );
        scalar(
            deserialize(4839.25_f32.into_deserializer(), &sugars),
            "4839.25",
        );
        scalar(deserialize(true.into_deserializer(), &sugars), "true");
        scalar(deserialize('Q'.into_deserializer(), &sugars), "'Q'");
        scalar(
            deserialize(BytesDeserializer::new(b"483920175534"), &sugars),
            "483920175534",
        );
        scalar(deserialize(().into_deserializer(), &sugars), "()");
    }
}
